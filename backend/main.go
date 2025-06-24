package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"io/ioutil"
	"time"
	"encoding/base64"
	"strings"
	"path/filepath"
	"strconv"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
	"backend/models"
	"github.com/satori/go.uuid"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	db     *gorm.DB
	jwtKey = []byte(getEnv("JWT_SECRET", "default-secret-key-change-in-production"))
)

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func waitForDatabase() error {
	dsn := "host=" + os.Getenv("DB_HOST") +
		" user=" + os.Getenv("DB_USER") +
		" password=" + os.Getenv("DB_PASSWORD") +
		" dbname=" + os.Getenv("DB_NAME") +
		" port=5432 sslmode=disable"

	var err error
	for i := 0; i < 30; i++ {
		db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			return nil
		}
		log.Printf("Attempt %d: Failed to connect to database: %v", i+1, err)
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("failed to connect to database after 30 attempts: %v", err)
}

func createDefaultAdmin() error {
	var count int64
	db.Model(&models.User{}).Where("username = ?", "admin").Count(&count)
	if count > 0 {
		return nil // Admin already exists
	}

	adminPassword := getEnv("DEFAULT_ADMIN_PASSWORD", "admin")
	if adminPassword == "admin" {
		log.Println("[WARNING] Using default admin password. Please set DEFAULT_ADMIN_PASSWORD environment variable for production.")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	admin := models.User{
		Username: "admin",
		Email:    "admin@wireguard-manager.com",
		Password: string(hash),
		Role:     "admin",
	}

	if err := db.Create(&admin).Error; err != nil {
		return err
	}

	log.Printf("Default admin user created: admin/%s", adminPassword)
	return nil
}

func main() {
	// Wait for database to be ready
	if err := waitForDatabase(); err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	// Migración automática de tablas
	if err := db.AutoMigrate(&models.User{}, &models.Server{}, &models.Peer{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create default admin user
	if err := createDefaultAdmin(); err != nil {
		log.Printf("Warning: Failed to create default admin: %v", err)
	}

	// Initialize router
	r := gin.Default()

	// Security middleware
	r.Use(cors.New(cors.Config{
		// AllowOrigins:     []string{"http://localhost:3000", "http://127.0.0.1:3000"},
		AllowAllOrigins:     true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Public routes
	r.POST("/api/auth/login", handleLogin)
	r.POST("/api/auth/register", handleRegister)

	// Protected routes
	authorized := r.Group("/api")
	authorized.Use(authMiddleware())
	{
		// Server management
		authorized.POST("/servers", createServer)
		authorized.GET("/servers", listServers)
		authorized.DELETE("/servers/:id", deleteServer)

		// Peer management
		authorized.POST("/peers", createPeer)
		authorized.GET("/peers", listPeers)
		authorized.DELETE("/peers/:id", deletePeer)
		authorized.GET("/peers/:id/qrcode", getPeerQRCode)
		authorized.GET("/peers/:id/config", getPeerConfig)

		// User management
		authorized.GET("/users", listUsers)
		authorized.POST("/users", createUser)
		authorized.PUT("/users/:id", updateUser)
		authorized.DELETE("/users/:id", deleteUser)
		authorized.GET("/auth/me", getMe)

		// Server Actions
		authorized.POST("/servers/:id/start", startServer)
		authorized.POST("/servers/:id/stop", stopServer)
		authorized.POST("/servers/:id/restart", restartServer)
		authorized.GET("/servers/:id/status", getServerStatus)

		// WireGuard management
		authorized.POST("/wg/genkeys", wgGenKeys)

		// Dashboard stats
		authorized.GET("/stats", getStats)
	}

	// Start server
	log.Println("Server starting on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Remove "Bearer " prefix if present
		if len(tokenString) > 7 && tokenString[:7] == "Bearer " {
			tokenString = tokenString[7:]
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims := token.Claims.(jwt.MapClaims)
		c.Set("user_id", claims["user_id"])
		c.Next()
	}
}

func handleRegister(c *gin.Context) {
	log.Println("[DEBUG] handleRegister called")
	type RegisterInput struct {
		Username string `json:"username" binding:"required,alphanum,min=3,max=32"`
		Email    string `json:"email" binding:"required,email,max=128"`
		Password string `json:"password" binding:"required,min=8,max=128"`
		Role     string `json:"role"`
	}
	var input RegisterInput
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Println("[DEBUG] Invalid input:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos: " + err.Error()})
		return
	}
	log.Printf("[DEBUG] Register input: %+v\n", input)

	// Set default role if not provided
	if input.Role == "" {
		input.Role = "user"
	}

	// Check if user exists (username or email)
	var count int64
	db.Model(&models.User{}).Where("username = ? OR email = ?", input.Username, input.Email).Count(&count)
	if count > 0 {
		log.Println("[DEBUG] User already exists:", input.Username, input.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "El usuario o email ya existe"})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("[DEBUG] Failed to hash password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error interno de servidor"})
		return
	}

	user := models.User{
		Username: input.Username,
		Email:    input.Email,
		Password: string(hash),
		Role:     input.Role,
	}
	log.Printf("[DEBUG] About to insert user: %+v\n", user)
	if err := db.Create(&user).Error; err != nil {
		log.Println("[DEBUG] Failed to create user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al crear usuario"})
		return
	}

	log.Printf("[DEBUG] User created: %+v\n", user)
	token := generateJWT(user.ID)
	c.JSON(http.StatusOK, gin.H{"token": token, "user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "role": user.Role}})
}

func handleLogin(c *gin.Context) {
	type LoginInput struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password" binding:"required"`
	}
	var input LoginInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var user models.User
	if input.Username != "" {
		db.Where("username = ?", input.Username).First(&user)
	} else if input.Email != "" {
		db.Where("email = ?", input.Email).First(&user)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username or email required"})
		return
	}

	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token := generateJWT(user.ID)
	c.JSON(http.StatusOK, gin.H{"token": token, "user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email}})
}

func generateJWT(userID uint) string {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(72 * time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(jwtKey)
	return tokenString
}

func createServer(c *gin.Context) {
	log.Println("[DEBUG] createServer called")
	type ServerInput struct {
		Name       string `json:"name" binding:"required"`
		PublicKey  string `json:"publicKey" binding:"required"`
		PrivateKey string `json:"privateKey" binding:"required"`
		ListenPort int    `json:"listenPort" binding:"required"`
		Address    string `json:"address" binding:"required"`
		DNS        string `json:"dns"`
		MTU        int    `json:"mtu"`
		ConfigPath string `json:"configPath" binding:"required"`
	}
	var input ServerInput
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Println("[DEBUG] Invalid server input:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check for name conflicts
	var existingServerName models.Server
	if err := db.Where("name = ?", input.Name).First(&existingServerName).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Server with name '%s' already exists", input.Name)})
		return
	}

	// Check for port conflicts
	var existingServer models.Server
	if err := db.Where("listen_port = ?", input.ListenPort).First(&existingServer).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("Port %d is already in use by another server", input.ListenPort)})
		return
	}

	log.Printf("[DEBUG] Server input: %+v\n", input)
	server := models.Server{
		Name:       input.Name,
		PublicKey:  input.PublicKey,
		PrivateKey: input.PrivateKey,
		ListenPort: input.ListenPort,
		Address:    input.Address,
		DNS:        input.DNS,
		MTU:        input.MTU,
		ConfigPath: strings.TrimSuffix(input.ConfigPath, ".conf"),
	}
	log.Printf("[DEBUG] About to insert server: %+v\n", server)
	if err := db.Create(&server).Error; err != nil {
		log.Println("[DEBUG] Failed to create server:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}
	log.Printf("[DEBUG] Server created: %+v\n", server)
	c.JSON(http.StatusOK, server)
}

func getBulkServerStatus() (map[string]string, error) {
	// This command lists all running containers with a name starting with "wg-manager-"
	// and formats the output as "container_name:status"
	cmd := exec.Command("docker", "ps", "--filter", "name=wg-manager-", "--format", "{{.Names}}:{{.State}}")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] Failed to execute 'docker ps': %v, Output: %s", err, string(out))
		return nil, err
	}

	statusMap := make(map[string]string)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return statusMap, nil // No containers found
	}

	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			// e.g. parts[0] = "wg-manager-ab12cd", parts[1] = "running"
			status := "inactive"
			if parts[1] == "running" {
				status = "active"
			}
			statusMap[parts[0]] = status
		}
	}
	log.Printf("[DEBUG] getBulkServerStatus found active containers: %v", statusMap)
	return statusMap, nil
}

func listServers(c *gin.Context) {
	log.Println("[DEBUG] listServers called")
	var servers []models.Server
	if err := db.Preload("Peers").Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list servers"})
		return
	}

	statusMap, err := getBulkServerStatus()
	if err != nil {
		log.Printf("[WARNING] Could not get bulk server status: %v", err)
		// Continue without status info if docker command fails
	}

	// Define a specific struct for the response to control JSON field names (camelCase)
	// and only expose the data needed by the frontend.
	type ServerResponse struct {
		ID         uint   `json:"id"`
		Name       string `json:"name"`
		Address    string `json:"address"`
		ListenPort int    `json:"listenPort"`
		Status     string `json:"status"`
		PublicKey  string `json:"publicKey"`
		Peers      []models.Peer `json:"peers"`
	}

	response := make([]ServerResponse, 0)
	for _, s := range servers {
		// interfaceName := getInterfaceName(s.ConfigPath)
		status, ok := statusMap[s.ContainerName]
		if !ok {
			status = "inactive" // Default to inactive if not found in docker ps output
		}
		response = append(response, ServerResponse{
			ID:         s.ID,
			Name:       s.Name,
			Address:    s.Address,
			ListenPort: s.ListenPort,
			Status:     status,
			PublicKey:  s.PublicKey,
			Peers:      s.Peers,
		})
	}

	log.Printf("[DEBUG] Found %d servers", len(servers))
	c.JSON(http.StatusOK, response)
}

func deleteServer(c *gin.Context) {
	id := c.Param("id")

	// Buscar el servidor para obtener el ContainerName antes de eliminarlo
	var server models.Server
	if err := db.First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if server.ContainerName != "" {
		// Eliminar el contenedor Docker asociado si existe
		cmd := exec.Command("docker", "rm", "-f", server.ContainerName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[WARNING] Could not remove container %s: %v, Output: %s", server.ContainerName, err, string(out))
		} else {
			log.Printf("[INFO] Removed container %s before deleting server", server.ContainerName)
		}
	}

	if err := db.Delete(&models.Server{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete server"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Server deleted successfully"})
}

func createPeer(c *gin.Context) {
	log.Println("[DEBUG] createPeer called")
	type PeerInput struct {
		Name     string `json:"name" binding:"required"`
		ServerID uint   `json:"serverID" binding:"required"`
	}
	var input PeerInput
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Println("[DEBUG] Invalid peer input:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("[DEBUG] Peer input: %+v\n", input)

	// Get the server to find the next available IP
	var server models.Server
	if err := db.Preload("Peers").First(&server, input.ServerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Simple IP allocation: find the last peer's IP and increment it.
	// NOTE: This is a very basic allocation and has limitations.
	// It assumes a /24 subnet and doesn't handle deleted IPs in the middle.
	lastIP := server.Address                                          // e.g., "10.0.0.1/24"
	ipParts := strings.Split(strings.Split(lastIP, "/")[0], ".") // ["10", "0", "0", "1"]

	// Get the last octet and increment it for the next peer
	lastOctet, _ := strconv.Atoi(ipParts[3])
	nextOctet := lastOctet + 1 + len(server.Peers)

	// Construct the new peer address
	newPeerAddress := fmt.Sprintf("%s.%s.%s.%d/32", ipParts[0], ipParts[1], ipParts[2], nextOctet)

	peer := models.Peer{
		Name:       input.Name,
		Address:    newPeerAddress,
		AllowedIPs: newPeerAddress, // A peer is typically allowed its own IP
		ServerID:   input.ServerID,
		// PublicKey and PrivateKey will be generated by the wireguard container
	}

	log.Printf("[DEBUG] About to insert peer: %+v\n", peer)
	if err := db.Create(&peer).Error; err != nil {
		log.Println("[DEBUG] Failed to create peer:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create peer"})
		return
	}
	log.Printf("[DEBUG] Peer created: %+v\n", peer)

	// Get the fresh server object to restart it, as the `server` variable
	// above doesn't have the new peer in its .Peers slice
	var freshServer models.Server
	if err := db.Preload("Peers").First(&freshServer, peer.ServerID).Error; err != nil {
		log.Printf("[ERROR] Peer %d created but its server %d was not found for restart: %v", peer.ID, peer.ServerID, err)
		c.JSON(http.StatusOK, peer) // Still return success, but log the error
		return
	}

	// Restart the server's container in the background to apply the new peer
	go func() {
		if freshServer.ContainerName != "" {
			if err := restartServerContainer(&freshServer); err != nil {
				log.Printf("[ERROR] Failed to restart server container for peer creation: %v", err)
			}
		} else {
			log.Printf("[INFO] Server %s has no active container. Peer will be added on next start.", freshServer.Name)
		}
	}()

	c.JSON(http.StatusOK, peer)
}

func listPeers(c *gin.Context) {
	log.Println("[DEBUG] listPeers called")
	var peers []models.Peer
	if err := db.Find(&peers).Error; err != nil {
		log.Println("[DEBUG] Failed to list peers:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list peers"})
		return
	}

	// Create a specific response struct to control JSON field names (camelCase)
	type PeerResponse struct {
		ID         uint   `json:"id"`
		Name       string `json:"name"`
		PublicKey  string `json:"publicKey"`
		Address    string `json:"address"`
		DNS        string `json:"dns"`
		AllowedIPs string `json:"allowedIPs"`
		ServerID   uint   `json:"serverID"`
		Status     string `json:"status"`
	}

	response := make([]PeerResponse, 0)
	for _, p := range peers {
		response = append(response, PeerResponse{
			ID:         p.ID,
			Name:       p.Name,
			PublicKey:  p.PublicKey,
			Address:    p.Address,
			DNS:        p.DNS,
			AllowedIPs: p.AllowedIPs,
			ServerID:   p.ServerID,
			Status:     p.Status,
		})
	}

	log.Printf("[DEBUG] Found %d peers", len(response))
	c.JSON(http.StatusOK, response)
}

func deletePeer(c *gin.Context) {
	id := c.Param("id")

	// We need server info *before* deleting the peer to trigger a restart
	var peer models.Peer
	if err := db.First(&peer, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Peer not found"})
		return
	}
	var server models.Server
	if err := db.First(&server, peer.ServerID).Error; err != nil {
		log.Printf("[WARNING] Peer %s found but its server %d was not. Deleting peer anyway.", id, peer.ServerID)
		// Fall through to delete the peer even if server is gone.
	}

	if err := db.Delete(&models.Peer{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete peer"})
		return
	}

	// Restart the server's container in the background to apply the peer removal
	if server.ID != 0 && server.ContainerName != "" {
		go func() {
			// We need a fresh server object to get the updated peer list for the PEERS count
			var freshServer models.Server
			if err := db.Preload("Peers").First(&freshServer, server.ID).Error; err != nil {
				log.Printf("[ERROR] Failed to reload server for container restart after peer deletion: %v", err)
				return
			}
			if err := restartServerContainer(&freshServer); err != nil {
				log.Printf("[ERROR] Failed to restart server container for peer deletion: %v", err)
			}
		}()
	}

	c.JSON(http.StatusOK, gin.H{"message": "Peer deleted successfully"})
}

func getPeerQRCode(c *gin.Context) {
	id := c.Param("id")
	var peer models.Peer
	if err := db.First(&peer, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Peer not found"})
		return
	}

	// Get server info for the endpoint
	var server models.Server
	if err := db.First(&server, peer.ServerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server for peer not found"})
		return
	}

	// Get all peers for the server, ordered, to find the index of our peer.
	// The linuxserver/wireguard container creates peers sequentially (peer1, peer2, ...),
	// which may not match our database ID if peers have been deleted.
	var serverPeers []models.Peer
	if err := db.Where("server_id = ?", server.ID).Order("id asc").Find(&serverPeers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list server peers to determine config path"})
		return
	}

	peerIndex := -1
	for i, p := range serverPeers {
		if p.ID == peer.ID {
			peerIndex = i + 1 // Peer numbers are 1-based
			break
		}
	}

	if peerIndex == -1 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not find peer in server's peer list"})
		return
	}

	// The config is now generated by the linuxserver/wireguard container.
	// We just need to read it. The path is now based on the peer's index, not its ID.
	peerConfigPath := filepath.Join(server.ConfigPath, "peer"+strconv.Itoa(peerIndex), "peer"+strconv.Itoa(peerIndex)+".conf")

	configBytes, err := ioutil.ReadFile(peerConfigPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read peer config file at %s: %v", peerConfigPath, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read peer config file"})
		return
	}
	config := string(configBytes)

	// Generate QR code PNG using qrencode
	cmd := exec.Command("qrencode", "-o", "-", "-t", "PNG")
	cmd.Stdin = strings.NewReader(config)

	pngData, err := cmd.Output()
	if err != nil {
		log.Printf("[ERROR] Failed to generate QR code: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate QR code"})
		return
	}

	// Encode PNG to base64 and create a data URI
	qrCodeBase64 := base64.StdEncoding.EncodeToString(pngData)
	qrCodeDataURI := fmt.Sprintf("data:image/png;base64,%s", qrCodeBase64)

	c.JSON(http.StatusOK, gin.H{"qrcode": qrCodeDataURI})
}

func getPeerConfig(c *gin.Context) {
	id := c.Param("id")
	var peer models.Peer
	if err := db.First(&peer, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Peer not found"})
		return
	}

	// Get server info
	var server models.Server
	if err := db.First(&server, peer.ServerID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Get all peers for the server, ordered, to find the index of our peer.
	// The linuxserver/wireguard container creates peers sequentially (peer1, peer2, ...),
	// which may not match our database ID if peers have been deleted.
	var serverPeers []models.Peer
	if err := db.Where("server_id = ?", server.ID).Order("id asc").Find(&serverPeers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list server peers to determine config path"})
		return
	}

	peerIndex := -1
	for i, p := range serverPeers {
		if p.ID == peer.ID {
			peerIndex = i + 1 // Peer numbers are 1-based
			break
		}
	}

	if peerIndex == -1 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not find peer in server's peer list"})
		return
	}

	// The config is now generated by the linuxserver/wireguard container.
	// We just need to read it. The path is now based on the peer's index, not its ID.
	peerConfigPath := filepath.Join(server.ConfigPath, "peer"+strconv.Itoa(peerIndex), "peer"+strconv.Itoa(peerIndex)+".conf")

	configBytes, err := ioutil.ReadFile(peerConfigPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read peer config file at %s: %v", peerConfigPath, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read peer config file"})
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=wg-%s.conf", peer.Name))
	c.String(http.StatusOK, string(configBytes))
}

func listUsers(c *gin.Context) {
	var users []models.User
	if err := db.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list users"})
		return
	}

	// Create a specific response struct to control JSON field names (camelCase)
	// and prevent leaking sensitive data like password hashes.
	type UserResponse struct {
		ID       uint   `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}

	response := make([]UserResponse, 0)
	for _, u := range users {
		response = append(response, UserResponse{
			ID:       u.ID,
			Username: u.Username,
			Email:    u.Email,
			Role:     u.Role,
		})
	}

	c.JSON(http.StatusOK, response)
}

func createUser(c *gin.Context) {
	log.Println("[DEBUG] createUser called")
	type UserInput struct {
		Username string `json:"username" binding:"required,alphanum,min=3,max=32"`
		Email    string `json:"email" binding:"required,email,max=128"`
		Password string `json:"password" binding:"required,min=8,max=128"`
		Role     string `json:"role"`
	}
	var input UserInput
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Println("[DEBUG] Invalid input:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Datos inválidos: " + err.Error()})
		return
	}
	log.Printf("[DEBUG] User input: %+v\n", input)

	// Set default role if not provided
	if input.Role == "" {
		input.Role = "user"
	}

	// Check if user exists (username or email)
	var count int64
	db.Model(&models.User{}).Where("username = ? OR email = ?", input.Username, input.Email).Count(&count)
	if count > 0 {
		log.Println("[DEBUG] User already exists:", input.Username, input.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "El usuario o email ya existe"})
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("[DEBUG] Failed to hash password:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error interno de servidor"})
		return
	}

	user := models.User{
		Username: input.Username,
		Email:    input.Email,
		Password: string(hash),
		Role:     input.Role,
	}
	log.Printf("[DEBUG] About to insert user: %+v\n", user)
	if err := db.Create(&user).Error; err != nil {
		log.Println("[DEBUG] Failed to create user:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error al crear usuario"})
		return
	}

	log.Printf("[DEBUG] User created: %+v\n", user)
	token := generateJWT(user.ID)
	c.JSON(http.StatusOK, gin.H{"token": token, "user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "role": user.Role}})
}

func updateUser(c *gin.Context) {
	id := c.Param("id")
	var user models.User
	if err := db.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	var input struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Role     string `json:"role"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if username or email already exists (excluding current user)
	if input.Username != "" && input.Username != user.Username {
		var count int64
		db.Model(&models.User{}).Where("username = ? AND id != ?", input.Username, id).Count(&count)
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
			return
		}
		user.Username = input.Username
	}

	if input.Email != "" && input.Email != user.Email {
		var count int64
		db.Model(&models.User{}).Where("email = ? AND id != ?", input.Email, id).Count(&count)
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Email already exists"})
			return
		}
		user.Email = input.Email
	}

	if input.Role != "" {
		user.Role = input.Role
	}

	if input.Password != "" {
		if len(input.Password) < 8 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters"})
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
			return
		}
		user.Password = string(hash)
	}

	if err := db.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully", "user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "role": user.Role}})
}

func deleteUser(c *gin.Context) {
	id := c.Param("id")
	if err := db.Delete(&models.User{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func getMe(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized: No user ID in token"})
		return
	}

	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"role":     user.Role,
	})
}

// Endpoint: Generar claves privadas/públicas
func wgGenKeys(c *gin.Context) {
	// Generate keys using the native Go library instead of shelling out to wg
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		log.Printf("[ERROR] Failed to generate private key: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate private key", "details": err.Error()})
		return
	}

	privKey := key.String()
	pubKey := key.PublicKey().String()

	c.JSON(http.StatusOK, gin.H{"privateKey": privKey, "publicKey": pubKey})
}

func getInterfaceName(configPath string) string {
	// Extracts "wg0" from "/etc/wireguard/wg0.conf"
	return strings.TrimSuffix(filepath.Base(configPath), filepath.Ext(configPath))
}

func getServerFromContext(c *gin.Context) (*models.Server, error) {
	id := c.Param("id")
	var server models.Server
	if err := db.Preload("Peers").First(&server, id).Error; err != nil {
		return nil, err
	}
	return &server, nil
}

func startServer(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Generate a unique container name if it doesn't exist
	if server.ContainerName == "" {
		u := uuid.NewV4()
		server.ContainerName = "wg-manager-" + u.String()[:8]
		if err := db.Save(server).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save unique container name"})
			return
		}
	}

	go func() {
		// 1. Eliminar cualquier contenedor con el mismo nombre
		log.Printf("[DEBUG] BG: Removing any existing container named %s", server.ContainerName)
		exec.Command("docker", "rm", "-f", server.ContainerName).Run()

		// 2. Eliminar cualquier contenedor que esté usando el puerto deseado
		// Buscar contenedores que tengan el puerto mapeado
		portStr := fmt.Sprintf("%d/udp", server.ListenPort)
		cmd := exec.Command("docker", "ps", "--filter", fmt.Sprintf("publish=%s", portStr), "--format", "{{.ID}}")
		out, err := cmd.CombinedOutput()
		if err == nil && len(strings.TrimSpace(string(out))) > 0 {
			containerIDs := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, cid := range containerIDs {
				if cid != "" {
					log.Printf("[DEBUG] BG: Removing container %s that is using port %s", cid, portStr)
					exec.Command("docker", "rm", "-f", cid).Run()
				}
			}
		}

		publicIP := getEnv("WG_PUBLIC_IP", "")
		if publicIP == "" {
			log.Printf("[ERROR] BG: WG_PUBLIC_IP environment variable not set. Cannot start container.")
			return
		}

		// Use the server.ConfigPath for the volume mount on the host side.
		hostConfigPath := server.ConfigPath
		
		cmd = exec.Command("docker", "run", "-d",
			"--name="+server.ContainerName,
			"--cap-add=NET_ADMIN",
			"--cap-add=SYS_MODULE",
			"-p", fmt.Sprintf("%d:51820/udp", server.ListenPort),
			"-e", "PUID=1000",
			"-e", "PGID=1000",
			"-e", "TZ=Etc/UTC",
			"-e", "SERVERURL="+publicIP,
			"-e", "SERVERPORT="+strconv.Itoa(server.ListenPort),
			"-e", "PEERS="+strconv.Itoa(len(server.Peers)),
			"-e", "PEERDNS=auto",
			"-e", "INTERNAL_SUBNET="+server.Address,
			"-e", "ALLOWEDIPS=0.0.0.0/0",
			"-e", "LOG_CONFS=true",
			"-v", hostConfigPath+":/config",
			"-v", "/lib/modules:/lib/modules",
			"--sysctl=net.ipv4.conf.all.src_valid_mark=1",
			"--sysctl=net.ipv4.ip_forward=1",
			"--restart=unless-stopped",
			"lscr.io/linuxserver/wireguard:latest",
		)

		log.Printf("[DEBUG] BG: Running command: %s", cmd.String())
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] BG: Failed to start container for server %s. Output: %s, Error: %v", server.Name, string(out), err)
		} else {
			log.Printf("[INFO] BG: Container %s for server %s started successfully. Output: %s", server.ContainerName, server.Name, string(out))
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": fmt.Sprintf("Start for server %s initiated in background", server.Name)})
}

func stopServer(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	go func() {
		cmd := exec.Command("docker", "stop", server.ContainerName)
		log.Printf("[DEBUG] BG: Running command: docker stop %s", server.ContainerName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] BG: Failed to stop container %s. Output: %s, Error: %v", server.ContainerName, string(out), err)
		} else {
			log.Printf("[INFO] BG: Container %s stopped successfully. Output: %s", server.ContainerName, string(out))
		}

		// Also remove the container so it can be started fresh
		cmd = exec.Command("docker", "rm", server.ContainerName)
		log.Printf("[DEBUG] BG: Running command: docker rm %s", server.ContainerName)
		out, err = cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] BG: Failed to remove container %s. Output: %s, Error: %v", server.ContainerName, string(out), err)
		} else {
			log.Printf("[INFO] BG: Container %s removed successfully. Output: %s", server.ContainerName, string(out))
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": fmt.Sprintf("Stop for server %s initiated in background", server.Name)})
}

func restartServer(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	go func() {
		cmd := exec.Command("docker", "restart", server.ContainerName)
		log.Printf("[DEBUG] BG: Running command: docker restart %s", server.ContainerName)
		out, err := cmd.CombinedOutput()
		if err != nil {
			log.Printf("[ERROR] BG: Failed to restart container %s. Output: %s, Error: %v", server.ContainerName, string(out), err)
		} else {
			log.Printf("[INFO] BG: Container %s restarted successfully. Output: %s", server.ContainerName, string(out))
		}
	}()

	c.JSON(http.StatusAccepted, gin.H{"message": fmt.Sprintf("Restart for server %s initiated in background", server.Name)})
}

// restartServerContainer stops, removes, and starts a new container for a given server,
// ensuring the PEERS environment variable is up-to-date. This is a synchronous operation.
func restartServerContainer(server *models.Server) error {
	log.Printf("[INFO] Initiating container restart for server: %s (Container: %s)", server.Name, server.ContainerName)
	// Stop
	if server.ContainerName != "" {
		stopCmd := exec.Command("docker", "stop", server.ContainerName)
		log.Printf("[DEBUG] Restarting container: stopping %s", server.ContainerName)
		if out, err := stopCmd.CombinedOutput(); err != nil {
			// Log error but continue, maybe it wasn't running
			log.Printf("[WARNING] Failed to stop container %s during restart. It might not have been running. Output: %s, Error: %v", server.ContainerName, string(out), err)
		}

		// Remove
		rmCmd := exec.Command("docker", "rm", server.ContainerName)
		log.Printf("[DEBUG] Restarting container: removing %s", server.ContainerName)
		if out, err := rmCmd.CombinedOutput(); err != nil {
			// Log error but continue
			log.Printf("[WARNING] Failed to remove container %s during restart. Output: %s, Error: %v", server.ContainerName, string(out), err)
		} else {
			log.Printf("[INFO] BG: Container %s removed successfully. Output: %s", server.ContainerName, string(out))
		}
	} else {
		log.Printf("[INFO] Server %s has no container name, cannot stop/rm. Will proceed to start.", server.Name)
	}

	// Start (logic adapted from startServer)
	publicIP := getEnv("WG_PUBLIC_IP", "")
	if publicIP == "" {
		log.Printf("[ERROR] WG_PUBLIC_IP environment variable not set. Cannot start container.")
		return fmt.Errorf("WG_PUBLIC_IP not set")
	}

	// We need to reload the server object to get the updated Peers list
	var freshServer models.Server
	if err := db.Preload("Peers").First(&freshServer, server.ID).Error; err != nil {
		return fmt.Errorf("failed to reload server from db: %w", err)
	}

	hostConfigPath := freshServer.ConfigPath
	
	// The container will create configs for peer1, peer2... up to PEERS count.
	// We need to tell it how many peers exist now.
	peerCount := len(freshServer.Peers)
	log.Printf("[INFO] Starting container for server %s with PEERS=%d", freshServer.Name, peerCount)

	startCmd := exec.Command("docker", "run", "-d",
		"--name="+freshServer.ContainerName,
		"--cap-add=NET_ADMIN",
		"--cap-add=SYS_MODULE",
		"-p", fmt.Sprintf("%d:51820/udp", freshServer.ListenPort),
		"-e", "PUID=1000",
		"-e", "PGID=1000",
		"-e", "TZ=Etc/UTC",
		"-e", "SERVERURL="+publicIP,
		"-e", "SERVERPORT="+strconv.Itoa(freshServer.ListenPort),
		"-e", "PEERS="+strconv.Itoa(peerCount),
		"-e", "PEERDNS=auto",
		"-e", "INTERNAL_SUBNET="+freshServer.Address,
		"-e", "ALLOWEDIPS=0.0.0.0/0",
		"-e", "LOG_CONFS=true",
		"-v", hostConfigPath+":/config",
		"-v", "/lib/modules:/lib/modules",
		"--sysctl=net.ipv4.conf.all.src_valid_mark=1",
		"--sysctl=net.ipv4.ip_forward=1",
		"--restart=unless-stopped",
		"lscr.io/linuxserver/wireguard:latest",
	)

	log.Printf("[DEBUG] Restarting container: running command: %s", startCmd.String())
	if out, err := startCmd.CombinedOutput(); err != nil {
		log.Printf("[ERROR] Failed to start container for server %s during restart. Output: %s, Error: %v", freshServer.Name, string(out), err)
		return err
	} else {
		log.Printf("[INFO] Container %s for server %s restarted successfully. Output: %s", freshServer.ContainerName, freshServer.Name, string(out))
	}
	return nil
}

func getServerStatus(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	cmd := exec.Command("docker", "ps", "-f", "name="+server.ContainerName, "-f", "status=running")
	out, err := cmd.CombinedOutput()

	// If there's no output, the container isn't running.
	if err != nil || len(strings.TrimSpace(string(out))) < 100 { // Heuristic check for empty output
		c.JSON(http.StatusOK, gin.H{"status": "inactive"})
		return
	}

	// If there's output and no error, it's active.
	c.JSON(http.StatusOK, gin.H{"status": "active", "details": string(out)})
}

// Handler para /api/stats
func getStats(c *gin.Context) {
	var totalServers int64
	db.Model(&models.Server{}).Count(&totalServers)

	var totalPeers int64
	db.Model(&models.Peer{}).Count(&totalPeers)

	var activePeers int64
	db.Model(&models.Peer{}).Where("status = ?", "active").Count(&activePeers)

	var rx, tx int64
	db.Model(&models.Peer{}).Select("COALESCE(SUM(transfer_rx),0)").Scan(&rx)
	db.Model(&models.Peer{}).Select("COALESCE(SUM(transfer_tx),0)").Scan(&tx)

	c.JSON(200, gin.H{
		"totalServers": totalServers,
		"totalPeers": totalPeers,
		"activePeers": activePeers,
		"traffic": gin.H{
			"rx": rx,
			"tx": tx,
		},
	})
} 