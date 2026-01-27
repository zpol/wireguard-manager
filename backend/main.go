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

const localNodeName = "local"

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func parseNodes(nodesStr string) []string {
	nodes := strings.Fields(nodesStr)
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		trimmed := strings.TrimSpace(node)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func resolveTargetNodes(mode string) ([]string, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "all"
	}
	switch mode {
	case "local":
		return []string{localNodeName}, nil
	case "all":
		nodes := parseNodes(getEnv("SSH_NODES", ""))
		if len(nodes) == 0 {
			return nil, fmt.Errorf("SSH_NODES is empty")
		}
		return nodes, nil
	default:
		return nil, fmt.Errorf("invalid deploymentMode: %s", mode)
	}
}

func getEffectiveTargetNodes(server models.Server) []string {
	if strings.TrimSpace(server.TargetNodes) != "" {
		return parseNodes(server.TargetNodes)
	}
	mode := server.DeploymentMode
	if mode == "" {
		mode = "all"
	}
	nodes, err := resolveTargetNodes(mode)
	if err != nil {
		return []string{}
	}
	return nodes
}

// Función para obtener el endpoint del servidor (FQDN o IP)
func getServerEndpoint() string {
	fqdn := getEnv("WG_FQDN", "")
	if fqdn != "" {
		return fqdn
	}
	return getEnv("WG_PUBLIC_IP", "")
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
		authorized.PUT("/peers/:id", updatePeer)

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
		PublicKey  string `json:"publicKey"`
		PrivateKey string `json:"privateKey"`
		ListenPort int    `json:"listenPort" binding:"required"`
		Address    string `json:"address" binding:"required"`
		DNS        string `json:"dns"`
		MTU        int    `json:"mtu"`
		InitialPeers int  `json:"initialPeers"`
		DeploymentMode string `json:"deploymentMode"`
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

	// Backend manages the config path now
	configPathForBackend := filepath.Join("/wg-configs", input.Name)
	if err := os.MkdirAll(configPathForBackend, 0755); err != nil {
		log.Printf("[ERROR] Could not create config directory %s: %v", configPathForBackend, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server config directory"})
		return
	}

	targetNodes, err := resolveTargetNodes(input.DeploymentMode)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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
		ConfigPath: configPathForBackend, // Use backend-managed path
		DeploymentMode: strings.ToLower(strings.TrimSpace(input.DeploymentMode)),
		TargetNodes: strings.Join(targetNodes, " "),
	}
	log.Printf("[DEBUG] About to insert server: %+v\n", server)
	if err := db.Create(&server).Error; err != nil {
		log.Println("[DEBUG] Failed to create server:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create server"})
		return
	}
	log.Printf("[DEBUG] Server created: %+v\n", server)

	// Crear N peers iniciales si initialPeers > 0
	peersToCreate := input.InitialPeers
	if peersToCreate < 0 { peersToCreate = 0 }
	for i := 1; i <= peersToCreate; i++ {
		peerName := fmt.Sprintf("peer%d", i)
		// Asignar IP secuencial
		ipParts := strings.Split(strings.Split(server.Address, "/")[0], ".")
		lastOctet, _ := strconv.Atoi(ipParts[3])
		peerIP := fmt.Sprintf("%s.%s.%s.%d/32", ipParts[0], ipParts[1], ipParts[2], lastOctet+i)
		peer := models.Peer{
			Name: peerName,
			Address: peerIP,
			AllowedIPs: peerIP,
			ServerID: server.ID,
		}
		if err := db.Create(&peer).Error; err != nil {
			log.Printf("[WARNING] Could not create initial peer %s: %v", peerName, err)
		}
	}

	// Lanzar el contenedor con el valor correcto de PEERS en los nodos seleccionados
	go func(srv models.Server, nPeers int) {
		targetNodes := getEffectiveTargetNodes(srv)
		if srv.ContainerName == "" {
			u := uuid.NewV4()
			srv.ContainerName = "wg-manager-" + u.String()[:8]
			db.Save(&srv)
		}
		// Eliminar cualquier contenedor previo en ambos nodos
		// runDockerOnAllNodes("rm", "-f", srv.ContainerName)
		publicIP := getServerEndpoint()
		hostConfigsPath := getEnv("HOST_WG_CONFIGS_PATH", "")
		hostPathForServer := filepath.Join(hostConfigsPath, srv.Name)
		dockerArgs := []string{
			"run", "-d",
			"--name=" + srv.ContainerName,
			"--cap-add=NET_ADMIN",
			"--cap-add=SYS_MODULE",
			"-p", fmt.Sprintf("%d:51820/udp", srv.ListenPort),
			"-e", "PUID=1000",
			"-e", "PGID=1000",
			"-e", "TZ=Etc/UTC",
			"-e", "SERVERURL=" + publicIP,
			"-e", "SERVERPORT=" + strconv.Itoa(srv.ListenPort),
			"-e", "PEERS=" + strconv.Itoa(nPeers),
			"-e", "PEERDNS=auto",
			"-e", "INTERNAL_SUBNET=" + srv.Address,
			"-e", "ALLOWEDIPS=0.0.0.0/0",
			"-e", "LOG_CONFS=true",
			"-v", hostPathForServer + ":/config",
			"-v", "/lib/modules:/lib/modules",
			"--sysctl=net.ipv4.conf.all.src_valid_mark=1",
			"--sysctl=net.ipv4.ip_forward=1",
			"--restart=unless-stopped",
			"lscr.io/linuxserver/wireguard:latest",
		}
		runDockerOnNodes(targetNodes, dockerArgs...)
	}(server, peersToCreate)

	c.JSON(http.StatusOK, server)
}

func listServers(c *gin.Context) {
	log.Println("[DEBUG] listServers called")
	var servers []models.Server
	if err := db.Preload("Peers").Find(&servers).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list servers"})
		return
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
		DeploymentMode string `json:"deploymentMode"`
		TargetNodes []string `json:"targetNodes"`
		ActiveNodes []string `json:"activeNodes"`
		Peers      []models.Peer `json:"peers"`
	}

	response := make([]ServerResponse, 0)
	for _, s := range servers {
		status := "inactive"
		targetNodes := getEffectiveTargetNodes(s)
		activeNodes := make([]string, 0)
		for _, node := range targetNodes {
			nodeStatus, err := getContainerStatusOnNode(node, s.ContainerName)
			if err != nil {
				continue
			}
			if nodeStatus == "active" {
				activeNodes = append(activeNodes, node)
			}
		}
		if len(activeNodes) > 0 {
			status = "active"
		}
		response = append(response, ServerResponse{
			ID:         s.ID,
			Name:       s.Name,
			Address:    s.Address,
			ListenPort: s.ListenPort,
			Status:     status,
			PublicKey:  s.PublicKey,
			DeploymentMode: s.DeploymentMode,
			TargetNodes: targetNodes,
			ActiveNodes: activeNodes,
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
		// Eliminar el contenedor Docker asociado si existe en ambos nodos
		runDockerOnNodes(getEffectiveTargetNodes(server), "rm", "-f", server.ContainerName)
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
		Tags     string `json:"tags"`
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
		Tags:       input.Tags,
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
		Tags       string `json:"tags"`
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
			Tags:       p.Tags,
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
	// We just need to read it from the shared volume.
	peerConfigPath := filepath.Join(server.ConfigPath, "peer"+strconv.Itoa(peerIndex), "peer"+strconv.Itoa(peerIndex)+".conf")

	configBytes, err := ioutil.ReadFile(peerConfigPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read peer config file at %s: %v", peerConfigPath, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read peer config file"})
		return
	}
	config := string(configBytes)

	// Reemplazar la IP del servidor con el FQDN si está configurado
	serverEndpoint := getServerEndpoint()
	if serverEndpoint != "" {
		// Buscar y reemplazar la línea Endpoint en la configuración
		lines := strings.Split(config, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "Endpoint = ") {
				// Extraer el puerto de la línea actual
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					port := parts[len(parts)-1]
					lines[i] = fmt.Sprintf("Endpoint = %s:%s", serverEndpoint, port)
				}
				break
			}
		}
		config = strings.Join(lines, "\n")
	}

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
	// We just need to read it from the shared volume.
	peerConfigPath := filepath.Join(server.ConfigPath, "peer"+strconv.Itoa(peerIndex), "peer"+strconv.Itoa(peerIndex)+".conf")

	configBytes, err := ioutil.ReadFile(peerConfigPath)
	if err != nil {
		log.Printf("[ERROR] Failed to read peer config file at %s: %v", peerConfigPath, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read peer config file"})
		return
	}

	config := string(configBytes)

	// Reemplazar la IP del servidor con el FQDN si está configurado
	serverEndpoint := getServerEndpoint()
	if serverEndpoint != "" {
		// Buscar y reemplazar la línea Endpoint en la configuración
		lines := strings.Split(config, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "Endpoint = ") {
				// Extraer el puerto de la línea actual
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					port := parts[len(parts)-1]
					lines[i] = fmt.Sprintf("Endpoint = %s:%s", serverEndpoint, port)
				}
				break
			}
		}
		config = strings.Join(lines, "\n")
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=wg-%s.conf", peer.Name))
	c.String(http.StatusOK, config)
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
	}

	response := make([]UserResponse, 0)
	for _, u := range users {
		response = append(response, UserResponse{
			ID:       u.ID,
			Username: u.Username,
			Email:    u.Email,
		})
	}

	log.Printf("[DEBUG] Found %d users", len(response))
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
	c.JSON(http.StatusOK, gin.H{"user": gin.H{"id": user.ID, "username": user.Username, "email": user.Email, "role": user.Role}})
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

func getStats(c *gin.Context) {
	// Total servers
	var totalServers int64
	db.Model(&models.Server{}).Count(&totalServers)

	// Total peers
	var totalPeers int64
	db.Model(&models.Peer{}).Count(&totalPeers)

	// Active peers
	var activePeers int64
	db.Model(&models.Peer{}).Where("status = ?", "active").Count(&activePeers)

	// Tráfico global
	var totalRx, totalTx int64
	db.Model(&models.Peer{}).Select("COALESCE(SUM(transfer_rx),0)").Scan(&totalRx)
	db.Model(&models.Peer{}).Select("COALESCE(SUM(transfer_tx),0)").Scan(&totalTx)

	// Tráfico por servidor
	var servers []models.Server
	db.Preload("Peers").Find(&servers)
	serverStats := make([]map[string]interface{}, 0)
	for _, s := range servers {
		rx, tx := int64(0), int64(0)
		for _, p := range s.Peers {
			rx += p.TransferRx
			tx += p.TransferTx
		}
		serverStats = append(serverStats, map[string]interface{}{
			"id": s.ID,
			"name": s.Name,
			"rx": rx,
			"tx": tx,
		})
	}

	// Tráfico por peer
	var peers []models.Peer
	db.Find(&peers)
	peerStats := make([]map[string]interface{}, 0)
	for _, p := range peers {
		peerStats = append(peerStats, map[string]interface{}{
			"id": p.ID,
			"name": p.Name,
			"serverID": p.ServerID,
			"rx": p.TransferRx,
			"tx": p.TransferTx,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"totalServers": totalServers,
		"totalPeers": totalPeers,
		"activePeers": activePeers,
		"traffic": gin.H{"rx": totalRx, "tx": totalTx},
		"servers": serverStats,
		"peers": peerStats,
	})
}

func startServer(c *gin.Context) {
	id := c.Param("id")
	var server models.Server
	if err := db.First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if server.ContainerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Server has no associated container"})
		return
	}

	// Start the container in the background
	go func() {
		runDockerOnNodes(getEffectiveTargetNodes(server), "start", server.ContainerName)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "Starting server container"})
}

func stopServer(c *gin.Context) {
	id := c.Param("id")
	var server models.Server
	if err := db.First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if server.ContainerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Server has no associated container"})
		return
	}

	// Stop the container in the background
	go func() {
		runDockerOnNodes(getEffectiveTargetNodes(server), "stop", server.ContainerName)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "Stopping server container"})
}

func restartServer(c *gin.Context) {
	id := c.Param("id")
	var server models.Server
	if err := db.Preload("Peers").First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	// Restart the container in the background
	go func() {
		if err := restartServerContainer(&server); err != nil {
			log.Printf("[ERROR] Failed to restart server container: %v", err)
		}
	}()

	c.JSON(http.StatusOK, gin.H{"message": "Restarting server container"})
}

func getServerStatus(c *gin.Context) {
	id := c.Param("id")
	var server models.Server
	if err := db.First(&server, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	if server.ContainerName == "" {
		c.JSON(http.StatusOK, gin.H{"status": "inactive", "message": "No container associated"})
		return
	}

	// Check container status
	cmd := exec.Command("docker", "inspect", "--format={{.State.Status}}", server.ContainerName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "inactive", "message": "Container not found"})
		return
	}

	status := strings.TrimSpace(string(out))
	if status == "running" {
		c.JSON(http.StatusOK, gin.H{"status": "active"})
	} else {
		c.JSON(http.StatusOK, gin.H{"status": "inactive", "message": status})
	}
}

func restartServerContainer(server *models.Server) error {
	if server.ContainerName == "" {
		return fmt.Errorf("server has no container name")
	}
	targetNodes := getEffectiveTargetNodes(*server)

	// Eliminar el contenedor en ambos nodos (ignora error si no existe)
	runDockerOnNodes(targetNodes, "rm", "-f", server.ContainerName)

	// Espera breve para asegurar que el contenedor se elimina antes de crear el nuevo
	time.Sleep(2 * time.Second)

	// Arrancar el contenedor en ambos nodos (docker run SIEMPRE, nunca docker start tras rm)
	publicIP := getServerEndpoint()
	hostConfigsPath := getEnv("HOST_WG_CONFIGS_PATH", "")
	hostPathForServer := filepath.Join(hostConfigsPath, server.Name)
	dockerArgs := []string{
		"run", "-d",
		"--name=" + server.ContainerName,
		"--cap-add=NET_ADMIN",
		"--cap-add=SYS_MODULE",
		"-p", fmt.Sprintf("%d:51820/udp", server.ListenPort),
		"-e", "PUID=1000",
		"-e", "PGID=1000",
		"-e", "TZ=Etc/UTC",
		"-e", "SERVERURL=" + publicIP,
		"-e", "SERVERPORT=" + strconv.Itoa(server.ListenPort),
		"-e", "PEERS=" + strconv.Itoa(len(server.Peers)),
		"-e", "PEERDNS=auto",
		"-e", "INTERNAL_SUBNET=" + server.Address,
		"-e", "ALLOWEDIPS=0.0.0.0/0",
		"-e", "LOG_CONFS=true",
		"-v", hostPathForServer + ":/config",
		"-v", "/lib/modules:/lib/modules",
		"--sysctl=net.ipv4.conf.all.src_valid_mark=1",
		"--sysctl=net.ipv4.ip_forward=1",
		"--restart=unless-stopped",
		"lscr.io/linuxserver/wireguard:latest",
	}
	runDockerOnNodes(targetNodes, dockerArgs...)
	return nil
}

// Handler para actualizar tags de un peer
func updatePeer(c *gin.Context) {
	id := c.Param("id")
	var input struct {
		Tags string `json:"tags"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var peer models.Peer
	if err := db.First(&peer, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Peer not found"})
		return
	}
	peer.Tags = input.Tags
	if err := db.Save(&peer).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update peer"})
		return
	}
	c.JSON(http.StatusOK, peer)
}

// Helper para ejecutar un comando Docker vía SSH en ambos nodos
func runDockerOnNodes(nodes []string, args ...string) {
	for _, node := range nodes {
		node := node
		log.Printf("[INFO] Ejecutando docker %s en %s", strings.Join(args, " "), node)
		go func() {
			out, err := runDockerCommandOnNode(node, args...)
			if err != nil {
				log.Printf("[ERROR] Docker command failed on %s: %v, Output: %s", node, err, string(out))
			} else if len(out) > 0 {
				log.Printf("[INFO] Docker command output on %s: %s", node, strings.TrimSpace(string(out)))
			}
		}()
	}
}

func runDockerCommandOnNode(node string, args ...string) ([]byte, error) {
	if node == localNodeName {
		cmd := exec.Command("docker", args...)
		return cmd.CombinedOutput()
	}
	cmdStr := fmt.Sprintf("export PATH=$PATH:/usr/bin; docker %s", strings.Join(args, " "))
	sshCmd := []string{"ssh", "root@" + node, cmdStr}
	cmd := exec.Command(sshCmd[0], sshCmd[1:]...)
	return cmd.CombinedOutput()
}

func getContainerStatusOnNode(node, containerName string) (string, error) {
	if strings.TrimSpace(containerName) == "" {
		return "inactive", fmt.Errorf("empty container name")
	}
	out, err := runDockerCommandOnNode(node, "inspect", "--format={{.State.Status}}", containerName)
	if err != nil {
		return "inactive", err
	}
	status := strings.TrimSpace(string(out))
	if status == "running" {
		return "active", nil
	}
	return "inactive", nil
}