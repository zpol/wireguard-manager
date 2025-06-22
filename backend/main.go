package main

import (
	"bytes"
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

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
	"backend/models"
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

	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
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

	log.Println("Default admin user created: admin/admin")
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
		AllowOrigins:     []string{"http://localhost:3000", "http://127.0.0.1:3000"},
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
		ConfigPath: input.ConfigPath,
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
	// Using "wg show" is more reliable for checking active interfaces.
	out, err := exec.Command("wg", "show").Output()
	if err != nil {
		// This can happen if no wg interfaces are up, which is not an error in our case.
		// The command returns a non-zero exit code if there are no interfaces to show.
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 && len(out) == 0 {
				return make(map[string]string), nil // No interfaces are up, return empty map
			}
		}
		log.Printf("[ERROR] Failed to execute 'wg show': %v, Output: %s", err, string(out))
		return nil, err
	}

	statusMap := make(map[string]string)
	lines := strings.Split(string(out), "\n")

	var currentInterface string
	for _, line := range lines {
		if strings.HasPrefix(line, "interface: ") {
			fields := strings.Fields(line)
			if len(fields) == 2 {
				currentInterface = fields[1]
				if currentInterface != "" {
					statusMap[currentInterface] = "active"
				}
			}
		}
	}
	log.Printf("[DEBUG] getBulkServerStatus found active interfaces: %v", statusMap)
	return statusMap, nil
}

func generateServerConfig(server models.Server) (string, error) {
	var config strings.Builder
	config.WriteString(fmt.Sprintf("# Interface: %s\n", server.Name))
	config.WriteString("[Interface]\n")
	config.WriteString(fmt.Sprintf("Address = %s\n", server.Address))
	config.WriteString(fmt.Sprintf("ListenPort = %d\n", server.ListenPort))
	config.WriteString(fmt.Sprintf("PrivateKey = %s\n", server.PrivateKey))
	config.WriteString("\n")

	for _, peer := range server.Peers {
		config.WriteString(fmt.Sprintf("# Peer: %s\n", peer.Name))
		config.WriteString("[Peer]\n")
		config.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))
		config.WriteString(fmt.Sprintf("AllowedIPs = %s\n", peer.AllowedIPs))
		config.WriteString("\n")
	}

	return config.String(), nil
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
		// Continue without status info if wg command fails
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
		interfaceName := getInterfaceName(s.ConfigPath)
		status, ok := statusMap[interfaceName]
		if !ok {
			status = "inactive" // Default to inactive if not found in wg output
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
	if err := db.Delete(&models.Server{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete server"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Server deleted successfully"})
}

func createPeer(c *gin.Context) {
	log.Println("[DEBUG] createPeer called")
	type PeerInput struct {
		Name       string `json:"name" binding:"required"`
		PublicKey  string `json:"publicKey" binding:"required"`
		PrivateKey string `json:"privateKey" binding:"required"`
		Address    string `json:"address" binding:"required"`
		DNS        string `json:"dns"`
		AllowedIPs string `json:"allowedIPs" binding:"required"`
		ServerID   uint   `json:"serverID" binding:"required"`
	}
	var input PeerInput
	if err := c.ShouldBindJSON(&input); err != nil {
		log.Println("[DEBUG] Invalid peer input:", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	log.Printf("[DEBUG] Peer input: %+v\n", input)
	peer := models.Peer{
		Name:       input.Name,
		PublicKey:  input.PublicKey,
		PrivateKey: input.PrivateKey,
		Address:    input.Address,
		DNS:        input.DNS,
		AllowedIPs: input.AllowedIPs,
		ServerID:   input.ServerID,
	}
	log.Printf("[DEBUG] About to insert peer: %+v\n", peer)
	if err := db.Create(&peer).Error; err != nil {
		log.Println("[DEBUG] Failed to create peer:", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create peer"})
		return
	}
	log.Printf("[DEBUG] Peer created: %+v\n", peer)
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
	if err := db.Delete(&models.Peer{}, id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete peer"})
		return
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

	// Generate WireGuard config for the peer
	// This is a client config, so the "Peer" section uses the server's public key
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s:%d
PersistentKeepalive = 25`, peer.PrivateKey, peer.Address, peer.DNS, server.PublicKey, peer.AllowedIPs, "your-server-ip", server.ListenPort) // TODO: Make endpoint IP configurable

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

	// Generate WireGuard config
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
DNS = %s

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s:%d
PersistentKeepalive = 25`, peer.PrivateKey, peer.Address, peer.DNS, server.PublicKey, peer.AllowedIPs, "your-server-ip", server.ListenPort)

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
	privKeyBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		c.JSON(500, gin.H{"error": "No se pudo generar clave privada", "details": err.Error()})
		return
	}
	privKey := string(privKeyBytes)
	pubKeyCmd := exec.Command("wg", "pubkey")
	pubKeyCmd.Stdin = bytes.NewReader(privKeyBytes)
	pubKeyBytes, err := pubKeyCmd.Output()
	if err != nil {
		c.JSON(500, gin.H{"error": "No se pudo generar clave pública", "details": err.Error()})
		return
	}
	pubKey := string(pubKeyBytes)
	c.JSON(200, gin.H{"privateKey": privKey, "publicKey": pubKey})
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

	interfaceName := getInterfaceName(server.ConfigPath)

	// Try to bring it down first to handle zombie interfaces
	log.Printf("[DEBUG] Ensuring interface is down before starting: wg-quick down %s", interfaceName)
	exec.Command("wg-quick", "down", interfaceName).Run() // Ignore errors, it's ok if it doesn't exist

	configContent, err := generateServerConfig(*server)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate server config", "details": err.Error()})
		return
	}

	// Ensure the directory exists before writing the file
	configDir := filepath.Dir(server.ConfigPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create config directory", "details": err.Error()})
		return
	}

	if err := ioutil.WriteFile(server.ConfigPath, []byte(configContent), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write config file", "details": err.Error()})
		return
	}

	cmd := exec.Command("wg-quick", "up", interfaceName)
	log.Printf("[DEBUG] Running command: wg-quick up %s", interfaceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] Failed to start server %s. Output: %s, Error: %v", interfaceName, string(out), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to start server %s", interfaceName), "details": string(out)})
		return
	}
	log.Printf("[INFO] Server %s started successfully. Output: %s", interfaceName, string(out))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Server %s started successfully", interfaceName), "output": string(out)})
}

func stopServer(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	interfaceName := getInterfaceName(server.ConfigPath)
	cmd := exec.Command("wg-quick", "down", interfaceName)
	log.Printf("[DEBUG] Running command: wg-quick down %s", interfaceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] Failed to stop server %s. Output: %s, Error: %v", interfaceName, string(out), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to stop server %s", interfaceName), "details": string(out)})
		return
	}
	log.Printf("[INFO] Server %s stopped successfully. Output: %s", interfaceName, string(out))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Server %s stopped successfully", interfaceName), "output": string(out)})
}

func restartServer(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	interfaceName := getInterfaceName(server.ConfigPath)
	// First, try to bring it down (ignoring errors if it's already down)
	log.Printf("[DEBUG] Stopping server for restart: wg-quick down %s", interfaceName)
	exec.Command("wg-quick", "down", interfaceName).Run()

	// Regenerate config in case peers have changed
	configContent, err := generateServerConfig(*server)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate server config", "details": err.Error()})
		return
	}
	// Ensure the directory exists before writing the file
	configDir := filepath.Dir(server.ConfigPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create config directory", "details": err.Error()})
		return
	}
	if err := ioutil.WriteFile(server.ConfigPath, []byte(configContent), 0600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to write config file", "details": err.Error()})
		return
	}

	// Then, bring it up
	cmd := exec.Command("wg-quick", "up", interfaceName)
	log.Printf("[DEBUG] Starting server after restart: wg-quick up %s", interfaceName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[ERROR] Failed to restart server %s. Output: %s, Error: %v", interfaceName, string(out), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to restart server %s", interfaceName), "details": string(out)})
		return
	}
	log.Printf("[INFO] Server %s restarted successfully. Output: %s", interfaceName, string(out))
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Server %s restarted successfully", interfaceName), "output": string(out)})
}

func getServerStatus(c *gin.Context) {
	server, err := getServerFromContext(c)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Server not found"})
		return
	}

	interfaceName := getInterfaceName(server.ConfigPath)
	cmd := exec.Command("wg", "show", interfaceName)
	out, err := cmd.CombinedOutput()

	// "wg show" exits with an error if the interface is down or doesn't exist.
	// We consider both cases "inactive".
	if err != nil || len(out) == 0 {
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