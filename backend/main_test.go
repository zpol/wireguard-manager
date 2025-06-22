package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Setup test DB and router
func setupTestEnv() (*gin.Engine, func()) {
	os.Setenv("JWT_SECRET", "testsecret")
	dbTest, _ := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	dbTest.AutoMigrate(&models.User{}, &models.Server{}, &models.Peer{})
	db = dbTest
	// Reusar el router de main.go
	r := gin.Default()
	r.POST("/api/auth/register", handleRegister)
	r.POST("/api/auth/login", handleLogin)
	r.GET("/api/users", listUsers)
	r.POST("/api/servers", createServer)
	r.GET("/api/servers", listServers)
	r.POST("/api/peers", createPeer)
	r.GET("/api/peers", listPeers)
	return r, func() {}
}

func TestUserLifecycle(t *testing.T) {
	r, cleanup := setupTestEnv()
	defer cleanup()

	// Crear usuario
	user := map[string]string{
		"username": "testuser",
		"email":    "test@user.com",
		"password": "testpassword123",
	}
	body, _ := json.Marshal(user)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Registro usuario falló: %s", w.Body.String())
	}

	// Listar usuarios
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/users", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Listar usuarios falló: %s", w.Body.String())
	}
	var users []models.User
	json.Unmarshal(w.Body.Bytes(), &users)
	if len(users) == 0 {
		t.Fatal("No se encontró el usuario creado")
	}
}

func TestPeerLifecycle(t *testing.T) {
	r, cleanup := setupTestEnv()
	defer cleanup()

	// Crear server necesario para peer
	server := map[string]interface{}{
		"name":        "testserver",
		"publicKey":   "pubkey",
		"privateKey":  "privkey",
		"listenPort":  51820,
		"address":     "10.0.0.1/24",
		"dns":         "8.8.8.8",
		"mtu":         1420,
		"configPath":  "/etc/wireguard/wg0.conf",
	}
	body, _ := json.Marshal(server)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/servers", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Crear server falló: %s", w.Body.String())
	}
	var createdServer models.Server
	json.Unmarshal(w.Body.Bytes(), &createdServer)

	// Crear peer
	peer := map[string]interface{}{
		"name":       "peer1",
		"publicKey":  "peerpubkey",
		"privateKey": "peerprivkey",
		"address":    "10.0.0.2/24",
		"dns":        "8.8.8.8",
		"allowedIPs": "0.0.0.0/0",
		"serverID":   createdServer.ID,
	}
	body, _ = json.Marshal(peer)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/peers", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Crear peer falló: %s", w.Body.String())
	}

	// Listar peers
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/api/peers", nil)
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Listar peers falló: %s", w.Body.String())
	}
	var peers []models.Peer
	json.Unmarshal(w.Body.Bytes(), &peers)
	if len(peers) == 0 {
		t.Fatal("No se encontró el peer creado")
	}
}

// Simulación de arranque/parada de WireGuard (mock)
func TestWireGuardStartStop(t *testing.T) {
	t.Log("Simulación: arrancar WireGuard (mock)")
	t.Log("Simulación: parar WireGuard (mock)")
} 