package services

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WireGuardService struct {
	configPath string
}

func NewWireGuardService(configPath string) *WireGuardService {
	return &WireGuardService{
		configPath: configPath,
	}
}

func (s *WireGuardService) GenerateKeyPair() (privateKey, publicKey string, err error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	return key.String(), key.PublicKey().String(), nil
}

func (s *WireGuardService) CreateServerConfig(server *models.Server) error {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
MTU = %d
%s

`, server.PrivateKey, server.Address, server.ListenPort, server.MTU, s.getDNSConfig(server.DNS))

	configPath := filepath.Join(s.configPath, fmt.Sprintf("wg%d.conf", server.ID))
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write server config: %v", err)
	}

	return nil
}

func (s *WireGuardService) CreatePeerConfig(peer *models.Peer, server *models.Server) error {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
%s

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s:%d
PersistentKeepalive = 25

`, peer.PrivateKey, peer.Address, s.getDNSConfig(peer.DNS),
		server.PublicKey, peer.AllowedIPs, server.Address, server.ListenPort)

	configPath := filepath.Join(s.configPath, fmt.Sprintf("peer_%d.conf", peer.ID))
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write peer config: %v", err)
	}

	return nil
}

func (s *WireGuardService) UpdateServerConfig(server *models.Server) error {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
MTU = %d
%s

`, server.PrivateKey, server.Address, server.ListenPort, server.MTU, s.getDNSConfig(server.DNS))

	// Add peer configurations
	for _, peer := range server.Peers {
		config += fmt.Sprintf(`[Peer]
PublicKey = %s
AllowedIPs = %s

`, peer.PublicKey, peer.AllowedIPs)
	}

	configPath := filepath.Join(s.configPath, fmt.Sprintf("wg%d.conf", server.ID))
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to update server config: %v", err)
	}

	return nil
}

func (s *WireGuardService) RestartWireGuard(serverID uint) error {
	cmd := exec.Command("wg-quick", "down", fmt.Sprintf("wg%d", serverID))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to stop wireguard: %v", err)
	}

	cmd = exec.Command("wg-quick", "up", fmt.Sprintf("wg%d", serverID))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start wireguard: %v", err)
	}

	return nil
}

func (s *WireGuardService) getDNSConfig(dns string) string {
	if dns == "" {
		return ""
	}
	return fmt.Sprintf("DNS = %s", dns)
}

func (s *WireGuardService) GenerateQRCode(peer *models.Peer, server *models.Server) (string, error) {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
%s

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s:%d
PersistentKeepalive = 25

`, peer.PrivateKey, peer.Address, s.getDNSConfig(peer.DNS),
		server.PublicKey, peer.AllowedIPs, server.Address, server.ListenPort)

	// Use qrencode to generate QR code
	cmd := exec.Command("qrencode", "-t", "ANSIUTF8", "-o", "-")
	cmd.Stdin = strings.NewReader(config)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to generate QR code: %v", err)
	}

	return string(output), nil
} 