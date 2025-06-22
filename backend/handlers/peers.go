package handlers

import (
    "net/http"
    "wireguard-manager/backend/models"
    "wireguard-manager/backend/database"

    "github.com/gin-gonic/gin"
)

type PeerInput struct {
    Name       string `json:"name" binding:"required"`
    PublicKey  string `json:"publicKey" binding:"required"`
    PrivateKey string `json:"privateKey" binding:"required"`
    Address    string `json:"address" binding:"required"`
    DNS        string `json:"dns"`
    AllowedIPs string `json:"allowedIPs" binding:"required"`
    ServerID   uint   `json:"serverID" binding:"required"`
}

func CreatePeer(c *gin.Context) {
    var input PeerInput
    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    userID, exists := c.Get("userID")
    if !exists {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
        return
    }

    peer := models.Peer{
        Name:       input.Name,
        PublicKey:  input.PublicKey,
        PrivateKey: input.PrivateKey,
        Address:    input.Address,
        DNS:        input.DNS,
        AllowedIPs: input.AllowedIPs,
        ServerID:   input.ServerID,
        UserID:     userID.(uint),
    }

    if err := database.DB.Create(&peer).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create peer"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Peer created successfully"})
}