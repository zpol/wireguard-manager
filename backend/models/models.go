package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username string `gorm:"uniqueIndex;not null"`
	Password string `gorm:"not null"`
	Email    string `gorm:"uniqueIndex;not null"`
	Role     string `gorm:"not null;default:'user'"`
}

type Server struct {
	gorm.Model
	Name        string `gorm:"not null"`
	PublicKey   string `gorm:"not null"`
	PrivateKey  string `gorm:"not null"`
	ListenPort  int    `gorm:"not null"`
	Address     string `gorm:"not null"`
	DNS         string
	MTU         int    `gorm:"default:1420"`
	ConfigPath  string `gorm:"not null"`
	LastSync    time.Time
	Peers       []Peer
}

type Peer struct {
	gorm.Model
	Name        string `gorm:"not null"`
	PublicKey   string `gorm:"not null"`
	PrivateKey  string `gorm:"not null"`
	Address     string `gorm:"not null"`
	DNS         string
	AllowedIPs  string `gorm:"not null"`
	ServerID    uint
	Server      Server
	LastHandshake time.Time
	TransferRx  int64
	TransferTx  int64
	Status      string `gorm:"default:'active'"`
}