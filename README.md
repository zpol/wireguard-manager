# WireGuard Manager

A secure and modern web interface to manage WireGuard VPN servers and peers.

## 🚀 Main Features

### ✅ User Management
- Create, edit, and delete users
- User roles (admin/user)
- Secure JWT authentication
- Password change
- Default admin user

### ✅ WireGuard Server Management
- Create and configure WireGuard servers
- Automatic public/private key generation
- Port and IP address configuration
- Configuration file management

### ✅ Peer (Client) Management
- Create and manage WireGuard peers
- QR code generation for quick setup
- Download configuration files
- Assign IPs and DNS

### ✅ WireGuard Operations
- Start/Stop/Restart WireGuard services
- View connection status
- Auto-generate configurations

## 🔧 Quick Installation

### Prerequisites
- Docker and Docker Compose
- WireGuard kernel module installed on the host
- Port 51820/UDP available for WireGuard
- Ports 3000 and 8080 available for the web interface

### Automatic Start
```bash
# Clone the repository
git clone <repository-url>
cd wireguard-manager

# Run the initialization script
./init.sh
```

### Manual Start
```bash
# 1. Configure environment variables
cp .env.example .env
# Edit .env with your settings

# 2. Start services
docker-compose up -d

# 3. Access the application
# URL: http://localhost:3000
# User: admin
# Password: admin
```

## 🔑 Default Credentials

- **User**: `admin`
- **Password**: `admin`

**⚠️ IMPORTANT**: Change the admin password immediately after the first login.

## 🛠️ Useful Commands

### Service Management
```bash
# View real-time logs
docker-compose logs -f

# View logs for a specific service
docker-compose logs backend
docker-compose logs frontend
docker-compose logs postgres

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Rebuild and restart
docker-compose up --build -d
```

### API Testing
```bash
# Run all tests
./test-api.sh
```

### Backup and Restore
```bash
# Database backup
docker-compose exec postgres pg_dump -U wireguard wireguard > backup.sql

# Restore database
docker-compose exec -T postgres psql -U wireguard wireguard < backup.sql
```

## 🔒 Security Configuration

### Environment Variables (.env)
```bash
# Database
DB_PASSWORD=your_secure_password

# JWT
JWT_SECRET=your_very_long_secret_key

# WireGuard
WIREGUARD_CONFIG_PATH=/etc/wireguard

# API
REACT_APP_API_URL=http://localhost:8080

# Security
ENABLE_HTTPS=false  # true in production
ALLOW_REGISTRATION=true
SESSION_TIMEOUT=60
```

### Ports Used
- **3000**: Frontend (React)
- **8080**: Backend API (Go)
- **5432**: PostgreSQL (development only)
- **51820**: WireGuard VPN (UDP)

## 🏗️ Architecture

### Backend (Go)
- **Framework**: Gin
- **Database**: PostgreSQL with GORM
- **Authentication**: JWT
- **Tools**: WireGuard CLI

### Frontend (React)
- **Framework**: React with TypeScript
- **UI**: Material-UI
- **State**: Context API
- **HTTP**: Axios

### Database
- **System**: PostgreSQL
- **Migration**: Automatic with GORM
- **Persistence**: Docker volume

## 🔍 Troubleshooting

### Common Issues

1. **Database connection error**
   ```bash
   docker-compose logs postgres
   docker-compose restart
   ```

2. **Frontend not loading**
   ```bash
   docker-compose logs frontend
   curl http://localhost:8080/api/wg/status
   ```

3. **Cannot create users**
   ```bash
   docker-compose logs backend | grep DEBUG
   ```

### Debug Logs
```bash
# View detailed logs
docker-compose logs backend | grep DEBUG

# View errors
docker-compose logs backend | grep ERROR
```

## 📊 Monitoring

### Available Metrics
- WireGuard connection status
- Number of active peers
- Data transfer per peer
- Server uptime

### Important Logs
- User authentication
- Configuration creation/modification
- WireGuard errors
- Failed access attempts

## 🚀 Upcoming Improvements

### Planned Features
- [ ] Dashboard with real-time metrics
- [ ] Email notifications
- [ ] Full REST API
- [ ] LDAP/Active Directory integration
- [ ] Automatic backup
- [ ] Advanced monitoring
- [ ] Responsive mobile interface

### Security Enhancements
- [ ] Two-factor authentication
- [ ] Rate limiting
- [ ] Full audit
- [ ] Configuration encryption

## 📞 Support

For technical support:
- Check logs: `docker-compose logs`
- Check status: `docker-compose ps`
- Run tests: `./test-api.sh`

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**WireGuard Manager** - A complete solution to securely and efficiently manage WireGuard VPN servers. 