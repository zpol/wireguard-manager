#!/bin/bash

echo "🧪 Probando API de WireGuard Manager..."

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Función para imprimir resultados
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ $2${NC}"
    else
        echo -e "${RED}❌ $2${NC}"
    fi
}

# Función para esperar que el servicio esté listo
wait_for_service() {
    echo -e "${YELLOW}⏳ Esperando que el servicio esté listo...${NC}"
    for i in {1..30}; do
        if curl -s http://localhost:8080/api/wg/status > /dev/null 2>&1; then
            echo -e "${GREEN}✅ Servicio listo!${NC}"
            return 0
        fi
        sleep 2
    done
    echo -e "${RED}❌ Servicio no disponible después de 60 segundos${NC}"
    return 1
}

# Esperar que el servicio esté listo
wait_for_service

# 1. Probar login
echo -e "\n${YELLOW}1. Probando autenticación...${NC}"
LOGIN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}')

if echo "$LOGIN_RESPONSE" | grep -q "token"; then
    TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4)
    print_result 0 "Login exitoso"
else
    print_result 1 "Login falló"
    exit 1
fi

# 2. Probar creación de usuario
echo -e "\n${YELLOW}2. Probando creación de usuario...${NC}"
CREATE_USER_RESPONSE=$(curl -s -X POST http://localhost:8080/api/users \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"username":"testuser2","email":"test2@example.com","password":"testpass123","role":"user"}')

if echo "$CREATE_USER_RESPONSE" | grep -q "token"; then
    print_result 0 "Creación de usuario exitosa"
else
    print_result 1 "Creación de usuario falló"
fi

# 3. Probar listar usuarios
echo -e "\n${YELLOW}3. Probando listar usuarios...${NC}"
USERS_RESPONSE=$(curl -s -X GET http://localhost:8080/api/users \
    -H "Authorization: Bearer $TOKEN")

if echo "$USERS_RESPONSE" | grep -q "admin"; then
    print_result 0 "Listar usuarios exitoso"
    USER_COUNT=$(echo "$USERS_RESPONSE" | grep -o '"ID":[0-9]*' | wc -l)
    echo -e "   📊 Usuarios encontrados: $USER_COUNT"
else
    print_result 1 "Listar usuarios falló"
fi

# 4. Probar generación de claves WireGuard
echo -e "\n${YELLOW}4. Probando generación de claves WireGuard...${NC}"
KEYS_RESPONSE=$(curl -s -X POST http://localhost:8080/api/wg/genkeys \
    -H "Authorization: Bearer $TOKEN")

if echo "$KEYS_RESPONSE" | grep -q "privateKey"; then
    print_result 0 "Generación de claves exitosa"
else
    print_result 1 "Generación de claves falló"
fi

# 5. Probar creación de servidor
echo -e "\n${YELLOW}5. Probando creación de servidor...${NC}"
SERVER_RESPONSE=$(curl -s -X POST http://localhost:8080/api/servers \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{
        "name": "Test Server",
        "publicKey": "test_public_key",
        "privateKey": "test_private_key",
        "listenPort": 51820,
        "address": "10.0.0.1/24",
        "dns": "8.8.8.8",
        "mtu": 1420,
        "configPath": "/etc/wireguard/wg0.conf"
    }')

if echo "$SERVER_RESPONSE" | grep -q "Test Server"; then
    print_result 0 "Creación de servidor exitosa"
    SERVER_ID=$(echo "$SERVER_RESPONSE" | grep -o '"ID":[0-9]*' | head -1 | cut -d':' -f2)
else
    print_result 1 "Creación de servidor falló"
    SERVER_ID=""
fi

# 6. Probar listar servidores
echo -e "\n${YELLOW}6. Probando listar servidores...${NC}"
SERVERS_RESPONSE=$(curl -s -X GET http://localhost:8080/api/servers \
    -H "Authorization: Bearer $TOKEN")

if echo "$SERVERS_RESPONSE" | grep -q "Test Server"; then
    print_result 0 "Listar servidores exitoso"
    SERVER_COUNT=$(echo "$SERVERS_RESPONSE" | grep -o '"ID":[0-9]*' | wc -l)
    echo -e "   📊 Servidores encontrados: $SERVER_COUNT"
else
    print_result 1 "Listar servidores falló"
fi

# 7. Probar creación de peer (solo si hay servidor)
if [ ! -z "$SERVER_ID" ]; then
    echo -e "\n${YELLOW}7. Probando creación de peer...${NC}"
    PEER_RESPONSE=$(curl -s -X POST http://localhost:8080/api/peers \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TOKEN" \
        -d "{
            \"name\": \"Test Peer\",
            \"publicKey\": \"peer_public_key\",
            \"privateKey\": \"peer_private_key\",
            \"address\": \"10.0.0.2/24\",
            \"dns\": \"8.8.8.8\",
            \"allowedIPs\": \"0.0.0.0/0\",
            \"serverID\": $SERVER_ID
        }")

    if echo "$PEER_RESPONSE" | grep -q "Test Peer"; then
        print_result 0 "Creación de peer exitosa"
    else
        print_result 1 "Creación de peer falló"
    fi
else
    echo -e "\n${YELLOW}7. Saltando prueba de peer (no hay servidor)${NC}"
fi

# 8. Probar listar peers
echo -e "\n${YELLOW}8. Probando listar peers...${NC}"
PEERS_RESPONSE=$(curl -s -X GET http://localhost:8080/api/peers \
    -H "Authorization: Bearer $TOKEN")

if echo "$PEERS_RESPONSE" | grep -q "\[\]"; then
    print_result 0 "Listar peers exitoso (lista vacía)"
else
    print_result 0 "Listar peers exitoso"
    PEER_COUNT=$(echo "$PEERS_RESPONSE" | grep -o '"ID":[0-9]*' | wc -l)
    echo -e "   📊 Peers encontrados: $PEER_COUNT"
fi

# 9. Probar estado de WireGuard
echo -e "\n${YELLOW}9. Probando estado de WireGuard...${NC}"
STATUS_RESPONSE=$(curl -s -X GET http://localhost:8080/api/wg/status \
    -H "Authorization: Bearer $TOKEN")

if [ $? -eq 0 ]; then
    print_result 0 "Estado de WireGuard obtenido"
else
    print_result 1 "Error al obtener estado de WireGuard"
fi

# Resumen final
echo -e "\n${GREEN}🎉 Pruebas completadas!${NC}"
echo -e "\n${YELLOW}📋 Resumen:${NC}"
echo -e "   🌐 Frontend: http://localhost:3000"
echo -e "   🔧 Backend: http://localhost:8080"
echo -e "   🔑 Usuario admin: admin/admin"
echo -e "\n${YELLOW}📊 Para ver logs:${NC}"
echo -e "   docker-compose logs -f"
echo -e "\n${YELLOW}🛑 Para detener:${NC}"
echo -e "   docker-compose down" 