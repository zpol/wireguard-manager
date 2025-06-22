#!/bin/bash

echo "🚀 Inicializando WireGuard Manager..."

# Verificar si Docker está instalado
if ! command -v docker &> /dev/null; then
    echo "❌ Docker no está instalado. Por favor instala Docker primero."
    exit 1
fi

# Verificar si Docker Compose está instalado
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose no está instalado. Por favor instala Docker Compose primero."
    exit 1
fi

# Verificar si el archivo .env existe
if [ ! -f .env ]; then
    echo "📝 Creando archivo .env desde .env.example..."
    cp .env.example .env
    echo "⚠️  Por favor edita el archivo .env con tus configuraciones antes de continuar."
    exit 1
fi

echo "🔧 Construyendo y levantando los servicios..."
docker-compose down -v
docker-compose build --no-cache
docker-compose up -d

echo "⏳ Esperando a que los servicios estén listos..."
sleep 10

# Verificar si los servicios están funcionando
if docker-compose ps | grep -q "Up"; then
    echo "✅ Servicios iniciados correctamente!"
    echo ""
    echo "🌐 Accede a la aplicación en: http://localhost:3000"
    echo "🔑 Credenciales por defecto:"
    echo "   Usuario: admin"
    echo "   Contraseña: admin"
    echo ""
    echo "⚠️  IMPORTANTE: Cambia la contraseña del admin después del primer login!"
    echo ""
    echo "📊 Para ver los logs: docker-compose logs -f"
    echo "🛑 Para detener: docker-compose down"
else
    echo "❌ Error al iniciar los servicios. Revisa los logs con: docker-compose logs"
    exit 1
fi 
