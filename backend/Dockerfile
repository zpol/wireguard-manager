FROM golang:1.21-alpine3.19


# RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
# Install required packages
RUN apk update
RUN apk add --no-cache \
    wireguard-tools \
    libqrencode-tools \
    git

# Set working directory
WORKDIR /app

# Copy go mod file
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN go build -o main .

# Create WireGuard config directory
RUN mkdir -p /etc/wireguard

# Expose port
EXPOSE 8080

# Run the application
CMD ["./main"] 