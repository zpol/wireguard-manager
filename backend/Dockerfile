# Use a Golang image
FROM golang:1.21-alpine

# Set the working directory
WORKDIR /app

# Install dependencies needed for the application
# - wireguard-tools and iptables are no longer needed in this container
# - Add docker-cli to manage other containers
RUN apk update && apk add --no-cache git build-base docker-cli

# Copy go.mod and go.sum to download dependencies first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application
COPY . .

# Build the Go application
RUN go build -o main .

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["./main"] 