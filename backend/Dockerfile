# Use a Golang image
FROM golang:1.23-alpine

# Set the working directory
WORKDIR /app

# Install dependencies for building
RUN apk update && apk add --no-cache git build-base docker-cli

# Copy the entire backend source code
COPY . .

# Initialize Go modules, creating a new go.mod file.
# This makes the build self-contained and independent of local mod files.
RUN go mod init backend

# Tidy will find all dependencies in the source code and add them
# to go.mod and go.sum, ensuring a consistent build.
RUN go mod tidy

# Build the Go application
RUN go build -o main .

# Expose the port the app runs on
EXPOSE 8080

# Run the application
CMD ["./main"] 