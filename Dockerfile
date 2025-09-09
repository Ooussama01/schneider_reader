# Use a minimal base image
FROM golang:1.22-alpine

# Set working directory
WORKDIR /app

# Copy code
COPY . .

# Download dependencies
RUN go mod tidy

# Build Go app
RUN go build -o app main.go

# Run the app
CMD ["./app"]
