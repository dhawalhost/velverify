# Standardized Dockerfile for WardSeal Go Services
# Stage 1: Build
FROM golang:1.26.2-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git tzdata ca-certificates

WORKDIR /src

# Leverage Docker cache for dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with optimizations
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -o /bin/dirsvc ./cmd/dirsvc

# Stage 2: Runtime
FROM alpine:3.21.3

# Metadata labels
LABEL org.opencontainers.image.source="https://github.com/dhawalhost/wardseal"
LABEL org.opencontainers.image.description="WardSeal Directory Service"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Install runtime essentials
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user for security
RUN addgroup -S wardseal && adduser -S wardseal -G wardseal
USER wardseal

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /bin/dirsvc /app/dirsvc

# Expose the service port
EXPOSE 8081

ENTRYPOINT ["/app/dirsvc"]