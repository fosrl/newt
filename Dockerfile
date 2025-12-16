FROM golang:1.25-alpine AS builder

# Install git and ca-certificates
RUN apk --no-cache add ca-certificates git tzdata

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /newt

FROM alpine:3.23 AS runner

RUN apk --no-cache add ca-certificates tzdata iputils

COPY --from=builder /newt /usr/local/bin/
COPY entrypoint.sh /

# Admin/metrics endpoint (Prometheus scrape)
EXPOSE 2112

RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["newt"]
