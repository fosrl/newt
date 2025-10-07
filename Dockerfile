FROM golang:1.25-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /newt

FROM alpine:3.22 AS runner

RUN apk --no-cache add ca-certificates tzdata

COPY --from=builder /newt /usr/local/bin/
COPY entrypoint.sh /

# Admin/metrics endpoint (Prometheus scrape)
EXPOSE 2112

RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["newt"]
