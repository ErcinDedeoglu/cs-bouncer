# === Stage 1: Build ===
FROM golang:1.24-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod .
COPY main.go .
COPY token.go .
COPY host.go .
RUN go mod tidy
RUN go build -o cs-bouncer .

# === Stage 2: Runtime ===
FROM alpine:latest
RUN apk add --no-cache iptables ip6tables docker-cli
WORKDIR /app
COPY --from=builder /app/cs-bouncer .

ENTRYPOINT ["/app/cs-bouncer"]