FROM golang:1.21-alpine3.18

RUN apk add --no-cache iptables

WORKDIR /app

COPY go.mod .
COPY main.go .
COPY token.go .

RUN go build -o cs-bouncer main.go

# Container will run as root to apply firewall rules
ENTRYPOINT ["/app/cs-bouncer"]