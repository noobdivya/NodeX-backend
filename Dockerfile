# NodeX P2P node (DHT + relay that browsers join over WebSockets).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/node .

FROM alpine:3.22
RUN adduser -D -H nodex
USER nodex
WORKDIR /tmp
COPY --from=build /out/node /usr/local/bin/nodex-node
# Set NODE_KEY so the node keeps the same address across deploys.
CMD ["nodex-node"]
