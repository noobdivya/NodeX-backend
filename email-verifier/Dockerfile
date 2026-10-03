# NodeX email verifier (sends and checks the sign-up email code).
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server

FROM alpine:3.22
# CA certificates: needed to talk TLS to the SMTP server.
RUN apk add --no-cache ca-certificates && adduser -D -H nodex
USER nodex
COPY --from=build /out/server /usr/local/bin/nodex-verifier
ENV APP_ENV=production
CMD ["nodex-verifier"]
