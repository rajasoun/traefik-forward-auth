FROM golang:1.14.3-alpine3.11 as builder

# Setup
RUN mkdir -p /go/src/github.com/thomseddon/traefik-forward-auth
WORKDIR /go/src/github.com/thomseddon/traefik-forward-auth

# Add libraries
RUN apk add --no-cache git
RUN go get github.com/go-delve/delve/cmd/dlv

# Copy & build
ADD . /go/src/github.com/thomseddon/traefik-forward-auth/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -installsuffix nocgo -gcflags="all=-N -l" -o /traefik-forward-auth github.com/rajasoun/traefik-forward-auth/cmd

# Copy into scratch container
FROM alpine:3.11
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
COPY --from=builder /go/bin/dlv ./

ENTRYPOINT ["./traefik-forward-auth"]
