# Batteries-included image: reconsentry plus the ProjectDiscovery tools it shells
# out to (subfinder, httpx), so `docker run` works with nothing else installed.
#
#   docker build -t reconsentry .
#   docker run --rm -v "$PWD:/work" -w /work reconsentry run --config scope.yaml

# ---- build reconsentry from source ----
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/reconsentry ./cmd/reconsentry

# ---- fetch ProjectDiscovery tools ----
FROM golang:1.26-alpine AS pdtools
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ---- runtime ----
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build   /out/reconsentry  /usr/local/bin/reconsentry
COPY --from=pdtools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=pdtools /go/bin/httpx     /usr/local/bin/httpx
ENTRYPOINT ["reconsentry"]
