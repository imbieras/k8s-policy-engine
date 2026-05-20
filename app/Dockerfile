FROM golang:1.25 AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && wget -q https://github.com/microsoft/onnxruntime/releases/download/v1.20.1/onnxruntime-linux-x64-1.20.1.tgz \
    && tar -xzf onnxruntime-linux-x64-1.20.1.tgz \
    && mkdir -p /app/onnxruntime/lib \
    && cp onnxruntime-linux-x64-1.20.1/lib/libonnxruntime.so.1.20.1 /app/onnxruntime/lib/ \
    && rm -rf onnxruntime-linux-x64-1.20.1 onnxruntime-linux-x64-1.20.1.tgz

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o policy-engine ./cmd/backend

FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/policy-engine .
COPY --from=builder /app/onnxruntime/lib /app/onnxruntime/lib
COPY --from=builder /app/models /app/models
COPY --from=builder /app/geoip /app/geoip

ENV LD_LIBRARY_PATH=/app/onnxruntime/lib

RUN mkdir -p /var/lib/policy-engine

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD /bin/sh -c 'curl -f http://localhost:8080/health || exit 1'

CMD ["/app/policy-engine"]
