FROM golang:1.23 AS go-builder

WORKDIR /app
COPY prometheus/ .
RUN mkdir -p /out && go build -o /out/prometheus_exporter

# Final image
FROM debian:bookworm-slim

COPY --from=go-builder /out/prometheus_exporter /usr/local/bin/

WORKDIR /app
CMD ["prometheus_exporter"]