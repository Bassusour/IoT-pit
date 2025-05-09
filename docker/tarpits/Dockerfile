FROM gcc:12 AS c-builder

WORKDIR /src
COPY servers/ ./servers/
COPY shared/ ./shared/
COPY makefile .

RUN make telnet_pit upnp_pit mqtt_pit

# Final runtime container
FROM debian:bookworm-slim

# Copy binaries to PATH
COPY --from=c-builder /src/bin/* /usr/local/bin/

# Install minimal runtime dependencies (if needed)
# RUN apt-get update && apt-get install -y musl && rm -rf /var/lib/apt/lists/*

# Optional script
COPY run.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run.sh

WORKDIR /app
CMD ["run.sh", "start"]
