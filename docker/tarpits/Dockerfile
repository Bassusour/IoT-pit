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

COPY run.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/run.sh

ENTRYPOINT ["/usr/local/bin/run.sh"]

# WORKDIR /app
# CMD ["run.sh", "start"]
