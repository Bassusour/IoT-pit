FROM alpine:3.9 as builder
RUN apk add --no-cache build-base
ADD endlessh/endlessh.c endlessh/Makefile /
ADD shared/ /
RUN make

FROM alpine:3.9

COPY --from=builder /endlessh /

ENTRYPOINT ["/endlessh"]

CMD ["-v"]
