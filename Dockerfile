FROM alpine:latest AS build-env
RUN apk add --no-cache gcc musl-dev
COPY loopback.c /opt
WORKDIR /opt
RUN gcc -o gfe-loopback loopback.c -pthread

FROM alpine:latest
COPY --from=build-env /opt/gfe-loopback /opt
USER nobody

EXPOSE 47984/tcp \
       47989/tcp \
       48010/tcp \
       47998/udp \
       47999/udp \
       48000/udp \
       48002/udp \
       48010/udp

ENTRYPOINT ["/opt/gfe-loopback"]
