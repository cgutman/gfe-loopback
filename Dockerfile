ARG ARCH=

FROM ${ARCH}alpine:latest AS build-env
RUN apk add --no-cache gcc musl-dev
COPY loopback.c /opt
WORKDIR /opt
RUN gcc -o gfe-loopback loopback.c -pthread

FROM ${ARCH}alpine:latest
RUN apk add --no-cache libcap
COPY --from=build-env /opt/gfe-loopback /opt
RUN setcap 'cap_net_bind_service=+ep' /opt/gfe-loopback
USER nobody

EXPOSE 47984/tcp \
       47989/tcp \
       48010/tcp \
       47998/udp \
       47999/udp \
       48000/udp \
       48002/udp \
       48010/udp \
       37984/tcp \
       37989/tcp \
       38010/tcp \
       37998/udp \
       37999/udp \
       38000/udp \
       38002/udp \
       38010/udp

ENTRYPOINT ["/opt/gfe-loopback"]
