FROM ubuntu:latest

EXPOSE 47984/tcp \
       47989/tcp \
       48010/tcp \
       47998/udp \
       47999/udp \
       48000/udp \
       48002/udp \
       48010/udp

RUN set -ex && \
    apt-get update && \
    apt-get install -y gcc && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

COPY loopback.c /opt

WORKDIR /opt

RUN gcc -o gfe-loopback loopback.c -pthread

USER nobody

ENTRYPOINT ["/opt/gfe-loopback"]
