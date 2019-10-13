FROM ubuntu:latest

EXPOSE 47984/tcp \
       47989/tcp \
       48010/tcp \
       47998/udp \
       47999/udp \
       48000/udp \
       48002/udp \
       48010/udp

USER root

RUN set -ex && \
    apt-get update && \
    apt-get install -y build-essential && \
    apt-get install -y git && \
    apt-get clean -y && \
    rm -rf /var/lib/apt/lists/*

RUN cd /opt && git clone https://github.com/cgutman/gfe-loopback.git && cd gfe-loopback && gcc -o gfe-loopback loopback.c -pthread

WORKDIR /opt/gfe-loopback

ENTRYPOINT ["/opt/gfe-loopback/gfe-loopback"]
