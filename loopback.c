#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <alloca.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

// Don't allow more than 16KB of traffic on each socket
#define MAX_BYTES_XFER (1024 * 1024 * 16)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define TCP_PORT_COUNT 3
unsigned short TCP_PORTS[TCP_PORT_COUNT] = {
    47989,
    47984,
    48010
};

#define UDP_PORT_COUNT 5
unsigned short UDP_PORTS[UDP_PORT_COUNT] = {
    47998,
    47999,
    48000,
    48002,
    48010
};

int splice_data(int from, int to, int len) {
    int err;
    char buf[1024];

    len = MIN(sizeof(buf), len);

    err = recv(from, buf, len, 0);
    if (err < 0) {
        perror("recv");
        return -1;
    }
    else if (err == 0) {
        return 0;
    }

    err = send(to, buf, err, 0);
    if (err < 0) {
        perror("send");
    }

    return err;
}

int connect_back(int sock) {
    int new_sock;
    struct sockaddr_in6 remote_addr;
    socklen_t remote_addr_len;
    struct sockaddr_in6 local_addr;
    socklen_t local_addr_len;
    char remote_addr_str[INET6_ADDRSTRLEN];
    int err;
    int opt;
    fd_set fds;
    struct timeval tv;

    remote_addr_len = sizeof(remote_addr);
    err = getpeername(sock, (struct sockaddr*)&remote_addr, &remote_addr_len);
    if (err < 0) {
        perror("getpeername");
        return -1;
    }

    // Convert to text form for printfs
    inet_ntop(remote_addr.sin6_family, &remote_addr.sin6_addr,
              remote_addr_str, sizeof(remote_addr_str));

    local_addr_len = sizeof(local_addr);
    err = getsockname(sock, (struct sockaddr*)&local_addr, &local_addr_len);
    if (err < 0) {
        perror("getsockname");
        return -1;
    }

    new_sock = socket(local_addr.sin6_family, SOCK_STREAM, IPPROTO_TCP);
    if (new_sock < 0) {
        perror("socket");
        return -1;
    }

    if (local_addr.sin6_family == AF_INET6) {
        // Also allow v4 traffic on this socket
        int val = 0;
        setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));
    }

    // Switch the new socket to non-blocking mode to allow connect() to timeout
    opt = 1;
    ioctl(new_sock, FIONBIO, &opt);

    // Connect to the peer using the same port it contacted us on
    remote_addr.sin6_port = local_addr.sin6_port;
    connect(new_sock, (struct sockaddr*)&remote_addr, remote_addr_len);

    // Wait 10 seconds for a successful connection or timeout
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    FD_ZERO(&fds);
    FD_SET(new_sock, &fds);
    err = select(new_sock + 1, NULL, &fds, NULL, &tv);
    if (err < 0) {
        perror("select");
        close(new_sock);
        return -1;
    }
    else if (err == 0) {
        // Timeout
        close(new_sock);
        fprintf(stderr, "Timeout connecting to [%s]:%d\n",
                remote_addr_str,
                ntohs(remote_addr.sin6_port));
        return -1;
    }
    else {
        int optval;
        unsigned int optlen;

        // Check the connection result
        optlen = sizeof(optval);
        getsockopt(new_sock, SOL_SOCKET, SO_ERROR, &optval, &optlen);
        if (optval) {
            fprintf(stderr, "Error connecting to [%s]:%d - %s (%d)\n",
                    remote_addr_str,
                    ntohs(remote_addr.sin6_port),
                    strerror(optval),
                    optval);
            close(new_sock);
            return -1;
        }

        // Switch back to blocking mode
        opt = 0;
        ioctl(new_sock, FIONBIO, &opt);

        fprintf(stderr, "Connected to [%s]:%d\n",
                remote_addr_str,
                ntohs(remote_addr.sin6_port));
        
        return new_sock;
    }
}

void* socket_thread(void* context) {
    int s1, s2;
    bool s1_read_shutdown = false;
    bool s2_read_shutdown = false;
    int err;
    int bytes_left = MAX_BYTES_XFER;

    s1 = (intptr_t)context;
    s2 = connect_back(s1);
    if (s2 < 0) {
        close(s1);
        return NULL;
    }

    for (;;) {
        fd_set fds;
        struct timeval tv;

        if (bytes_left <= 0) {
            fprintf(stderr, "Connection data limit exceeded\n");
            break;
        }

        FD_ZERO(&fds);

        if (!s1_read_shutdown)
            FD_SET(s1, &fds);
        if (!s2_read_shutdown)
            FD_SET(s2, &fds);

        if (s1_read_shutdown && s2_read_shutdown) {
            // If both sides closed, tear it down
            break;
        }

        // Wait 10 seconds for data
        tv.tv_sec = 10;
        tv.tv_usec = 0;
        err = select(MAX(s1, s2) + 1, &fds, NULL, NULL, &tv);
        if (err < 0) {
            perror("select");
            break;
        }
        else if (err == 0) {
            fprintf(stderr, "Connection idle timeout expired\n");
            break;
        }
        else if (FD_ISSET(s1, &fds)) {
            err = splice_data(s1, s2, bytes_left);
            if (err == 0) {
                s1_read_shutdown = true;
                shutdown(s2, SHUT_WR);
            }
            else if (err < 0) {
                break;
            }
            else {
                bytes_left -= err;
            }
        }
        else if (FD_ISSET(s2, &fds)) {
            err = splice_data(s2, s1, bytes_left);
            if (err == 0) {
                s2_read_shutdown = true;
                shutdown(s1, SHUT_WR);
            }
            else if (err < 0) {
                break;
            }
            else {
                bytes_left -= err;
            }
        }
    }

    fprintf(stderr, "Disconnecting after %d bytes transferred\n", (MAX_BYTES_XFER - bytes_left));

    close(s1);
    close(s2);
    return NULL;
}

int create_socket(unsigned short port, int proto) {
    int sock;
    struct sockaddr_in6 addr;
    int err;
    int val;

    sock = socket(AF_INET6,
                  proto == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM,
                  proto);
    if (sock < 0) {
        perror("sock");
        return -1;
    }

    // Use this socket for both v6 and v4 traffic
    val = 0;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val));

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    err = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (err < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    if (proto == IPPROTO_TCP) {
        err = listen(sock, 1);
        if (err < 0) {
            perror("listen");
            close(sock);
            return -1;
        }
    }

    return sock;
}

int main(int argc, char* argv[]) {
    fd_set fds;
    int listeners[TCP_PORT_COUNT];
    int udp_socks[UDP_PORT_COUNT];
    int i;
    int err;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // Prevent SIGPIPEs from killing us
    signal(SIGPIPE, SIG_IGN);

    for (i = 0; i < TCP_PORT_COUNT; i++) {
        listeners[i] = create_socket(TCP_PORTS[i], IPPROTO_TCP);
        if (listeners[i] < 0) {
            return -1;
        }
    }

    for (i = 0; i < UDP_PORT_COUNT; i++) {
        udp_socks[i] = create_socket(UDP_PORTS[i], IPPROTO_UDP);
        if (udp_socks[i] < 0) {
            return -1;
        }
    }

    for (;;) {
        FD_ZERO(&fds);

        int nfds = 0;
        for (i = 0; i < TCP_PORT_COUNT; i++) {
            FD_SET(listeners[i], &fds);
            nfds = MAX(nfds, listeners[i] + 1);
        }
        for (i = 0; i < UDP_PORT_COUNT; i++) {
            FD_SET(udp_socks[i], &fds);
            nfds = MAX(nfds, udp_socks[i] + 1);
        }

        err = select(nfds, &fds, NULL, NULL, NULL);
        if (err < 0) {
            perror("select");
            return -1;
        }

        for (i = 0; i < TCP_PORT_COUNT; i++) {
            if (FD_ISSET(listeners[i], &fds)) {
                int sock;
                pthread_t thread;

                sock = accept(listeners[i], NULL, NULL);
                if (sock < 0) {
                    perror("accept");
                    break;
                }

                if (pthread_create(&thread, &attr, socket_thread, (void*)(intptr_t)sock)) {
                    close(sock);
                }
            }
        }

        for (i = 0; i < UDP_PORT_COUNT; i++) {
            if (FD_ISSET(udp_socks[i], &fds)) {
                char buf[32];
                struct sockaddr_in6 remote_addr;
                socklen_t remote_addr_len;
                char remote_addr_str[INET6_ADDRSTRLEN];

                remote_addr_len = sizeof(remote_addr);
                err = recvfrom(udp_socks[i], buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &remote_addr_len);
                if (err < 0) {
                    perror("recvfrom");
                    break;
                }

                inet_ntop(remote_addr.sin6_family, &remote_addr.sin6_addr,
                          remote_addr_str, sizeof(remote_addr_str));

                fprintf(stderr, "Sending %d bytes to [%s]:%d\n", err, remote_addr_str, UDP_PORTS[i]);

                remote_addr.sin6_port = htons(UDP_PORTS[i]);
                err = sendto(udp_socks[i], buf, err, 0, (struct sockaddr*)&remote_addr, remote_addr_len);
                if (err < 0) {
                    perror("sendto");
                    break;
                }

                // Throttle send rate by sleeping 10 ms between packets
                usleep(1000 * 10);
            }
        }
    }
}