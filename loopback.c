#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <alloca.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>

// Don't allow more than 16KB of traffic on each socket
#define MAX_BYTES_XFER (1024 * 1024 * 16)

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

// Server test ports will be offset by this amount from the client equivalent
#define SERVER_TEST_PORT_OFFSET -10000

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

typedef struct {
    struct in6_addr addr;
    unsigned char count;
} history_t;

history_t* traffic_history = NULL;
unsigned int traffic_history_entries = 0;
unsigned int traffic_history_limit = 0;
struct timespec traffic_history_epoch;

#define TRAFFIC_HISTORY_RESET_TIME_SEC 60
#define TRAFFIC_HISTORY_THROTTLE_COUNT 255

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
    struct pollfd pfd;

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

    // Connect to the peer on the incoming port with the server test port offset negated
    remote_addr.sin6_port = htons(ntohs(local_addr.sin6_port) - SERVER_TEST_PORT_OFFSET);
    connect(new_sock, (struct sockaddr*)&remote_addr, remote_addr_len);

    // Wait 10 seconds for a successful connection or timeout
    pfd.fd = new_sock;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    err = poll(&pfd, 1, 10000);
    if (err < 0) {
        perror("poll");
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

    do {
        struct pollfd pfds[2];
        int nfds = 0;

        if (bytes_left <= 0) {
            fprintf(stderr, "Connection data limit exceeded\n");
            break;
        }

        if (!s1_read_shutdown) {
            pfds[nfds].fd = s1;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }
        if (!s2_read_shutdown) {
            pfds[nfds].fd = s2;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        if (s1_read_shutdown && s2_read_shutdown) {
            // If both sides closed, tear it down
            break;
        }

        // Wait 10 seconds for data
        err = poll(pfds, nfds, 10000);
        if (err < 0) {
            perror("poll");
            break;
        }
        else if (err == 0) {
            fprintf(stderr, "Connection idle timeout expired\n");
            break;
        }
        else {
            for (int i = 0; i < nfds; i++) {
                if (pfds[i].revents != 0) {
                    if (pfds[i].fd == s1) {
                        // Traffic: S1 -> S2
                        err = splice_data(s1, s2, bytes_left);
                        if (err == 0) {
                            s1_read_shutdown = true;
                            shutdown(s2, SHUT_WR);
                        }
                    }
                    else {
                        // Traffic: S2 -> S1
                        err = splice_data(s2, s1, bytes_left);
                        if (err == 0) {
                            s2_read_shutdown = true;
                            shutdown(s1, SHUT_WR);
                        }
                    }

                    if (err < 0) {
                        break;
                    }
                    else {
                        bytes_left -= err;
                    }
                }
            }
        }
    } while (err >= 0);

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

int is_traffic_allowed(struct in6_addr* address) {
    struct timespec now;
    unsigned int i;

    // Reset the traffic history if needed
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec > traffic_history_epoch.tv_sec + TRAFFIC_HISTORY_RESET_TIME_SEC) {
        free(traffic_history);

        traffic_history = NULL;
        traffic_history_entries = 0;
        traffic_history_limit = 0;

        // The current history epoch starts now
        traffic_history_epoch = now;
    }

    // Search for an existing entry for this address
    for (i = 0; i < traffic_history_entries; i++) {
        int cmp_res = memcmp(address, &traffic_history[i].addr, sizeof(*address));
        if (cmp_res == 0) {
            // This entry matches the given address
            if (traffic_history[i].count == TRAFFIC_HISTORY_THROTTLE_COUNT) {
                // This traffic is blocked due to DDoS throttling
                return 0;
            }
            else {
                // This traffic is allowed
                traffic_history[i].count++;
                return 1;
            }
        }
        else if (cmp_res > 0) {
            // We have already passed the location where this address would be.
            // Break out of the loop so we can add it.
            break;
        }
    }

    // If we made it to this point, we need to add an entry to the history array.

    // Resize the history array if required
    if (traffic_history_entries == traffic_history_limit) {
        unsigned int new_buffer_limit = traffic_history_limit == 0 ? 1 : traffic_history_limit * 2;
        history_t* new_buffer = realloc(traffic_history, new_buffer_limit * sizeof(history_t));
        if (new_buffer == NULL) {
            fprintf(stderr, "Unable to allocate traffic history: %d\n", new_buffer_limit);

            // Deny traffic if we can't allocate memory. Something is fishy...
            return 0;
        }

        traffic_history = new_buffer;
        traffic_history_limit = new_buffer_limit;
    }

    // Slide existing entries over to make room for this one
    memmove(&traffic_history[i+1], &traffic_history[i], (traffic_history_entries - i) * sizeof(history_t));

    traffic_history[i].addr = *address;
    traffic_history[i].count = 1;
    traffic_history_entries++;

    return 1;
}

void usage() {
    printf("gfe-loopback [--reference-port <port number>]\n");
}

int main(int argc, char* argv[]) {
    fd_set fds;
    int server_test_listeners[TCP_PORT_COUNT];
    int server_test_udp_socks[UDP_PORT_COUNT];
    int client_test_listeners[TCP_PORT_COUNT];
    int client_test_udp_socks[UDP_PORT_COUNT];
    int reference_port_listener;
    int i;
    int err;
    pthread_attr_t attr;
    unsigned short reference_port = 0;

    for (i = 1; i < argc; i++) {
        if (strcasecmp(argv[i], "--reference-port") == 0 && i + 1 < argc) {
            reference_port = atoi(argv[++i]);
        }
        else {
            usage();
            return -1;
        }
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // Prevent SIGPIPEs from killing us
    signal(SIGPIPE, SIG_IGN);

    if (reference_port != 0) {
        reference_port_listener = create_socket(reference_port, IPPROTO_TCP);
        if (reference_port_listener < 0) {
            return -1;
        }
    }

    for (i = 0; i < TCP_PORT_COUNT; i++) {
        server_test_listeners[i] = create_socket(TCP_PORTS[i] + SERVER_TEST_PORT_OFFSET, IPPROTO_TCP);
        if (server_test_listeners[i] < 0) {
            return -1;
        }

        client_test_listeners[i] = create_socket(TCP_PORTS[i], IPPROTO_TCP);
        if (client_test_listeners[i] < 0) {
            return -1;
        }
    }

    for (i = 0; i < UDP_PORT_COUNT; i++) {
        server_test_udp_socks[i] = create_socket(UDP_PORTS[i] + SERVER_TEST_PORT_OFFSET, IPPROTO_UDP);
        if (server_test_udp_socks[i] < 0) {
            return -1;
        }

        client_test_udp_socks[i] = create_socket(UDP_PORTS[i], IPPROTO_UDP);
        if (client_test_udp_socks[i] < 0) {
            return -1;
        }
    }

    for (;;) {
        FD_ZERO(&fds);

        int nfds = 0;
        for (i = 0; i < TCP_PORT_COUNT; i++) {
            FD_SET(server_test_listeners[i], &fds);
            nfds = MAX(nfds, server_test_listeners[i] + 1);

            FD_SET(client_test_listeners[i], &fds);
            nfds = MAX(nfds, client_test_listeners[i] + 1);
        }
        for (i = 0; i < UDP_PORT_COUNT; i++) {
            FD_SET(server_test_udp_socks[i], &fds);
            nfds = MAX(nfds, server_test_udp_socks[i] + 1);

            FD_SET(client_test_udp_socks[i], &fds);
            nfds = MAX(nfds, client_test_udp_socks[i] + 1);
        }
        if (reference_port != 0) {
            FD_SET(reference_port_listener, &fds);
            nfds = MAX(nfds, reference_port_listener + 1);
        }

        err = select(nfds, &fds, NULL, NULL, NULL);
        if (err < 0) {
            perror("select");
            return -1;
        }

        if (reference_port != 0) {
            // For the reference port socket, we'll just accept and gracefully close the socket
            if (FD_ISSET(reference_port_listener, &fds)) {
                int sock;
                struct sockaddr_in6 remote_addr;
                socklen_t remote_addr_len;
                char remote_addr_str[INET6_ADDRSTRLEN];

                remote_addr_len = sizeof(remote_addr);
                sock = accept(reference_port_listener, (struct sockaddr*)&remote_addr, &remote_addr_len);
                if (sock < 0) {
                    perror("accept");
                    continue;
                }

                inet_ntop(remote_addr.sin6_family, &remote_addr.sin6_addr,
                          remote_addr_str, sizeof(remote_addr_str));

                fprintf(stderr, "Accepted connection from [%s]:%d on TCP %d\n", remote_addr_str, ntohs(remote_addr.sin6_port), reference_port);

                shutdown(sock, SHUT_WR);
                close(sock);
            }
        }

        for (i = 0; i < TCP_PORT_COUNT; i++) {
            // For the server test socket, we'll spin off another thread to proxy some traffic
            if (FD_ISSET(server_test_listeners[i], &fds)) {
                int sock;
                pthread_t thread;

                sock = accept(server_test_listeners[i], NULL, NULL);
                if (sock < 0) {
                    perror("accept");
                    continue;
                }

                if (pthread_create(&thread, &attr, socket_thread, (void*)(intptr_t)sock)) {
                    close(sock);
                }
            }

            // For the client test socket, we'll just accept and gracefully close the socket
            if (FD_ISSET(client_test_listeners[i], &fds)) {
                int sock;
                struct sockaddr_in6 remote_addr;
                socklen_t remote_addr_len;
                char remote_addr_str[INET6_ADDRSTRLEN];

                remote_addr_len = sizeof(remote_addr);
                sock = accept(client_test_listeners[i], (struct sockaddr*)&remote_addr, &remote_addr_len);
                if (sock < 0) {
                    perror("accept");
                    continue;
                }

                inet_ntop(remote_addr.sin6_family, &remote_addr.sin6_addr,
                          remote_addr_str, sizeof(remote_addr_str));

                fprintf(stderr, "Accepted connection from [%s]:%d on TCP %d\n", remote_addr_str, ntohs(remote_addr.sin6_port), TCP_PORTS[i]);

                shutdown(sock, SHUT_WR);
                close(sock);
            }
        }

        for (i = 0; i < UDP_PORT_COUNT; i++) {
            // For incoming packets on the server test socket, resend them to the standard port
            if (FD_ISSET(server_test_udp_socks[i], &fds)) {
                char buf[1500];
                struct sockaddr_in6 remote_addr;
                socklen_t remote_addr_len;
                char remote_addr_str[INET6_ADDRSTRLEN];

                remote_addr_len = sizeof(remote_addr);
                err = recvfrom(server_test_udp_socks[i], buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &remote_addr_len);
                if (err < 0) {
                    perror("recvfrom");
                    continue;
                }

                inet_ntop(remote_addr.sin6_family, &remote_addr.sin6_addr,
                          remote_addr_str, sizeof(remote_addr_str));

                if (is_traffic_allowed(&remote_addr.sin6_addr)) {
                    fprintf(stderr, "Echoing %d bytes to [%s]:%d\n", err, remote_addr_str, UDP_PORTS[i]);

                    remote_addr.sin6_port = htons(UDP_PORTS[i]);
                    err = sendto(server_test_udp_socks[i], buf, err, 0, (struct sockaddr*)&remote_addr, remote_addr_len);
                    if (err < 0) {
                        perror("sendto");
                    }
                }
                else {
                    fprintf(stderr, "[%s] is throttled by DDoS mitigation (incoming len = %d)\n", remote_addr_str, err);
                }
            }

            // For incoming packets on the client test socket, resend them on the port we received them
            if (FD_ISSET(client_test_udp_socks[i], &fds)) {
                char buf[1500];
                struct sockaddr_in6 remote_addr;
                socklen_t remote_addr_len;
                char remote_addr_str[INET6_ADDRSTRLEN];

                remote_addr_len = sizeof(remote_addr);
                err = recvfrom(client_test_udp_socks[i], buf, sizeof(buf), 0, (struct sockaddr*)&remote_addr, &remote_addr_len);
                if (err < 0) {
                    perror("recvfrom");
                    continue;
                }

                inet_ntop(remote_addr.sin6_family, &remote_addr.sin6_addr,
                          remote_addr_str, sizeof(remote_addr_str));

                if (is_traffic_allowed(&remote_addr.sin6_addr)) {
                    fprintf(stderr, "Echoing %d bytes from UDP %d to [%s]:%d\n", err, UDP_PORTS[i], remote_addr_str, ntohs(remote_addr.sin6_port));

                    err = sendto(client_test_udp_socks[i], buf, err, 0, (struct sockaddr*)&remote_addr, remote_addr_len);
                    if (err < 0) {
                        perror("sendto");
                    }
                }
                else {
                    fprintf(stderr, "[%s] is throttled by DDoS mitigation (incoming len = %d)\n", remote_addr_str, err);
                }
            }
        }
    }
}