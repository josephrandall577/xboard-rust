#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// Only this synthetic hostname is intercepted; no host DNS configuration changes.
static int audit_getaddrinfo(const char *node, const char *service,
                            const struct addrinfo *hints, struct addrinfo **result) {
    if (!node || strcmp(node, "audit-two.invalid") != 0)
        return getaddrinfo(node, service, hints, result);
    struct addrinfo *first = calloc(1, sizeof(*first));
    struct addrinfo *second = calloc(1, sizeof(*second));
    struct sockaddr_in *a = calloc(1, sizeof(*a));
    struct sockaddr_in *b = calloc(1, sizeof(*b));
    a->sin_len = sizeof(*a); a->sin_family = AF_INET;
    b->sin_len = sizeof(*b); b->sin_family = AF_INET;
    a->sin_port = b->sin_port = service ? htons((unsigned short)atoi(service)) : 0;
    inet_pton(AF_INET, "127.0.0.2", &a->sin_addr);
    inet_pton(AF_INET, "127.0.0.1", &b->sin_addr);
    first->ai_family = second->ai_family = AF_INET;
    first->ai_socktype = second->ai_socktype = SOCK_STREAM;
    first->ai_protocol = second->ai_protocol = IPPROTO_TCP;
    first->ai_addrlen = second->ai_addrlen = sizeof(*a);
    first->ai_addr = (struct sockaddr*)a; second->ai_addr = (struct sockaddr*)b;
    first->ai_next = second;
    first->ai_canonname = strdup("xboard-audit-resolver");
    *result = first;
    return 0;
}
static void audit_freeaddrinfo(struct addrinfo *ai) {
    if (!ai || !ai->ai_canonname || strcmp(ai->ai_canonname, "xboard-audit-resolver") != 0) {
        freeaddrinfo(ai);
        return;
    }
    while (ai) {
        struct addrinfo *next = ai->ai_next;
        free(ai->ai_canonname); free(ai->ai_addr); free(ai);
        ai = next;
    }
}
static int audit_connect(int fd, const struct sockaddr *address, socklen_t length) {
    if (address->sa_family == AF_INET &&
        ((const struct sockaddr_in *)address)->sin_addr.s_addr == htonl(0x7f000002)) {
        errno = ECONNREFUSED;
        return -1;
    }
    return connect(fd, address, length);
}
#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { const void *replacement; const void *original; } \
    interpose_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)&replacement, (const void *)&original };
INTERPOSE(audit_getaddrinfo, getaddrinfo)
INTERPOSE(audit_freeaddrinfo, freeaddrinfo)
INTERPOSE(audit_connect, connect)
