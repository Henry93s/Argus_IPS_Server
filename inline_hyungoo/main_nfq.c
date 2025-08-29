//cat > main_nfq.c <<'EOF'
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "nfq_iface.h"
#include "ruleset.h"

static volatile sig_atomic_t g_run = 1;
static void on_sigint(int s){ (void)s; g_run = 0; }

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0); // line-buffered
    signal(SIGINT, on_sigint);

    if (ruleset_init(NULL) != 0) {
        fprintf(stderr, "ruleset_init failed\n");
        return 1;
    }

    struct nfq_q_handle* qh = NULL;
    struct nfq_handle* h = nfq_setup(&qh, 0); // queue 0
    if (!h) return 1;

    const int fd = nfq_fd(h);
    char buf[8192];

    printf("[NFQ] listening on queue 0 (Ctrl+C to stop)\n");

    while (g_run) {
        const int r = recv(fd, buf, sizeof(buf), 0);
        if (r >= 0) {
            nfq_handle_packet(h, buf, r);
            continue;
        }
        if (errno == EINTR) continue;
        perror("recv");
        break;
    }

    nfq_teardown(h, qh);
    printf("[NFQ] bye\n");

    (void)errno; (void)strlen; (void)write;
    printf("ok\n");
    return 0;
}
