// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "rekernel.h"
#include "rk_format.h"

#define DEFAULT_BPF_OBJ "rekernel.bpf.o"
#define MAX_CLIENTS     64
#define MAX_EVENTS      (MAX_CLIENTS + 2)
#define PACKET_LINE_MAX (256 + INTERFACETOKEN_BUFF_SIZE)

static volatile sig_atomic_t exiting;
static int client_fd[MAX_CLIENTS];
static int net_uid_map_fd = -1;
static int g_ep = -1;

static void on_sigint(int sig) { (void)sig; exiting = 1; }

static int libbpf_quiet(enum libbpf_print_level lvl, const char *fmt, va_list ap)
{
	if (lvl == LIBBPF_DEBUG && !getenv("REKERNELD_VERBOSE"))
		return 0;
	return vfprintf(stderr, fmt, ap);
}

static void client_add(int fd)
{
	for (int i = 0; i < MAX_CLIENTS; i++) {
		if (client_fd[i] < 0) {
			client_fd[i] = fd;
			return;
		}
	}
	close(fd);
}

static void client_drop(int ep, int fd)
{
	epoll_ctl(ep, EPOLL_CTL_DEL, fd, NULL);
	close(fd);
	for (int i = 0; i < MAX_CLIENTS; i++)
		if (client_fd[i] == fd)
			client_fd[i] = -1;
}

static int handle_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	static int verbose = -1;
	char line[PACKET_LINE_MAX];
	int n;

	if (verbose < 0)
		verbose = getenv("REKERNELD_VERBOSE") ? 1 : 0;

	if (size < sizeof(struct rk_event))
		return 0;

	n = rk_format((const struct rk_event *)data, line, sizeof(line) - 1);
	if (n <= 0)
		return 0;
	if (n > (int)sizeof(line) - 1)
		n = sizeof(line) - 1;
	line[n++] = '\n';

	if (verbose)
		fprintf(stderr, "[evt] %.*s", n, line);

	for (int i = 0; i < MAX_CLIENTS; i++) {
		int fd = client_fd[i];
		if (fd < 0)
			continue;
		if (write(fd, line, n) < 0) {
			if (errno == EINTR || errno == EAGAIN) {
				if (verbose)
					fprintf(stderr, "[drop] fd=%d %s\n", fd, strerror(errno));
			} else {
				client_drop(g_ep, fd);
			}
		}
	}
	return 0;
}

static void send_version(int fd)
{
	char line[64];
	int n = snprintf(line, sizeof(line) - 1, "type=Version,version=%s;", REKERNEL_VERSION);
	if (n > 0) {
		line[n++] = '\n';
		if (write(fd, line, n) < 0) {
		}
	}
}

static void handle_command(int fd, char *buf)
{
	char *line, *save = NULL;
	for (line = strtok_r(buf, "\r\n", &save); line; line = strtok_r(NULL, "\r\n", &save)) {
		unsigned int uid;
		__u8 one = 1;
		if (sscanf(line, "ADD_MONITOR_NET %u", &uid) == 1) {
			if (net_uid_map_fd >= 0)
				bpf_map_update_elem(net_uid_map_fd, &uid, &one, BPF_ANY);
		} else if (sscanf(line, "DEL_MONITOR_NET %u", &uid) == 1) {
			if (net_uid_map_fd >= 0)
				bpf_map_delete_elem(net_uid_map_fd, &uid);
		} else if (strcmp(line, "GET_VERSION") == 0) {
			send_version(fd);
		}
	}
}

static int make_server(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	const char *name = REKERNEL_SOCKET_NAME;
	size_t nlen = strlen(name);
	socklen_t alen;
	int s;

	s = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (s < 0)
		return -1;

	addr.sun_path[0] = '\0';
	memcpy(addr.sun_path + 1, name, nlen);
	alen = offsetof(struct sockaddr_un, sun_path) + 1 + nlen;

	if (bind(s, (struct sockaddr *)&addr, alen) < 0) {
		fprintf(stderr, "bind @%s failed: %s\n", name, strerror(errno));
		close(s);
		return -1;
	}
	if (listen(s, 16) < 0) {
		close(s);
		return -1;
	}
	return s;
}

int main(int argc, char **argv)
{
	const char *bpf_obj_path = argc > 1 ? argv[1] : DEFAULT_BPF_OBJ;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct ring_buffer *rb = NULL;
	int ep = -1, srv = -1, rb_fd, events_fd, rc = 1;
	struct epoll_event ev;

	for (int i = 0; i < MAX_CLIENTS; i++)
		client_fd[i] = -1;

	signal(SIGINT, on_sigint);
	signal(SIGTERM, on_sigint);
	signal(SIGPIPE, SIG_IGN);
	libbpf_set_print(libbpf_quiet);

	obj = bpf_object__open_file(bpf_obj_path, NULL);
	if (!obj || libbpf_get_error(obj)) {
		fprintf(stderr, "failed to open BPF object '%s'\n", bpf_obj_path);
		obj = NULL;
		goto out;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "failed to load BPF object: %s\n", strerror(errno));
		fprintf(stderr, "Re-run with REKERNELD_VERBOSE=1 for the full libbpf relocation/verifier log.\n");
		goto out;
	}
	bpf_object__for_each_program(prog, obj) {
		if (!bpf_program__attach(prog))
			fprintf(stderr, "warning: failed to attach %s\n",
				bpf_program__name(prog));
	}

	net_uid_map_fd = bpf_object__find_map_fd_by_name(obj, "net_uid_map");
	events_fd = bpf_object__find_map_fd_by_name(obj, "events");
	if (net_uid_map_fd < 0 || events_fd < 0) {
		fprintf(stderr, "BPF maps not found in object\n");
		goto out;
	}

	rb = ring_buffer__new(events_fd, handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		goto out;
	}
	rb_fd = ring_buffer__epoll_fd(rb);

	srv = make_server();
	if (srv < 0)
		goto out;

	ep = epoll_create1(EPOLL_CLOEXEC);
	if (ep < 0)
		goto out;
	g_ep = ep;

	ev.events = EPOLLIN; ev.data.fd = rb_fd;
	epoll_ctl(ep, EPOLL_CTL_ADD, rb_fd, &ev);
	ev.events = EPOLLIN; ev.data.fd = srv;
	epoll_ctl(ep, EPOLL_CTL_ADD, srv, &ev);

	fprintf(stderr, "Thank you for choosing Re:Kernel-eBPF!\n");
	fprintf(stderr, "Created Re:Kernel server! Socket name: @%s\n", REKERNEL_SOCKET_NAME);

	while (!exiting) {
		struct epoll_event evs[MAX_EVENTS];
		int n = epoll_wait(ep, evs, MAX_EVENTS, -1);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (int i = 0; i < n; i++) {
			int fd = evs[i].data.fd;

			if (fd == rb_fd) {
				ring_buffer__consume(rb);
			} else if (fd == srv) {
				int c;
				while ((c = accept4(srv, NULL, NULL,
						    SOCK_NONBLOCK | SOCK_CLOEXEC)) >= 0) {
					ev.events = EPOLLIN | EPOLLRDHUP;
					ev.data.fd = c;
					if (epoll_ctl(ep, EPOLL_CTL_ADD, c, &ev) == 0) {
						client_add(c);
						send_version(c);
					} else {
						close(c);
					}
				}
				if (c < 0 && (errno == ECONNABORTED || errno == EINTR))
					continue;
			} else {
				char buf[512];
				ssize_t r = read(fd, buf, sizeof(buf) - 1);
				if (r > 0) {
					buf[r] = '\0';
					handle_command(fd, buf);
				}
				if (r <= 0 || (evs[i].events & (EPOLLHUP | EPOLLRDHUP)))
					client_drop(ep, fd);
			}
		}
	}
	rc = 0;
out:
	if (rb)
		ring_buffer__free(rb);
	if (srv >= 0)
		close(srv);
	if (ep >= 0)
		close(ep);
	if (obj)
		bpf_object__close(obj);
	return rc;
}
