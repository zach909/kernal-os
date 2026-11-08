// SPDX-License-Identifier: GPL-2.0-only
/*
 * Boot test for the KOS LSM. Runs as PID 1 (the core) in a throwaway kernel and
 * prints "ok - ..." / "not ok - ..." for each check, then
 * "KOS-LSM-TEST-DONE failures=N" and reboots (QEMU exits).
 *
 * Every refusal is tested next to the allowance that proves it is the rule
 * and not a broken environment (a connect that is refused with EACCES, then
 * the same connect succeeding once the core allowed it).
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define KOS_PR_CLAIM_CORE 0x4b4f5301
#define KOS_PR_CONFINE    0x4b4f5302
#define KOS_PR_STATUS     0x4b4f5303
#define KOS_STATUS_CORE   0x40000000
#define SFS "/sys/kernel/security/kos/"
#define PORT 9000

static int failures;

static void check(int cond, const char *name)
{
	printf("%s - %s\n", cond ? "ok" : "not ok", name);
	fflush(stdout);
	if (!cond)
		failures++;
}

static int refused(long rc, int e) { return rc < 0 && errno == e; }
static int has(const char *hay, const char *needle) { return strstr(hay, needle) != NULL; }

static int write_rule(const char *line)
{
	int fd = open(SFS "rules", O_WRONLY);
	ssize_t n;
	int e;

	if (fd < 0)
		return -1;
	n = write(fd, line, strlen(line));
	e = errno;
	close(fd);
	errno = e;
	return n < 0 ? -1 : 0;
}

static int slurp(const char *path, char *buf, size_t size)
{
	int fd = open(path, O_RDONLY);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, size - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = 0;
	return (int)n;
}

static struct sockaddr_in v4(const char *ip, int port)
{
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port) };

	inet_pton(AF_INET, ip, &a.sin_addr);
	return a;
}

static int tcp4(void) { return socket(AF_INET, SOCK_STREAM, 0); }

static int try_connect(const char *ip, int port)
{
	int s = tcp4(), rc, e;
	struct sockaddr_in a = v4(ip, port);

	if (s < 0)
		return -1;
	rc = connect(s, (void *)&a, sizeof(a));
	e = errno;
	close(s);
	errno = e;
	return rc;
}

/* Run fn in a child that the core confined as `app` (0: not confined). */
static int in_child(unsigned app, int (*fn)(void))
{
	pid_t p;
	int st;

	fflush(stdout);
	p = fork();
	if (p == 0) {
		failures = 0;			/* count only this child's checks */
		if (app && prctl(KOS_PR_CONFINE, app, 0, 0, 0)) {
			printf("not ok - confine as app %u: %s\n", app, strerror(errno));
			_exit(100);
		}
		_exit(fn());
	}
	waitpid(p, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

#define CHILD(app, fn) do { failures += in_child(app, fn); } while (0)

/* ---- children ----------------------------------------------------------- */

static int c_identity(void)
{
	long st = prctl(KOS_PR_STATUS, 0, 0, 0, 0);
	char buf[256];

	check(st == 7, "a confined child reports its app id and is not the core");
	check(refused(prctl(KOS_PR_CONFINE, 8, 0, 0, 0), EPERM), "an app cannot confine itself again or change id");
	check(refused(prctl(KOS_PR_CLAIM_CORE, 0, 0, 0, 0), EPERM), "an app cannot claim the core");
	check(refused(write_rule("allow 7 tcp connect 127.0.0.1 9000"), EPERM), "an app cannot write firewall rules");
	check(refused(slurp(SFS "log", buf, sizeof(buf)), EPERM), "an app cannot read the log");
	check(slurp(SFS "rules", buf, sizeof(buf)) < 0, "an app cannot read the rules");
	check(slurp(SFS "status", buf, sizeof(buf)) > 0, "status is readable by an app");
	return failures;
}

static int c_claim_denied(void)
{
	check(refused(prctl(KOS_PR_CLAIM_CORE, 0, 0, 0, 0), EPERM), "only PID 1 can claim the core");
	return failures;
}

static int c_unconfined_control(void)
{
	/* The same calls an app is refused must work for the core, or the test proves nothing. */
	check(tcp4() >= 0, "control: the core can create an inet socket");
	check(open("/tmp/ctl-null", O_RDONLY) >= 0, "control: the core can open a device node");
	check(prctl(KOS_PR_STATUS, 0, 0, 0, 0) == KOS_STATUS_CORE || prctl(KOS_PR_STATUS, 0, 0, 0, 0) == 0,
	      "control: a plain child of the core is the core or nothing");
	return failures;
}

static int c_default_deny(void)
{
	struct sockaddr_un u = { .sun_family = AF_UNIX };
	int s;

	check(refused(tcp4(), EACCES), "app 7 with no rule cannot create a TCP socket");
	check(refused(socket(AF_INET, SOCK_DGRAM, 0), EACCES), "app 7 with no rule cannot create a UDP socket");
	check(refused(socket(AF_INET6, SOCK_STREAM, 0), EACCES), "app 7 with no rule cannot create an IPv6 socket");
	check(refused(socket(AF_INET, SOCK_RAW, IPPROTO_ICMP), EACCES), "app 7 cannot create a raw socket");
	check(refused(socket(AF_PACKET, SOCK_RAW, 0), EACCES), "app 7 cannot create a packet socket");
	check(refused(socket(AF_NETLINK, SOCK_RAW, 0), EACCES), "app 7 cannot create a netlink socket");
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	check(s >= 0, "app 7 can create a unix socket (the command channel is a socketpair)");
	strcpy(u.sun_path, "/tmp/kos-test.sock");
	check(refused(bind(s, (void *)&u, sizeof(u)), EACCES), "app 7 cannot bind a unix socket");
	check(refused(connect(s, (void *)&u, sizeof(u)), EACCES), "app 7 cannot connect to a unix socket");
	u.sun_path[0] = 0;
	strcpy(u.sun_path + 1, "kos-abstract");
	check(refused(connect(s, (void *)&u, sizeof(u.sun_family) + 13), EACCES), "app 7 cannot connect to an abstract unix socket");
	{
		int sv[2];

		check(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0 && write(sv[0], "x", 1) == 1, "app 7 can use a socketpair");
	}
	return failures;
}

static int c_devices(void)
{
	check(open("/tmp/dev-null", O_RDONLY) >= 0, "an app can open /dev/null-like (1:3)");
	check(open("/tmp/dev-zero", O_RDONLY) >= 0, "an app can open zero (1:5)");
	check(open("/tmp/dev-urandom", O_RDONLY) >= 0, "an app can open urandom (1:9)");
	check(refused(open("/tmp/dev-tty", O_RDONLY), EACCES), "an app cannot open a tty (5:1)");
	check(refused(open("/tmp/dev-mem", O_RDONLY), EACCES), "an app cannot open mem (1:1)");
	check(refused(open("/tmp/dev-input", O_RDONLY), EACCES), "an app cannot open an input device (13:64)");
	check(refused(open("/tmp/dev-disk", O_RDONLY), EACCES), "an app cannot open a block device (8:0)");
	check(refused(mknod("/tmp/new-dev", S_IFCHR | 0600, makedev(1, 3)), EPERM), "an app cannot create a device node, even null");
	return failures;
}

static int c_kernel_interfaces(void)
{
	union bpf_attr b;
	struct perf_event_attr p;

	memset(&b, 0, sizeof(b));
	memset(&p, 0, sizeof(p));
	p.size = sizeof(p);
	check(refused(syscall(SYS_bpf, BPF_MAP_CREATE, &b, sizeof(b)), EPERM), "an app cannot call bpf()");
	check(refused(syscall(SYS_perf_event_open, &p, 0, -1, -1, 0), EPERM), "an app cannot call perf_event_open()");
	check(refused(ptrace(PTRACE_TRACEME, 0, 0, 0), EPERM), "an app cannot ptrace-traceme");
	return failures;
}

static int c_bpf_perf_control(void)
{
	union bpf_attr b;
	struct perf_event_attr p;

	memset(&b, 0, sizeof(b));
	memset(&p, 0, sizeof(p));
	p.size = sizeof(p);
	check(!refused(syscall(SYS_bpf, BPF_MAP_CREATE, &b, sizeof(b)), EPERM), "control: the core's bpf() is not refused by the LSM");
	check(!refused(syscall(SYS_perf_event_open, &p, 0, -1, -1, 0), EPERM), "control: the core's perf_event_open() is not refused by the LSM");
	return failures;
}

static int c_with_rule(void)
{
	struct sockaddr_in a;
	int s;

	check(try_connect("127.0.0.1", PORT) == 0, "app 8 connects to exactly the host and port the core allowed");
	check(refused(try_connect("127.0.0.1", PORT + 1), EACCES), "app 8 cannot connect to another port");
	check(refused(try_connect("127.0.0.2", PORT), EACCES), "app 8 cannot connect to another host");
	check(refused(try_connect("0.0.0.0", PORT), EACCES), "app 8 cannot reach loopback through 0.0.0.0");
	s = socket(AF_INET, SOCK_DGRAM, 0);
	check(s >= 0, "app 8 may create a UDP socket (it has a rule)");
	a = v4("127.0.0.1", PORT);
	check(refused(connect(s, (void *)&a, sizeof(a)), EACCES), "a TCP rule does not allow UDP");
	check(refused(sendto(s, "x", 1, 0, (void *)&a, sizeof(a)), EACCES), "a TCP rule does not allow a UDP send");
	a.sin_family = AF_UNSPEC;
	check(refused(sendto(s, "x", 1, 0, (void *)&a, sizeof(a)), EACCES), "AF_UNSPEC does not smuggle a UDP destination past the rule");
	close(s);
	{
		struct sockaddr_in a4 = v4("127.0.0.1", PORT);
		int s6 = socket(AF_INET6, SOCK_DGRAM, 0);

		check(refused(sendto(s6, "x", 1, 0, (void *)&a4, sizeof(a4)), EACCES),
		      "an AF_INET address on an IPv6 UDP socket is still checked as IPv4");
		close(s6);
	}
	s = tcp4();
	a = v4("127.0.0.1", 9100);
	check(refused(bind(s, (void *)&a, sizeof(a)), EACCES), "app 8 cannot listen without a listen rule");
	check(refused(listen(s, 4), EACCES), "an unbound socket cannot listen");
	close(s);
	return failures;
}

static int c_other_app(void)
{
	check(refused(try_connect("127.0.0.1", PORT), EACCES), "app 9 has no rule: app 8's rule is not its rule");
	return failures;
}

static int c_listen(void)
{
	struct sockaddr_in a = v4("127.0.0.1", 9100), b = v4("127.0.0.1", 9101);
	int s = tcp4();

	check(bind(s, (void *)&a, sizeof(a)) == 0, "app 8 binds the one address and port the core allowed");
	check(listen(s, 4) == 0, "app 8 listens on it");
	close(s);
	s = tcp4();
	check(refused(bind(s, (void *)&b, sizeof(b)), EACCES), "app 8 cannot bind another port");
	a.sin_port = 0;
	check(refused(bind(s, (void *)&a, sizeof(a)), EACCES), "app 8 cannot bind an ephemeral port");
	close(s);
	return failures;
}

static int c_ipv6_rule(void)
{
	struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(9200) };
	int s = socket(AF_INET6, SOCK_STREAM, 0), rc, e;

	inet_pton(AF_INET6, "::1", &a.sin6_addr);
	check(s >= 0, "app 8 may create an IPv6 socket once it has a rule");
	rc = connect(s, (void *)&a, sizeof(a));
	e = errno;
	check(!(rc < 0 && e == EACCES), "an IPv6 rule lets the hook through (the kernel may still say refused or unreachable)");
	a.sin6_port = htons(9201);
	check(refused(connect(s, (void *)&a, sizeof(a)), EACCES), "another IPv6 port is refused");
	return failures;
}

static int c_after_revoke(void)
{
	check(refused(try_connect("127.0.0.1", PORT), EACCES) || refused(tcp4(), EACCES), "after revoke the app is refused again");
	return failures;
}

static int c_status(void)
{
	printf("# status %d\n", (int)prctl(KOS_PR_STATUS, 0, 0, 0, 0));
	return prctl(KOS_PR_STATUS, 0, 0, 0, 0) == 7 ? 0 : 1;
}

static int c_exec_and_fork(void)
{
	char *argv[] = { "/init", "--status", NULL };
	pid_t p = fork();
	int st;

	if (p == 0) {
		execv("/init", argv);
		_exit(98);
	}
	waitpid(p, &st, 0);
	check(WIFEXITED(st) && WEXITSTATUS(st) == 0, "confinement survives fork and exec");
	return failures;
}

/* ---- the core ----------------------------------------------------------- */

static void mknod_ok(const char *path, mode_t type, int maj, int min)
{
	if (mknod(path, type | 0666, makedev(maj, min)))
		printf("# mknod %s: %s\n", path, strerror(errno));
}

int main(int argc, char **argv)
{
	char buf[4096];
	struct ifreq ifr;
	struct sockaddr_in a = v4("127.0.0.1", PORT);
	int ls, one = 1, ctl;

	if (argc > 1 && !strcmp(argv[1], "--status"))
		return c_status();

	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);
	mount("tmpfs", "/tmp", "tmpfs", 0, NULL);
	setvbuf(stdout, NULL, _IOLBF, 0);

	printf("# KOS LSM boot test\n");
	check(slurp(SFS "status", buf, sizeof(buf)) > 0 && has(buf, "core=unclaimed"), "the module is up and the core is unclaimed");

	CHILD(0, c_claim_denied);
	check(refused(prctl(KOS_PR_CONFINE, 7, 0, 0, 0), EPERM), "nobody can confine before the core is claimed");
	check(prctl(KOS_PR_CLAIM_CORE, 0, 0, 0, 0) == 0, "init claims the core");
	check(refused(prctl(KOS_PR_CLAIM_CORE, 0, 0, 0, 0), EBUSY), "the core can be claimed only once per boot");
	check(prctl(KOS_PR_STATUS, 0, 0, 0, 0) == KOS_STATUS_CORE, "status says core, no app id");
	check(slurp(SFS "status", buf, sizeof(buf)) > 0 && has(buf, "core=claimed"), "status file says the core is claimed");
	check(refused(prctl(KOS_PR_CONFINE, 0, 0, 0, 0), EINVAL), "app id 0 is refused");
	check(refused(prctl(KOS_PR_CONFINE, 0x40000000UL, 0, 0, 0), EINVAL), "an app id past the maximum is refused");

	/* device nodes made by the core */
	mknod_ok("/tmp/ctl-null", S_IFCHR, 1, 3);
	mknod_ok("/tmp/dev-null", S_IFCHR, 1, 3);
	mknod_ok("/tmp/dev-zero", S_IFCHR, 1, 5);
	mknod_ok("/tmp/dev-urandom", S_IFCHR, 1, 9);
	mknod_ok("/tmp/dev-tty", S_IFCHR, 5, 1);
	mknod_ok("/tmp/dev-mem", S_IFCHR, 1, 1);
	mknod_ok("/tmp/dev-input", S_IFCHR, 13, 64);
	mknod_ok("/tmp/dev-disk", S_IFBLK, 8, 0);

	/* loopback up, and a listener the core owns */
	ctl = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, "lo");
	ifr.ifr_flags = IFF_UP | IFF_RUNNING;
	check(ioctl(ctl, SIOCSIFFLAGS, &ifr) == 0, "loopback is up");
	close(ctl);
	ls = tcp4();
	setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	check(bind(ls, (void *)&a, sizeof(a)) == 0 && listen(ls, 16) == 0, "the core listens on 127.0.0.1:9000");

	CHILD(0, c_unconfined_control);
	CHILD(0, c_bpf_perf_control);
	CHILD(7, c_identity);
	CHILD(7, c_default_deny);
	CHILD(7, c_devices);
	CHILD(7, c_kernel_interfaces);

	/* the firewall: rules are typed out, written by the core, one app each */
	check(write_rule("allow 8 tcp connect 127.0.0.1 9000") == 0, "core writes: allow app 8 tcp connect 127.0.0.1 9000");
	check(write_rule("allow 8 tcp connect 127.0.0.1 9000") == 0, "writing the same rule twice is harmless");
	CHILD(8, c_with_rule);
	CHILD(9, c_other_app);
	check(write_rule("allow 8 tcp listen 127.0.0.1 9100\n") == 0, "core writes a listen rule (trailing newline ok)");
	CHILD(8, c_listen);
	check(write_rule("allow 8 tcp connect ::1 9200") == 0, "core writes an IPv6 rule");
	CHILD(8, c_ipv6_rule);

	check(slurp(SFS "rules", buf, sizeof(buf)) > 0 && has(buf, "allow 8 tcp connect 127.0.0.1 9000") &&
	      has(buf, "allow 8 tcp listen 127.0.0.1 9100") && has(buf, "allow 8 tcp connect ::1 9200"), "the rules read back");

	check(refused(write_rule("allow 8 tcp connect 127.0.0.1 0"), EINVAL), "port 0 is refused");
	check(refused(write_rule("allow 0 tcp connect 127.0.0.1 80"), EINVAL), "app 0 is refused");
	check(refused(write_rule("allow 8 tcp connect 127.0.0.1"), EINVAL), "a rule missing its port is refused");
	check(refused(write_rule("allow 8 tcp connect * 80"), EINVAL), "a wildcard host is refused");
	check(refused(write_rule("allow 8 tcp connect 10.0.0.0/8 80"), EINVAL), "a range is refused");
	check(refused(write_rule("allow 8 tcp connect 127.0.0.1x 80"), EINVAL), "trailing junk after an address is refused");
	check(refused(write_rule("allow 8 tcp connect ::1/128 80"), EINVAL), "an IPv6 prefix is refused");
	check(refused(write_rule("allow 8 tcp connect localhost 80"), EINVAL), "a host name is refused (the core resolves names, the kernel never does)");
	check(refused(write_rule("allow 8 tcp connect 127.0.0.1 80x"), EINVAL), "trailing junk after a port is refused");
	check(refused(write_rule("allow 8 icmp connect 127.0.0.1 80"), EINVAL), "an unknown protocol is refused");
	check(refused(write_rule("allow  8 tcp connect 127.0.0.1 80"), EINVAL), "a double space is refused");
	check(refused(write_rule("allow 8 tcp connect 127.0.0.1 80 extra"), EINVAL), "an extra word is refused");
	check(refused(write_rule("allow 8 tcp connect 127.0.0.1 80\001"), EINVAL), "a control character is refused");
	check(refused(write_rule("flush"), EINVAL), "an unknown command is refused");
	check(refused(write_rule("allow 1073741824 tcp connect 127.0.0.1 80"), EINVAL), "an app id past the maximum is refused");

	check(write_rule("revoke 8 tcp connect 127.0.0.1 9000") == 0, "core revokes the connect rule");
	CHILD(8, c_after_revoke);
	check(write_rule("revoke-app 8") == 0, "core revokes everything of app 8");
	check(slurp(SFS "rules", buf, sizeof(buf)) >= 0 && !has(buf, "allow 8 "), "no rule of app 8 is left");

	CHILD(7, c_exec_and_fork);

	/* the log: every allowed and every denied attempt */
	{
		int n = slurp(SFS "log", buf, sizeof(buf));

		check(n > 0, "the core can read the log");
		check(has(buf, "deny app=7 create family=2"), "log: app 7's TCP socket was denied");
		check(has(buf, "allow app=8 connect tcp 127.0.0.1 9000"), "log: app 8's allowed connect is recorded");
		check(has(buf, "deny app=8 connect tcp 127.0.0.1 9001"), "log: app 8's denied connect is recorded");
		check(has(buf, "deny app=7 open device 5:1"), "log: the denied tty open is recorded");
		check(has(buf, "deny app=7 bpf"), "log: the denied bpf call is recorded");
		check(slurp(SFS "log", buf, sizeof(buf)) == 0, "reading the log drains it");
	}

	printf("KOS-LSM-TEST-DONE failures=%d\n", failures);
	fflush(stdout);
	sync();
	reboot(RB_AUTOBOOT);
	for (;;)
		pause();
}
