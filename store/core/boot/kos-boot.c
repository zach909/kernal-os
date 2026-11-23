/* kos-boot: the booting binary. The first KOS program that runs after the pre-boot environment.
 *
 * It does one job: check that the core (every file under kos/ and bin/) is exactly what the
 * sealed manifest says, and only then start it. It is a compiled binary, so nothing here can be
 * edited like a script; it uses libcrypto's SHA-256 (vetted), never a hash of its own.
 *
 *   kos-boot [--root DIR] [--manifest FILE] [--python PATH] [--check] [--] [ARGS...]
 *
 * Fails closed with ONE message and exit status 1 for every cause (missing or changed file, a file
 * not in the manifest, a link, a bad manifest line), so the refusal does not say which check failed.
 * --check is for the person building the system: it says what it found and starts nothing.
 *
 * Not covered (see the README gaps table): the manifest is only as trustworthy as where it lives
 * (it must sit in the signed pre-boot image); there is a gap between hashing a file and Python
 * opening it (no fd-passing yet); the Python interpreter itself is not hashed.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>

#define MAX_ENTRIES 4096
#define MAX_REL 255
#define MAX_MANIFEST (1024 * 1024)
#define MAX_DEPTH 16
#define MAX_ENV 256

extern char **environ;

struct entry {
    char hex[65];
    char path[MAX_REL + 1];
};

static struct entry ents[MAX_ENTRIES];
static int nents;
static int check_mode;
static int rootfd = -1;

static void refuse(const char *detail)
{
    fputs("kos-boot: refusing to start\n", stderr);
    if (check_mode && detail)
        fprintf(stderr, "kos-boot: check: %s\n", detail);
    _exit(1);
}

/* A relative path made only of safe characters, no empty part, no "." or ".." part. */
static int safe_rel(const char *p)
{
    size_t n = strlen(p), i, start = 0;
    if (n == 0 || n > MAX_REL || p[0] == '/')
        return 0;
    for (i = 0; i <= n; i++) {
        if (i < n) {
            char c = p[i];
            int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                     c == '.' || c == '_' || c == '-' || c == '/';
            if (!ok)
                return 0;
        }
        if (i == n || p[i] == '/') {
            size_t len = i - start;
            if (len == 0)
                return 0;
            if ((len == 1 && p[start] == '.') || (len == 2 && p[start] == '.' && p[start + 1] == '.'))
                return 0;
            start = i + 1;
        }
    }
    return 1;
}

/* Open root/rel one part at a time, refusing a link at any step. Returns an fd or -1. */
static int open_nofollow(const char *rel, int want_dir)
{
    char buf[MAX_REL + 1];
    char *part, *next;
    int fd = dup(rootfd);
    if (fd < 0 || strlen(rel) > MAX_REL)
        return -1;
    strcpy(buf, rel);
    for (part = buf; part && *part; part = next) {
        int last, nfd;
        next = strchr(part, '/');
        last = (next == NULL);
        if (next)
            *next++ = '\0';
        nfd = openat(fd, part,
                     O_RDONLY | O_NOFOLLOW | O_CLOEXEC | ((last && !want_dir) ? 0 : O_DIRECTORY));
        close(fd);
        if (nfd < 0)
            return -1;
        fd = nfd;
    }
    return fd;
}

static int hash_fd(int fd, char hex[65])
{
    unsigned char md[EVP_MAX_MD_SIZE], buf[65536];
    unsigned int mdlen = 0, i;
    struct stat st;
    EVP_MD_CTX *ctx;
    ssize_t n;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    while ((n = read(fd, buf, sizeof buf)) > 0)
        if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1)
            n = -1, errno = EIO;
    if (n < 0 || EVP_DigestFinal_ex(ctx, md, &mdlen) != 1 || mdlen != 32) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    EVP_MD_CTX_free(ctx);
    for (i = 0; i < mdlen; i++)
        sprintf(hex + 2 * i, "%02x", md[i]);
    return 0;
}

static int is_hex64(const char *s)
{
    int i;
    for (i = 0; i < 64; i++)
        if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
            return 0;
    return 1;
}

static int find_entry(const char *rel)
{
    int i;
    for (i = 0; i < nents; i++)
        if (strcmp(ents[i].path, rel) == 0)
            return i;
    return -1;
}

/* Every line is exactly: 64 lowercase hex, two spaces, a safe relative path. */
static void load_manifest(const char *path)
{
    static char text[MAX_MANIFEST + 1];
    struct stat st;
    ssize_t got = 0, n;
    char *line, *nl;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        refuse("manifest cannot be opened");
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > MAX_MANIFEST)
        refuse("manifest is not a plain file of a sane size");
    while (got < st.st_size && (n = read(fd, text + got, (size_t)(st.st_size - got))) > 0)
        got += n;
    close(fd);
    if (got != st.st_size)
        refuse("manifest read short");
    text[got] = '\0';
    if (strlen(text) != (size_t)got)
        refuse("manifest holds a NUL byte");
    for (line = text; *line;) {
        nl = strchr(line, '\n');
        if (!nl)
            refuse("manifest does not end in a newline");
        *nl = '\0';
        if (strlen(line) < 67 || line[64] != ' ' || line[65] != ' ' || !is_hex64(line))
            refuse("manifest line is not '<sha256>  <path>'");
        if (!safe_rel(line + 66))
            refuse("manifest path is not a safe relative path");
        if (nents >= MAX_ENTRIES)
            refuse("manifest is too long");
        if (find_entry(line + 66) >= 0)
            refuse("manifest lists a path twice");
        memcpy(ents[nents].hex, line, 64);
        ents[nents].hex[64] = '\0';
        strcpy(ents[nents].path, line + 66);
        nents++;
        line = nl + 1;
    }
    if (nents == 0)
        refuse("manifest is empty");
}

static void walk(const char *rel, int depth)
{
    DIR *d;
    struct dirent *e;
    int fd = open_nofollow(rel, 1);
    if (fd < 0 || depth > MAX_DEPTH)
        refuse("a core folder is missing, is a link, or is too deep");
    d = fdopendir(fd);
    if (!d)
        refuse("a core folder cannot be read");
    while ((e = readdir(d)) != NULL) {
        char child[MAX_REL + 1];
        struct stat st;
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (strcmp(e->d_name, "__pycache__") == 0)
            continue;
        if (strlen(rel) + 1 + strlen(e->d_name) > MAX_REL ||
            snprintf(child, sizeof child, "%s/%s", rel, e->d_name) < 0 || !safe_rel(child))
            refuse("a core file has an unsafe name");
        if (fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0)
            refuse("a core file cannot be examined");
        if (S_ISDIR(st.st_mode))
            walk(child, depth + 1);
        else if (S_ISREG(st.st_mode)) {
            if (find_entry(child) < 0)
                refuse("a file in the core is not in the manifest");
        } else
            refuse("a core file is a link or a special file");
    }
    closedir(d);
}

static int keep_env(const char *kv)
{
    static const char *const ok[] = {"PATH=", "HOME=", "TERM=", "LANG=", "LC_ALL=", "USER=", "KOS_", NULL};
    int i;
    for (i = 0; ok[i]; i++)
        if (strncmp(kv, ok[i], strlen(ok[i])) == 0)
            return 1;
    return 0;
}

int main(int argc, char **argv)
{
    const char *root = ".", *manifest = NULL, *python = "/usr/bin/python3";
    char manpath[4096], script[MAX_REL + 4096], *envp[MAX_ENV + 1], **args;
    char hex[65];
    int i, ne = 0, a = 1;

    for (; a < argc; a++) {
        if (strcmp(argv[a], "--") == 0) {
            a++;
            break;
        } else if (strcmp(argv[a], "--check") == 0)
            check_mode = 1;
        else if (strcmp(argv[a], "--root") == 0 && a + 1 < argc)
            root = argv[++a];
        else if (strcmp(argv[a], "--manifest") == 0 && a + 1 < argc)
            manifest = argv[++a];
        else if (strcmp(argv[a], "--python") == 0 && a + 1 < argc)
            python = argv[++a];
        else
            break;
    }
    if (python[0] != '/')
        refuse("the interpreter path must be absolute");
    rootfd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (rootfd < 0)
        refuse("the root folder cannot be opened");
    if (manifest == NULL) {
        if (snprintf(manpath, sizeof manpath, "%s/CORE.sha256", root) >= (int)sizeof manpath)
            refuse("the root path is too long");
        manifest = manpath;
    }

    load_manifest(manifest);
    for (i = 0; i < nents; i++) {
        int fd = open_nofollow(ents[i].path, 0);
        int bad = (fd < 0) || hash_fd(fd, hex) != 0 || strcmp(hex, ents[i].hex) != 0;
        if (fd >= 0)
            close(fd);
        if (bad)
            refuse("a core file is missing, is a link, or does not match the manifest");
    }
    walk("kos", 0);
    walk("bin", 0);
    if (find_entry("bin/kos") < 0)
        refuse("bin/kos is not in the manifest");

    if (check_mode) {
        printf("kos-boot: core verified (%d files)\n", nents);
        return 0;
    }

    for (i = 0; environ && environ[i] && ne < MAX_ENV; i++)
        if (keep_env(environ[i]))
            envp[ne++] = environ[i];
    envp[ne] = NULL;

    if (snprintf(script, sizeof script, "%s/bin/kos", root) >= (int)sizeof script)
        refuse("the root path is too long");
    args = calloc((size_t)(argc - a) + 5, sizeof *args);
    if (!args)
        refuse("out of memory");
    args[0] = "python3";
    args[1] = "-I";
    args[2] = "-B";
    args[3] = script;
    for (i = a; i < argc; i++)
        args[4 + i - a] = argv[i];
    execve(python, args, envp);
    refuse("the interpreter cannot be started");
    return 1;
}
