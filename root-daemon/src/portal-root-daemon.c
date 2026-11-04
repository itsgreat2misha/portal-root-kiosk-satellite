// portal-root-daemon: minimal per-boot root helper for Meta Portal (aloha).
//
// Intended to be started exactly once per boot by a uid-0 delegated child
// inside the provisioner's privileged window (see FORK.md). It is NOT
// persistent: it dies with the boot, and the autoroot helper re-establishes
// it after the next reboot (or the provisioner is re-run).
//
// Protocol (TCP, 127.0.0.1 only, line based, one command per connection
// line; EXEC may be repeated on the same connection):
//
//   ID            -> "ID uid=<u> euid=<u> gid=<g> egid=<g> capeff=<hex> ctx=<selinux>\nEND\n"
//   EXEC <cmd>    -> raw stdout+stderr of `/bin/sh -c <cmd>`, then
//                    "EXIT <code>\nEND\n"
//   STOP          -> "BYE\n", then the daemon exits(0) after closing.
//
// Anything else    -> "ERR unknown-command\nEND\n"
//
// At startup the daemon appends one identity line (pid, uid/euid/gid/egid,
// CapEff/CapBnd, SELinux context, boot id) to the identity log so a host
// can verify from /data alone that the helper really ran as uid 0.
//
// Build (Android NDK; or `make` in this directory):
//   aarch64-linux-android28-clang -O2 -Wall -Wextra -fPIE -pie \
//       -o portal-root-daemon portal-root-daemon.c
//
// No third-party code; libc only.

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *g_identity_log = "/data/local/tmp/portal-root-daemon-identity.log";
static const char *g_pidfile = "/data/portal-root/daemon.pid";
static volatile sig_atomic_t g_stop = 0;

static void on_term(int sig) {
  (void)sig;
  g_stop = 1;
}

// ---------------------------------------------------------------------------
// Small file helpers

static int read_small_file(const char *path, char *buf, size_t cap) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n = read(fd, buf, cap - 1);
  close(fd);
  if (n < 0) return -1;
  buf[n] = '\0';
  // Strip trailing whitespace/newlines for log friendliness.
  while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                   buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
    buf[--n] = '\0';
  }
  return 0;
}

// Extract a hex field like "CapEff:\t000001ffffffffff" from /proc/self/status.
static void status_hex_field(const char *name, char *out, size_t cap) {
  char buf[4096];
  out[0] = '\0';
  if (read_small_file("/proc/self/status", buf, sizeof(buf)) != 0) return;
  size_t name_len = strlen(name);
  char *p = buf;
  while ((p = strstr(p, name)) != NULL) {
    if (p[name_len] == ':') {
      p += name_len + 1;
      while (*p == ' ' || *p == '\t') p++;
      size_t i = 0;
      while (p[i] && p[i] != '\n' && i + 1 < cap) {
        out[i] = p[i];
        i++;
      }
      out[i] = '\0';
      return;
    }
    p += name_len;
  }
}

static void selinux_context(char *out, size_t cap) {
  out[0] = '\0';
  if (read_small_file("/proc/self/attr/current", out, cap) != 0) {
    snprintf(out, cap, "unknown");
  }
}

static void boot_id(char *out, size_t cap) {
  out[0] = '\0';
  if (read_small_file("/proc/sys/kernel/random/boot_id", out, cap) != 0) {
    snprintf(out, cap, "unknown");
  }
}

static void append_identity_log(void) {
  char capeff[32], capbnd[32], ctx[256], boot[64];
  status_hex_field("CapEff", capeff, sizeof(capeff));
  status_hex_field("CapBnd", capbnd, sizeof(capbnd));
  selinux_context(ctx, sizeof(ctx));
  boot_id(boot, sizeof(boot));
  int fd = open(g_identity_log, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
  if (fd < 0) return;
  char line[1024];
  int n = snprintf(line, sizeof(line),
                   "start ts=%lld pid=%d uid=%d euid=%d gid=%d egid=%d "
                   "capeff=%s capbnd=%s ctx=%s boot_id=%s\n",
                   (long long)time(NULL), (int)getpid(), (int)getuid(),
                   (int)geteuid(), (int)getgid(), (int)getegid(), capeff,
                   capbnd, ctx, boot);
  if (n > 0) (void)!write(fd, line, (size_t)n);
  close(fd);
}

// ---------------------------------------------------------------------------
// Socket helpers

static int write_all(int fd, const char *buf, size_t len) {
  while (len > 0) {
    ssize_t n = write(fd, buf, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    buf += n;
    len -= (size_t)n;
  }
  return 0;
}

static int fd_printf(int fd, const char *fmt, ...) {
  char buf[2048];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return -1;
  if ((size_t)n >= sizeof(buf)) n = (int)sizeof(buf) - 1;
  return write_all(fd, buf, (size_t)n);
}

// Read one line (up to cap-1 chars) without stdio buffering surprises.
static ssize_t read_line(int fd, char *buf, size_t cap) {
  size_t i = 0;
  while (i + 1 < cap) {
    char c;
    ssize_t n = read(fd, &c, 1);
    if (n == 0) break;
    if (n < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (c == '\n') break;
    if (c != '\r') buf[i++] = c;
  }
  buf[i] = '\0';
  return (ssize_t)i;
}

// ---------------------------------------------------------------------------
// EXEC implementation: fork /bin/sh -c, merge stdout+stderr, stream back,
// enforce a wall-clock timeout so one bad command cannot wedge the daemon.

#define EXEC_TIMEOUT_SECONDS 30

static void handle_exec(int client, const char *cmd) {
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fd_printf(client, "ERR pipe-failed\nEND\n");
    return;
  }
  pid_t pid = fork();
  if (pid == 0) {
    // Child: own process group so the parent can kill the whole tree.
    setpgid(0, 0);
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);
    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
    _exit(127);
  }
  close(pipefd[1]);
  if (pid < 0) {
    close(pipefd[0]);
    fd_printf(client, "ERR fork-failed\nEND\n");
    return;
  }

  time_t deadline = time(NULL) + EXEC_TIMEOUT_SECONDS;
  int status = 0;
  bool child_done = false;
  char buf[4096];
  for (;;) {
    if (!child_done) {
      pid_t w = waitpid(pid, &status, WNOHANG);
      if (w == pid) child_done = true;
    }
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(pipefd[0], &rfds);
    struct timeval tv = {0, 200 * 1000};
    int ready = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
    if (ready > 0 && FD_ISSET(pipefd[0], &rfds)) {
      ssize_t n = read(pipefd[0], buf, sizeof(buf));
      if (n > 0) {
        if (write_all(client, buf, (size_t)n) != 0) {
          // Client went away: stop the command.
          kill(-pid, SIGKILL);
          child_done = true;
          break;
        }
        continue;
      }
      if (n == 0) break;  // EOF: writer side fully closed.
    }
    if (child_done) {
      // Drain whatever remains, briefly.
      ssize_t n = read(pipefd[0], buf, sizeof(buf));
      if (n > 0) (void)write_all(client, buf, (size_t)n);
      break;
    }
    if (time(NULL) > deadline) {
      kill(-pid, SIGKILL);
      fd_printf(client, "\nEXEC_TIMEOUT seconds=%d\n", EXEC_TIMEOUT_SECONDS);
      waitpid(pid, &status, 0);
      child_done = true;
      // Drain to EOF quickly.
      int flags = fcntl(pipefd[0], F_GETFL, 0);
      fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
      ssize_t n;
      while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        (void)write_all(client, buf, (size_t)n);
      }
      break;
    }
  }
  close(pipefd[0]);
  if (!child_done) waitpid(pid, &status, 0);
  int code = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
  fd_printf(client, "EXIT %d\nEND\n", code);
}

// ---------------------------------------------------------------------------

static void handle_client(int client) {
  char line[8192];
  for (;;) {
    ssize_t n = read_line(client, line, sizeof(line));
    if (n <= 0) return;
    if (strcmp(line, "ID") == 0) {
      char capeff[32], ctx[256];
      status_hex_field("CapEff", capeff, sizeof(capeff));
      selinux_context(ctx, sizeof(ctx));
      fd_printf(client,
                "ID uid=%d euid=%d gid=%d egid=%d capeff=%s ctx=%s pid=%d\n"
                "END\n",
                (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid(),
                capeff, ctx, (int)getpid());
    } else if (strncmp(line, "EXEC ", 5) == 0) {
      handle_exec(client, line + 5);
    } else if (strcmp(line, "STOP") == 0) {
      fd_printf(client, "BYE\n");
      g_stop = 1;
      return;
    } else if (line[0] == '\0') {
      continue;
    } else {
      fd_printf(client, "ERR unknown-command\nEND\n");
    }
    if (g_stop) return;
  }
}

int main(int argc, char **argv) {
  int port = 37373;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      port = atoi(argv[++i]);
    } else if (strcmp(argv[i], "--identity-log") == 0 && i + 1 < argc) {
      g_identity_log = argv[++i];
    } else if (strcmp(argv[i], "--pidfile") == 0 && i + 1 < argc) {
      g_pidfile = argv[++i];
    } else {
      fprintf(stderr, "unknown argument: %s\n", argv[i]);
      return 2;
    }
  }
  if (port <= 0 || port > 65535) {
    fprintf(stderr, "bad port\n");
    return 2;
  }

  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = on_term;
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);

  append_identity_log();

  if (g_pidfile != NULL && g_pidfile[0] != '\0') {
    int fd = open(g_pidfile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd >= 0) {
      char buf[32];
      int n = snprintf(buf, sizeof(buf), "%d\n", (int)getpid());
      if (n > 0) (void)!write(fd, buf, (size_t)n);
      close(fd);
    }
  }

  int server = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server < 0) {
    perror("socket");
    return 1;
  }
  int one = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);  // 127.0.0.1 only, ever.
  addr.sin_port = htons((uint16_t)port);
  if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("bind");
    return 1;
  }
  if (listen(server, 4) != 0) {
    perror("listen");
    return 1;
  }

  while (!g_stop) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(server, &rfds);
    struct timeval tv = {1, 0};
    int ready = select(server + 1, &rfds, NULL, NULL, &tv);
    if (ready < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (ready == 0) continue;
    int client = accept(server, NULL, NULL);
    if (client < 0) continue;
    handle_client(client);
    close(client);
  }

  close(server);
  if (g_pidfile != NULL && g_pidfile[0] != '\0') unlink(g_pidfile);
  return 0;
}
