#include "devspace-auth-common.h"
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>

#define DEVSPACE_RELAY_MAX_ARGUMENTS 128

static bool safe_bundle(const char *path, uid_t uid, char canonical[PATH_MAX]) {
  if (!devspace_canonical_absolute(path, canonical)) return false;
  struct stat state;
  if (lstat(canonical, &state) != 0 || !S_ISDIR(state.st_mode) || S_ISLNK(state.st_mode)) return false;
  if (state.st_uid != uid || (state.st_mode & (S_IWGRP | S_IWOTH)) != 0) return false;
  return true;
}

static int timeout_value(const char *value) {
  if (value == NULL) return 120000;
  char *end = NULL;
  long parsed = strtol(value, &end, 10);
  if (end == value || *end != '\0' || parsed < 1000 || parsed > 120000) return -1;
  return (int)parsed;
}

static int bridge_streams(int connection) {
  struct pollfd descriptors[2] = {
    { .fd = STDIN_FILENO, .events = POLLIN | POLLHUP, .revents = 0 },
    { .fd = connection, .events = POLLIN | POLLHUP, .revents = 0 },
  };
  unsigned char buffer[16384];
  bool input_open = true;
  while (true) {
    descriptors[0].fd = input_open ? STDIN_FILENO : -1;
    int result;
    do { result = poll(descriptors, 2, -1); } while (result < 0 && errno == EINTR);
    if (result < 0) return 72;
    if (input_open && (descriptors[0].revents & POLLIN) != 0) {
      ssize_t count = read(STDIN_FILENO, buffer, sizeof(buffer));
      if (count > 0) {
        ssize_t offset = 0;
        while (offset < count) {
          ssize_t written = write(connection, buffer + offset, (size_t)(count - offset));
          if (written < 0 && errno == EINTR) continue;
          if (written <= 0) return 72;
          offset += written;
        }
      } else {
        input_open = false;
        shutdown(connection, SHUT_WR);
      }
    }
    if (input_open && (descriptors[0].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
      input_open = false;
      shutdown(connection, SHUT_WR);
    }
    if ((descriptors[1].revents & POLLIN) != 0) {
      ssize_t count = read(connection, buffer, sizeof(buffer));
      if (count > 0) {
        ssize_t offset = 0;
        while (offset < count) {
          ssize_t written = write(STDOUT_FILENO, buffer + offset, (size_t)(count - offset));
          if (written < 0 && errno == EINTR) continue;
          if (written <= 0) return 72;
          offset += written;
        }
        fsync(STDOUT_FILENO);
      } else return 0;
    }
    if ((descriptors[1].revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
      unsigned char final_buffer[16384];
      ssize_t count;
      while ((count = read(connection, final_buffer, sizeof(final_buffer))) > 0) {
        (void)write(STDOUT_FILENO, final_buffer, (size_t)count);
      }
      return 0;
    }
  }
}

int main(int argc, char *argv[]) {
  const char *bundle = devspace_argument(argc, argv, "--approval-app");
  const char *app_executable = devspace_argument(argc, argv, "--approval-app-executable");
  const char *app_digest = devspace_argument(argc, argv, "--approval-app-sha256");
  const char *nonce = devspace_argument(argc, argv, "--nonce");
  const char *timeout_text = devspace_argument(argc, argv, "--timeout-ms");
  int timeout_ms = timeout_value(timeout_text);
  if (bundle == NULL || app_executable == NULL || !devspace_safe_digest(app_digest)
      || !devspace_safe_identifier(nonce) || timeout_ms < 0) return 64;
  uid_t uid = getuid();
  char canonical_bundle[PATH_MAX];
  if (!safe_bundle(bundle, uid, canonical_bundle)) return 70;
  char canonical_executable[PATH_MAX];
  struct stat executable_state;
  if (!devspace_regular_file(
        app_executable, uid, true, S_IWGRP | S_IWOTH,
        DEVSPACE_AUTH_MAX_FILE_BYTES, canonical_executable, &executable_state
      ) || (executable_state.st_mode & S_IXUSR) == 0
      || !devspace_sha256_matches(canonical_executable, app_digest)) return 70;

  char work_root[PATH_MAX];
  if (getcwd(work_root, sizeof(work_root)) == NULL) return 70;
  char directory[PATH_MAX];
  int directory_length = snprintf(directory, sizeof(directory), "%s/relay-%ld-%s", work_root, (long)getpid(), nonce);
  if (directory_length < 0 || (size_t)directory_length >= sizeof(directory)) return 70;
  if (mkdir(directory, 0700) != 0) return 70;
  char socket_path[PATH_MAX];
  int socket_length = snprintf(socket_path, sizeof(socket_path), "%s/approval.sock", directory);
  if (socket_length < 0 || (size_t)socket_length >= sizeof(socket_path)) return 70;

  int listener = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listener < 0) { rmdir(directory); return 71; }
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  if (strlen(socket_path) >= sizeof(address.sun_path)) { close(listener); rmdir(directory); return 70; }
  strcpy(address.sun_path, socket_path);
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0
      || chmod(socket_path, 0600) != 0 || listen(listener, 1) != 0) {
    close(listener); unlink(socket_path); rmdir(directory); return 71;
  }

  char *open_arguments[DEVSPACE_RELAY_MAX_ARGUMENTS];
  int output = 0;
  open_arguments[output++] = "/usr/bin/open";
  open_arguments[output++] = "-n";
  open_arguments[output++] = "-g";
  open_arguments[output++] = canonical_bundle;
  open_arguments[output++] = "--args";
  open_arguments[output++] = "--relay-socket";
  open_arguments[output++] = socket_path;
  for (int index = 1; index < argc; index += 1) {
    if (strcmp(argv[index], "--approval-app") == 0
        || strcmp(argv[index], "--approval-app-executable") == 0
        || strcmp(argv[index], "--approval-app-sha256") == 0) {
      index += 1;
      continue;
    }
    if (output + 1 >= DEVSPACE_RELAY_MAX_ARGUMENTS) {
      close(listener); unlink(socket_path); rmdir(directory); return 64;
    }
    open_arguments[output++] = argv[index];
  }
  open_arguments[output] = NULL;
  pid_t child = fork();
  if (child < 0) { close(listener); unlink(socket_path); rmdir(directory); return 71; }
  if (child == 0) {
    execv("/usr/bin/open", open_arguments);
    _exit(127);
  }
  int open_status = 0;
  while (waitpid(child, &open_status, 0) < 0 && errno == EINTR) {}
  if (!WIFEXITED(open_status) || WEXITSTATUS(open_status) != 0) {
    close(listener); unlink(socket_path); rmdir(directory); return 71;
  }

  struct pollfd poller = { .fd = listener, .events = POLLIN, .revents = 0 };
  int polled;
  do { polled = poll(&poller, 1, timeout_ms); } while (polled < 0 && errno == EINTR);
  if (polled <= 0 || (poller.revents & POLLIN) == 0) {
    close(listener); unlink(socket_path); rmdir(directory); return 78;
  }
  int connection = accept(listener, NULL, NULL);
  close(listener);
  if (connection < 0) { unlink(socket_path); rmdir(directory); return 71; }
  uid_t peer_uid = (uid_t)-1;
  gid_t peer_gid = (gid_t)-1;
  if (getpeereid(connection, &peer_uid, &peer_gid) != 0 || peer_uid != uid) {
    close(connection); unlink(socket_path); rmdir(directory); return 70;
  }
  int result = bridge_streams(connection);
  close(connection);
  unlink(socket_path);
  rmdir(directory);
  return result;
}
