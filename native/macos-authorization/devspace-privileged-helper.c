#include "devspace-auth-common.h"
#include <pwd.h>
#include <sys/wait.h>

struct task_spec {
  char descriptor_digest[DEVSPACE_AUTH_DIGEST_CHARS + 1];
  char cwd[PATH_MAX];
  char script[PATH_MAX];
  char script_digest[DEVSPACE_AUTH_DIGEST_CHARS + 1];
  uid_t user_uid;
};

static bool parse_line(char *line, const char *prefix, char *output, size_t output_size) {
  size_t prefix_length = strlen(prefix);
  if (strncmp(line, prefix, prefix_length) != 0) return false;
  const char *value = line + prefix_length;
  size_t length = strcspn(value, "\r\n");
  if (length < 1 || length >= output_size) return false;
  memcpy(output, value, length);
  output[length] = '\0';
  return true;
}

static bool load_spec(const char *path, struct task_spec *spec) {
  FILE *file = fopen(path, "r");
  if (file == NULL) return false;
  char line[PATH_MAX + 128];
  if (fgets(line, sizeof(line), file) == NULL || strcmp(line, "DEVSPACE_AUTH_SPEC_V1\n") != 0) {
    fclose(file);
    return false;
  }
  char uid_text[32] = {0};
  bool ok = fgets(line, sizeof(line), file) != NULL
    && parse_line(line, "descriptorDigest=", spec->descriptor_digest, sizeof(spec->descriptor_digest))
    && fgets(line, sizeof(line), file) != NULL
    && parse_line(line, "cwd=", spec->cwd, sizeof(spec->cwd))
    && fgets(line, sizeof(line), file) != NULL
    && parse_line(line, "script=", spec->script, sizeof(spec->script))
    && fgets(line, sizeof(line), file) != NULL
    && parse_line(line, "scriptSha256=", spec->script_digest, sizeof(spec->script_digest))
    && fgets(line, sizeof(line), file) != NULL
    && parse_line(line, "userUid=", uid_text, sizeof(uid_text));
  if (ok && fgets(line, sizeof(line), file) != NULL) ok = false;
  fclose(file);
  if (!ok || !devspace_safe_digest(spec->descriptor_digest) || !devspace_safe_digest(spec->script_digest)) return false;
  char *end = NULL;
  unsigned long parsed = strtoul(uid_text, &end, 10);
  if (end == uid_text || *end != '\0' || parsed > UINT32_MAX) return false;
  spec->user_uid = (uid_t)parsed;
  return true;
}

int main(int argc, char *argv[]) {
  if (geteuid() != 0) {
    fprintf(stderr, "privileged helper requires effective uid 0\n");
    return 77;
  }
  const char *spec_path = devspace_argument(argc, argv, "--spec");
  const char *spec_digest = devspace_argument(argc, argv, "--sha256");
  const char *uid_text = devspace_argument(argc, argv, "--uid");
  const char *descriptor_digest = devspace_argument(argc, argv, "--descriptor-digest");
  if (spec_path == NULL || !devspace_safe_digest(spec_digest) || uid_text == NULL
      || !devspace_safe_digest(descriptor_digest)) return 64;
  char *uid_end = NULL;
  unsigned long uid_value = strtoul(uid_text, &uid_end, 10);
  if (uid_end == uid_text || *uid_end != '\0' || uid_value > UINT32_MAX) return 64;
  uid_t requested_uid = (uid_t)uid_value;

  char canonical_spec[PATH_MAX];
  struct stat spec_state;
  if (!devspace_regular_file(
        spec_path,
        requested_uid,
        true,
        S_IRWXG | S_IRWXO,
        DEVSPACE_AUTH_MAX_FILE_BYTES,
        canonical_spec,
        &spec_state
      ) || !devspace_sha256_matches(canonical_spec, spec_digest)) return 70;

  struct task_spec spec = {0};
  if (!load_spec(canonical_spec, &spec) || spec.user_uid != requested_uid
      || strcmp(spec.descriptor_digest, descriptor_digest) != 0) return 70;
  char canonical_cwd[PATH_MAX];
  if (!devspace_canonical_absolute(spec.cwd, canonical_cwd)) return 70;
  struct stat cwd_state;
  if (stat(canonical_cwd, &cwd_state) != 0 || !S_ISDIR(cwd_state.st_mode)) return 70;
  char canonical_script[PATH_MAX];
  struct stat script_state;
  if (!devspace_regular_file(
        spec.script,
        requested_uid,
        true,
        S_IRWXG | S_IRWXO,
        DEVSPACE_AUTH_MAX_FILE_BYTES,
        canonical_script,
        &script_state
      ) || !devspace_sha256_matches(canonical_script, spec.script_digest)) return 70;

  pid_t child = fork();
  if (child < 0) return 71;
  if (child == 0) {
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) _exit(72);
    if (chdir(canonical_cwd) != 0) _exit(72);
    struct passwd *account = getpwuid(requested_uid);
    char uid_environment[64];
    if (snprintf(
          uid_environment,
          sizeof(uid_environment),
          "DEVSPACE_REQUESTING_UID=%s",
          uid_text
        ) < 0) _exit(72);
    char home_environment[PATH_MAX + 6];
    char *environment[6] = {
      "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
      "DEVSPACE_AUTHORIZED=1",
      uid_environment,
      "LANG=C.UTF-8",
      NULL,
      NULL,
    };
    if (account != NULL && account->pw_dir != NULL
        && devspace_single_line(account->pw_dir, PATH_MAX)) {
      int home_length = snprintf(
        home_environment,
        sizeof(home_environment),
        "HOME=%s",
        account->pw_dir
      );
      if (home_length < 0 || (size_t)home_length >= sizeof(home_environment)) _exit(72);
      environment[4] = home_environment;
    }
    execle("/bin/zsh", "zsh", canonical_script, (char *)NULL, environment);
    _exit(127);
  }

  int status = 0;
  while (waitpid(child, &status, 0) < 0) {
    if (errno == EINTR) continue;
    status = 71 << 8;
    break;
  }
  int exit_code = WIFEXITED(status) ? WEXITSTATUS(status)
    : WIFSIGNALED(status) ? 128 + WTERMSIG(status)
    : 71;
  printf("__DEVSPACE_HELPER_RESULT__:%d\n", exit_code);
  fflush(stdout);
  devspace_secure_zero(&spec, sizeof(spec));
  return 0;
}
