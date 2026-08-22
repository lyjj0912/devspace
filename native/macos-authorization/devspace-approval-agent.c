#include "devspace-auth-common.h"
#import <AppKit/AppKit.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>

static int connect_relay_socket(const char *path) {
  if (path == NULL) return 0;
  if (path[0] != '/' || strchr(path, '\n') != NULL || strchr(path, '\r') != NULL) return 64;
  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  size_t length = strlen(path);
  if (length >= sizeof(address.sun_path)) return 64;
  memcpy(address.sun_path, path, length + 1);
  int descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
  if (descriptor < 0) return 69;
  if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) {
    close(descriptor);
    return 69;
  }
  if (dup2(descriptor, STDIN_FILENO) < 0
      || dup2(descriptor, STDOUT_FILENO) < 0
      || dup2(descriptor, STDERR_FILENO) < 0) {
    close(descriptor);
    return 69;
  }
  if (descriptor > STDERR_FILENO) close(descriptor);
  return 0;
}

static const char *authorization_state(OSStatus status) {
  if (status == errAuthorizationCanceled) return "CANCELED";
  if (status == errAuthorizationDenied) return "DENIED";
  if (status == errAuthorizationInteractionNotAllowed) return "TIMED_OUT";
  return "RESULT_UNKNOWN";
}

static int verify_helper(const char *helper, const char *expected_digest, char canonical[PATH_MAX]) {
  struct stat state;
  if (!devspace_regular_file(helper, getuid(), true, S_IWGRP | S_IWOTH, DEVSPACE_AUTH_MAX_FILE_BYTES, canonical, &state)) {
    fprintf(stderr, "approval agent rejected helper path, owner, mode, or type\n");
    return 70;
  }
  if ((state.st_mode & S_IXUSR) == 0) {
    fprintf(stderr, "approval agent requires an owner-executable helper\n");
    return 70;
  }
  if (!devspace_sha256_matches(canonical, expected_digest)) {
    fprintf(stderr, "approval agent rejected helper digest\n");
    return 70;
  }
  return 0;
}

static int self_test(const char *helper, const char *helper_digest) {
  char canonical[PATH_MAX];
  int status = verify_helper(helper, helper_digest, canonical);
  if (status != 0) return status;
  printf("DEVSPACE_AUTHORIZATION_SELF_TEST\tPASS\t%s\n", helper_digest);
  return 0;
}

static int devspace_authorization_main(int argc, char *argv[]) {
  const char *relay_socket = devspace_argument(argc, argv, "--relay-socket");
  int relay_status = connect_relay_socket(relay_socket);
  if (relay_status != 0) return relay_status;
  const char *helper = devspace_argument(argc, argv, "--helper");
  const char *helper_digest = devspace_argument(argc, argv, "--helper-sha256");
  if (helper == NULL || !devspace_safe_digest(helper_digest)) {
    fprintf(stderr, "approval agent requires a helper and SHA-256 digest\n");
    return 64;
  }
  if (devspace_argument(argc, argv, "--self-test") != NULL || (argc > 1 && strcmp(argv[1], "--self-test") == 0)) {
    return self_test(helper, helper_digest);
  }

  const char *descriptor_digest = devspace_argument(argc, argv, "--descriptor-digest");
  const char *nonce = devspace_argument(argc, argv, "--nonce");
  const char *prompt = devspace_argument(argc, argv, "--prompt");
  const char *timeout_text = devspace_argument(argc, argv, "--timeout-ms");
  if (!devspace_safe_digest(descriptor_digest) || !devspace_safe_identifier(nonce)
      || !devspace_single_line(prompt, 2000) || timeout_text == NULL) {
    fprintf(stderr, "approval agent request arguments are invalid\n");
    return 64;
  }
  char *timeout_end = NULL;
  long timeout_ms = strtol(timeout_text, &timeout_end, 10);
  if (timeout_end == timeout_text || *timeout_end != '\0' || timeout_ms < 1000 || timeout_ms > 120000) {
    fprintf(stderr, "approval agent timeout is invalid\n");
    return 64;
  }
  char canonical_helper[PATH_MAX];
  int helper_status = verify_helper(helper, helper_digest, canonical_helper);
  if (helper_status != 0) return helper_status;

  AuthorizationRef authorization = NULL;
  OSStatus status = AuthorizationCreate(
    NULL,
    kAuthorizationEmptyEnvironment,
    kAuthorizationFlagDefaults,
    &authorization
  );
  if (status != errAuthorizationSuccess || authorization == NULL) {
    fprintf(stderr, "authorization_create_status=%d\n", (int)status);
    devspace_emit_result("RESULT_UNKNOWN", descriptor_digest, NULL);
    return 69;
  }

  AuthorizationItem right = {
    kAuthorizationRightExecute,
    (UInt32)strlen(canonical_helper),
    canonical_helper,
    0
  };
  AuthorizationRights rights = { 1, &right };
  AuthorizationItem environment_item = {
    kAuthorizationEnvironmentPrompt,
    (UInt32)strlen(prompt),
    (void *)prompt,
    0
  };
  AuthorizationEnvironment environment = { 1, &environment_item };
  AuthorizationFlags flags = kAuthorizationFlagInteractionAllowed
    | kAuthorizationFlagExtendRights
    | kAuthorizationFlagPreAuthorize;
  status = AuthorizationCopyRights(authorization, &rights, &environment, flags, NULL);
  if (status != errAuthorizationSuccess) {
    fprintf(stderr, "authorization_copy_rights_status=%d\n", (int)status);
    devspace_emit_result(authorization_state(status), descriptor_digest, NULL);
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return status == errAuthorizationCanceled || status == errAuthorizationDenied ? 77 : 69;
  }
  devspace_emit_result("APPROVED", descriptor_digest, nonce);

  struct pollfd input = { .fd = STDIN_FILENO, .events = POLLIN, .revents = 0 };
  int poll_status;
  do {
    poll_status = poll(&input, 1, (int)timeout_ms);
  } while (poll_status < 0 && errno == EINTR);
  if (poll_status <= 0 || (input.revents & POLLIN) == 0) {
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return 78;
  }

  char line[PATH_MAX * 2];
  if (fgets(line, sizeof(line), stdin) == NULL) {
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return 78;
  }
  line[strcspn(line, "\r\n")] = '\0';
  char *save = NULL;
  char *verb = strtok_r(line, "\t", &save);
  char *received_descriptor = strtok_r(NULL, "\t", &save);
  char *spec_path = strtok_r(NULL, "\t", &save);
  char *spec_digest = strtok_r(NULL, "\t", &save);
  char *extra = strtok_r(NULL, "\t", &save);
  if (verb == NULL || strcmp(verb, "LAUNCH") != 0 || received_descriptor == NULL
      || strcmp(received_descriptor, descriptor_digest) != 0 || spec_path == NULL
      || !devspace_safe_digest(spec_digest) || extra != NULL) {
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return 79;
  }
  char canonical_spec[PATH_MAX];
  struct stat spec_state;
  if (!devspace_regular_file(
        spec_path,
        getuid(),
        true,
        S_IRWXG | S_IRWXO,
        DEVSPACE_AUTH_MAX_FILE_BYTES,
        canonical_spec,
        &spec_state
      ) || !devspace_sha256_matches(canonical_spec, spec_digest)) {
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return 79;
  }

  char uid_text[32];
  snprintf(uid_text, sizeof(uid_text), "%u", getuid());
  char *helper_arguments[] = {
    "--spec", canonical_spec,
    "--sha256", (char *)spec_digest,
    "--uid", uid_text,
    "--descriptor-digest", (char *)descriptor_digest,
    NULL,
  };
  FILE *communications = NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
  status = AuthorizationExecuteWithPrivileges(
    authorization,
    canonical_helper,
    kAuthorizationFlagDefaults,
    helper_arguments,
    &communications
  );
#pragma clang diagnostic pop
  if (status != errAuthorizationSuccess || communications == NULL) {
    AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
    return 80;
  }

  int helper_exit = 81;
  char output[16384];
  while (fgets(output, sizeof(output), communications) != NULL) {
    if (strncmp(output, "__DEVSPACE_HELPER_RESULT__:", 27) == 0) {
      char *end = NULL;
      long parsed = strtol(output + 27, &end, 10);
      if (end != output + 27 && parsed >= 0 && parsed <= 255) helper_exit = (int)parsed;
      continue;
    }
    fputs(output, stdout);
    fflush(stdout);
  }
  fclose(communications);
  AuthorizationFree(authorization, kAuthorizationFlagDestroyRights);
  return helper_exit;
}

int main(int argc, char *argv[]) {
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    [application setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [application activateIgnoringOtherApps:YES];
    return devspace_authorization_main(argc, argv);
  }
}
