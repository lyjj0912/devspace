#ifndef DEVSPACE_AUTH_COMMON_H
#define DEVSPACE_AUTH_COMMON_H

#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DEVSPACE_AUTH_MAX_FILE_BYTES (1024 * 1024)
#define DEVSPACE_AUTH_DIGEST_PREFIX "sha256:"
#define DEVSPACE_AUTH_DIGEST_CHARS 71

static inline void devspace_secure_zero(void *buffer, size_t length) {
  volatile unsigned char *cursor = (volatile unsigned char *)buffer;
  while (length-- > 0) *cursor++ = 0;
}

static inline bool devspace_safe_identifier(const char *value) {
  if (value == NULL) return false;
  size_t length = strlen(value);
  if (length < 1 || length > 256) return false;
  for (size_t index = 0; index < length; index += 1) {
    unsigned char current = (unsigned char)value[index];
    bool alpha_numeric = (current >= 'a' && current <= 'z')
      || (current >= 'A' && current <= 'Z')
      || (current >= '0' && current <= '9');
    if (!alpha_numeric && current != '.' && current != '_' && current != ':' && current != '-') return false;
  }
  return true;
}

static inline bool devspace_safe_digest(const char *value) {
  if (value == NULL || strlen(value) != DEVSPACE_AUTH_DIGEST_CHARS) return false;
  if (strncmp(value, DEVSPACE_AUTH_DIGEST_PREFIX, strlen(DEVSPACE_AUTH_DIGEST_PREFIX)) != 0) return false;
  for (size_t index = strlen(DEVSPACE_AUTH_DIGEST_PREFIX); index < DEVSPACE_AUTH_DIGEST_CHARS; index += 1) {
    char current = value[index];
    if (!((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f'))) return false;
  }
  return true;
}

static inline bool devspace_single_line(const char *value, size_t maximum) {
  if (value == NULL) return false;
  size_t length = strlen(value);
  if (length < 1 || length > maximum) return false;
  return strchr(value, '\n') == NULL && strchr(value, '\r') == NULL;
}

static inline bool devspace_canonical_absolute(const char *path, char output[PATH_MAX]) {
  if (path == NULL || path[0] != '/' || strchr(path, '\n') != NULL || strchr(path, '\r') != NULL) return false;
  if (realpath(path, output) == NULL) return false;
  return strcmp(path, output) == 0;
}

static inline bool devspace_regular_file(
  const char *path,
  uid_t expected_owner,
  bool require_owner,
  mode_t forbidden_mode,
  off_t maximum_size,
  char canonical[PATH_MAX],
  struct stat *state_out
) {
  if (!devspace_canonical_absolute(path, canonical)) return false;
  struct stat state;
  if (lstat(canonical, &state) != 0) return false;
  if (!S_ISREG(state.st_mode) || S_ISLNK(state.st_mode)) return false;
  if (require_owner && state.st_uid != expected_owner) return false;
  if ((state.st_mode & forbidden_mode) != 0) return false;
  if (state.st_size < 0 || state.st_size > maximum_size) return false;
  if (state_out != NULL) *state_out = state;
  return true;
}

static inline bool devspace_sha256_file(const char *path, char output[DEVSPACE_AUTH_DIGEST_CHARS + 1]) {
  int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) return false;
  CC_SHA256_CTX context;
  if (CC_SHA256_Init(&context) != 1) {
    close(descriptor);
    return false;
  }
  unsigned char buffer[16384];
  while (true) {
    ssize_t count = read(descriptor, buffer, sizeof(buffer));
    if (count == 0) break;
    if (count < 0) {
      if (errno == EINTR) continue;
      devspace_secure_zero(buffer, sizeof(buffer));
      close(descriptor);
      return false;
    }
    if (CC_SHA256_Update(&context, buffer, (CC_LONG)count) != 1) {
      devspace_secure_zero(buffer, sizeof(buffer));
      close(descriptor);
      return false;
    }
  }
  unsigned char digest[CC_SHA256_DIGEST_LENGTH];
  bool success = CC_SHA256_Final(digest, &context) == 1;
  devspace_secure_zero(buffer, sizeof(buffer));
  close(descriptor);
  if (!success) return false;
  memcpy(output, DEVSPACE_AUTH_DIGEST_PREFIX, strlen(DEVSPACE_AUTH_DIGEST_PREFIX));
  for (size_t index = 0; index < CC_SHA256_DIGEST_LENGTH; index += 1) {
    snprintf(output + strlen(DEVSPACE_AUTH_DIGEST_PREFIX) + (index * 2), 3, "%02x", digest[index]);
  }
  output[DEVSPACE_AUTH_DIGEST_CHARS] = '\0';
  devspace_secure_zero(digest, sizeof(digest));
  return true;
}

static inline bool devspace_sha256_matches(const char *path, const char *expected) {
  if (!devspace_safe_digest(expected)) return false;
  char actual[DEVSPACE_AUTH_DIGEST_CHARS + 1];
  if (!devspace_sha256_file(path, actual)) return false;
  bool matches = strcmp(actual, expected) == 0;
  devspace_secure_zero(actual, sizeof(actual));
  return matches;
}

static inline const char *devspace_argument(int argc, char *argv[], const char *name) {
  for (int index = 1; index + 1 < argc; index += 1) {
    if (strcmp(argv[index], name) == 0) return argv[index + 1];
  }
  return NULL;
}

static inline void devspace_emit_result(const char *state, const char *descriptor_digest, const char *nonce) {
  if (nonce != NULL) {
    printf("DEVSPACE_AUTHORIZATION_RESULT\t%s\t%s\t%s\n", state, descriptor_digest, nonce);
  } else {
    printf("DEVSPACE_AUTHORIZATION_RESULT\t%s\t%s\n", state, descriptor_digest);
  }
  fflush(stdout);
}

#endif
