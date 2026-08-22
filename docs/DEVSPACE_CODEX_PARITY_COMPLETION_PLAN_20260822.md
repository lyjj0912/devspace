# DevSpace Codex-Parity Completion Plan

**문서 상태:** 실행 기준 계획서
**작성일:** 2026-08-22 (KST)
**대상 제품:** DevSpace Universal Broker v2 — `PERSONAL_DIRECT_OWNER`
**목적:** ChatGPT를 소통 창구로 사용할 때도 Codex를 통해 사용자와 함께 작업할 때와 실질적으로 동일한 권한·기능·환경을 제공하도록 DevSpace를 수정·구현·검증한다.
**중요:** 이 문서는 세션 compact 이후에도 그대로 읽고 작업을 재개할 수 있도록 만든 단일 실행 계획서다. 별도 회의록·보충 설계서·임시 계획서를 추가하지 않는다.

---

## 0. 이 문서를 읽은 새 세션의 행동 규칙

새 세션 또는 compact 이후 작업자는 반드시 다음 순서를 지킨다.

1. 이 문서를 처음부터 끝까지 읽는다.
2. 현재 Git branch, HEAD, working tree, production runtime revision, schema generation을 읽기 전용으로 확인한다.
3. 이 문서에 기록된 기준 상태와 현재 상태가 다르면 차이를 먼저 보고한다.
4. 사용자에게 이미 승인받은 범위 안에서는 계획대로 실제 구현·검증을 진행한다.
5. 임의로 제품 목표를 축소하거나 “보안 정책상 불가능”이라고 재정의하지 않는다.
6. 일반 사용자 실행과 **사용자 승인형 권한 상승**을 구분한다.
7. mock/stub 결과를 actual-host 최종 PASS 증거로 사용하지 않는다.
8. 실패한 run의 일부 PASS를 다음 run에 이어 붙이지 않는다.
9. 새로운 설계 문서를 여러 개 만들지 않는다. 이 파일만 갱신한다.
10. 작업 완료 전 `PASS`를 선언하지 않는다.

---

## 1. 정정된 제품 목표

### 1.1 잘못 이해했던 목표

기존 구현과 문서 일부는 다음 전제를 제품 정책으로 고정했다.

```text
DevSpace는 user-account-only 제품이다.
sudo, Authorization Services, 관리자 권한, privileged helper는 항상 차단한다.
권한이 필요한 작업은 DevSpace 밖에서 수동으로 수행한다.
```

이 전제는 잘못됐다.

### 1.2 올바른 목표

DevSpace의 목표는 다음이다.

```text
사용자가 Codex를 통해 작업할 때 사용할 수 있는 권한·기능·환경을,
ChatGPT + DevSpace를 통해 작업할 때도 실질적으로 동일하게 제공한다.
```

의미:

- DevSpace broker 자체는 기본적으로 일반 사용자 권한으로 실행한다.
- 일반 작업은 기존 sandbox/no-new-privileges 경계를 유지한다.
- 관리자 권한이 필요한 작업은 실제 OS 네이티브 인증 UI를 표시한다.
- 사용자가 비밀번호, Touch ID, UAC 등으로 직접 승인한다.
- 승인된 정확한 단일 작업만 상승 권한으로 수행한다.
- 비밀번호나 인증 비밀은 ChatGPT, DevSpace, MCP payload, 로그, 파일, 환경변수에 들어가지 않는다.
- 사용자가 거부·취소·timeout하면 명확한 상태로 실패한다.
- Codex에서도 OS 정책상 불가능한 작업은 DevSpace에서도 동일하게 실패할 수 있다.
- Codex에서 사용자 승인 후 가능한 작업은 DevSpace에서도 가능해야 한다.

### 1.3 Codex parity의 판정 기준

동일한 머신과 동일한 task-owned fixture에 대해 비교한다.

| 기능 | Codex | ChatGPT + DevSpace | 목표 |
|---|---|---|---|
| 일반 파일 CRUD | 성공 | 성공 | 동일 |
| 관리자 권한 파일 작업 | 인증 UI 후 성공 | 인증 UI 후 성공 | 동일 |
| 승인 취소 | 취소 오류 | 취소 오류 | 동일 |
| Accessibility 최초 요청 | TCC 안내/설정 | 동일 | 동일 |
| Screen Recording 최초 요청 | TCC 안내/설정 | 동일 | 동일 |
| raw packet capture | 승인 후 성공 | 승인 후 성공 | 동일 |
| privileged debugger attach | 승인 후 성공 또는 OS 차단 | 동일 | 동일 |
| SIP 보호 대상 attach | OS 차단 | 동일한 OS 차단 | 동일 |
| Computer Use click/type | 성공 | 성공 | 동일 |

---

## 2. 현재 확인된 실제 상태

작업 시작 전 반드시 다시 읽기 전용으로 확인한다. 아래 값은 2026-08-22 기준 스냅샷이다.

```text
Repository:
  /Users/lyjj0912/Documents/devspace-personal

Branch:
  codex/personal-direct-owner-completion-20260822

Observed HEAD:
  a435f452b1baa10bb4455ee7064dce3b674ed03e

Observed runtime revision:
  a435f452b1baa10bb4455ee7064dce3b674ed03e

Observed build digest:
  sha256:509cb72aaf3d0e988c5058652411aec551a31002f2109683de71f17d7a8892f8

Observed schema generation:
  sha256:5e84c4d1a74d2662340f56a339a96f8378343af3d1294e7f61f4192d9b7daa06
```

### 2.1 이미 동작하는 실제 기능

다음은 mock/stub이 아니라 실제로 검증됐다.

- target discovery/refresh/probe
- local 및 SSH exec
- foreground/background/PTY/process lifecycle
- 파일 CRUD, patch, hash, search, copy, move, sync
- symlink, binary, sparse, large file, Unicode path, mode/xattr
- Git context/worktree
- local↔company, local↔OCI artifact transfer
- artifact publish/receive/dedup/restart durability
- SQLite WAL/transaction/savepoint/FK/contention/backup
- OAuth connector readiness
- company Chrome DevTools MCP
- company Jira MCP
- controlled LLDB memory read/write
- controlled Linux `/proc/self/mem` read/write
- kernel/OS introspection
- DNS/TLS/HTTP/HTTP2
- network syscall analysis with `strace`
- broker restart and reconnect
- append-only audit chain
- immutable package identity/readiness

### 2.2 현재 실패 또는 미완성인 실제 기능

#### A. 권한 상승

현재 구현은 다음을 일률적으로 차단한다.

```text
sudo
su
Authorization Services
security_authtrampoline
setuid/setgid execution
administrator privileges AppleScript
Linux capabilities
Windows high-integrity token
```

문제는 “무승인 상승 차단” 자체가 아니라 **사용자 승인형 상승 lane이 전혀 없다는 점**이다.

#### B. Generic GUI / TCC

- local `gui.capabilities`: configured/available 일부 확인
- actual `gui.observe`: `System Events` 권한 위반 `-10004`
- company generic GUI: Accessibility disabled
- 현재 `gui-node.applescript`는 안정적인 서명 bundle identity가 아닌 임시 `osascript` 실행에 의존

#### C. `codex-computer-use-mcp`

- MCP initialize: 성공
- tools/list: 성공
- 10개 tool schema discovery: 성공
- `list_apps`: provider timeout/error
- `get_app_state`: provider timeout/error
- DevSpace proxy와 direct stdio 양쪽에서 재현
- underlying `SkyComputerUseService`/`SkyComputerUseClient` lifecycle 또는 IPC 문제

#### D. Raw packet capture

- macOS `tcpdump`: `/dev/bpf` 권한 거부
- Linux `tcpdump`: raw socket capability 부족
- syscall-level 분석은 성공했으나 packet capture positive path는 없음

#### E. 일부 원격 target

실제 online 검증:

```text
local
company
oci-phoenix
```

실제 offline 또는 미복구:

```text
windows / desktop-vb91sit
aws-ai-agent
oci-free-phoenix
oracle-ai-agent
```

#### F. A–Z validator 판정 결함

기존 A–Z 보고는 다음을 잘못 섞었다.

- “권한 상승 차단”을 기능 PASS로 계산
- 환경 차단과 제품 미구현을 충분히 분리하지 않음
- positive capability와 negative security test를 분리하지 않음
- actual Computer Use failure가 있는데 schema discovery를 부분 성공으로 간주
- raw capture 미구현을 정책상 정상으로 과대 해석

---

## 3. 수정하지 말아야 할 보안 불변식

Codex parity는 무인 root 또는 비밀번호 전달을 뜻하지 않는다.

다음은 계속 금지한다.

```text
채팅으로 관리자 비밀번호 입력 요구
비밀번호를 stdin/env/file/log/audit/MCP payload로 전달
NOPASSWD sudoers 설치
영구 root broker
전역적으로 열린 root shell
사용자 승인 없는 privileged helper dispatch
승인 receipt 재사용
승인한 명령과 다른 명령 실행
unsigned/untrusted client의 helper 호출
다른 사용자의 GUI session 또는 권한 사용
MCP provider가 임의로 privilege 획득
OS 인증 UI 우회
```

다음은 구현해야 한다.

```text
실제 네이티브 인증 UI
사용자의 직접 승인
정확한 단일 작업에 결합된 일회성 승인
승인 취소/거부/timeout 처리
승인 후 최소 권한 execution
승인 종료 후 일반 권한 복귀
비밀정보 비노출 audit
Codex와 동일한 TCC 승인 workflow
```

---

## 4. 목표 아키텍처

### 4.1 두 개의 execution lane

```text
ChatGPT
  │
  ▼
DevSpace broker (항상 일반 사용자)
  │
  ├── Ordinary lane
  │     ├── 기존 validation
  │     ├── macOS sandbox-exec
  │     ├── Linux no-new-privs
  │     └── Windows medium-integrity
  │
  └── User-authorized lane
        ├── DevSpace Approval Agent
        ├── 네이티브 OS 인증 UI
        ├── 일회성 authorization receipt
        ├── 최소 권한 privileged helper
        └── exact operation execution
```

### 4.2 기본 원칙

- broker는 root로 실행하지 않는다.
- 일반 요청은 ordinary lane으로 간다.
- elevation은 명시적이어야 한다.
- 승인 UI는 로그인된 실제 사용자 session에 나타난다.
- helper는 임의 shell server가 아니다.
- helper는 정확히 고정된 descriptor만 실행한다.
- result와 dispatch state를 audit에 기록한다.
- 승인 receipt와 command descriptor는 cryptographically bound된다.

---

## 5. Public schema 수정

Top-level tool 8개는 유지한다.

```text
target
context
fs
exec
process
mcp
artifact
gui
```

### 5.1 `exec` 입력 확장

```json
{
  "target": "local",
  "command": "/usr/sbin/tcpdump -i lo0 -c 20 ...",
  "mode": "foreground",
  "elevation": {
    "mode": "prompt",
    "reason": "DevSpace loopback packet-capture E2E",
    "scope": "operation",
    "timeoutMs": 120000
  }
}
```

기본값:

```json
{
  "elevation": {
    "mode": "none"
  }
}
```

허용 값:

```text
none
prompt
```

`none`에서 privilege 명령을 요청하면 provider dispatch 전에 차단한다.

### 5.2 `target` capability 확장

```json
{
  "elevation": {
    "policy": "prompt",
    "configured": true,
    "available": true,
    "mechanism": "macos-authorization-services",
    "requiresUserInteraction": true
  }
}
```

### 5.3 Unified config 수정

현재:

```text
elevationPolicy must be deny
```

수정:

```text
deny
prompt
```

향후 OS별 확장 가능:

```text
macos-authorization-services
windows-uac
linux-polkit
```

단, 첫 구현은 macOS local/company를 P0로 한다.

### 5.4 `gui` operation 확장

현재:

```text
capabilities
observe
act
wait
```

수정:

```text
capabilities
request_access
observe
act
wait
```

예:

```json
{
  "operation": "request_access",
  "target": "local",
  "permissions": [
    "accessibility",
    "screen_capture"
  ]
}
```

---

## 6. Elevation lifecycle

### 6.1 Process 상태

기존 상태에 추가:

```text
WAITING_AUTHORIZATION
```

전체 개념:

```text
STARTING
WAITING_AUTHORIZATION
RUNNING
EXITED
SIGNALED
FAILED
ORPHANED
UNKNOWN
```

### 6.2 Authorization 상태

```text
NOT_REQUIRED
PENDING
APPROVED
DENIED
CANCELED
TIMED_OUT
EXPIRED
RESULT_UNKNOWN
```

### 6.3 오류 코드

추가 또는 의미 정리:

```text
ELEVATION_REQUIRED
ELEVATION_DENIED
ELEVATION_CANCELED
ELEVATION_TIMED_OUT
ELEVATION_UNAVAILABLE
ELEVATION_RESULT_UNKNOWN
```

현재 `ELEVATION_BLOCKED`는 다음에만 사용한다.

```text
elevation.mode=none인데 privilege 명령이 포함됨
target policy가 deny임
승인 lane을 우회하려는 요청
```

### 6.4 Dispatch state

```text
NOT_DISPATCHED
DISPATCHED
ACKNOWLEDGED
UNKNOWN
```

승인 UI가 표시되었지만 helper dispatch 전 거부된 경우:

```text
dispatchState = NOT_DISPATCHED
authorizationState = DENIED/CANCELED/TIMED_OUT
```

helper에 전달된 뒤 결과가 불명확한 경우:

```text
dispatchState = UNKNOWN
authorizationState = RESULT_UNKNOWN
```

자동 mutation 재시도 금지.

---

## 7. Replay 및 idempotency

이전 JSON-RPC replay bug를 elevation에도 재발시키지 않는다.

### 7.1 Implicit JSON-RPC ID

```text
MCP session/transport namespace 내부에서만 유효
```

새 MCP session에서 같은 JSON-RPC ID를 재사용해도 충돌하지 않는다.

### 7.2 Explicit request ID

```text
_meta.devspace.requestId
```

만 cross-session/cross-transport idempotency에 사용한다.

### 7.3 Elevation prompt coalescing

동일 explicit requestId + 동일 descriptor:

```text
기존 operation 상태 반환
새 prompt 생성 금지
중복 helper dispatch 금지
```

동일 explicit requestId + 다른 descriptor:

```text
PRECONDITION_FAILED
providerDispatchCount = 0
```

### 7.4 Receipt binding

Receipt는 다음에 결합한다.

```text
operationId
explicit requestId digest
targetId
targetGeneration
runtimeRevision
schemaGeneration
absolute executable
argv digest
cwd
environment digest
reason
expiry
nonce
user UID/session
```

다른 작업에 재사용할 수 없다.

---

## 8. macOS Approval Agent

### 8.1 형태

```text
DevSpace Approval Agent.app
고정 bundle identifier
고정 code signature
로그인된 Aqua session에서 실행
일반 사용자 권한
```

### 8.2 역할

1. broker에서 operation descriptor 수신
2. safe summary 표시
3. 사용자에게 실제 macOS 인증 UI 표시
4. 승인/거부/취소/timeout 반환
5. authorization external form을 helper로 전달
6. 사용 후 폐기
7. audit용 비밀 없는 receipt 생성

### 8.3 표시 내용

```text
작업 종류
대상 머신
필요한 이유
absolute executable
요약된 argv
script hash
일회성 승인 여부
timeout
```

전체 비밀 command나 password는 표시·저장하지 않는다.

### 8.4 실행 위치

Approval Agent는 ordinary `sandbox-exec` 안에서 실행하지 않는다.

현재 macOS sandbox profile의 다음 규칙은 ordinary lane에만 적용한다.

```text
deny authorization-right-obtain
deny setuid/setgid execution
deny sudo/su/security_authtrampoline
```

---

## 9. macOS Privileged Helper

### 9.1 형태

```text
DevSpace Privileged Helper
root LaunchDaemon
authenticated XPC
기본 네트워크 접근 없음
interactive UI 없음
```

### 9.2 설치·등록

- signed app bundle 안에 helper 포함
- `SMAppService` 기반 등록
- 사용자 승인 필요
- install/status/uninstall lifecycle 제공
- rollback 가능
- task-owned test helper label 별도 사용

### 9.3 Caller 검증

Helper는 반드시 다음을 검증한다.

```text
XPC audit token
client code-signing requirement
bundle identifier
user UID
Aqua session
operation descriptor digest
authorization right
authorization expiry
nonce
runtime identity
request ID
replay 여부
```

### 9.4 명령 형식

#### 단순 명령

```text
absolute executable
argv array
canonical cwd
bounded environment allowlist
timeout
max output bytes
```

#### 복합 작업

broker가 immutable task script를 생성한다.

필수 검증:

```text
absolute canonical path
task-owned root 안
regular file
symlink 아님
owner = 요청 사용자
mode = 0600
inode/preimage 고정
SHA-256 고정
O_NOFOLLOW 상당의 안전한 open
```

Helper는 고정 shell로 exact script만 실행한다.

### 9.5 금지

```text
root shell service
arbitrary text command socket
unbounded env inheritance
PATH 기반 executable lookup
approval 없이 helper dispatch
다른 UID의 authorization receipt 사용
```

---

## 10. 기존 no-elevation 경계 리팩터링

현재 파일:

```text
src/v2/no-elevation.ts
```

역할을 두 부분으로 나눈다.

```text
ordinary-execution-boundary.ts
authorized-execution-boundary.ts
```

또는 기존 파일을 유지하되 API를 명시적으로 분리한다.

### 10.1 Ordinary lane

계속 유지:

```text
macOS sandbox-exec
Linux setpriv --no-new-privs
Windows non-elevated token
broker root 거부
MCP provider ordinary wrapper
```

### 10.2 Authorized lane

다음을 거치지 않는다.

```text
deny authorization-right-obtain
sudo executable deny
setpriv --no-new-privs
Windows medium-integrity prelude
```

대신 Approval Agent + helper contract를 거친다.

### 10.3 `assertNoElevationCommand`

현재 blanket 차단에서 다음으로 변경한다.

```text
elevation.mode=none:
  privilege command → ELEVATION_BLOCKED

elevation.mode=prompt:
  privilege command → authorized lane
  ordinary lane dispatch 금지

elevation.mode=prompt이지만 target policy=deny:
  ELEVATION_UNAVAILABLE
```

---

## 11. GUI/TCC 수정

### 11.1 현재 문제

`gui-node.applescript`를 `/usr/bin/osascript`로 매번 실행하면 안정적인 TCC principal이 아니다.

### 11.2 목표

```text
DevSpace GUI Agent.app
고정 bundle ID
고정 signature
사용자 login session
Accessibility permission
Screen Recording permission
authenticated IPC
```

### 11.3 Permission request

#### Accessibility

```text
AXIsProcessTrustedWithOptions(prompt=true)
```

#### Screen Recording

```text
CGPreflightScreenCaptureAccess()
CGRequestScreenCaptureAccess()
```

### 11.4 Workflow

```text
gui.capabilities
→ permissions 상태 반환

gui.request_access
→ 실제 TCC prompt 또는 System Settings 안내

사용자 승인
→ Agent 재시작 필요 여부 반환

gui.wait
→ capability 재탐지

gui.observe
→ 실제 accessibility tree

gui.act
→ task-owned click/type

screenshot
→ 실제 screen capture

cleanup
```

### 11.5 Remote company Mac

SSH가 직접 `osascript`를 실행하지 않는다.

```text
SSH transport
→ remote user-session GUI Agent IPC
→ TCC-bound signed Agent
```

local/company 모두 동일한 agent contract를 사용한다.

---

## 12. `codex-computer-use-mcp` 복구

### 12.1 현재 실패

```text
initialize = PASS
tools/list = PASS
list_apps = timeout/provider error
get_app_state = timeout/provider error
```

### 12.2 Readiness 기준 변경

현재 wrapper의 `pgrep SkyComputerUseService`만으로 ready 처리하지 않는다.

새 handshake:

```text
service process 존재
Aqua session 일치
IPC socket 존재
socket owner/mode 정상
service heartbeat 성공
client handshake 성공
tools/list 성공
probe tool 성공
```

### 12.3 Timeout 분리

```text
SERVICE_START_TIMEOUT
IPC_CONNECT_TIMEOUT
MCP_INITIALIZE_TIMEOUT
TOOL_LIST_TIMEOUT
APP_DISCOVERY_TIMEOUT
SCREENSHOT_TIMEOUT
ACCESSIBILITY_TIMEOUT
```

### 12.4 Stale lifecycle

```text
service 존재 + socket 응답 없음
→ stale service/session

task-owned client connection close
→ service heartbeat 재확인

필요 시 user-session service 재시작
→ initialize
→ tools/list
→ read-only probe
```

실제 mutation은 자동 재시도하지 않는다.

### 12.5 Positive actual-host test

task-owned test application을 사용한다.

```text
list_apps
get_app_state
open task app
observe screenshot/tree
select text field
type_text
click task button
state readback
close task app
cleanup
```

Generic GUI 성공으로 Computer Use 실패를 대체하지 않는다.

---

## 13. Packet capture 구현

### 13.1 Negative test

```text
elevation.mode=none
tcpdump
→ ELEVATION_BLOCKED 또는 ELEVATION_REQUIRED
providerDispatchCount = 0
```

### 13.2 Positive test

```text
task-owned loopback server
127.0.0.1:<fixed task port>
bounded client requests
exact BPF filter
packet count 제한
duration 제한
task-owned pcap path
elevation.mode=prompt
실제 인증 UI
사용자 승인
tcpdump 실행
pcap stat/hash/readback
permanent cleanup
```

무관한 사용자/회사 네트워크 트래픽은 캡처하지 않는다.

### 13.3 Linux

P0는 macOS local/company다.

Linux는 다음 중 선택한다.

```text
polkit 기반 interactive authorization
또는 target policy=deny
```

무인 sudo는 사용하지 않는다.

---

## 14. Debugger·메모리 parity

테스트를 세 등급으로 구분한다.

### Level 1 — Self

```text
self process memory read/write
```

이미 actual PASS.

### Level 2 — Same-user task-owned process

```text
ordinary debugger attach
task-owned process only
```

Codex와 DevSpace 결과 비교.

### Level 3 — User-approved privileged attach

```text
elevation.mode=prompt
실제 승인 UI
task-owned protected fixture
bounded attach/read
detach
cleanup
```

SIP/Hardened Runtime 등 Codex에서도 막히는 대상은:

```text
OS_POLICY_PARITY
```

로 판정한다.

---

## 15. 시스템 관리 parity

Actual positive test를 추가한다.

```text
task-owned protected path create/read/remove
task-owned LaunchDaemon install/start/status/stop/uninstall
task-owned helper registration/unregistration
protected system log read
bounded installer/package action
```

모든 label/path는 task prefix를 사용한다.

```text
com.devspace.test.<runId>
```

최종 residue:

```text
launchd label 0
helper 0
protected fixture 0
authorization receipt 0
temporary script 0
```

---

## 16. Remote target 처리

Configured target은 다음 중 하나여야 한다.

```text
ENABLED_ONLINE_TESTED
ENABLED_OFFLINE_BLOCKER
DISABLED_EXCLUDED
```

Target probe 오류를 정확히 분리한다.

```text
DNS_FAILED
ROUTE_UNREACHABLE
CONNECTION_REFUSED
CONNECT_TIMEOUT
HOST_KEY_MISMATCH
AUTHENTICATION_FAILED
REMOTE_SHELL_FAILED
GUI_SESSION_UNAVAILABLE
AUTHORIZATION_AGENT_UNAVAILABLE
```

우선순위:

1. local macOS
2. company macOS
3. oci-phoenix Linux
4. Windows
5. 나머지 cloud targets

최종 완전 PASS 전에는:

- enabled target 전부 actual test
- 또는 사용자가 명시적으로 disabled 처리

가 필요하다.

---

## 17. Release gate 수정

현재 release gate는 privileged helper 관련 파일/문자열 자체를 금지한다.

이 blanket ban을 제거하고 **안전한 helper contract 검증**으로 교체한다.

### 17.1 금지 유지

```text
NOPASSWD
sudo -n
password material
root password
raw secret
unsigned helper
arbitrary root shell
unbounded root command server
world-writable helper
untrusted LaunchDaemon
```

### 17.2 필수 검증

```text
signed Approval Agent
signed Privileged Helper
fixed bundle IDs
fixed code requirements
SMAppService manifest
XPC entitlement/identity
helper path/mode/owner
no network entitlement unless required
descriptor validation
authorization receipt binding
replay protection
redacted audit
install/uninstall/rollback tests
```

### 17.3 Package contents

Immutable package에는 다음을 포함한다.

```text
Approval Agent
Privileged Helper
GUI Agent
helper manifests
code signature evidence
entitlement evidence
source gate receipt
actual-host gate scripts
```

---

## 18. A–Z 판정 모델 수정

새 상태:

```text
PASS
EXPECTED_DENIAL_PASS
BLOCKED_PRODUCT_GAP
BLOCKED_ENVIRONMENT
OS_POLICY_PARITY
NOT_RUN
FAIL
UNKNOWN
```

### 18.1 Positive/negative 분리 예시

#### Elevation negative

```text
elevation.mode=none
privilege command
providerDispatchCount=0
EXPECTED_DENIAL_PASS
```

#### Elevation positive

```text
elevation.mode=prompt
native prompt shown
user approved
exact helper dispatch
ACKNOWLEDGED
exitCode=0
PASS
```

Negative만 성공하면 elevation 기능 PASS가 아니다.

### 18.2 Final validator 조건

```text
UNKNOWN = 0
NOT_RUN = 0
BLOCKED_PRODUCT_GAP = 0
unexpected FAIL = 0
positive capability 누락 = 0
duplicate prompt = 0
duplicate privileged dispatch = 0
credential leakage = 0
cross-run evidence mixing = 0
runtime identity drift = 0
task residue = 0
```

`BLOCKED_ENVIRONMENT`는 configured-target 완전 PASS에 허용하지 않는다.

---

## 19. 구현 단계

# Phase 0 — Baseline과 문서 고정

### 작업

- 현재 branch/HEAD/runtime/schema/readiness 재확인
- 이 문서를 canonical plan으로 등록
- 기존 Personal spec의 잘못된 user-account-only 문구 식별
- 별도 설계 문서 생성 금지

### 종료 조건

```text
working tree clean
current baseline receipt 생성
single canonical plan
single canonical spec
```

---

# Phase 1 — 계약과 schema 수정

### 주요 파일

```text
src/v2/contracts.ts
src/v2/unified-config.ts
src/v2/contracts.test.ts
src/v2/config.test.ts
src/v2/authority-policy.ts
src/v2/authority.test.ts
src/v2/operation-risk.ts
```

### 작업

- user-account-only instruction 교체
- `elevation.mode` schema 추가
- target `elevationPolicy=prompt` 추가
- 오류 코드와 lifecycle 상태 추가
- privilege command classifier를 lane router로 변경
- positive/negative test 분리

### 종료 조건

```text
typecheck PASS
schema tests PASS
ordinary lane regression PASS
prompt lane schema PASS
```

---

# Phase 2 — Execution lane 분리

### 주요 파일

```text
src/v2/no-elevation.ts
src/v2/execution.ts
src/v2/execution.test.ts
src/v2/personal-process-runtime.test.ts
src/v2/targets.ts
src/v2/targets.test.ts
```

### 작업

- ordinary boundary 유지
- authorized execution interface 추가
- WAITING_AUTHORIZATION 상태
- request/receipt binding
- exact descriptor
- dispatch state 및 output handling
- local/remote capability probe 분리

### 종료 조건

```text
ordinary sudo → NOT_DISPATCHED
prompt request → WAITING_AUTHORIZATION
denied/canceled/timeout 상태 정확
중복 request coalescing
```

---

# Phase 3 — macOS Approval Agent / Helper

### 신규 구성요소

```text
DevSpace Approval Agent.app
DevSpace Privileged Helper
XPC protocol
SMAppService registration
```

### 작업

- signed bundles
- code requirement 검증
- native prompt
- authorization external form
- exact operation helper dispatch
- output streaming
- cancellation
- install/uninstall/rollback
- receipt destruction

### 종료 조건

```text
실제 native auth prompt
승인 positive test
거부 test
취소 test
timeout test
replay test
credential leakage 0
helper residue 0
```

---

# Phase 4 — GUI/TCC Agent

### 주요 파일

```text
src/v2/gui.ts
src/v2/gui-node.ts
src/v2/gui.test.ts
target configuration
new GUI Agent project
```

### 작업

- temporary osascript 제거 또는 fallback 축소
- signed GUI Agent
- `request_access`
- Accessibility status/request
- Screen Recording status/request
- remote user-session IPC
- observe/act/screenshot

### 종료 조건

```text
local request_access PASS
company request_access PASS
observe PASS
task-owned click/type PASS
screenshot PASS
TCC denial/approval/restart 상태 정확
```

---

# Phase 5 — Computer Use 복구

### 작업

- wrapper readiness 강화
- socket heartbeat
- stale service detection
- timeout taxonomy
- client lifecycle
- direct stdio parity
- actual task app test

### 종료 조건

```text
initialize PASS
tools/list PASS
list_apps PASS
get_app_state PASS
type_text PASS
click PASS
state readback PASS
cleanup PASS
```

---

# Phase 6 — Privileged 기능

### 작업

- bounded tcpdump
- protected file operation
- LaunchDaemon fixture
- system log read
- privileged debugger fixture
- user-approved cleanup

### 종료 조건

```text
negative no-prompt denial PASS
positive prompt path PASS
pcap hash/readback PASS
protected CRUD PASS
LaunchDaemon lifecycle PASS
debugger parity PASS/OS_POLICY_PARITY
residue 0
```

---

# Phase 7 — Remote parity

### 작업

- local/company macOS
- oci-phoenix Linux
- Windows UAC design/implementation
- remaining SSH endpoint recovery 또는 disabled 처리

### 종료 조건

```text
enabled target 전부 online
또는 explicit disabled
platform-specific elevation capability 정확
```

---

# Phase 8 — Release/acceptance gate

### 작업

- blanket privileged-ban 제거
- signed helper validation
- immutable candidate
- actual positive/negative gates
- A–Z validator 개정
- audit-backed run manifest

### 종료 조건

```text
source gate PASS
candidate actual gate PASS
rollback rehearsal PASS
production atomic deploy PASS
ChatGPT schema refresh PASS
new MCP session PASS
```

---

# Phase 9 — 최종 immutable A–Z

Run 시작 시 다음을 고정한다.

```text
runId
sourceRevision
runtimeRevision
buildDigest
schemaGeneration
connectorEpoch
targetGeneration
routeGeneration
helper signature digest
agent signature digest
```

Run 도중 다음 변경 금지:

```text
코드
환경변수
route
provider
helper
agent
connector
target registry
fixture reuse
```

실패 시:

```text
run FAIL
수정
새 runId
A부터 다시 시작
```

---

## 20. Actual test matrix

### Elevation

```text
none + sudo → expected denial
prompt + approve → success
prompt + deny → denied
prompt + cancel → canceled
prompt + timeout → timed out
same requestId/same action → one prompt/one dispatch
same requestId/different action → precondition failed
restart while waiting → deterministic recovery
```

### TCC

```text
unapproved Accessibility
request prompt
approve
agent restart
capability recheck
observe
act
revoke
capability recheck
```

```text
unapproved Screen Recording
request prompt
approve
screenshot
revoke
capability recheck
```

### Computer Use

```text
service down
service start
initialize
tools/list
list_apps
get_app_state
type_text
click
state readback
client reconnect
service restart
cleanup
```

### Packet capture

```text
ordinary denial
approved loopback capture
packet count bound
BPF filter exact
pcap hash
readback
cleanup
```

### Debugger

```text
self
same-user task process
approved privileged task process
SIP-protected negative parity
```

### Files and system

```text
protected path CRUD
LaunchDaemon install/start/status/stop/uninstall
system log read
helper rollback
```

### Remote

```text
local
company
OCI
Windows
remaining enabled targets
```

---

## 21. Audit 요구사항

기록:

```text
operationId
explicit requestId digest
principal fingerprint prefix
product profile
source/runtime revision
build/schema digest
connector epoch
target/route generation
risk
elevation mode
authorization state
prompt timestamp
decision timestamp
helper identity digest
descriptor digest
dispatch state
exit code
output digest
receipt digest
```

기록 금지:

```text
password
authorization secret
raw external form
full sensitive command
full environment
private key
token
cookie
credential memory
```

Audit validator는 전체 chain과 run window를 모두 검증한다.

---

## 22. Rollback

### Approval Agent / Helper 실패

```text
candidate helper unregister
candidate agent remove
previous production unchanged
authorization receipts destroy
task launchd labels remove
```

### Production deploy 실패

```text
runtime pointer restore
environment restore
PM2 previous process restore
helper registration previous state restore
OAuth/artifact DB snapshot restore if modified
readiness verify
```

### TCC

TCC 상태를 강제로 변경하거나 DB를 직접 수정하지 않는다.

사용자가 System Settings에서 승인·해제한다.

---

## 23. 권장 커밋 순서

```text
1. docs(contract): replace user-account-only with Codex parity
2. feat(schema): add prompt elevation capability and lifecycle
3. refactor(exec): split ordinary and user-authorized lanes
4. feat(macos): add approval agent and privileged helper
5. feat(audit): bind one-shot authorization to exact actions
6. feat(gui): add signed TCC-aware GUI agent
7. fix(computer-use): repair service readiness and tool execution
8. feat(privileged): add approved packet capture and debugger paths
9. fix(targets): expose parity capabilities and exact offline reasons
10. fix(release): validate secure helpers instead of blanket banning them
11. fix(acceptance): separate positive capability from denial tests
12. test(actual-host): immutable Codex-parity A–Z
```

각 커밋은 해당 범위 테스트를 통과한 후 다음 커밋으로 진행한다.

---

## 24. 최종 Definition of Done

다음 조건이 전부 충족되어야 한다.

```text
broker 자체 일반 사용자 실행
ordinary lane sandbox 유지
무승인 privilege 차단
native prompt 표시
사용자 승인형 privilege 성공
password/secret leakage 0
exact action receipt binding
중복 prompt 0
중복 privileged dispatch 0
Accessibility request/observe/act PASS
Screen Recording request/screenshot PASS
codex-computer-use-mcp actual tools PASS
approved tcpdump PASS
controlled debugger parity PASS
protected CRUD PASS
LaunchDaemon lifecycle PASS
enabled remote targets actual PASS
audit UNKNOWN 0
NOT_RUN 0
BLOCKED_PRODUCT_GAP 0
unexpected FAIL 0
cross-run evidence mixing 0
task residue 0
candidate rollback PASS
production readiness PASS
새 ChatGPT MCP session actual PASS
```

최종 상태 문자열:

```text
DEVSPACE_CODEX_PARITY_AZ_PASS
```

---

## 25. Compact 이후 재개 체크포인트

작업자는 이 표를 갱신한다.

| Phase | 상태 | Commit | Evidence | 다음 작업 |
|---|---|---|---|---|
| 0 Baseline | PASS | phase-1 contract commit | source/runtime `a435f452…`; canonical plan fixed; production 12/12 ready | 유지 |
| 1 Contract/schema | PASS | phase-1 contract commit | typecheck, build, `v2:test`, budget, quick load PASS | Phase 2 provider interface |
| 2 Execution lanes | IN_PROGRESS | phase-1 contract commit | ordinary denial + prompt target/provider pre-dispatch tests PASS | actual authorization provider and receipt lifecycle |
| 3 Approval Agent/Helper | NOT_STARTED | - | - | - |
| 4 GUI/TCC Agent | NOT_STARTED | - | - | - |
| 5 Computer Use | NOT_STARTED | - | - | - |
| 6 Privileged capabilities | NOT_STARTED | - | - | - |
| 7 Remote parity | NOT_STARTED | - | - | - |
| 8 Release/acceptance | NOT_STARTED | - | - | - |
| 9 Immutable A–Z | NOT_STARTED | - | - | - |

상태 값:

```text
NOT_STARTED
IN_PROGRESS
BLOCKED
PASS
FAIL
```

---

## 26. 미래 작업자에게 금지하는 잘못된 결론

다음 문장을 다시 사용하지 않는다.

```text
DevSpace는 user-account-only이므로 sudo는 원래 불가능하다.
tcpdump 권한 거부는 기능 PASS다.
Accessibility 미승인은 사용자 문제이므로 DevSpace 완료다.
Computer Use tools/list가 되므로 Computer Use는 동작한다.
Codex에서도 가능하지만 ChatGPT에서는 보안상 불가능하다.
```

올바른 원칙:

```text
Codex에서 실제 사용자 승인으로 가능한 기능은
ChatGPT + DevSpace에서도 동일하거나 실질적으로 동등한
사용자 승인 절차를 통해 가능해야 한다.
```
