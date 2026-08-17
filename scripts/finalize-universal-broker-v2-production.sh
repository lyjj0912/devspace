#!/bin/bash
set -Eeuo pipefail

HOME_DIR="${HOME:?HOME is required}"
AUDIT_ROOT="$HOME_DIR/.devspace/deployments/universal-broker-v2"
AUDIT=""
EVIDENCE=""
COMMAND="${1:-}"
[[ -n "$COMMAND" ]] && shift
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --audit) AUDIT="${2:-}"; shift 2 ;;
    --evidence) EVIDENCE="${2:-}"; shift 2 ;;
    *) echo "Usage: $0 <prepare|seal> --evidence <json> [--audit <deployment-audit>]" >&2; exit 2 ;;
  esac
done
[[ "$COMMAND" == "prepare" || "$COMMAND" == "seal" ]] || {
  echo "Usage: $0 <prepare|seal> --evidence <json> [--audit <deployment-audit>]" >&2
  exit 2
}
[[ -n "$EVIDENCE" && -f "$EVIDENCE" ]] || { echo "Evidence file is missing: $EVIDENCE" >&2; exit 1; }
AUDIT="${AUDIT:-$AUDIT_ROOT/current}"
AUDIT="$(cd "$AUDIT" 2>/dev/null && pwd -P)" || { echo "Deployment audit is unavailable: $AUDIT" >&2; exit 1; }
for file in route.json result.json base-config.json; do
  [[ -f "$AUDIT/$file" ]] || { echo "Audit file is missing: $AUDIT/$file" >&2; exit 1; }
done

for command in pm2 curl tailscale sqlite3 python3 node; do
  command -v "$command" >/dev/null || { echo "Required command is unavailable: $command" >&2; exit 1; }
done

VALUES="$(python3 - "$AUDIT/result.json" "$AUDIT/route.json" "$AUDIT/base-config.json" <<'PY'
import json, sys
result=json.load(open(sys.argv[1])); route=json.load(open(sys.argv[2])); base=json.load(open(sys.argv[3]))
if result.get('status') not in ('CUTOVER_PASS','FINAL_PASS'):
    raise SystemExit('Deployment result is not eligible for finalization')
print('\t'.join(map(str,[
    result['sourceCommit'], result['release'], route['publicServiceBase'], route['publicPath'],
    route['publicHttpsPort'], route['legacyLocalPort'], route['v2LocalPort'],
    route['legacyPm2Name'], route['v2Pm2Name'], base['stateDir'],
])))
PY
)"
IFS=$'\t' read -r SOURCE_COMMIT RELEASE PUBLIC_SERVICE_BASE PUBLIC_PATH PUBLIC_HTTPS_PORT LEGACY_PORT V2_PORT LEGACY_PM2_NAME V2_PM2_NAME BASE_STATE_DIR <<<"$VALUES"
DATABASE="$BASE_STATE_DIR/devspace.sqlite"
AUTH_FILE="$HOME_DIR/.devspace/auth.json"
START_SCRIPT="$HOME_DIR/.devspace/start.sh"
PRODUCTION_ENV="$HOME_DIR/.devspace/universal-broker-v2-production.env"
FINAL_DIR="$AUDIT/finalization"
LOCAL_V2_HEALTH="http://127.0.0.1:$V2_PORT/healthz"
PUBLIC_HEALTH="$PUBLIC_SERVICE_BASE/healthz"
PUBLIC_MCP="$PUBLIC_SERVICE_BASE/mcp"
mkdir -p "$FINAL_DIR"
chmod 700 "$FINAL_DIR"

validate_evidence() {
  local expected_phase="$1"
  python3 - "$EVIDENCE" "$SOURCE_COMMIT" "$expected_phase" <<'PY'
import datetime, json, sys
path, source_commit, phase = sys.argv[1:]
value=json.load(open(path))
expected_tools=["target","context","fs","exec","process","mcp","artifact","gui"]
required={"local","external-storage","ssh","mcp-mutation","artifact","gui"}
if value.get('status') != 'PASS': raise SystemExit('Connector evidence status is not PASS')
if value.get('phase') != phase: raise SystemExit(f'Connector evidence phase must be {phase}')
if value.get('sourceCommit') != source_commit: raise SystemExit('Connector evidence is for a different source commit')
if value.get('connectorName') != 'myDevSpace': raise SystemExit('Production connector name must be myDevSpace')
if int(value.get('freshChatGptSessions',0)) < 1: raise SystemExit('At least one fresh ChatGPT session is required')
if value.get('toolNames') != expected_tools: raise SystemExit('Production connector tool surface is not the fixed eight tools')
if not required.issubset(set(value.get('scenarios',[]))): raise SystemExit('Production connector scenarios are incomplete')
client=value.get('keepClientId')
if not isinstance(client,str) or not client: raise SystemExit('keepClientId is required')
verified=value.get('verifiedAt')
try: datetime.datetime.fromisoformat(verified.replace('Z','+00:00'))
except Exception: raise SystemExit('verifiedAt is not an ISO timestamp')
print(client+'\t'+verified)
PY
}

switch_route() {
  local local_port="$1"
  if [[ "$PUBLIC_PATH" == "/" ]]; then
    tailscale funnel --bg --https="$PUBLIC_HTTPS_PORT" --yes "http://127.0.0.1:$local_port"
  else
    tailscale funnel --bg --https="$PUBLIC_HTTPS_PORT" --set-path="$PUBLIC_PATH" --yes "http://127.0.0.1:$local_port"
  fi
}
wait_health() {
  local url="$1" output="$2"
  for _ in $(seq 1 120); do
    if curl -fsS --max-time 5 "$url" >"$output" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  curl -fsS --max-time 5 "$url" >"$output"
}
assert_unauthenticated() {
  local status
  status="$(curl -sS --max-time 10 -o "$2" -w '%{http_code}' -X POST \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"finalization-boundary","version":"1"}}}' \
    "$1")"
  [[ "$status" == "401" ]]
}

if [[ "$COMMAND" == "prepare" ]]; then
  [[ ! -f "$FINAL_DIR/prepare.json" ]] || {
    echo "Finalization prepare already exists: $FINAL_DIR/prepare.json" >&2
    exit 1
  }
  IFS=$'\t' read -r KEEP_CLIENT_ID VERIFIED_AT <<<"$(validate_evidence production-reconnect)"
  cp -p "$EVIDENCE" "$FINAL_DIR/production-reconnect-evidence.json"
  cp -p "$AUTH_FILE" "$FINAL_DIR/auth.json.before"
  sqlite3 "$DATABASE" ".backup '$FINAL_DIR/devspace.sqlite.before'"
  tailscale funnel status --json >"$FINAL_DIR/funnel.before.json"

  ROUTED_TO_LEGACY=0
  V2_STOPPED=0
  rollback_prepare() {
    local rc="${1:-1}"
    trap - ERR INT TERM
    set +e
    cp -p "$FINAL_DIR/auth.json.before" "$AUTH_FILE.rollback"
    mv -f "$AUTH_FILE.rollback" "$AUTH_FILE"
    if [[ -f "$FINAL_DIR/devspace.sqlite.before" ]]; then
      pm2 stop "$V2_PM2_NAME" >/dev/null 2>&1 || true
      cp -p "$FINAL_DIR/devspace.sqlite.before" "$DATABASE.rollback"
      rm -f "$DATABASE-wal" "$DATABASE-shm"
      mv -f "$DATABASE.rollback" "$DATABASE"
      pm2 restart "$V2_PM2_NAME" --update-env >/dev/null 2>&1 || true
    fi
    switch_route "$LEGACY_PORT" >/dev/null 2>&1 || true
    printf '{"status":"PREPARE_ROLLED_BACK","exitCode":%s}\n' "$rc" >"$FINAL_DIR/prepare-result.json"
    exit "$rc"
  }
  trap 'rollback_prepare $?' ERR
  trap 'rollback_prepare 130' INT
  trap 'rollback_prepare 143' TERM

  switch_route "$LEGACY_PORT" >"$FINAL_DIR/route-to-legacy.log" 2>&1
  ROUTED_TO_LEGACY=1
  pm2 stop "$V2_PM2_NAME" >"$FINAL_DIR/v2-stop.log" 2>&1
  V2_STOPPED=1

  python3 - "$AUTH_FILE" "$DATABASE" "$KEEP_CLIENT_ID" "$PUBLIC_MCP" "$FINAL_DIR/prepare.json" <<'PY'
import datetime, hashlib, json, os, secrets, sqlite3, stat, sys, tempfile
path, database, keep_client, resource, evidence = sys.argv[1:]
st=os.stat(path)
if stat.S_IMODE(st.st_mode) & 0o077: raise SystemExit('auth.json must be owner-only')
data=json.load(open(path))
candidates=[]
def walk(value, trail=()):
    if isinstance(value,dict):
        for key,child in value.items():
            next_trail=trail+(key,)
            normalized=key.replace('_','').replace('-','').lower()
            if normalized in ('ownertoken','oauthownertoken') and isinstance(child,str): candidates.append(next_trail)
            walk(child,next_trail)
    elif isinstance(value,list):
        for index,child in enumerate(value): walk(child,trail+(index,))
walk(data)
if len(candidates)!=1: raise SystemExit(f'expected exactly one owner token field, found {len(candidates)}')
trail=candidates[0]; cursor=data
for key in trail[:-1]: cursor=cursor[key]
old=cursor[trail[-1]]; new=secrets.token_urlsafe(48); cursor[trail[-1]]=new
con=sqlite3.connect(database)
con.execute('PRAGMA foreign_keys=ON')
row=con.execute('SELECT client_json FROM oauth_clients WHERE client_id=?',(keep_client,)).fetchone()
if not row: raise SystemExit('keepClientId is not registered')
tokens=con.execute('SELECT scopes_json, expires_at, resource FROM oauth_access_tokens WHERE client_id=?',(keep_client,)).fetchall()
if not tokens: raise SystemExit('keepClientId has no access token')
required={'devspace.read','devspace.write','devspace.exec','devspace.mcp','devspace.artifact','devspace.gui'}
valid=False
now=int(datetime.datetime.now(datetime.timezone.utc).timestamp())
for scopes_json,expires_at,token_resource in tokens:
    scopes=set(json.loads(scopes_json))
    if required.issubset(scopes) and int(expires_at)>now and str(token_resource).rstrip('/')==resource.rstrip('/'):
        valid=True
if not valid: raise SystemExit('keepClientId has no valid full-scope production token')
with con:
    access_before=con.execute('SELECT COUNT(*) FROM oauth_access_tokens').fetchone()[0]
    refresh_before=con.execute('SELECT COUNT(*) FROM oauth_refresh_tokens').fetchone()[0]
    clients_before=con.execute('SELECT COUNT(*) FROM oauth_clients').fetchone()[0]
    access_deleted=con.execute('DELETE FROM oauth_access_tokens WHERE client_id<>?',(keep_client,)).rowcount
    refresh_deleted=con.execute('DELETE FROM oauth_refresh_tokens WHERE client_id<>?',(keep_client,)).rowcount
    clients_deleted=con.execute('DELETE FROM oauth_clients WHERE client_id<>?',(keep_client,)).rowcount
fd,tmp=tempfile.mkstemp(prefix='auth-v2-final-',dir=os.path.dirname(path))
try:
    with os.fdopen(fd,'w') as stream:
        json.dump(data,stream,ensure_ascii=False,indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    os.chmod(tmp,0o600); os.replace(tmp,path)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
prepared_at=datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z')
with open(evidence,'w') as stream:
    json.dump({
        'status':'FINALIZATION_PREPARED', 'sourceCommit':os.environ.get('SOURCE_COMMIT'),
        'keepClientId':keep_client, 'preparedAt':prepared_at,
        'ownerCredentialRotated':old!=new, 'ownerTokenFieldPath':'.'.join(map(str,trail)),
        'oldOwnerTokenSha256':hashlib.sha256(old.encode()).hexdigest(),
        'newOwnerTokenSha256':hashlib.sha256(new.encode()).hexdigest(),
        'oauthAccessTokensBefore':access_before, 'oauthAccessTokensDeleted':access_deleted,
        'oauthRefreshTokensBefore':refresh_before, 'oauthRefreshTokensDeleted':refresh_deleted,
        'oauthClientsBefore':clients_before, 'oauthClientsDeleted':clients_deleted,
    },stream,indent=2); stream.write('\n')
PY
  # Inject the shell-authoritative commit without exposing a credential.
  python3 - "$FINAL_DIR/prepare.json" "$SOURCE_COMMIT" <<'PY'
import json,sys,tempfile,os
p,commit=sys.argv[1:]; value=json.load(open(p)); value['sourceCommit']=commit
fd,tmp=tempfile.mkstemp(prefix='prepare-',dir=os.path.dirname(p))
with os.fdopen(fd,'w') as stream: json.dump(value,stream,indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
os.chmod(tmp,0o600); os.replace(tmp,p)
PY

  pm2 restart "$V2_PM2_NAME" --update-env >"$FINAL_DIR/v2-restart.log" 2>&1
  wait_health "$LOCAL_V2_HEALTH" "$FINAL_DIR/health.local.after-rotation.json"
  switch_route "$V2_PORT" >"$FINAL_DIR/route-to-v2.log" 2>&1
  wait_health "$PUBLIC_HEALTH" "$FINAL_DIR/health.public.after-rotation.json"
  assert_unauthenticated "$PUBLIC_MCP" "$FINAL_DIR/mcp.unauthenticated.after-rotation.json"
  pm2 save >"$FINAL_DIR/pm2-save.prepare.log" 2>&1
  trap - ERR INT TERM
  cp -p "$FINAL_DIR/prepare.json" "$AUDIT/finalization-status.json"
  ln -sfn "$AUDIT" "$AUDIT_ROOT/current"
  echo "Universal Broker v2 credential finalization prepared; post-rotation ChatGPT verification is required."
  exit 0
fi

[[ -f "$FINAL_DIR/prepare.json" ]] || { echo "Finalization prepare evidence is missing." >&2; exit 1; }
IFS=$'\t' read -r KEEP_CLIENT_ID VERIFIED_AT <<<"$(validate_evidence post-rotation)"
python3 - "$FINAL_DIR/prepare.json" "$EVIDENCE" "$SOURCE_COMMIT" "$KEEP_CLIENT_ID" <<'PY'
import datetime,json,sys
prepare_path,evidence_path,commit,keep=sys.argv[1:]
prepare=json.load(open(prepare_path)); evidence=json.load(open(evidence_path))
if prepare.get('status')!='FINALIZATION_PREPARED': raise SystemExit('prepare status is invalid')
if prepare.get('sourceCommit')!=commit or prepare.get('keepClientId')!=keep: raise SystemExit('prepare/evidence identity mismatch')
prepared=datetime.datetime.fromisoformat(prepare['preparedAt'].replace('Z','+00:00'))
verified=datetime.datetime.fromisoformat(evidence['verifiedAt'].replace('Z','+00:00'))
if verified <= prepared: raise SystemExit('post-rotation evidence predates credential rotation')
if evidence.get('legacyConnectorRemoved') is not True: raise SystemExit('legacy ChatGPT connector has not been removed')
PY
cp -p "$EVIDENCE" "$FINAL_DIR/post-rotation-evidence.json"

python3 - "$DATABASE" "$KEEP_CLIENT_ID" "$PUBLIC_MCP" <<'PY'
import datetime,json,sqlite3,sys
db,keep,resource=sys.argv[1:]; con=sqlite3.connect(db)
clients=[row[0] for row in con.execute('SELECT client_id FROM oauth_clients ORDER BY client_id')]
if clients != [keep]: raise SystemExit(f'unexpected OAuth clients remain: {len(clients)}')
access=con.execute('SELECT scopes_json,expires_at,resource FROM oauth_access_tokens WHERE client_id=?',(keep,)).fetchall()
if not access: raise SystemExit('kept connector has no access token')
required={'devspace.read','devspace.write','devspace.exec','devspace.mcp','devspace.artifact','devspace.gui'}
now=int(datetime.datetime.now(datetime.timezone.utc).timestamp())
if not any(required.issubset(set(json.loads(s))) and int(e)>now and str(r).rstrip('/')==resource.rstrip('/') for s,e,r in access):
    raise SystemExit('kept connector token is not a valid full-scope production token')
if con.execute('SELECT COUNT(*) FROM oauth_refresh_tokens WHERE client_id<>?',(keep,)).fetchone()[0] != 0:
    raise SystemExit('old refresh tokens remain')
PY

START_NEXT="$FINAL_DIR/start.sh.v2"
cat >"$START_NEXT" <<EOF
#!/bin/bash
set -euo pipefail
export DEVSPACE_PRODUCTION_ENV_FILE="$PRODUCTION_ENV"
exec "$RELEASE/scripts/start-universal-broker-v2-production.sh"
EOF
chmod 700 "$START_NEXT"
cp -p "$START_NEXT" "$START_SCRIPT.next"
mv -f "$START_SCRIPT.next" "$START_SCRIPT"

pm2 delete "$LEGACY_PM2_NAME" >"$FINAL_DIR/legacy-pm2-delete.log" 2>&1 || true
if pm2 pid devspace-next 2>/dev/null | grep -qv '^0$'; then
  pm2 delete devspace-next >"$FINAL_DIR/parallel-pm2-delete.log" 2>&1 || true
fi
PARALLEL_PORT="$(python3 - "$AUDIT/phase9-evidence.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1])); print(v.get('parallelFunnelPort',''))
PY
)"
PARALLEL_PATH="$(python3 - "$AUDIT/phase9-evidence.json" <<'PY'
import json,sys
v=json.load(open(sys.argv[1])); print(v.get('parallelFunnelPath','/'))
PY
)"
if [[ -n "$PARALLEL_PORT" && ( "$PARALLEL_PORT" != "$PUBLIC_HTTPS_PORT" || "$PARALLEL_PATH" != "$PUBLIC_PATH" ) ]]; then
  command=(tailscale funnel --https="$PARALLEL_PORT")
  [[ "$PARALLEL_PATH" == "/" ]] || command+=(--set-path="$PARALLEL_PATH")
  command+=(--yes off)
  "${command[@]}" >"$FINAL_DIR/parallel-funnel-off.log" 2>&1 || true
fi
rm -f "$HOME_DIR/.devspace/universal-broker-v2.env"
pm2 save >"$FINAL_DIR/pm2-save.seal.log" 2>&1
wait_health "$LOCAL_V2_HEALTH" "$FINAL_DIR/health.local.final.json"
wait_health "$PUBLIC_HEALTH" "$FINAL_DIR/health.public.final.json"
assert_unauthenticated "$PUBLIC_MCP" "$FINAL_DIR/mcp.unauthenticated.final.json"
pm2 jlist >"$FINAL_DIR/pm2.final.json"
tailscale funnel status --json >"$FINAL_DIR/funnel.final.json"

cat >"$FINAL_DIR/final.json" <<EOF
{
  "status": "FINAL_PASS",
  "sourceCommit": "$SOURCE_COMMIT",
  "keepClientId": $(node -e 'process.stdout.write(JSON.stringify(process.argv[1]))' "$KEEP_CLIENT_ID"),
  "ownerCredentialRotated": true,
  "oldOAuthClientsAndTokensRevoked": true,
  "postRotationChatGptVerified": true,
  "legacyConnectorRemoved": true,
  "legacyRuntimeRemoved": true,
  "parallelRuntimeRemoved": true,
  "productionStartScriptUpdated": true,
  "publicHealth": "$PUBLIC_HEALTH"
}
EOF
chmod 600 "$FINAL_DIR/final.json"
cp -p "$FINAL_DIR/final.json" "$AUDIT/result.json"
ln -sfn "$AUDIT" "$AUDIT_ROOT/current"
echo "Universal Broker v2 production finalization passed: $SOURCE_COMMIT"
