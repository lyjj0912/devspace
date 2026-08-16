export const REMOTE_FILESYSTEM_RESULT_MARKER = "__DEVSPACE_V2_FS_JSON__";

/**
 * Self-contained Python helper used for POSIX SSH targets. Requests and results
 * are base64/JSON framed so target aliases, paths, and file contents never
 * become shell syntax. The helper deliberately implements only generic
 * filesystem primitives; no application-specific behavior belongs here.
 */
export const REMOTE_FILESYSTEM_HELPER_SOURCE = String.raw`
import base64, errno, hashlib, json, os, shutil, stat, sys, tempfile

MARKER = "__DEVSPACE_V2_FS_JSON__"
req = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))

def expanded(value):
    return os.path.abspath(os.path.expanduser(value))

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()

def kind(mode):
    if stat.S_ISREG(mode): return "file"
    if stat.S_ISDIR(mode): return "directory"
    if stat.S_ISLNK(mode): return "symlink"
    if stat.S_ISSOCK(mode): return "socket"
    if stat.S_ISFIFO(mode): return "fifo"
    if stat.S_ISCHR(mode): return "character-device"
    if stat.S_ISBLK(mode): return "block-device"
    return "other"

def metadata(path):
    value = os.lstat(path)
    result = {
        "path": path,
        "type": kind(value.st_mode),
        "size": value.st_size,
        "mode": stat.S_IMODE(value.st_mode),
        "mtimeMs": value.st_mtime_ns / 1000000,
        "birthtimeMs": getattr(value, "st_birthtime", value.st_ctime) * 1000,
        "uid": value.st_uid,
        "gid": value.st_gid,
        "canonicalPath": os.path.realpath(path),
    }
    if stat.S_ISLNK(value.st_mode): result["linkTarget"] = os.readlink(path)
    return result

def optional_lstat(path):
    try: return os.lstat(path)
    except FileNotFoundError: return None

def assert_confined(root, candidate):
    root = os.path.realpath(expanded(root))
    if not os.path.isdir(root): raise NotADirectoryError(root)
    probe = candidate
    suffix = []
    while not os.path.lexists(probe):
        parent = os.path.dirname(probe)
        if parent == probe: raise FileNotFoundError(candidate)
        suffix.insert(0, os.path.basename(probe))
        probe = parent
    resolved = os.path.realpath(probe)
    if suffix: resolved = os.path.join(resolved, *suffix)
    try: common = os.path.commonpath((root, resolved))
    except ValueError: raise PermissionError("path-outside-confined-root")
    if common != root: raise PermissionError("path-outside-confined-root")

def require_parent(path, create):
    parent = os.path.dirname(path)
    if create: os.makedirs(parent, exist_ok=True)
    if not os.path.isdir(parent): raise NotADirectoryError(parent)
    return parent

def verify_destination(path, options):
    existing = optional_lstat(path)
    if existing is not None and stat.S_ISLNK(existing.st_mode):
        raise PermissionError("refuse-symlink-publication")
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise IsADirectoryError(path)
    if existing is not None and not options.get("overwrite", False):
        raise RuntimeError("destination-exists")
    expected_hash = options.get("expectedSha256")
    if expected_hash is not None:
        if existing is None or not stat.S_ISREG(existing.st_mode) or digest(path).lower() != expected_hash.lower():
            raise RuntimeError("sha256-precondition")
    return existing

def remove_existing(path):
    value = optional_lstat(path)
    if value is None: return
    if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode): shutil.rmtree(path)
    else: os.unlink(path)

def copy_item(source, destination):
    value = os.lstat(source)
    if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode):
        shutil.copytree(source, destination, symlinks=True)
    elif stat.S_ISREG(value.st_mode):
        shutil.copy2(source, destination, follow_symlinks=False)
    else:
        raise RuntimeError("unsupported-copy-type")

def staging_identity():
    return os.getuid(), os.getgid()

def staging_path(value):
    path = expanded(value)
    parent = os.path.dirname(path)
    name = os.path.basename(path)
    if parent not in ("/tmp", "/var/tmp") or not name.startswith(".devspace-v2-"):
        raise PermissionError("invalid-staging-path")
    return path

def stage_export(source, destination):
    destination = staging_path(destination)
    value = os.lstat(source)
    if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode):
        raise IsADirectoryError(source)
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with open(source, "rb") as incoming, os.fdopen(descriptor, "wb", closefd=True) as outgoing:
            descriptor = -1
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush(); os.fsync(outgoing.fileno())
        uid, gid = staging_identity()
        os.chown(destination, uid, gid)
        os.chmod(destination, 0o600)
        return {"source": source, "temporary": destination, "size": value.st_size, "sha256": digest(destination), "uid": uid, "gid": gid}
    except Exception:
        try: os.unlink(destination)
        except FileNotFoundError: pass
        raise
    finally:
        if descriptor >= 0: os.close(descriptor)

def publish_staging(source, destination, options):
    source = staging_path(source)
    source_value = os.lstat(source)
    uid, _ = staging_identity()
    if not stat.S_ISREG(source_value.st_mode) or stat.S_ISLNK(source_value.st_mode) or source_value.st_uid != uid:
        raise PermissionError("invalid-staging-source")
    parent = require_parent(destination, bool(options.get("createParents", False)))
    existing = verify_destination(destination, options)
    mode = int(options.get("mode", stat.S_IMODE(existing.st_mode) if existing is not None else 0o600))
    descriptor, temporary = tempfile.mkstemp(prefix=".devspace-v2-", suffix=".tmp", dir=parent)
    try:
        os.fchmod(descriptor, mode)
        with open(source, "rb") as incoming, os.fdopen(descriptor, "wb", closefd=True) as outgoing:
            descriptor = -1
            shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush(); os.fsync(outgoing.fileno())
        os.replace(temporary, destination)
        if options.get("uid") is not None or options.get("gid") is not None:
            value = os.stat(destination)
            os.chown(destination, int(options.get("uid", value.st_uid)), int(options.get("gid", value.st_gid)))
        directory_fd = os.open(parent, os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        value = os.stat(destination)
        return {"path": destination, "size": value.st_size, "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid, "sha256": digest(destination), "overwritten": existing is not None}
    finally:
        if descriptor >= 0: os.close(descriptor)
        try: os.unlink(temporary)
        except FileNotFoundError: pass

def search_files(root, query, options):
    maximum = int(options.get("limit", 50))
    maximum = max(1, min(maximum, 500))
    maximum_bytes = int(options.get("maxFileBytes", 2 * 1024 * 1024))
    recursive = bool(options.get("recursive", True))
    results = []
    visited = 0
    candidates = []
    if os.path.isfile(root):
        candidates = [root]
    elif not os.path.isdir(root):
        raise NotADirectoryError(root)
    elif recursive:
        for directory, names, files in os.walk(root):
            names[:] = [name for name in names if name not in (".git", "node_modules", "dist", "build")]
            for name in files:
                candidates.append(os.path.join(directory, name))
                if len(candidates) >= 20000: break
            if len(candidates) >= 20000: break
    else:
        candidates = [entry.path for entry in os.scandir(root) if entry.is_file(follow_symlinks=False)]
    needle = query.encode("utf-8")
    for path in candidates:
        if len(results) >= maximum: break
        visited += 1
        try:
            value = os.lstat(path)
            if not stat.S_ISREG(value.st_mode) or value.st_size > maximum_bytes: continue
            with open(path, "rb") as stream: content = stream.read(maximum_bytes + 1)
            if b"\x00" in content: continue
            for number, line in enumerate(content.decode("utf-8", errors="replace").splitlines(), 1):
                if query in line:
                    results.append({"path": path, "line": number, "text": line[:500]})
                    if len(results) >= maximum: break
        except (PermissionError, FileNotFoundError, OSError):
            continue
    return {"path": root, "query": query, "results": results, "visitedFiles": visited, "truncated": len(results) >= maximum}

def execute():
    op = req["op"]
    options = req.get("options") or {}
    path = expanded(req["path"]) if req.get("path") is not None else None
    destination = expanded(req["destination"]) if req.get("destination") is not None else None
    confined_root = req.get("confinedRoot")
    if confined_root is not None and path is not None: assert_confined(confined_root, path)
    if confined_root is not None and destination is not None: assert_confined(confined_root, destination)
    if op == "stat": return metadata(path)
    if op == "list":
        if not os.path.isdir(path): raise NotADirectoryError(path)
        offset = int(options.get("offset", 0)); limit = max(1, min(int(options.get("limit", 100)), 1000))
        entries = []
        for entry in sorted(os.scandir(path), key=lambda value: value.name):
            if entry.is_dir(follow_symlinks=False): entry_type = "directory"
            elif entry.is_file(follow_symlinks=False): entry_type = "file"
            elif entry.is_symlink(): entry_type = "symlink"
            else: entry_type = "other"
            entries.append({"name": entry.name, "type": entry_type})
        page = entries[offset:offset + limit]
        result = {"path": path, "entries": page, "totalEntries": len(entries), "offset": offset, "limit": limit}
        if offset + len(page) < len(entries): result["nextOffset"] = offset + len(page)
        return result
    if op == "read":
        value = os.lstat(path)
        if not stat.S_ISREG(value.st_mode): raise IsADirectoryError(path)
        offset = int(options.get("offset", 0)); maximum = max(1, min(int(options.get("maxBytes", 12000)), 1000000))
        with open(path, "rb") as stream:
            stream.seek(offset); content = stream.read(maximum)
        next_offset = offset + len(content) if offset + len(content) < value.st_size else None
        result = {"path": path, "contentBase64": base64.b64encode(content).decode("ascii"), "offset": offset, "bytesRead": len(content), "size": value.st_size, "truncated": next_offset is not None}
        if next_offset is not None: result["nextOffset"] = next_offset
        return result
    if op == "search": return search_files(path, req["query"], options)
    if op == "hash":
        value = os.lstat(path)
        if not stat.S_ISREG(value.st_mode): raise IsADirectoryError(path)
        return {"path": path, "algorithm": "sha256", "sha256": digest(path), "size": value.st_size}
    if op == "mkdir":
        recursive = bool(options.get("recursive", False)); mode = int(options.get("mode", 0o700))
        if recursive: os.makedirs(path, mode=mode, exist_ok=True)
        else: os.mkdir(path, mode=mode)
        return {"path": path, "created": True, "mode": stat.S_IMODE(os.stat(path).st_mode)}
    if op == "write_content":
        parent = require_parent(path, bool(options.get("createParents", False)))
        existing = verify_destination(path, options)
        content = base64.b64decode(req["contentBase64"], validate=True)
        mode = int(options.get("mode", stat.S_IMODE(existing.st_mode) if existing is not None else 0o600))
        descriptor, temporary = tempfile.mkstemp(prefix=".devspace-v2-", suffix=".tmp", dir=parent)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(content); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(parent, os.O_RDONLY)
            try: os.fsync(directory_fd)
            finally: os.close(directory_fd)
        finally:
            if descriptor >= 0: os.close(descriptor)
            try: os.unlink(temporary)
            except FileNotFoundError: pass
        value = os.stat(path)
        return {"path": path, "size": value.st_size, "mode": stat.S_IMODE(value.st_mode), "uid": value.st_uid, "gid": value.st_gid, "sha256": digest(path), "overwritten": existing is not None}
    if op == "prepare_write":
        require_parent(path, bool(options.get("createParents", False)))
        existing = verify_destination(path, options)
        return {"path": path, "existing": existing is not None, "mode": int(options.get("mode", stat.S_IMODE(existing.st_mode) if existing is not None else 0o600))}
    if op == "publish_write":
        temporary = expanded(req["temporary"])
        require_parent(path, False)
        existing = verify_destination(path, options)
        if not os.path.isfile(temporary): raise FileNotFoundError(temporary)
        mode = int(options.get("mode", stat.S_IMODE(existing.st_mode) if existing is not None else 0o600))
        os.chmod(temporary, mode)
        with open(temporary, "rb") as stream: os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(os.path.dirname(path), os.O_RDONLY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
        value = os.stat(path)
        return {"path": path, "size": value.st_size, "mode": stat.S_IMODE(value.st_mode), "sha256": digest(path), "overwritten": existing is not None}
    if op == "stage_export":
        return stage_export(path, req["temporary"])
    if op == "publish_staging":
        return publish_staging(req["temporary"], path, options)
    if op == "cleanup":
        temporary = expanded(req["temporary"])
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        return {"path": temporary, "removed": True}
    if op in ("copy", "sync"):
        os.lstat(path); require_parent(destination, bool(options.get("createParents", False)))
        existing = optional_lstat(destination)
        if existing is not None and not options.get("overwrite", False): raise RuntimeError("destination-exists")
        if existing is not None: remove_existing(destination)
        copy_item(path, destination)
        return {"source": path, "destination": destination, "copied": True, "overwritten": existing is not None, "synchronized": op == "sync"}
    if op == "move":
        os.lstat(path); require_parent(destination, bool(options.get("createParents", False)))
        existing = optional_lstat(destination)
        if existing is not None and not options.get("overwrite", False): raise RuntimeError("destination-exists")
        if existing is not None: remove_existing(destination)
        try: os.replace(path, destination)
        except OSError as error:
            if error.errno != errno.EXDEV or not options.get("allowCrossDevice", False): raise
            copy_item(path, destination); remove_existing(path)
        return {"source": path, "destination": destination, "moved": True}
    if op == "remove":
        if options.get("disposition") != "permanent": raise RuntimeError("unsupported-disposition")
        value = os.lstat(path)
        expected_hash = options.get("expectedSha256")
        if expected_hash is not None:
            if not stat.S_ISREG(value.st_mode) or digest(path).lower() != expected_hash.lower(): raise RuntimeError("sha256-precondition")
        if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode):
            if not options.get("recursive", False): raise RuntimeError("recursive-required")
            shutil.rmtree(path)
        else: os.unlink(path)
        return {"path": path, "removed": True, "disposition": "permanent"}
    raise RuntimeError("unsupported-operation")

try:
    print(MARKER + json.dumps({"ok": True, "data": execute()}, separators=(",", ":"), ensure_ascii=False))
except FileNotFoundError as error:
    print(MARKER + json.dumps({"ok": False, "code": "PATH_NOT_FOUND", "message": str(error)}, separators=(",", ":")))
except (NotADirectoryError, IsADirectoryError) as error:
    print(MARKER + json.dumps({"ok": False, "code": "PATH_TYPE_MISMATCH", "message": str(error)}, separators=(",", ":")))
except PermissionError as error:
    print(MARKER + json.dumps({"ok": False, "code": "PERMISSION_DENIED", "message": str(error)}, separators=(",", ":")))
except RuntimeError as error:
    code = "PRECONDITION_FAILED" if str(error) in ("destination-exists", "sha256-precondition") else "PRECONDITION_FAILED"
    print(MARKER + json.dumps({"ok": False, "code": code, "message": str(error)}, separators=(",", ":")))
except Exception as error:
    print(MARKER + json.dumps({"ok": False, "code": "TRANSPORT_INTERRUPTED", "message": type(error).__name__ + ": " + str(error)}, separators=(",", ":")))
`;
