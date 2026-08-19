export const REMOTE_FILESYSTEM_RESULT_MARKER = "__DEVSPACE_V2_FS_JSON__";

/** POSIX SSH helper with staged, preimage-fenced, verified publication. */
export const REMOTE_FILESYSTEM_HELPER_SOURCE = String.raw`
import base64, errno, hashlib, json, os, shutil, stat, sys, tempfile, uuid

MARKER = "__DEVSPACE_V2_FS_JSON__"
req = json.loads(base64.b64decode(sys.argv[1]).decode("utf-8"))

def expanded(value):
    return os.path.abspath(os.path.expanduser(value))

def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""): value.update(chunk)
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

def optional_lstat(path):
    try: return os.lstat(path)
    except FileNotFoundError: return None

def metadata(path):
    value = os.lstat(path)
    result = {"path": path, "type": kind(value.st_mode), "size": value.st_size,
        "mode": stat.S_IMODE(value.st_mode), "mtimeMs": value.st_mtime_ns / 1000000,
        "birthtimeMs": getattr(value, "st_birthtime", value.st_ctime) * 1000,
        "uid": value.st_uid, "gid": value.st_gid, "canonicalPath": os.path.realpath(path)}
    if stat.S_ISLNK(value.st_mode): result["linkTarget"] = os.readlink(path)
    return result

def preimage(path):
    value = optional_lstat(path)
    if value is None: return {"exists": False}
    item_type = kind(value.st_mode)
    result = {"exists": True, "type": item_type, "device": str(value.st_dev),
        "inode": str(value.st_ino), "mode": stat.S_IMODE(value.st_mode), "size": value.st_size,
        "mtimeNs": str(value.st_mtime_ns), "ctimeNs": str(value.st_ctime_ns)}
    if item_type == "file": result["sha256"] = digest(path)
    if item_type == "symlink": result["linkTarget"] = os.readlink(path)
    return result

def assert_preimage(path, expected):
    if preimage(path) != expected: raise RuntimeError("destination-preimage-changed")

def assert_confined(root, candidate):
    root = os.path.realpath(expanded(root))
    if not os.path.isdir(root): raise NotADirectoryError(root)
    probe = candidate; suffix = []
    while not os.path.lexists(probe):
        parent = os.path.dirname(probe)
        if parent == probe: raise FileNotFoundError(candidate)
        suffix.insert(0, os.path.basename(probe)); probe = parent
    resolved = os.path.realpath(probe)
    if suffix: resolved = os.path.join(resolved, *suffix)
    try: common = os.path.commonpath((root, resolved))
    except ValueError: raise PermissionError("path-outside-confined-root")
    if common != root: raise PermissionError("path-outside-confined-root")

def require_parent(path, create):
    parent = os.path.dirname(path)
    if create: os.makedirs(parent, mode=0o700, exist_ok=True)
    if not os.path.isdir(parent): raise NotADirectoryError(parent)
    return parent

def resolve_final(path, behavior):
    if os.path.islink(path):
        if behavior == "follow": return os.path.realpath(path)
        if behavior in ("preserve", "replace"): return path
        raise PermissionError("refuse-final-symlink")
    return path

def verify_destination(path, options):
    existing = optional_lstat(path)
    if existing is not None and stat.S_ISLNK(existing.st_mode) and options.get("finalSymlink") != "replace":
        raise PermissionError("refuse-symlink-publication")
    if existing is not None and not (stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)):
        raise IsADirectoryError(path)
    if existing is not None and not options.get("overwrite", False): raise RuntimeError("destination-exists")
    expected_hash = options.get("expectedSha256")
    if expected_hash is not None:
        if existing is None or not stat.S_ISREG(existing.st_mode) or digest(path).lower() != expected_hash.lower():
            raise RuntimeError("sha256-precondition")
    return existing

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)

def publish_temporary(temporary, path, options, expected_preimage, expected_content=None):
    parent = require_parent(path, False); existing = verify_destination(path, options)
    assert_preimage(path, expected_preimage)
    staged = os.lstat(temporary)
    if not stat.S_ISREG(staged.st_mode) or stat.S_ISLNK(staged.st_mode): raise IsADirectoryError(temporary)
    staged_size = staged.st_size; staged_hash = digest(temporary)
    if expected_content is not None:
        if int(expected_content.get("size", -1)) != staged_size or str(expected_content.get("sha256", "")).lower() != staged_hash:
            raise RuntimeError("staged-content-mismatch")
    mode = int(options.get("mode", stat.S_IMODE(existing.st_mode) if existing is not None and stat.S_ISREG(existing.st_mode) else 0o600))
    os.chmod(temporary, mode)
    with open(temporary, "rb") as stream: os.fsync(stream.fileno())
    if expected_preimage.get("exists", False): os.replace(temporary, path)
    else: os.link(temporary, path); os.unlink(temporary)
    fsync_directory(parent)
    value = os.lstat(path); actual_hash = digest(path)
    if not stat.S_ISREG(value.st_mode) or value.st_size != staged_size or actual_hash != staged_hash:
        raise RuntimeError("post-readback-mismatch")
    return {"path": path, "size": value.st_size, "mode": stat.S_IMODE(value.st_mode),
        "uid": value.st_uid, "gid": value.st_gid, "sha256": actual_hash,
        "overwritten": bool(expected_preimage.get("exists", False))}

def stage_bytes(path, content, options):
    parent = require_parent(path, bool(options.get("createParents", False)))
    expected = preimage(path); verify_destination(path, options)
    descriptor, temporary = tempfile.mkstemp(prefix=".devspace-v2-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1; stream.write(content); stream.flush(); os.fsync(stream.fileno())
        return publish_temporary(temporary, path, options, expected,
            {"size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    finally:
        if descriptor >= 0: os.close(descriptor)
        try: os.unlink(temporary)
        except FileNotFoundError: pass

def copy_regular_atomic(source, destination, options):
    source_before = preimage(source)
    if source_before.get("type") != "file": raise IsADirectoryError(source)
    parent = require_parent(destination, bool(options.get("createParents", False)))
    destination_before = preimage(destination); verify_destination(destination, options)
    descriptor, temporary = tempfile.mkstemp(prefix=".devspace-v2-", suffix=".tmp", dir=parent)
    try:
        with open(source, "rb") as incoming, os.fdopen(descriptor, "wb", closefd=True) as outgoing:
            descriptor = -1; shutil.copyfileobj(incoming, outgoing, 1024 * 1024)
            outgoing.flush(); os.fsync(outgoing.fileno())
        if preimage(source) != source_before or digest(temporary) != source_before["sha256"]:
            raise RuntimeError("source-preimage-changed")
        return publish_temporary(temporary, destination, options, destination_before,
            {"size": source_before["size"], "sha256": source_before["sha256"]})
    finally:
        if descriptor >= 0: os.close(descriptor)
        try: os.unlink(temporary)
        except FileNotFoundError: pass

def tree_digest(root):
    value = hashlib.sha256()
    for directory, names, files in os.walk(root, followlinks=False):
        names.sort(); files.sort(); relative_directory = os.path.relpath(directory, root)
        for name in list(names):
            path = os.path.join(directory, name); relative = os.path.normpath(os.path.join(relative_directory, name))
            if os.path.islink(path): value.update(("l\\0" + relative + "\\0" + os.readlink(path) + "\\0").encode()); names.remove(name)
            else: value.update(("d\\0" + relative + "\\0").encode())
        for name in files:
            path = os.path.join(directory, name); relative = os.path.normpath(os.path.join(relative_directory, name))
            if os.path.islink(path): value.update(("l\\0" + relative + "\\0" + os.readlink(path) + "\\0").encode())
            else: value.update(("f\\0" + relative + "\\0" + digest(path) + "\\0").encode())
    return value.hexdigest()

def copy_item_atomic(source, destination, options):
    source_value = os.lstat(source)
    if stat.S_ISREG(source_value.st_mode):
        result = copy_regular_atomic(source, destination, options); return result["sha256"], result
    if not stat.S_ISDIR(source_value.st_mode) or stat.S_ISLNK(source_value.st_mode): raise RuntimeError("unsupported-copy-type")
    if not options.get("recursive", False): raise RuntimeError("recursive-required")
    if optional_lstat(destination) is not None:
        if not options.get("overwrite", False): raise RuntimeError("destination-exists")
        raise RuntimeError("atomic-directory-overwrite-unavailable")
    parent = require_parent(destination, bool(options.get("createParents", False)))
    temporary = tempfile.mkdtemp(prefix=".devspace-v2-", suffix=".tmp", dir=parent); os.rmdir(temporary)
    try:
        before = tree_digest(source); shutil.copytree(source, temporary, symlinks=True, copy_function=shutil.copy2)
        after = tree_digest(source); copied = tree_digest(temporary)
        if before != after or before != copied: raise RuntimeError("source-preimage-changed")
        if optional_lstat(destination) is not None: raise RuntimeError("destination-preimage-changed")
        os.rename(temporary, destination); fsync_directory(parent)
        return copied, {"source": source, "destination": destination, "sha256": copied}
    finally:
        if os.path.lexists(temporary): shutil.rmtree(temporary)

def safe_move(source, destination, options):
    source_before = preimage(source)
    if not source_before.get("exists"): raise FileNotFoundError(source)
    destination_before = preimage(destination); existing = optional_lstat(destination)
    if existing is not None and not options.get("overwrite", False): raise RuntimeError("destination-exists")
    if existing is not None and stat.S_ISLNK(existing.st_mode) and options.get("finalSymlink") != "replace": raise PermissionError("refuse-symlink-publication")
    if source_before.get("type") == "file":
        try:
            assert_preimage(destination, destination_before)
            if destination_before.get("exists"): os.replace(source, destination)
            else: os.link(source, destination); os.unlink(source)
            fsync_directory(os.path.dirname(destination))
            result = metadata(destination); result.update({"moved": True, "crossDevice": False, "sha256": digest(destination)}); return result
        except OSError as error:
            if error.errno != errno.EXDEV or not options.get("allowCrossDevice", True): raise
        copied = copy_regular_atomic(source, destination, options)
        if preimage(source) != source_before or copied["sha256"] != source_before["sha256"]: raise RuntimeError("cross-device-verification-failed")
        os.unlink(source); fsync_directory(os.path.dirname(source)); copied.update({"moved": True, "crossDevice": True}); return copied
    if destination_before.get("exists"): raise RuntimeError("atomic-directory-overwrite-unavailable")
    try:
        os.rename(source, destination); return {"source": source, "destination": destination, "moved": True, "crossDevice": False}
    except OSError as error:
        if error.errno != errno.EXDEV or not options.get("allowCrossDevice", True): raise
    copied_digest, _ = copy_item_atomic(source, destination, dict(options, recursive=True))
    if tree_digest(source) != copied_digest or tree_digest(destination) != copied_digest: raise RuntimeError("cross-device-verification-failed")
    shutil.rmtree(source); return {"source": source, "destination": destination, "moved": True, "crossDevice": True, "sha256": copied_digest}

def trash_root(): return expanded("~/.devspace/trash")

def write_json_sync(path, data):
    parent = os.path.dirname(path); descriptor, temporary = tempfile.mkstemp(prefix=".metadata-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as stream:
            descriptor = -1; json.dump(data, stream, separators=(",", ":")); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path); fsync_directory(parent)
    finally:
        if descriptor >= 0: os.close(descriptor)
        try: os.unlink(temporary)
        except FileNotFoundError: pass

def trash_item(path, options):
    value = os.lstat(path)
    if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode) and not options.get("recursive", False): raise RuntimeError("recursive-required")
    root = trash_root(); os.makedirs(root, mode=0o700, exist_ok=True)
    trash_id = str(uuid.uuid4()); entry = os.path.join(root, trash_id); os.mkdir(entry, 0o700); payload = os.path.join(entry, "payload")
    item_type = kind(value.st_mode)
    expected = digest(path) if item_type == "file" else tree_digest(path) if item_type == "directory" else hashlib.sha256(("symlink\\0" + os.readlink(path)).encode()).hexdigest()
    item = {"version": 1, "trashId": trash_id, "originalPath": path, "type": item_type, "sha256": expected, "state": "RESERVED"}
    write_json_sync(os.path.join(entry, "metadata.json"), item)
    safe_move(path, payload, {"overwrite": False, "recursive": True, "allowCrossDevice": True, "finalSymlink": "replace"})
    item["state"] = "AVAILABLE"; write_json_sync(os.path.join(entry, "metadata.json"), item)
    return {"path": path, "removed": True, "disposition": "trash", "recoverable": True, "trashId": trash_id, "restoreOperation": "restore"}

def restore_item(trash_id, destination, options):
    if not trash_id or any(character not in "0123456789abcdef-" for character in trash_id.lower()): raise RuntimeError("invalid-trash-id")
    entry = os.path.join(trash_root(), trash_id)
    with open(os.path.join(entry, "metadata.json"), "r", encoding="utf-8") as stream: item = json.load(stream)
    if item.get("state") != "AVAILABLE" or item.get("trashId") != trash_id: raise RuntimeError("trash-not-available")
    destination = destination or item["originalPath"]
    result = safe_move(os.path.join(entry, "payload"), destination, {"overwrite": bool(options.get("overwrite", False)), "recursive": True, "allowCrossDevice": True, "finalSymlink": "replace"})
    shutil.rmtree(entry); result.update({"trashId": trash_id, "restored": True, "originalPath": item["originalPath"], "path": destination}); return result

def search_files(root, query, options):
    maximum = max(1, min(int(options.get("limit", 50)), 500)); maximum_bytes = int(options.get("maxFileBytes", 2 * 1024 * 1024))
    recursive = bool(options.get("recursive", True)); results = []; visited = 0; candidates = []
    if os.path.isfile(root): candidates = [root]
    elif not os.path.isdir(root): raise NotADirectoryError(root)
    elif recursive:
        for directory, names, files in os.walk(root):
            names[:] = [name for name in names if name not in (".git", "node_modules", "dist", "build")]
            for name in files:
                candidates.append(os.path.join(directory, name))
                if len(candidates) >= 20000: break
            if len(candidates) >= 20000: break
    else: candidates = [entry.path for entry in os.scandir(root) if entry.is_file(follow_symlinks=False)]
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
        except (PermissionError, FileNotFoundError, OSError): continue
    return {"path": root, "query": query, "results": results, "visitedFiles": visited, "truncated": len(results) >= maximum}

def execute():
    op = req["op"]; options = req.get("options") or {}
    path = expanded(req["path"]) if req.get("path") is not None else None
    destination = expanded(req["destination"]) if req.get("destination") is not None else None
    confined_root = req.get("confinedRoot")
    if confined_root is not None and path is not None: assert_confined(confined_root, path)
    if confined_root is not None and destination is not None: assert_confined(confined_root, destination)
    if path is not None: path = resolve_final(path, options.get("finalSymlink", "preserve" if op in ("stat", "remove") else "follow" if op in ("read", "search", "hash") else "reject"))
    if destination is not None: destination = resolve_final(destination, options.get("finalSymlink", "reject"))
    if op == "stat": return metadata(path)
    if op == "list":
        if not os.path.isdir(path): raise NotADirectoryError(path)
        offset = int(options.get("offset", 0)); limit = max(1, min(int(options.get("limit", 100)), 1000)); entries = []
        for entry in sorted(os.scandir(path), key=lambda value: value.name):
            entry_type = "directory" if entry.is_dir(follow_symlinks=False) else "file" if entry.is_file(follow_symlinks=False) else "symlink" if entry.is_symlink() else "other"
            entries.append({"name": entry.name, "type": entry_type})
        page = entries[offset:offset + limit]; result = {"path": path, "entries": page, "totalEntries": len(entries), "offset": offset, "limit": limit}
        if offset + len(page) < len(entries): result["nextOffset"] = offset + len(page)
        return result
    if op == "read":
        value = os.lstat(path)
        if not stat.S_ISREG(value.st_mode): raise IsADirectoryError(path)
        offset = int(options.get("offset", 0)); maximum = max(1, min(int(options.get("maxBytes", 12000)), 1000000))
        with open(path, "rb") as stream: stream.seek(offset); content = stream.read(maximum)
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
        if bool(options.get("recursive", False)): os.makedirs(path, mode=0o700, exist_ok=True)
        else: os.mkdir(path, mode=0o700)
        return {"path": path, "created": True, "mode": stat.S_IMODE(os.stat(path).st_mode)}
    if op == "write_content": return stage_bytes(path, base64.b64decode(req["contentBase64"], validate=True), options)
    if op == "prepare_write": require_parent(path, bool(options.get("createParents", False))); verify_destination(path, options); return {"path": path, "preimage": preimage(path)}
    if op == "publish_write": return publish_temporary(expanded(req["temporary"]), path, options, req.get("preimage") or {"exists": False}, req.get("expectedContent"))
    if op == "cleanup":
        temporary = expanded(req["temporary"])
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        return {"path": temporary, "removed": True}
    if op in ("copy", "sync"):
        _, result = copy_item_atomic(path, destination, options); result.update({"source": path, "destination": destination, "copied": True, "synchronized": op == "sync"}); return result
    if op == "move": result = safe_move(path, destination, options); result.update({"source": path, "destination": destination, "moved": True}); return result
    if op == "remove":
        if options.get("disposition", "trash") == "trash": return trash_item(path, options)
        value = os.lstat(path)
        if stat.S_ISDIR(value.st_mode) and not stat.S_ISLNK(value.st_mode):
            if not options.get("recursive", False): raise RuntimeError("recursive-required")
            shutil.rmtree(path)
        else: os.unlink(path)
        if os.path.lexists(path): raise RuntimeError("post-readback-mismatch")
        return {"path": path, "removed": True, "disposition": "permanent"}
    if op == "restore": return restore_item(str(req.get("trashId", "")), path, options)
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
    print(MARKER + json.dumps({"ok": False, "code": "PRECONDITION_FAILED", "message": str(error)}, separators=(",", ":")))
except Exception as error:
    print(MARKER + json.dumps({"ok": False, "code": "TRANSPORT_INTERRUPTED", "message": type(error).__name__ + ": " + str(error)}, separators=(",", ":")))
`;
