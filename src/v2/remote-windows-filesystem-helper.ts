import { UniversalBrokerError } from "./errors.js";

export const REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER = "__DEVSPACE_V2_FS_JSON__";

/** Build a self-contained PowerShell script for one framed Windows filesystem request. */
export function windowsFilesystemScript(request: Record<string, unknown>): string {
  const requestBase64 = Buffer.from(JSON.stringify(request), "utf8").toString("base64");
  const source = String.raw`
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Marker = '${REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER}'
$RequestBase64 = '${requestBase64}'

function Reply([bool]$Ok, $Data, [string]$Code, [string]$Message) {
  $body = if ($Ok) {
    @{ ok = $true; data = $Data }
  } else {
    @{ ok = $false; code = $Code; message = $Message }
  }
  [Console]::Out.WriteLine($Marker + ($body | ConvertTo-Json -Compress -Depth 12))
}

function FullPath([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { throw 'path-required' }
  if ($Value -eq '~') { return [IO.Path]::GetFullPath($HOME) }
  if ($Value.StartsWith('~\') -or $Value.StartsWith('~/')) {
    return [IO.Path]::GetFullPath((Join-Path $HOME $Value.Substring(2)))
  }
  return [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Value))
}

function ItemType($Item) {
  if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return 'symlink' }
  if ($Item.PSIsContainer) { return 'directory' }
  return 'file'
}

function ResolveFinal([string]$Path, [string]$Behavior) {
  if (-not (Existing $Path)) { return $Path }
  $item = Get-Item -LiteralPath $Path -Force
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) { return $Path }
  if ($Behavior -eq 'follow') { return (Resolve-Path -LiteralPath $Path).ProviderPath }
  if ($Behavior -in @('preserve','replace')) { return $Path }
  throw 'refuse-final-symlink'
}

function Metadata([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force
  return @{
    path = $item.FullName
    type = ItemType $item
    size = if ($item.PSIsContainer) { 0 } else { [int64]$item.Length }
    mode = $null
    mtimeMs = ([DateTimeOffset]$item.LastWriteTimeUtc).ToUnixTimeMilliseconds()
    birthtimeMs = ([DateTimeOffset]$item.CreationTimeUtc).ToUnixTimeMilliseconds()
  }
}

function Sha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Existing([string]$Path) {
  return Test-Path -LiteralPath $Path
}

function Preimage([string]$Path) {
  if (-not (Existing $Path)) { return @{ exists = $false } }
  $item = Get-Item -LiteralPath $Path -Force
  $type = ItemType $item
  $result = @{
    exists = $true
    type = $type
    size = if ($item.PSIsContainer) { 0 } else { [int64]$item.Length }
    attributes = ([int64]$item.Attributes).ToString()
    creationTicks = ([int64]$item.CreationTimeUtc.Ticks).ToString()
    writeTicks = ([int64]$item.LastWriteTimeUtc.Ticks).ToString()
  }
  if ($type -eq 'file') { $result.sha256 = Sha256 $Path }
  if ($type -eq 'symlink') { $result.linkTarget = [string]$item.Target }
  return $result
}

function AssertPreimage([string]$Path, $Expected) {
  $expectedJson = $Expected | ConvertTo-Json -Compress -Depth 8
  $actualJson = (Preimage $Path) | ConvertTo-Json -Compress -Depth 8
  if ($expectedJson -ne $actualJson) { throw 'destination-preimage-changed' }
}

function VerifyDestination([string]$Path, $Options) {
  $exists = Existing $Path
  if ($exists) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { throw 'destination-is-directory' }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -and [string]$Options.finalSymlink -ne 'replace') { throw 'refuse-symlink-publication' }
    if (-not [bool]$Options.overwrite) { throw 'destination-exists' }
  }
  if ($null -ne $Options.expectedSha256) {
    if (-not $exists -or (Sha256 $Path) -ne ([string]$Options.expectedSha256).ToLowerInvariant()) {
      throw 'sha256-precondition'
    }
  }
  return $exists
}

function FlushFile([string]$Path) {
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
  try { $stream.Flush($true) } finally { $stream.Dispose() }
}

function PublishTemporary([string]$Path, [string]$Temporary, $Options, $ExpectedPreimage, $ExpectedContent) {
  [void](RequireParent $Path $false)
  $existed = VerifyDestination $Path $Options
  AssertPreimage $Path $ExpectedPreimage
  if (-not (Test-Path -LiteralPath $Temporary -PathType Leaf)) { throw 'temporary-not-file' }
  $staged = Get-Item -LiteralPath $Temporary -Force
  $stagedHash = Sha256 $Temporary
  if ($null -ne $ExpectedContent) {
    if ([int64]$ExpectedContent.size -ne [int64]$staged.Length -or ([string]$ExpectedContent.sha256).ToLowerInvariant() -ne $stagedHash) {
      throw 'staged-content-mismatch'
    }
  }
  FlushFile $Temporary
  if ($existed) {
    [IO.File]::Replace($Temporary, $Path, $null, $true)
  } else {
    [IO.File]::Move($Temporary, $Path)
  }
  $published = Get-Item -LiteralPath $Path -Force
  $publishedHash = Sha256 $Path
  if ([int64]$published.Length -ne [int64]$staged.Length -or $publishedHash -ne $stagedHash) { throw 'post-readback-mismatch' }
  $meta = Metadata $Path
  $meta.sha256 = $publishedHash
  $meta.overwritten = $existed
  return $meta
}

function RequireParent([string]$Path, [bool]$Create) {
  $parent = Split-Path -Parent $Path
  if ($Create -and -not (Test-Path -LiteralPath $parent)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
  }
  if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'parent-not-directory' }
  return $parent
}

function AtomicBytes([string]$Path, [byte[]]$Bytes, $Options) {
  $parent = RequireParent $Path ([bool]$Options.createParents)
  $expected = Preimage $Path
  [void](VerifyDestination $Path $Options)
  $temporary = Join-Path $parent ('.devspace-v2-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllBytes($temporary, $Bytes)
    FlushFile $temporary
    return PublishTemporary $Path $temporary $Options $expected @{ size = [int64]$Bytes.Length; sha256 = Sha256 $temporary }
  } finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
  }
}

function CopyFileAtomic([string]$Source, [string]$Destination, $Options) {
  $sourceBefore = Preimage $Source
  if ([string]$sourceBefore.type -ne 'file') { throw 'not-file' }
  $destinationBefore = Preimage $Destination
  [void](VerifyDestination $Destination $Options)
  $parent = RequireParent $Destination ([bool]$Options.createParents)
  $temporary = Join-Path $parent ('.devspace-v2-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::Copy($Source, $temporary, $false)
    FlushFile $temporary
    $sourceAfter = Preimage $Source
    if (($sourceBefore | ConvertTo-Json -Compress -Depth 8) -ne ($sourceAfter | ConvertTo-Json -Compress -Depth 8)) { throw 'source-preimage-changed' }
    return PublishTemporary $Destination $temporary $Options $destinationBefore @{ size = [int64]$sourceBefore.size; sha256 = [string]$sourceBefore.sha256 }
  } finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
  }
}

function MoveFileSafe([string]$Source, [string]$Destination, $Options) {
  $sourceBefore = Preimage $Source
  if ([string]$sourceBefore.type -ne 'file') { throw 'not-file' }
  $destinationBefore = Preimage $Destination
  $existed = VerifyDestination $Destination $Options
  AssertPreimage $Destination $destinationBefore
  try {
    if ($existed) { [IO.File]::Replace($Source, $Destination, $null, $true) }
    else { [IO.File]::Move($Source, $Destination) }
    $result = Metadata $Destination
    $result.sha256 = Sha256 $Destination
    $result.moved = $true
    $result.crossDevice = $false
    return $result
  } catch [IO.IOException] {
    $published = CopyFileAtomic $Source $Destination $Options
    $sourceAfter = Preimage $Source
    if (($sourceBefore | ConvertTo-Json -Compress -Depth 8) -ne ($sourceAfter | ConvertTo-Json -Compress -Depth 8) -or [string]$published.sha256 -ne [string]$sourceBefore.sha256) {
      throw 'cross-device-verification-failed'
    }
    [IO.File]::Delete($Source)
    $published.moved = $true
    $published.crossDevice = $true
    return $published
  }
}

function TrashRoot() { return Join-Path $HOME '.devspace\trash' }

function WriteJsonSync([string]$Path, $Value) {
  $json = ($Value | ConvertTo-Json -Compress -Depth 12) + [Environment]::NewLine
  $bytes = [Text.Encoding]::UTF8.GetBytes($json)
  $stream = [IO.File]::Open($Path, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
  try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
}

function TrashItem([string]$Path, $Options) {
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.PSIsContainer -and -not [bool]$Options.recursive) { throw 'recursive-required' }
  $root = TrashRoot
  [IO.Directory]::CreateDirectory($root) | Out-Null
  $trashId = [Guid]::NewGuid().ToString('D')
  $entry = Join-Path $root $trashId
  [IO.Directory]::CreateDirectory($entry) | Out-Null
  $payload = Join-Path $entry 'payload'
  $metadata = @{ version = 1; trashId = $trashId; originalPath = $Path; type = ItemType $item; state = 'RESERVED' }
  if (-not $item.PSIsContainer) { $metadata.sha256 = Sha256 $Path }
  WriteJsonSync (Join-Path $entry 'metadata.json') $metadata
  if ($item.PSIsContainer) { [IO.Directory]::Move($Path, $payload) }
  else { [void](MoveFileSafe $Path $payload ([pscustomobject]@{ overwrite = $false; createParents = $false; finalSymlink = 'replace' })) }
  $metadata.state = 'AVAILABLE'
  WriteJsonSync (Join-Path $entry 'metadata.json') $metadata
  return @{ path = $Path; removed = $true; disposition = 'trash'; recoverable = $true; trashId = $trashId; restoreOperation = 'restore' }
}

function RestoreItem([string]$TrashId, [string]$Destination, $Options) {
  if ($TrashId -notmatch '^[0-9a-fA-F-]{36}$') { throw 'invalid-trash-id' }
  $entry = Join-Path (TrashRoot) $TrashId
  $metadata = Get-Content -LiteralPath (Join-Path $entry 'metadata.json') -Raw | ConvertFrom-Json
  if ([string]$metadata.state -ne 'AVAILABLE' -or [string]$metadata.trashId -ne $TrashId) { throw 'trash-not-available' }
  if ([string]::IsNullOrWhiteSpace($Destination)) { $Destination = [string]$metadata.originalPath }
  $payload = Join-Path $entry 'payload'
  if ([string]$metadata.type -eq 'directory') {
    if (Existing $Destination) { throw 'destination-exists' }
    [IO.Directory]::Move($payload, $Destination)
  } else {
    [void](MoveFileSafe $payload $Destination ([pscustomobject]@{ overwrite = [bool]$Options.overwrite; createParents = $true; finalSymlink = 'replace' }))
  }
  Remove-Item -LiteralPath $entry -Force -Recurse
  return @{ trashId = $TrashId; restored = $true; originalPath = [string]$metadata.originalPath; path = $Destination }
}

try {
  $requestJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($RequestBase64))
  $request = $requestJson | ConvertFrom-Json
  $op = [string]$request.op
  $options = if ($null -eq $request.options) { [pscustomobject]@{} } else { $request.options }
  $path = if ($null -eq $request.path) { $null } else { FullPath ([string]$request.path) }
  $destination = if ($null -eq $request.destination) { $null } else { FullPath ([string]$request.destination) }
  if ($null -ne $path) {
    $defaultFinal = if ($op -in @('stat','remove')) { 'preserve' } elseif ($op -in @('read','search','hash')) { 'follow' } else { 'reject' }
    $behavior = if ([string]::IsNullOrWhiteSpace([string]$options.finalSymlink)) { $defaultFinal } else { [string]$options.finalSymlink }
    $path = ResolveFinal $path $behavior
  }
  if ($null -ne $destination) {
    $destinationBehavior = if ([string]::IsNullOrWhiteSpace([string]$options.finalSymlink)) { 'reject' } else { [string]$options.finalSymlink }
    $destination = ResolveFinal $destination $destinationBehavior
  }
  $data = $null

  switch ($op) {
    'stat' { $data = Metadata $path; break }
    'list' {
      if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw 'not-directory' }
      $offset = [Math]::Max(0, [int]$options.offset)
      $limit = [Math]::Min(1000, [Math]::Max(1, [int]$options.limit))
      $all = @(Get-ChildItem -LiteralPath $path -Force | Sort-Object Name)
      $page = @($all | Select-Object -Skip $offset -First $limit | ForEach-Object {
        @{ name = $_.Name; type = ItemType $_ }
      })
      $data = @{ path = $path; entries = $page; totalEntries = $all.Count; offset = $offset; limit = $limit }
      if ($offset + $page.Count -lt $all.Count) { $data.nextOffset = $offset + $page.Count }
      break
    }
    'read' {
      $item = Get-Item -LiteralPath $path -Force
      if ($item.PSIsContainer) { throw 'not-file' }
      $offset = [Math]::Max(0, [int64]$options.offset)
      $maximum = [Math]::Min(1000000, [Math]::Max(1, [int]$options.maxBytes))
      $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
      try {
        [void]$stream.Seek($offset, [IO.SeekOrigin]::Begin)
        $buffer = New-Object byte[] $maximum
        $count = $stream.Read($buffer, 0, $buffer.Length)
        $selected = if ($count -eq $buffer.Length) { $buffer } else { $buffer[0..([Math]::Max(0,$count-1))] }
        if ($count -eq 0) { $selected = [byte[]]@() }
      } finally { $stream.Dispose() }
      $next = $offset + $count
      $data = @{
        path = $path
        contentBase64 = [Convert]::ToBase64String($selected)
        offset = $offset
        bytesRead = $count
        size = [int64]$item.Length
        truncated = $next -lt [int64]$item.Length
      }
      if ($next -lt [int64]$item.Length) { $data.nextOffset = $next }
      break
    }
    'search' {
      $limit = [Math]::Min(500, [Math]::Max(1, [int]$options.limit))
      $recursive = [bool]$options.recursive
      $maximumBytes = [Math]::Min(2097152, [Math]::Max(1, [int64]$options.maxFileBytes))
      $items = if (Test-Path -LiteralPath $path -PathType Leaf) {
        @(Get-Item -LiteralPath $path -Force)
      } else {
        @(Get-ChildItem -LiteralPath $path -File -Force -Recurse:$recursive -ErrorAction SilentlyContinue | Select-Object -First 20000)
      }
      $results = [Collections.Generic.List[object]]::new()
      $visited = 0
      foreach ($item in $items) {
        if ($results.Count -ge $limit) { break }
        if ($item.Length -gt $maximumBytes) { continue }
        $visited++
        $number = 0
        foreach ($line in [IO.File]::ReadLines($item.FullName)) {
          $number++
          if ($line.Contains([string]$request.query)) {
            $results.Add(@{ path = $item.FullName; line = $number; text = $line.Substring(0, [Math]::Min(500,$line.Length)) })
            if ($results.Count -ge $limit) { break }
          }
        }
      }
      $data = @{ path = $path; query = [string]$request.query; results = @($results); visitedFiles = $visited; truncated = $results.Count -ge $limit }
      break
    }
    'hash' {
      $item = Get-Item -LiteralPath $path -Force
      if ($item.PSIsContainer) { throw 'not-file' }
      $data = @{ path = $path; algorithm = 'sha256'; sha256 = Sha256 $path; size = [int64]$item.Length }
      break
    }
    'mkdir' {
      if ([bool]$options.recursive) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
      else { New-Item -ItemType Directory -Path $path | Out-Null }
      $data = @{ path = $path; created = $true }
      break
    }
    'write_content' {
      $bytes = [Convert]::FromBase64String([string]$request.contentBase64)
      $data = AtomicBytes $path $bytes $options
      break
    }
    'prepare_write' {
      [void](RequireParent $path ([bool]$options.createParents))
      [void](VerifyDestination $path $options)
      $data = @{ path = $path; preimage = Preimage $path }
      break
    }
    'publish_write' {
      $temporary = FullPath ([string]$request.temporary)
      $data = PublishTemporary $path $temporary $options $request.preimage $request.expectedContent
      break
    }
    'cleanup' {
      $temporary = FullPath ([string]$request.temporary)
      Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
      $data = @{ path = $temporary; removed = $true }
      break
    }
    { $_ -in @('copy','sync') } {
      $sourceItem = Get-Item -LiteralPath $path -Force
      if ($sourceItem.PSIsContainer) {
        if (-not [bool]$options.recursive) { throw 'recursive-required' }
        if (Existing $destination) {
          if (-not [bool]$options.overwrite) { throw 'destination-exists' }
          throw 'atomic-directory-overwrite-unavailable'
        }
        $parent = RequireParent $destination ([bool]$options.createParents)
        $temporary = Join-Path $parent ('.devspace-v2-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        try {
          Copy-Item -LiteralPath $path -Destination $temporary -Recurse
          if (Existing $destination) { throw 'destination-preimage-changed' }
          [IO.Directory]::Move($temporary, $destination)
          $data = @{ source = $path; destination = $destination; copied = $true; overwritten = $false; synchronized = $op -eq 'sync' }
        } finally {
          if (Existing $temporary) { Remove-Item -LiteralPath $temporary -Force -Recurse -ErrorAction SilentlyContinue }
        }
      } else {
        $published = CopyFileAtomic $path $destination $options
        $data = @{ source = $path; destination = $destination; copied = $true; overwritten = [bool]$published.overwritten; synchronized = $op -eq 'sync'; size = [int64]$published.size; sha256 = [string]$published.sha256 }
      }
      break
    }
    'move' {
      $sourceItem = Get-Item -LiteralPath $path -Force
      if ($sourceItem.PSIsContainer) {
        if (Existing $destination) { throw 'atomic-directory-overwrite-unavailable' }
        [IO.Directory]::Move($path, $destination)
        $data = @{ source = $path; destination = $destination; moved = $true; overwritten = $false; crossDevice = $false }
      } else {
        $published = MoveFileSafe $path $destination $options
        $data = @{ source = $path; destination = $destination; moved = $true; overwritten = [bool]$published.overwritten; crossDevice = [bool]$published.crossDevice; size = [int64]$published.size; sha256 = [string]$published.sha256 }
      }
      break
    }
    'remove' {
      if ([string]::IsNullOrWhiteSpace([string]$options.disposition) -or [string]$options.disposition -eq 'trash') {
        $data = TrashItem $path $options
      } else {
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -and -not [bool]$options.recursive) { throw 'recursive-required' }
        Remove-Item -LiteralPath $path -Force -Recurse:([bool]$options.recursive)
        if (Existing $path) { throw 'post-readback-mismatch' }
        $data = @{ path = $path; removed = $true; disposition = 'permanent' }
      }
      break
    }
    'restore' {
      $data = RestoreItem ([string]$request.trashId) $path $options
      break
    }
    default { throw 'unsupported-operation' }
  }
  Reply $true $data $null $null
} catch {
  $message = [string]$_.Exception.Message
  $code = if ($message -match 'Cannot find path|does not exist|not found') { 'PATH_NOT_FOUND' }
    elseif ($message -match 'Access.*denied|Unauthorized|refuse-symlink') { 'PERMISSION_DENIED' }
    elseif ($message -match 'not-directory|not-file|is-directory') { 'PATH_TYPE_MISMATCH' }
    elseif ($message -match 'destination-exists|sha256-precondition|recursive-required|unsupported-disposition|parent-not-directory|preimage|readback|staged-content|cross-device|atomic-directory|trash') { 'PRECONDITION_FAILED' }
    else { 'TRANSPORT_INTERRUPTED' }
  Reply $false $null $code $message
}
`;
  return source;
}

/** Build an encoded command for small callers and contract tests. */
export function windowsFilesystemCommand(request: Record<string, unknown>): string {
  const encoded = Buffer.from(windowsFilesystemScript(request), "utf16le").toString("base64");
  if (encoded.length > 90_000) {
    throw new UniversalBrokerError(
      "RESOURCE_QUOTA_EXCEEDED",
      "Windows filesystem helper command exceeds the safe SSH command budget.",
    );
  }
  return `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`;
}
