import { UniversalBrokerError } from "./errors.js";

export const REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER = "__DEVSPACE_V2_FS_JSON__";

/** Build a self-contained PowerShell command for one framed Windows filesystem request. */
export function windowsFilesystemCommand(request: Record<string, unknown>): string {
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
  if ($Item.PSIsContainer) { return 'directory' }
  if (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return 'symlink' }
  return 'file'
}

function Metadata([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force
  return @{
    path = $item.FullName
    type = ItemType $item
    size = if ($item.PSIsContainer) { 0 } else { [int64]$item.Length }
    mode = $null
    mtimeMs = [DateTimeOffset]$item.LastWriteTimeUtc.ToUniversalTime().ToUnixTimeMilliseconds()
    birthtimeMs = [DateTimeOffset]$item.CreationTimeUtc.ToUniversalTime().ToUnixTimeMilliseconds()
  }
}

function Sha256([string]$Path) {
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Existing([string]$Path) {
  return Test-Path -LiteralPath $Path
}

function VerifyDestination([string]$Path, $Options) {
  $exists = Existing $Path
  if ($exists) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer) { throw 'destination-is-directory' }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'refuse-symlink-publication' }
    if (-not [bool]$Options.overwrite) { throw 'destination-exists' }
  }
  if ($null -ne $Options.expectedSha256) {
    if (-not $exists -or (Sha256 $Path) -ne ([string]$Options.expectedSha256).ToLowerInvariant()) {
      throw 'sha256-precondition'
    }
  }
  return $exists
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
  $existed = VerifyDestination $Path $Options
  $temporary = Join-Path $parent ('.devspace-v2-' + [Guid]::NewGuid().ToString('N') + '.tmp')
  try {
    [IO.File]::WriteAllBytes($temporary, $Bytes)
    if ($existed) { Remove-Item -LiteralPath $Path -Force }
    Move-Item -LiteralPath $temporary -Destination $Path -Force
  } finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue }
  }
  $meta = Metadata $Path
  $meta.sha256 = Sha256 $Path
  $meta.overwritten = $existed
  return $meta
}

try {
  $requestJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($RequestBase64))
  $request = $requestJson | ConvertFrom-Json
  $op = [string]$request.op
  $options = if ($null -eq $request.options) { [pscustomobject]@{} } else { $request.options }
  $path = if ($null -eq $request.path) { $null } else { FullPath ([string]$request.path) }
  $destination = if ($null -eq $request.destination) { $null } else { FullPath ([string]$request.destination) }
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
      $exists = VerifyDestination $path $options
      $data = @{ path = $path; existing = $exists }
      break
    }
    'publish_write' {
      $temporary = FullPath ([string]$request.temporary)
      [void](RequireParent $path $false)
      $exists = VerifyDestination $path $options
      if (-not (Test-Path -LiteralPath $temporary -PathType Leaf)) { throw 'temporary-not-file' }
      if ($exists) { Remove-Item -LiteralPath $path -Force }
      Move-Item -LiteralPath $temporary -Destination $path -Force
      $data = Metadata $path
      $data.sha256 = Sha256 $path
      $data.overwritten = $exists
      break
    }
    'cleanup' {
      $temporary = FullPath ([string]$request.temporary)
      Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
      $data = @{ path = $temporary; removed = $true }
      break
    }
    { $_ -in @('copy','sync') } {
      [void](RequireParent $destination ([bool]$options.createParents))
      $exists = Existing $destination
      if ($exists -and -not [bool]$options.overwrite) { throw 'destination-exists' }
      if ($exists) { Remove-Item -LiteralPath $destination -Force -Recurse }
      Copy-Item -LiteralPath $path -Destination $destination -Force -Recurse:([bool]$options.recursive)
      $data = @{ source = $path; destination = $destination; copied = $true; overwritten = $exists; synchronized = $op -eq 'sync' }
      break
    }
    'move' {
      [void](RequireParent $destination ([bool]$options.createParents))
      $exists = Existing $destination
      if ($exists -and -not [bool]$options.overwrite) { throw 'destination-exists' }
      if ($exists) { Remove-Item -LiteralPath $destination -Force -Recurse }
      Move-Item -LiteralPath $path -Destination $destination -Force
      $data = @{ source = $path; destination = $destination; moved = $true; overwritten = $exists }
      break
    }
    'remove' {
      if ([string]$options.disposition -ne 'permanent') { throw 'unsupported-disposition' }
      $item = Get-Item -LiteralPath $path -Force
      if ($item.PSIsContainer -and -not [bool]$options.recursive) { throw 'recursive-required' }
      Remove-Item -LiteralPath $path -Force -Recurse:([bool]$options.recursive)
      $data = @{ path = $path; removed = $true; disposition = 'permanent' }
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
    elseif ($message -match 'destination-exists|sha256-precondition|recursive-required|unsupported-disposition|parent-not-directory') { 'PRECONDITION_FAILED' }
    else { 'TRANSPORT_INTERRUPTED' }
  Reply $false $null $code $message
}
`;
  const encoded = Buffer.from(source, "utf16le").toString("base64");
  if (encoded.length > 90_000) {
    throw new UniversalBrokerError(
      "RESOURCE_QUOTA_EXCEEDED",
      "Windows filesystem helper command exceeds the safe SSH command budget.",
    );
  }
  return `powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ${encoded}`;
}
