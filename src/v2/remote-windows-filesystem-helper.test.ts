import assert from "node:assert/strict";
import test from "node:test";
import {
  REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER,
  windowsFilesystemCommand,
} from "./remote-windows-filesystem-helper.js";

test("Windows filesystem helper is one bounded encoded PowerShell command", () => {
  const command = windowsFilesystemCommand({
    op: "write_content",
    path: "C:\\Temp\\file.txt",
    contentBase64: Buffer.from("hello").toString("base64"),
    options: { overwrite: true },
  });
  assert.match(command, /^powershell\.exe .* -EncodedCommand [A-Za-z0-9+/=]+$/);
  const encoded = command.split(" ").at(-1)!;
  const source = Buffer.from(encoded, "base64").toString("utf16le");
  assert.match(source, new RegExp(REMOTE_WINDOWS_FILESYSTEM_RESULT_MARKER));
  assert.match(source, /write_content/);
  assert.match(source, /\(\[DateTimeOffset\]\$item\.LastWriteTimeUtc\)\.ToUnixTimeMilliseconds\(\)/u);
  assert.match(source, /\(\[DateTimeOffset\]\$item\.CreationTimeUtc\)\.ToUnixTimeMilliseconds\(\)/u);
  const requestMatch = source.match(/\$RequestBase64 = '([^']+)'/);
  assert.ok(requestMatch);
  const request = JSON.parse(Buffer.from(requestMatch[1]!, "base64").toString("utf8"));
  assert.equal(request.path, "C:\\Temp\\file.txt");
  assert.ok(Buffer.byteLength(command) < 100_000);
});
