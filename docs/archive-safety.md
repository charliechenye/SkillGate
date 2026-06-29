# Archive Safety Foundation

SkillGate treats archives as untrusted installation artifacts. A bundle can contain path traversal entries, unsafe links, oversized files, misleading compression metadata, nested packages, or binary payloads. The archive layer therefore inspects ZIP-compatible archives without executing any archive content.

This foundation is internal in Batch 1. It does not add `skillgate mcpb scan`, MCPB manifest parsing, bundle-specific findings, SARIF changes, or recursive archive scanning.

## Supported Format

Batch 1 supports ZIP-compatible archives through Python's standard `zipfile` implementation.

Supported compression methods are:

- stored entries;
- deflated entries.

BZIP2, LZMA, TAR, TGZ, RAR, and 7z are not supported. Unsupported compression fails closed.

Python's `zipfile` may interpret structural ZIP metadata such as ZIP64 fields. SkillGate does not treat unknown application-specific extra fields, archive comments, or member comments as instructions, capabilities, or trusted metadata.

Encrypted archives and encrypted members are rejected because SkillGate cannot completely inspect content it cannot read.

## Limits

The default safety limits are intentionally conservative initial values:

- maximum archive bytes: `104857600`;
- maximum members: `1000`;
- maximum total uncompressed bytes: `104857600`;
- maximum uncompressed bytes per member: `20971520`;
- maximum compression ratio per file: `100.0`;
- maximum normalized path length: `240` Unicode code points;
- nested archives disabled by default.

These limits are internal defaults for the reusable archive layer. Public CLI configuration can be added later when MCPB scanning is introduced.

## Path Handling

Archive member names are normalized before extraction. SkillGate converts backslashes to forward slashes, collapses safe `.` and repeated separator segments, and preserves safe relative hierarchy.

SkillGate rejects:

- parent traversal such as `../file` or mixed-separator traversal;
- POSIX absolute paths;
- Windows drive-letter paths;
- UNC paths;
- NUL bytes;
- empty or ambiguous paths;
- paths longer than the configured normalized path limit;
- duplicate normalized paths;
- file/directory path collisions;
- regular files used as parent directories.

Archives may omit explicit directory entries. SkillGate creates missing parent directories during safe extraction.

## Links And Special Entries

Batch 1 allows only normal directories and regular files. ZIP symlinks are rejected when detectable from external attributes. Device files, sockets, FIFOs, and other special entries are also rejected when detectable.

SkillGate does not follow or materialize links.

## Nested Archives

SkillGate detects nested ZIP-compatible archives by extension and by ZIP magic bytes during streaming. Extensions are matched case-insensitively for `.zip`, `.mcpb`, `.jar`, and `.whl`.

By default, nested archives are rejected with fail-closed safety errors. If internal callers explicitly allow nested archives, SkillGate materializes and hashes the nested member, marks it as a nested archive in the manifest, records that it was retained but not recursively inspected, and never recurses into it.

## Extraction Lifecycle

The inspection lifecycle is:

1. Hash the caller-provided archive with bounded chunked reads.
2. Parse and validate all ZIP central-directory metadata.
3. Reject unsafe or incomplete archives before creating temporary storage whenever the problem is metadata-detectable.
4. Create one SkillGate-owned temporary extraction directory.
5. Stream each regular file in bounded chunks.
6. Verify resolved paths stay inside the extraction root.
7. Hash each accepted file while writing it.
8. Verify actual streamed byte counts match declared sizes and configured limits.
9. Inspect only a bounded content prefix for nested-archive magic and text/binary classification.
10. Store only the resulting metadata, then discard the raw prefix.

SkillGate never uses `ZipFile.extract()` or `extractall()`.

If inspection fails after temporary storage is created, the temporary directory is removed before the typed error is returned to the caller. Cleanup is idempotent for successful results and removes only the temporary directory created by SkillGate.

## Permissions

SkillGate does not restore executable bits from ZIP metadata. On POSIX platforms, files are written with restrictive read/write permissions and directories with restrictive traversal permissions where practical. Windows permission behavior is platform-dependent, but SkillGate still avoids intentionally making extracted files executable.

## Manifest Behavior

`archive_manifest()` returns deterministic structured data with:

- archive SHA-256;
- ZIP format;
- member counts and byte totals;
- active limits;
- sorted member records;
- normalized member paths;
- compressed and uncompressed sizes;
- rounded compression ratios;
- member SHA-256 values;
- nested-archive and text-scannability flags;
- stable skip reasons.

The manifest excludes temporary extraction paths, archive filesystem paths, original member names, timestamps, comments, and environment-specific data. The archive hash is the stable archive identity.

## No Execution Guarantee

The archive layer never imports Python from the archive, invokes shell commands, runs package managers, starts MCP servers, loads dynamic libraries, executes binaries, or inspects binaries by running them.

Text/binary classification is advisory and static. Binary and unsupported files are still materialized, hashed, and represented in the manifest.

## Known Limitations

Batch 1 does not recursively inspect nested archives. It does not parse MCPB manifests, validate MCPB entry points, produce SARIF, add CLI exit-code mapping, perform malware analysis, use YARA, or sandbox dynamic execution.

This foundation is intended to be reused by future MCPB pre-install scanning, where the extracted static files can be passed into SkillGate's existing discovery and rule engine after ZIP safety has been established.