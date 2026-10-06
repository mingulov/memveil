# Capability fixtures

Synthetic evidence trees for the profiles and doctor test lanes.
Each evidence directory mirrors an evidence root: host path `P`
becomes `<fixture>` + `P`, plus a `meta.txt` header with
`arch`/`release`/`euid` and optional `denied`/`asserted_guest_tech`.
Live-shaped fixtures can be seeded with
`tools/probe-inventory --emit-fixture`; the committed trees below
are built by `gen-fixtures.sh` for determinism. Rerunning it
reproduces the evidence and manifest files byte for byte.

No fixture content is a recorded kernel signature. The
tracepoint `format` files are illustrative 144-byte stand-ins,
the `vmlinux` files hold 24-byte text markers, and device nodes
are empty markers. CPU data is one fake processor with chosen
flag tokens.

## Evidence fixtures

| Directory | Shape |
|---|---|
| `ordinary-7.0/` | x86_64 7.0.0, no guest nodes, plain flags, hooks present; second CPU block carries token-lookalike model text as a verdict-source decoy |
| `snp-7.0/` | sev-guest node plus `sev sev_snp` flags |
| `tdx-7.0/` | tdx_guest node plus `tdx_guest` flag |
| `sev-classic-7.0/` | sev-guest node plus `sev` flag without `sev_snp` |
| `unavailable-evidence/` | no cpuinfo, no nodes; hooks present |
| `conflicting-evidence/` | both guest nodes present |
| `conflicting-flags/` | sev-guest node with flags lacking `sev` |
| `user-asserted-snp/` | no cpuinfo, no nodes, `asserted_guest_tech=snp` |
| `user-asserted-agree/` | SNP evidence plus matching assertion |
| `user-asserted-conflict/` | SNP evidence plus `tdx` assertion |
| `missing-btf/` | ordinary without the BTF file |
| `missing-tracepoint/` | ordinary without the tracepoint tree |
| `denied-tracepoint/` | format file held but meta-denied |
| `denied-guest-node/` | sev-guest marker held but meta-denied |
| `changed-signature/` | format bytes differ from `profiles-test` |
| `oversized-format/` | 131073-byte format file, past the 128 KiB read cap |
| `denied-id-changed/` | id file held but meta-denied, format bytes differ from `profiles-test` |
| `conflicting-flags-sev-tdx/` | sev-guest node with `sev sev_snp tdx_guest` flags |
| `conflicting-flags-tdx-sev/` | tdx_guest node with `sev tdx_guest` flags |
| `ready-validated/` | format bytes match `profiles-test` |
| `kernel-6.8/` | release 6.8.0, hooks present |
| `arch-mismatch/` | arch aarch64, release 7.0.0 |
| `malformed-release/` | release `not-a-kernel-release` |

## Profiles fixtures

| Directory | Shape |
|---|---|
| `profiles-test/` | manifest plus `test-validated.json`: validated, x86_64, min 7.0, recorded format, supported attempt-trace. Test device only, never admitted by `profiles/`. |
| `profiles-empty/` | empty manifest: no admitted profiles |
| `profiles-bad-manifest-blank/` | manifest with a blank line |
| `profiles-bad-manifest-dup/` | manifest with a duplicate entry |
| `profiles-bad-manifest-escape/` | manifest with a `..` path escape |
| `profiles-bad-doc/` | manifest naming a truncated JSON document |

## Meta fixtures

| Directory | Shape |
|---|---|
| `meta-bad-dup/` | duplicate `arch` key |
| `meta-bad-unknown-key/` | unknown key |
| `meta-bad-euid-alpha/` | non-decimal euid |
| `meta-bad-euid-huge/` | euid past 2**31-1 |
| `meta-bad-denied-relative/` | non-absolute denied entry |
| `meta-bad-tech/` | assertion outside the `snp`/`sev-classic`/`tdx` vocabulary |
| `meta-bad-arch-long/` | 33-byte arch (bound is 32) |
| `meta-bad-release-long/` | 129-byte release (bound is 128) |
| `meta-bad-denied-long/` | 257-byte denied entry (bound is 256) |
| `meta-bad-nul/` | NUL byte inside the release value |
| `meta-bad-utf8/` | invalid UTF-8 byte inside the release value |
| `meta-release-hostile/` | release with `/` plus a control byte (path-skip and sanitizer coverage) |
