# verify-audit

Independent verifier for the Core0 audit log.

Every Core0 service (keys, pii, files) writes a tamper-evident, append-only audit log. Each entry carries the SHA-256 hash of the previous entry, so removing, reordering or changing any entry breaks the chain. `verify-audit` lets you check that chain yourself, on your own machine, without trusting Obsydia or the Core0 nodes.

The `internal/audit` package in this repository is byte-for-byte the package that runs inside the Core0 services. `verify-audit` reads the log with the same code that wrote it.

## What it checks

**A local audit log** (`verify-audit <log>`)

- the hash chain of every entry, across the live file and its daily gzip archives
- each archive against the hash recorded in the chain when it was rotated
- archives that are gone without a recorded deletion (90-day retention)
- a damaged tail set aside after a crash, and the recovery entry that records it

**A shipped copy** (`verify-audit shipped ...`)

- decrypts every batch (`*.jsonl.age`) with your age identity
- checks each batch signature and that the signing certificate belongs to the service the batch claims to come from
- optionally checks that every certificate was issued by your Core0 CA (`-ca`)
- checks the sequence and hash chain of each stream (service/node) and reports missing entries
- reports silences longer than `-max-gap` (services send heartbeats while idle)
- optionally checks every entry anchored in the hourly anchor mails against the copy (`-anchors`)

## Install

Download the binary for your platform from [Releases](https://github.com/obsydia-tech/verify-audit/releases) and check it:

```
sha256sum -c SHA256SUMS --ignore-missing
```

Or build from source (Go 1.25 or newer):

```
go install github.com/obsydia-tech/verify-audit/cmd/verify-audit@latest
```

Linux only. The audit package uses `fdatasync`, as Core0 does.

## Usage

```
verify-audit <audit log path>
verify-audit shipped -identity <age key file> [-ca <Core0 CA PEM>] [-anchors <mbox or .eml dir>] [-max-gap 2m] <shipped copy directory>
```

Examples:

```
verify-audit ./audit.log
verify-audit shipped -identity ~/core0-audit.key -ca core0-ca.pem -anchors ~/mail/core0-anchors.mbox /srv/core0-audit-copy
```

Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | `CHAIN OK` / `SHIPPED COPY OK` |
| 1 | problems found, each listed in the output |
| 2 | usage error or input that cannot be read |

## Format

An entry is one JSON line:

```
{"seq":42,"prev_hash":"<sha256 of the previous line>","ts":"...","path":[...],"event":"...","actor_id":"...","tenant_id":"...","result":"ok"}
```

The first entry's `prev_hash` is 64 zeros. A shipped batch is an age-encrypted JSON object with the service, node, sequence range, stream head, the raw entries, and an ECDSA signature over all of them made with the service's mTLS certificate.

## Security

Report vulnerabilities as described in [SECURITY.md](https://github.com/obsydia-tech/.github/blob/main/SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
