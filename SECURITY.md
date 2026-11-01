# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's
**Security** tab and choose **Report a vulnerability**
(<https://github.com/arkavo-org/tdf-iroh-s3/security/advisories/new>).
Do not open a public issue.

Include what you found, how to reproduce it, and what an attacker gains.
We will acknowledge the report, keep you informed while we work on a fix, and
credit you in the advisory unless you prefer otherwise.

## Supported versions

Only the latest commit on `main` is supported. The node is not published as a
crate; deployments build from `main`.

## Scope

In scope: this node, which covers the iroh blobs protocol handling, ingest
validation, the HTTP API, publish sessions and moderation, and how it uses S3.
Read access to content is enforced by the OpenTDF encryption layer, not by this
node. Report issues in OpenTDF itself to the
[OpenTDF project](https://github.com/opentdf).

Dependency advisories that do not affect the node are recorded, with the
reason, in [`.cargo/audit.toml`](.cargo/audit.toml).
