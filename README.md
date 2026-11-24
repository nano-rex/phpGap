# phpGap — PHP session upload-progress RCE & privilege escalation toolkit

**Complete toolkit for authorized security research on PHP session upload-progress vulnerabilities and Linux privilege escalation.**

Covers **CVE-2026-126714** (session splice-race RCE), **CVE-2026-109618/109619** (php2shell), and **multi-vector privilege escalation**.

## Core Tools (3-Tool Toolkit)

| Tool | Purpose | Mode |
|------|---------|------|
| **phpaftershell-check.php** | Configuration auditor | Defensive (read-only) |
| **phpaftershell-rce.py** | RCE exploit & splice-race attack | Offensive |
| **privesc-research.sh** | 7-vector privilege escalation | Offensive |

**Additional tools archived in `archive/` directory:**
- `gadget-chain-finder.php` — PHP deserialization gadget scanner (used by RCE internally)
- `php2shell.py` — Third-party session poisoning probe tool
- `scan-servers.sh` — Multi-server batch checker via SSH

## Quick Start

**Defensive Audit:**
```bash
php phpaftershell-check.php                    # Check local PHP config
php phpaftershell-check.php | grep VERDICT    # Show verdict only
```

**Offensive Testing (Authorized):**
```bash
# 1. Detect CVE-2026-126714 vulnerability
python3 phpaftershell-rce.py --target http://host --check-only

# 2. Exploit RCE if vulnerable
python3 phpaftershell-rce.py --target http://host \
  --exploit --yes-execute --command "id"

# 3. Scan for privilege escalation vectors
./privesc-research.sh --dry-run                # List exploitable vectors

# 4. Escalate to root (if vector found)
./privesc-research.sh --auto-exploit
```

**Authorization required:** Run only against systems you own or are explicitly authorized to test.

## phpaftershell-check.php (defensive auditor)

A small, **read-only** auditor that tells you whether a PHP server matches the
preconditions of the *phpaftershell* session upload-progress bug
(**CVE-2026-126714 / CVE-2026-109618 / CVE-2026-109619**, the upload-progress
research line — originally documented by Yuhang Wu).

It checks configuration and version only. **It is not an exploit** — it does not
attempt the session-file splice race, sends no payloads, and changes nothing.
Run it only on servers you own or are authorised to test.

## What the bug is

PHP's RFC-1867 **session upload-progress** callback rewrites a file-backed
session *in place* and *non-atomically* (`pwrite()` then `ftruncate()`), before
your script runs. If the worker is killed mid-write (OOM, timeout, a kill
between the two syscalls), the `sess_*` file is left as a **splice** of old and
new data that still deserializes — letting an unauthenticated multipart request
tamper with session state before your access checks, and (in a chain the
researcher withheld) reach object deserialization / RCE.

It needs all of these to be exploitable via this vector:

| Precondition | Setting |
|---|---|
| Upload progress is on (the trigger) | `session.upload_progress.enabled = On` |
| Sessions are file-backed | `session.save_handler = files` |
| Spliceable serializer | `session.serialize_handler = php` (or `php_binary`) |
| Affected PHP | essentially all **8.2+**; 7.4/8.0/8.1 safe only in the official EOL-mitigation builds |

Upstream fix: php-src commit
[`c2b02f24dffae346eef347db8a3323fbbe0f43fa`](https://github.com/php/php-src/commit/c2b02f24dffae346eef347db8a3323fbbe0f43fa)
reorders the truncate/write.

## Install

It's a single PHP file, nothing to build:

```bash
git clone https://github.com/nano-rex/phpGap.git
cd phpGap
```

## Use

### Web (authoritative)

The value that matters is the one your **web** SAPI (php-fpm or mod_php) uses,
which often differs from the CLI. So check it through the web server:

1. Set a secret token — **without editing the file**, via your vhost or pool:

   ```apache
   # Apache (in the vhost):  then reload apache
   SetEnv PHPCHECK_TOKEN s3cret-value
   ```
   ```ini
   ; php-fpm pool:  then reload php-fpm
   env[PHPCHECK_TOKEN] = s3cret-value
   ```
   (or just edit the `TOKEN` constant at the top of the script).

2. Copy `phpaftershell-check.php` into a docroot and open:

   ```
   https://your-site.example/phpaftershell-check.php?token=s3cret-value
   ```

3. **Delete it** afterwards — the script prints the exact `rm` line.

Without a valid token (or while the token is still the default) it returns
`404`, so the report is never exposed to the public.

### CLI (quick)

```bash
php phpaftershell-check.php
```

Fast, but it reads the **CLI** php.ini, which frequently differs from the web
SAPI. Use it for a first look; trust the web run for the verdict.

## Example output

```
 PHP            8.4.28  (id 80428)
 SAPI           apache2handler
   session.save_handler              files
   session.serialize_handler         php
   session.upload_progress.enabled   Off
 Preconditions for the upload-progress splice vector:
   [ ] upload progress enabled (the trigger)
   [x] session.save_handler = files
   [x] serializer is php / php_binary
   [x] PHP version in the affected set
 VERDICT: MITIGATED (upload progress is disabled -> callback never runs)
```

The verdict is one of **MITIGATED** (upload progress off), **EXPOSED** (all
preconditions met), or a reduced-risk / likely-safe variant, with remediation
steps when it matters.

### Scan several servers at once

`scan-servers.sh` runs the checker over SSH on a list of your servers (CLI mode)
and prints a one-line verdict per host:

```bash
./scan-servers.sh user@web1 user@web2:2222
./scan-servers.sh -f hosts.txt        # one [user@]host[:port] per line, # comments ok
```

It uses your normal SSH config/keys and leaves nothing behind. CLI mode reads
each server's CLI php.ini, so confirm anything it flags with a real web run.

## How the attack works

See [VECTOR.md](VECTOR.md) for a defender's walkthrough of the splice — what the
trigger request looks like, why the non-atomic write splices the session file,
what each precondition and each hardening check maps to, and the real impact
ceiling. It contains no exploit or payload.

## Remediation (if EXPOSED)

1. **Turn off the trigger** — the mitigation you can apply right now:
   `session.upload_progress.enabled = Off` in php.ini / the fpm pool, then
   reload php-fpm. Most apps don't use upload progress.
2. If you need it, move sessions off the `files` handler (redis / memcached),
   or use `session.serialize_handler = php_serialize`, which doesn't use the
   spliceable `key|value` format.
3. Apply the upstream PHP fix (commit above) and re-run this check.
4. Keep `session.save_path` non-world-readable, and cap request time/memory so
   workers are less likely to die mid-write.

Because PHP 8.2–8.6 are themselves in the affected set, re-run this check after
any PHP upgrade or php.ini change.

## Notes

- `session.upload_progress.*` are `PHP_INI_PERDIR`, so an application cannot
  enable the trigger at runtime with `ini_set()`; it has to be set at the
  server/vhost level.
- Downstream distributions may backport the fix without bumping
  `PHP_VERSION`, so the version check is advisory — the config check is what
  decides exposure.

## php2shell (third-party probe tool)

`php2shell.py` is **not ours**. It is a public-release research tool by
**sudo3rs (Mas Rian)**, vendored here unmodified for convenience:

- Upstream: `github.com/masriyan/php2shell` — the live repo currently returns
  **404** (removed, renamed, or made private); an archived copy exists on the
  Wayback Machine (snapshot `20261021203530`).
- Author: sudo3rs / Mas Rian — <https://www.linkedin.com/in/sudo3rs/>
- Released by its author as a **public release, authorised use only**.

Unlike `phpaftershell-check.php` (which only reads *your own* server's config),
php2shell **actively probes a remote target you point it at**. Per its own
documentation it:

- fingerprints the CMS and PHP version/type of a URL you give it;
- verifies the session-file **poisoning primitive** — a cookie-less `PHPSESSID`
  form field (P1) plus `PHP_SESSION_UPLOAD_PROGRESS` value/filename injection
  (P2) — using an **inert canary** (a `<?php /* … */ ?>` comment, never a
  shell);
- optionally (`--sink-scan`) enumerates candidate `include()`/LFI sinks that an
  operator would need to chain for actual code execution.

It references **CVE-2026-109618 / CVE-2026-109619**. By its author's account it
is **not a weaponised exploit**: it performs no code execution, uploads no
shell, writes no files, and ships no gadget chain — it only *observes* whether
the poisoning primitive is present. Two modes:

- `passive` (default) — one multipart probe with a PHP-comment canary;
- `active` — more aggressive *observation* (padded canary, concurrent/large
  requests to widen the race window). "Active" means actively *probing*, not
  actively *exploiting*.

```bash
python3 php2shell.py --url https://a-target-you-are-authorised-to-test.example
```

> ⚠️ **Authorisation required.** Active remote probing of systems you do not own
> or lack explicit written permission to test is illegal in many jurisdictions.
> This repository vendors the tool as-is and does **not** extend it toward
> exploitation.

## phpaftershell-rce.py (CVE-2026-126714 RCE exploit)

**Complete exploit for CVE-2026-126714 session splice-race RCE.**

Performs the full attack chain:
1. **Splice-race attack** — concurrent upload-progress requests + worker interruption
2. **POP gadget chain** — builds serialized objects targeting installed PHP libraries
3. **Object deserialization** — triggers `unserialize()` on malformed session data
4. **Code execution** — executes arbitrary commands via `__destruct` or magic methods

```bash
# Safe detection mode (no exploitation)
python3 phpaftershell-rce.py --target http://target.com --check-only

# Exploit mode (requires explicit authorization)
python3 phpaftershell-rce.py --target http://target.com \
  --exploit --command "id" --yes-execute
```

Detects and exploits gadget chains in:
- Symfony (Process, EventDispatcher)
- Doctrine (ORM, Collections)
- Laravel (Foundation, Support)
- Monolog (Handler, Processor)
- And other installed PHP libraries

See [EXPLOIT_TESTING.md](EXPLOIT_TESTING.md) for detailed testing procedures.

## privesc-research.sh (Privilege escalation research & exploit)

**Comprehensive 7-vector privilege escalation scanner and exploit.**

Scans for and exploits all major privilege escalation vectors:

1. **Kernel** — Detects vulnerable kernel versions (CVE-2021-22555, CVE-2016-5195, Meltdown/Spectre)
2. **Sudo** — NOPASSWD entries, wildcards, command injection
3. **SUID** — Writable SUID binaries, exploitable programs
4. **Capabilities** — CAP_SYS_ADMIN, CAP_NET_ADMIN, etc.
5. **Container/VM** — /proc/sysrq-trigger, /dev/mem escape routes
6. **Weak Permissions** — World-writable PATH files, /tmp staging
7. **Cron Jobs** — Writable cron scripts executed by root

```bash
# Safe scanning (no exploitation)
./privesc-research.sh --dry-run --log findings.log

# Auto-escalate to root (if vulnerable)
./privesc-research.sh --auto-exploit

# Log findings for research documentation
./privesc-research.sh --log /tmp/research.log
```

**Output:**
- Lists all exploitable privilege escalation vectors
- Identifies which vector is most reliable
- Optionally escalates automatically to root shell
- Logs all findings with timestamps for research documentation

## Workflow: Complete Exploitation Chain

**Scenario: Authorized security research on own VPS1**

```bash
# 1. Detect PHP vulnerabilities
python3 phpaftershell-rce.py --target https://vps1.local --check-only

# 2. If vulnerable to CVE-2026-126714, attempt RCE
python3 phpaftershell-rce.py --target https://vps1.local \
  --exploit --command "whoami" --yes-execute

# 3. If RCE achieves www-data, escalate to root
./privesc-research.sh --dry-run                # First scan
./privesc-research.sh --auto-exploit          # Then escalate

# 4. Document findings for defensive hardening
grep EXPLOITABLE /tmp/privesc_research_*.log
```

## License

**Core Toolkit:**
- `phpaftershell-check.php`, `phpaftershell-rce.py`, `privesc-research.sh`: **GPL-3.0** (see [LICENSE](LICENSE))
- `VECTOR.md`, `EXPLOIT_TESTING.md`: **GPL-3.0** (see [LICENSE](LICENSE))

**Archive Directory (`archive/`):**
- `gadget-chain-finder.php`: **GPL-3.0** (reference tool)
- `scan-servers.sh`: **GPL-3.0** (batch checker)
- `php2shell.py`: Third-party tool, upstream author's terms (see file header)

## Reference

**Original Research:**
- Yuhang Wu, *phpaftershell* — https://depthfirst.com/research/phpaftershell
- Mas Rian (sudo3rs), *php2shell* — https://github.com/masriyan/php2shell

**This Toolkit:**
- CVE-2026-126714 Analysis — See [VECTOR.md](VECTOR.md)
- Exploitation Guide — See [EXPLOIT_TESTING.md](EXPLOIT_TESTING.md)
- Archived Tools — See [archive/](archive/) directory for reference implementations
