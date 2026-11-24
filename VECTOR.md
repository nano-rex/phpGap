# Attack vector: the phpaftershell session splice

A defender's explanation of **how** CVE‑2026‑126714 works and **why** each check
in `phpaftershell-check.php` exists. This is background for hardening and
detection. It intentionally contains **no exploit, no payload, and not the
memory‑corruption chain** — that was withheld by the researcher for coordinated
disclosure, and this repo keeps it that way.

## The mechanism, step by step

1. **The trigger runs before your code.** When PHP receives a
   `multipart/form-data` POST that includes a field named
   `session.upload_progress.name` (default `PHP_SESSION_UPLOAD_PROGRESS`), and
   `session.upload_progress.enabled = On`, PHP runs its RFC‑1867
   upload‑progress callback *during request parsing* — before your script's
   first line. No authentication is required for this to run.

2. **The callback rewrites a session file in place.** With
   `session.save_handler = files`, that callback opens the `sess_<id>` file and
   rewrites it. The write is **not atomic**: PHP does a `pwrite()` and a
   `ftruncate()` as two separate syscalls (the vulnerable orderings are what the
   upstream fix reorders).

3. **A mid‑write death leaves a splice.** If the worker dies between/within
   those syscalls — OOM kill, `max_execution_time`, or an externally‑timed kill
   — the file is left holding a **splice**: the head of the new session data
   followed by the tail of the old. With the `php` / `php_binary` serializer the
   format is just `key|serialized_value` repeated, with no length prefix,
   checksum, or commit marker, so a spliced file still parses as "valid"
   sessions — just with attacker‑influenced contents.

4. **The victim deserializes it.** The next `session_start()` reads the spliced
   file and deserializes it. That lets session state be altered *before* your
   access checks, and — in the withheld chain — steers deserialization at a
   PHP‑native class with a memory‑corruption bug to reach code execution.

## Why each precondition matters (and maps to a check)

| Precondition | Why it's required | Check in the script |
|---|---|---|
| `upload_progress.enabled = On` | without it, the callback never runs — no trigger | section [1] |
| `save_handler = files` | the splice is a *file* artifact; redis/memcached stores aren't rewritten this way | section [1] |
| `serialize_handler = php`/`php_binary` | the `key\|value` format tolerates a splice; `php_serialize` is one serialized blob that a splice tends to break | section [1] |
| affected PHP (≈8.2+) | the non‑atomic write path | section [1] |
| `use_strict_mode = Off` | lets an attacker pin a chosen session id, so the splice can be aimed at a victim | section [2] |

## Impact ceiling (what it is and isn't)

- Code execution, if the withheld chain is reproduced, runs **as the web/php
  user** (e.g. `www-data`) — **not root**. The script's section [3] shows what
  user PHP runs as; if that's root, any code‑exec is instant root, which is a
  configuration you control.
- It is a **race**, not a deterministic one‑shot (the write‑up reports ~10–11
  attempts), and there is **no public one‑click exploit**.

## Defences (in priority order)

1. **Disable the trigger:** `session.upload_progress.enabled = Off`.
2. **Patch PHP** to a build with php‑src commit
   `c2b02f24dffae346eef347db8a3323fbbe0f43fa` (distros may backport without
   bumping `PHP_VERSION`).
3. **Shrink the blast radius:** run PHP as an unprivileged user (never root),
   set `open_basedir`, disable command‑exec functions you don't use, keep
   `session.save_path` private (0700, owned by the web user, not shared `/tmp`),
   `use_strict_mode = On`.
4. **Detect probing:** alert on `multipart/form-data` POSTs carrying the
   `PHP_SESSION_UPLOAD_PROGRESS` field, especially to endpoints that don't
   normally take uploads.

## Reference

Yuhang Wu, *phpaftershell* — https://depthfirst.com/research/phpaftershell
· php‑src fix commit `c2b02f24dffae346eef347db8a3323fbbe0f43fa`
· RFC 1867 — https://www.rfc-editor.org/rfc/rfc1867.html
