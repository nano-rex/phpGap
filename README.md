# phpaftershell-check

A small, **read-only** auditor that tells you whether a PHP server matches the
preconditions of the *phpaftershell* session upload-progress bug
(**CVE-2026-126714**, and the earlier php2shell / upload-progress research by
Yuhang Wu).

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
git clone https://github.com/nano-rex/phpaftershell-check.git
cd phpaftershell-check
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

## License

GPL-3.0 (see [LICENSE](LICENSE)).

## Reference

Yuhang Wu, *phpaftershell* — https://depthfirst.com/research/phpaftershell
