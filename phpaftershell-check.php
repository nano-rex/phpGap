<?php
/**
 * phpaftershell-check.php  --  PHP session upload-progress exposure auditor
 *
 * Checks whether THIS PHP server matches the preconditions of the
 * "phpaftershell" session-splice class of bug, tracked under several IDs for
 * the same session.upload_progress line of research (CVE-2026-126714, and the
 * php2shell IDs CVE-2026-109618 / CVE-2026-109619; NVD may still return 0
 * results for these during the advisory window), and reviews how much damage
 * a hypothetical code-execution would do (blast
 * radius): what user PHP runs as, which dangerous functions are reachable,
 * open_basedir, session storage permissions, and session-fixation settings.
 *
 * It is a READ-ONLY configuration and version audit. It does NOT attempt the
 * splice race, sends no payloads, deserializes nothing, and contains no
 * exploit. Run it only on a server you own or are authorised to test.
 * See VECTOR.md for how the attack works and why each check is here.
 *
 * Two ways to run:
 *   - Web (authoritative): copy to your docroot, open it in a browser, then
 *     DELETE it. Checks the real web SAPI (php-fpm / mod_php) config.
 *         https://example.com/phpaftershell-check.php?token=YOUR_SECRET
 *   - CLI (quick, but only checks the CLI php.ini, which often differs):
 *         php phpaftershell-check.php
 *
 * Gate: when served over the web it requires ?token=... matching the token,
 * so a config report is not exposed to the public. Set the token either by
 * editing TOKEN below or, without editing the file, via an environment
 * variable in your vhost / fpm pool:
 *     SetEnv PHPCHECK_TOKEN your-secret      (Apache)
 *     env[PHPCHECK_TOKEN] = your-secret      (php-fpm pool)
 * While the token is still the default, web mode refuses to run (returns 404),
 * so the report can never be served with a token everyone knows.
 */

const TOKEN = 'CHANGE_ME';          // web mode token (or set env PHPCHECK_TOKEN)
const SELF_DELETE_HINT = true;      // print a reminder to remove this file

// ---------------------------------------------------------------------------
$cli = (PHP_SAPI === 'cli');
if (!$cli) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex');
    $token = getenv('PHPCHECK_TOKEN');
    if ($token === false || $token === '') { $token = TOKEN; }
    $given = $_GET['token'] ?? '';
    // never serve with the default token, and never with an empty one
    if ($token === 'CHANGE_ME' || !hash_equals($token, (string) $given)) {
        http_response_code(404);
        echo "Not found.\n";   // don't advertise the auditor to the public
        exit;
    }
}

function ini_str($k) { $v = ini_get($k); return ($v === false) ? '(unset)' : $v; }
function ini_on($k)  { return filter_var(ini_get($k), FILTER_VALIDATE_BOOL); }
function yn($b)      { return $b ? 'yes' : 'no'; }

$out = [];
$add = function (string $line = '') use (&$out) { $out[] = $line; };
$warns = [];   // collected blast-radius warnings

$add(str_repeat('=', 70));
$add(' phpaftershell exposure check  (CVE-2026-126714 / -109618 / -109619)');
$add(' read-only config/version audit -- authorised testing only');
$add(str_repeat('=', 70));

/* ---- who/what -------------------------------------------------------- */
$euid = function_exists('posix_geteuid') ? posix_geteuid() : null;
$uname = null;
if ($euid !== null && function_exists('posix_getpwuid')) {
    $pw = posix_getpwuid($euid);
    $uname = $pw['name'] ?? (string) $euid;
} else {
    $uname = get_current_user() ?: '(unknown)';
}
$add(sprintf(' PHP            %s  (id %d)', PHP_VERSION, PHP_VERSION_ID));
$add(sprintf(' SAPI           %s%s', PHP_SAPI,
        $cli ? '   <-- CLI ini; the web server (fpm/mod_php) may differ!' : ''));
$add(sprintf(' Server         %s', $_SERVER['SERVER_SOFTWARE'] ?? php_uname('n')));
$add(sprintf(' Running as     %s%s', $uname,
        ($euid === 0) ? '   <-- PHP RUNS AS ROOT' : (($euid !== null) ? " (uid $euid)" : '')));
if ($euid === 0) {
    $warns[] = 'PHP is running as root: ANY code-execution bug becomes instant '
             . 'root. Run php-fpm/the web server as an unprivileged user.';
}
$add('');

/* ====================================================================== *
 * 1) Upload-progress splice preconditions
 * ====================================================================== */
$save_handler = ini_str('session.save_handler');
$serializer   = ini_str('session.serialize_handler');
$save_path     = ini_get('session.save_path') ?: '';
$up_enabled   = ini_on('session.upload_progress.enabled');
$up_name      = ini_str('session.upload_progress.name');
$up_prefix    = ini_str('session.upload_progress.prefix');
$up_cleanup   = ini_on('session.upload_progress.cleanup');

$add(' [1] Upload-progress splice preconditions');
$add(sprintf('   session.save_handler              %s', $save_handler));
$add(sprintf('   session.serialize_handler         %s', $serializer));
$add(sprintf('   session.save_path                 %s', $save_path !== '' ? $save_path : '(default)'));
$add(sprintf('   session.upload_progress.enabled   %s', $up_enabled ? 'On' : 'Off'));
$add(sprintf('   session.upload_progress.name      %s', $up_name));
$add(sprintf('   session.upload_progress.prefix    %s', $up_prefix));
$add(sprintf('   session.upload_progress.cleanup   %s', $up_cleanup ? 'On' : 'Off'));
$add('');

$cond = [];
$cond['upload progress enabled (the trigger)'] = $up_enabled;
$cond['session.save_handler = files']          = (strtolower($save_handler) === 'files');
$cond['serializer is php / php_binary']        = in_array(strtolower($serializer), ['php', 'php_binary'], true);

$vid = PHP_VERSION_ID;
if ($vid >= 80200) {
    $ver_affected = true;
    $ver_note = 'PHP >= 8.2: listed as affected (original and/or Variant A/B).';
} elseif ($vid >= 70400) {
    $ver_affected = true;
    $ver_note = 'PHP 7.4/8.0/8.1: safe ONLY if this is an official EOL '
              . 'upload-progress-mitigation build; unpatched builds are affected.';
} else {
    $ver_affected = false;
    $ver_note = 'Below 7.4: this specific research does not apply (but is EOL).';
}
$cond['PHP version in the affected set'] = $ver_affected;

foreach ($cond as $label => $ok) {
    $add(sprintf('   [%s] %s', $ok ? 'x' : ' ', $label));
}
$add('   note: ' . $ver_note);
$add('');

$all = !in_array(false, $cond, true);
$add(str_repeat('-', 70));
if (!$up_enabled) {
    $verdict = 'MITIGATED (upload progress is disabled -> callback never runs)';
} elseif ($all) {
    $verdict = 'EXPOSED: this server matches every precondition of the vector';
} elseif (!$cond['session.save_handler = files']) {
    $verdict = 'LIKELY SAFE from this vector: sessions are not file-backed (' . $save_handler . ')';
} elseif (!$cond['serializer is php / php_binary']) {
    $verdict = 'REDUCED RISK: serializer "' . $serializer . '" is not the spliceable key|value format';
} else {
    $verdict = 'LIKELY SAFE from this vector (a precondition is not met)';
}
$add(' VERDICT: ' . $verdict);
$add(str_repeat('-', 70));
if ($up_enabled && !$up_cleanup) {
    $warns[] = 'session.upload_progress.cleanup is Off: the progress entry (and '
             . 'the window in which a poisoned sess_* file can be read) persists '
             . 'longer, widening the race. cleanup=On (the default) narrows it but '
             . 'is NOT a fix -- disable upload_progress instead.';
}
$add('');

/* ====================================================================== *
 * 2) Session-fixation surface (does the splice vector have a way in?)
 * ====================================================================== */
$strict   = ini_on('session.use_strict_mode');
$httponly = ini_on('session.cookie_httponly');
$secure   = ini_on('session.cookie_secure');
$add(' [2] Session-targeting surface');
$add(sprintf('   session.use_strict_mode           %s %s', $strict ? 'On' : 'Off',
        $strict ? '' : '<-- attacker can pin a known session id'));
$add(sprintf('   session.cookie_httponly           %s', $httponly ? 'On' : 'Off'));
$add(sprintf('   session.cookie_secure             %s', $secure ? 'On' : 'Off'));
if (!$strict) {
    $warns[] = 'session.use_strict_mode is Off: an attacker can choose the '
             . 'session id, which makes aiming a splice at a victim easier. Set it On.';
}
$add('');

/* ====================================================================== *
 * 3) Blast radius -- how bad a hypothetical code-exec would be
 * ====================================================================== */
$add(' [3] Blast radius (how contained a hypothetical code-exec would be)');

// dangerous functions reachable?
$danger = ['system','exec','shell_exec','passthru','proc_open','popen','pcntl_exec'];
$disabled = array_filter(array_map('trim', explode(',', (string) ini_get('disable_functions'))));
$reachable = [];
foreach ($danger as $fn) {
    if (!in_array($fn, $disabled, true) && function_exists($fn)) { $reachable[] = $fn; }
}
$add(sprintf('   disable_functions                 %s', $disabled ? implode(',', $disabled) : '(none)'));
$add(sprintf('   command-exec functions reachable  %s', $reachable ? implode(',', $reachable) : 'none'));
if ($reachable) {
    $warns[] = 'Command-exec functions are reachable (' . implode(',', $reachable)
             . '). If you do not need them, add them to disable_functions.';
}

// open_basedir
$obd = ini_get('open_basedir');
$add(sprintf('   open_basedir                      %s', $obd ?: '(not set)'));
if (!$obd) {
    $warns[] = 'open_basedir is not set: PHP can read/write anywhere the web '
             . 'user can. Pin it to each site docroot (+ its tmp).';
}

// allow_url_include (the dangerous one) / allow_url_fopen
$aui = ini_on('allow_url_include');
$add(sprintf('   allow_url_include                 %s %s', $aui ? 'On' : 'Off', $aui ? '<-- remote code include!' : ''));
if ($aui) { $warns[] = 'allow_url_include is On: turn it Off (remote file inclusion -> RCE).'; }

// info leaks
$add(sprintf('   expose_php                        %s', ini_on('expose_php') ? 'On (leaks version)' : 'Off'));
$add(sprintf('   display_errors                    %s', ini_on('display_errors') ? 'On (leaks paths/data)' : 'Off'));
if (ini_on('display_errors') && !$cli) {
    $warns[] = 'display_errors is On for the web SAPI: turn it Off in production.';
}

// session storage permissions (tells you who else can read sess_* files)
if ($save_path !== '') {
    $sp = $save_path;
    if (strpos($sp, ';') !== false) { $sp = substr($sp, strrpos($sp, ';') + 1); } // "N;/path"
    $st = @stat($sp);
    if ($st !== false) {
        $mode = $st['mode'] & 0777;
        $add(sprintf('   session.save_path perms           %s on %s', sprintf('%04o', $mode), $sp));
        if ($mode & 0004) { $warns[] = "session.save_path ($sp) is world-readable: other local users can read sess_* files. chmod 0700 and own it by the web user."; }
        if ($mode & 0002) { $warns[] = "session.save_path ($sp) is world-writable."; }
        if ($sp === sys_get_temp_dir() || $sp === '/tmp') { $warns[] = "sessions are stored in a shared temp dir ($sp): use a private per-app directory."; }
    } else {
        $add(sprintf('   session.save_path perms           (could not stat %s -- open_basedir?)', $sp));
    }
}
$add('');

/* ====================================================================== *
 * Warnings summary + remediation
 * ====================================================================== */
if ($warns) {
    $add(' Hardening findings:');
    foreach ($warns as $i => $w) { $add(sprintf('   %d. %s', $i + 1, $w)); }
    $add('');
}

if ($up_enabled && $all) {
    $add(' Fix the splice vector:');
    $add('   1. Turn off the trigger now:  session.upload_progress.enabled = Off');
    $add('      (php.ini / the fpm pool, then reload php-fpm). Most apps do not use it.');
    $add('   2. Or move sessions off files (redis/memcached), or set');
    $add('      session.serialize_handler = php_serialize (not the spliceable format).');
    $add('   3. Apply the upstream fix (php-src commit');
    $add('      c2b02f24dffae346eef347db8a3323fbbe0f43fa) and re-run this check.');
    $add('');
}

$add(' Re-run after any PHP upgrade or php.ini change (8.2-8.6 are all affected).');
$add(' Detection: in access logs, the trigger is a multipart POST that carries');
$add('   the field "' . $up_name . '" to an upload endpoint. The poisoning');
$add('   primitive also sends a PHPSESSID *form field* (not a cookie) to pin a');
$add('   chosen session id -- a request with both a PHPSESSID body field and the');
$add('   "' . $up_name . '" field, but no matching session cookie, is the signature.');

if (!$cli && SELF_DELETE_HINT) {
    $self = $_SERVER['SCRIPT_FILENAME'] ?? __FILE__;
    $add('');
    $add(' REMINDER: delete this file now -- it reports your config:');
    $add('     rm ' . $self);
}

echo implode("\n", $out), "\n";
