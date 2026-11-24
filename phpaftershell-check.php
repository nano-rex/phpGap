<?php
/**
 * phpaftershell-check.php  --  PHP session upload-progress exposure auditor
 *
 * Checks whether THIS PHP server matches the preconditions of the
 * "phpaftershell" session-splice class of bug (CVE-2026-126714 and the
 * earlier php2shell / upload-progress line of research by Yuhang Wu).
 *
 * It is a READ-ONLY configuration and version audit. It does NOT attempt the
 * splice race, does not corrupt anything, and contains no exploit. Run it only
 * on a server you own or are authorised to test.
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

$out = [];
$out[] = str_repeat('=', 68);
$out[] = ' phpaftershell exposure check  (CVE-2026-126714, upload-progress splice)';
$out[] = str_repeat('=', 68);
$out[] = sprintf(' PHP            %s  (id %d)', PHP_VERSION, PHP_VERSION_ID);
$out[] = sprintf(' SAPI           %s%s', PHP_SAPI,
        $cli ? '   <-- CLI ini; the web server (fpm/mod_php) may differ!' : '');
$out[] = sprintf(' Server         %s', $_SERVER['SERVER_SOFTWARE'] ?? php_uname('n'));
$out[] = '';

/* ---- the settings that matter ---------------------------------------- */
$save_handler = ini_str('session.save_handler');
$serializer   = ini_str('session.serialize_handler');
$save_path     = ini_str('session.save_path');
$up_enabled   = ini_on('session.upload_progress.enabled');
$up_name      = ini_str('session.upload_progress.name');
$up_prefix    = ini_str('session.upload_progress.prefix');
$up_cleanup   = ini_on('session.upload_progress.cleanup');

$out[] = ' Relevant php.ini (as this SAPI sees it):';
$out[] = sprintf('   session.save_handler              %s', $save_handler);
$out[] = sprintf('   session.serialize_handler         %s', $serializer);
$out[] = sprintf('   session.save_path                 %s', $save_path);
$out[] = sprintf('   session.upload_progress.enabled   %s', $up_enabled ? 'On' : 'Off');
$out[] = sprintf('   session.upload_progress.name      %s', $up_name);
$out[] = sprintf('   session.upload_progress.prefix    %s', $up_prefix);
$out[] = sprintf('   session.upload_progress.cleanup   %s', $up_cleanup ? 'On' : 'Off');
$out[] = '';

/* ---- precondition logic ---------------------------------------------- */
// The bug needs the file-backed session store, the concatenated "key|value"
// serializer (php / php_binary -- php_serialize uses a different format), and
// the upload-progress callback actually running.
$cond = [];
$cond['upload progress enabled (the trigger)'] = $up_enabled;
$cond['session.save_handler = files']          = (strtolower($save_handler) === 'files');
$cond['serializer is php / php_binary']        = in_array(strtolower($serializer), ['php', 'php_binary'], true);

// Version. Per the Nov 2026 write-up essentially all of 8.2+ is affected
// (original path, plus Variant A/B after the php2shell fix). 7.4/8.0/8.1 are
// safe ONLY in the official EOL mitigation builds; unpatched ones keep the
// vulnerable path. Downstream distros may backport a fix without bumping
// PHP_VERSION, so version alone is advisory.
$vid = PHP_VERSION_ID;
if ($vid >= 80200) {
    $ver_affected = true;
    $ver_note = 'PHP >= 8.2: listed as affected (original and/or Variant A/B).';
} elseif ($vid >= 70400) {
    $ver_affected = true; // can't prove it's a mitigation build from the version
    $ver_note = 'PHP 7.4/8.0/8.1: safe ONLY if this is an official EOL '
              . 'upload-progress-mitigation build; unpatched builds are affected.';
} else {
    $ver_affected = false;
    $ver_note = 'Below 7.4: this specific research does not apply (but is EOL/unsupported).';
}
$cond['PHP version in the affected set'] = $ver_affected;

$out[] = ' Preconditions for the upload-progress splice vector:';
foreach ($cond as $label => $ok) {
    $out[] = sprintf('   [%s] %s', $ok ? 'x' : ' ', $label);
}
$out[] = '   note: ' . $ver_note;
$out[] = '';

/* ---- verdict --------------------------------------------------------- */
$all = !in_array(false, $cond, true);
$out[] = str_repeat('-', 68);
if (!$up_enabled) {
    $verdict = 'MITIGATED (upload progress is disabled -> callback never runs)';
} elseif ($all) {
    $verdict = 'EXPOSED: this server matches every precondition of the vector';
} elseif (!$cond['session.save_handler = files']) {
    $verdict = 'LIKELY SAFE from this vector: sessions are not file-backed ('
             . $save_handler . ')';
} elseif (!$cond['serializer is php / php_binary']) {
    $verdict = 'REDUCED RISK: serializer "' . $serializer . '" is not the '
             . 'spliceable key|value format (keep an eye on it anyway)';
} else {
    $verdict = 'LIKELY SAFE from this vector (a precondition is not met)';
}
$out[] = ' VERDICT: ' . $verdict;
$out[] = str_repeat('-', 68);
$out[] = '';

/* ---- remediation ----------------------------------------------------- */
if ($up_enabled && $all) {
    $out[] = ' What to do:';
    $out[] = '  1. Primary mitigation you can apply now -- turn off the trigger:';
    $out[] = '         session.upload_progress.enabled = Off';
    $out[] = '     (set it in php.ini / the fpm pool, then reload php-fpm). Only';
    $out[] = '     disables upload-progress reporting, which most apps do not use.';
    $out[] = '  2. If you need upload progress, move sessions off the files handler';
    $out[] = '     (redis / memcached), or use session.serialize_handler = php_serialize,';
    $out[] = '     which does not use the spliceable key|value format.';
    $out[] = '  3. Track and apply the upstream PHP fix';
    $out[] = '     (php-src commit c2b02f24dffae346eef347db8a3323fbbe0f43fa';
    $out[] = '      reorders the truncate/write), then re-run this check.';
    $out[] = '  4. Harden session files: non-world-readable save_path on its own';
    $out[] = '     mount, and cap request time/memory so workers are less likely to';
    $out[] = '     be killed mid-write.';
    $out[] = '';
}

if (!$cli && SELF_DELETE_HINT) {
    $self = $_SERVER['SCRIPT_FILENAME'] ?? __FILE__;
    $out[] = ' REMINDER: delete this file now -- it reports your config:';
    $out[] = '     rm ' . $self;
    $out[] = '';
}

echo implode("\n", $out), "\n";
