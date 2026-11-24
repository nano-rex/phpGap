<?php
/**
 * Vulnerable PHP Test Suite  --  FOR AUTHORIZED SECURITY TESTING ONLY
 * =====================================================================
 * DANGER: This file is DELIBERATELY vulnerable. It exposes real SQL
 * injection, reflected XSS, Local File Inclusion AND unauthenticated
 * remote command execution (shell_exec). Anyone who can reach this URL
 * can run arbitrary commands on this server.
 *
 * Only deploy it on a throwaway host that is firewalled to your own IP
 * (or offline to the public internet). Delete it when you are done.
 */

echo "<h1>PHP Vulnerability Test Suite</h1>";
echo "<hr>";

// ---------------------------------------------------------------------
// Test 1: SQL Injection  (real, backed by a SQLite database)
// ---------------------------------------------------------------------
echo "<h2>1. SQL Injection Test</h2>";
if (isset($_GET['id'])) {
    $db = new PDO('sqlite:' . __DIR__ . '/vuln_test.db');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)");
    // Seed deterministic rows the exploit can look for
    $db->exec("INSERT OR IGNORE INTO users (id, username, password) VALUES
        (1, 'admin', 'S3cr3t_Adm1n_PW'),
        (2, 'operator', 'Op3rator_PW'),
        (3, 'guest', 'guest')");

    // VULNERABLE: raw string concatenation, no binding
    $id = $_GET['id'];
    $sql = "SELECT id, username, password FROM users WHERE id = $id";
    echo "Query: " . htmlspecialchars($sql) . "<br>";
    try {
        $rows = $db->query($sql)->fetchAll(PDO::FETCH_ASSOC);
        echo "<pre>";
        foreach ($rows as $row) {
            echo "id=" . $row['id'] . " username=" . $row['username'] . " password=" . $row['password'] . "\n";
        }
        echo "</pre>";
        echo "[VULNERABLE] SQL Injection possible<br>";
    } catch (Exception $e) {
        echo "SQL error: " . htmlspecialchars($e->getMessage()) . "<br>";
    }
} else {
    echo "Test: ?id=1 OR 1=1<br>";
}

// ---------------------------------------------------------------------
// Test 2: XSS  (real reflected)
// ---------------------------------------------------------------------
echo "<h2>2. XSS (Cross-Site Scripting) Test</h2>";
if (isset($_GET['name'])) {
    // VULNERABLE: output without escaping
    echo "Hello, " . $_GET['name'] . "<br>";
    echo "[VULNERABLE] XSS possible<br>";
} else {
    echo "Test: ?name=<script>alert(1)</script><br>";
}

// ---------------------------------------------------------------------
// Test 3: Command Injection / RCE  (real, via shell_exec)
// ---------------------------------------------------------------------
echo "<h2>3. Command Injection Test</h2>";
if (isset($_GET['cmd'])) {
    // VULNERABLE: direct shell execution of user input
    $cmd = $_GET['cmd'];
    echo "Command: " . htmlspecialchars($cmd) . "<br>";
    $out = shell_exec($cmd . ' 2>&1');
    echo "<pre>" . htmlspecialchars((string)$out) . "</pre>";
    echo "[VULNERABLE] Command injection possible<br>";
} else {
    echo "Test: ?cmd=id<br>";
}

// ---------------------------------------------------------------------
// Test 4: LFI (Local File Inclusion)  (real; limited by open_basedir)
// ---------------------------------------------------------------------
echo "<h2>4. LFI (Local File Inclusion) Test</h2>";
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    if (file_exists($file)) {
        echo "File contents:<br><pre>";
        echo htmlspecialchars(file_get_contents($file));
        echo "</pre>";
        echo "[VULNERABLE] LFI possible<br>";
    } else {
        echo "File not found<br>";
    }
} else {
    echo "Test: ?file=/etc/passwd<br>";
}

// ---------------------------------------------------------------------
// Test 5: Session Upload Progress (CVE-2026-126714)
// ---------------------------------------------------------------------
echo "<h2>5. Session Upload Progress (CVE-2026-126714) Test</h2>";
$upload_progress = ini_get('session.upload_progress.enabled');
echo "upload_progress: " . ($upload_progress ? 'ON' : 'OFF') . "\n";
if ($upload_progress) {
    echo "[VULNERABLE] Upload progress enabled\n";
} else {
    echo "[SAFE] Upload progress disabled\n";
}

// ---------------------------------------------------------------------
// Test 6: File Upload
// ---------------------------------------------------------------------
echo "<h2>6. File Upload Test</h2>";
if ($_FILES && isset($_FILES['upload'])) {
    echo "[VULNERABLE] File upload detected: " . htmlspecialchars($_FILES['upload']['name']) . "\n";
} else {
    echo "[DETECTED] File upload vector available\n";
}

echo "\n<hr>\n";
echo "<h2>Summary</h2>\n";
echo "Vulnerabilities on this page:\n";
echo "&#10003; SQL Injection\n";
echo "&#10003; XSS\n";
echo "&#10003; Command Injection\n";
echo "&#10003; LFI\n";
echo "&#10003; Upload Progress RCE\n";
echo "&#10003; File Upload\n";
?>
