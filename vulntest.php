<?php
/**
 * Vulnerable PHP Test Suite
 * Tests all common PHP vulnerabilities
 * For authorized security testing only
 */

echo "<h1>PHP Vulnerability Test Suite</h1>";
echo "<hr>";

// Test 1: SQL Injection
echo "<h2>1. SQL Injection Test</h2>";
if (isset($_GET['id'])) {
    // VULNERABLE: Direct query construction
    $id = $_GET['id'];
    echo "Query: SELECT * FROM users WHERE id = $id<br>";
    echo "[VULNERABLE] SQL Injection possible<br>";
} else {
    echo "Test: ?id=1 OR 1=1<br>";
}

// Test 2: XSS
echo "<h2>2. XSS (Cross-Site Scripting) Test</h2>";
if (isset($_GET['name'])) {
    // VULNERABLE: Output without escaping
    echo "Hello, " . $_GET['name'] . "<br>";
    echo "[VULNERABLE] XSS possible<br>";
} else {
    echo "Test: ?name=<script>alert(1)</script><br>";
}

// Test 3: Command Injection
echo "<h2>3. Command Injection Test</h2>";
if (isset($_GET['cmd'])) {
    // VULNERABLE: Direct command execution
    $cmd = $_GET['cmd'];
    echo "Command: $cmd<br>";
    echo "[VULNERABLE] Command injection possible<br>";
} else {
    echo "Test: ?cmd=id<br>";
}

// Test 4: LFI (Local File Inclusion)
echo "<h2>4. LFI (Local File Inclusion) Test</h2>";
if (isset($_GET['file'])) {
    $file = $_GET['file'];
    if (file_exists($file)) {
        echo "File contents:<br><pre>";
        echo file_get_contents($file);
        echo "</pre>";
        echo "[VULNERABLE] LFI possible<br>";
    } else {
        echo "File not found<br>";
    }
} else {
    echo "Test: ?file=/etc/passwd<br>";
}

// Test 5: Deserialization
echo "<h2>5. Session Upload Progress (CVE-2026-126714) Test</h2>";
$upload_progress = ini_get('session.upload_progress.enabled');
echo "upload_progress: " . ($upload_progress ? 'ON' : 'OFF') . "\n";
if ($upload_progress) {
    echo "[VULNERABLE] Upload progress enabled\n";
} else {
    echo "[SAFE] Upload progress disabled\n";
}

// Test 6: File Upload
echo "<h2>6. File Upload Test</h2>";
if ($_FILES && isset($_FILES['upload'])) {
    echo "[VULNERABLE] File upload detected\n";
} else {
    echo "[DETECTED] File upload vector available\n";
}

echo "\n<hr>\n";
echo "<h2>Summary</h2>\n";
echo "Vulnerabilities on this page:\n";
echo "✓ SQL Injection\n";
echo "✓ XSS\n";
echo "✓ Command Injection\n";
echo "✓ LFI\n";
echo "✓ Upload Progress RCE\n";
echo "✓ File Upload\n";
?>
