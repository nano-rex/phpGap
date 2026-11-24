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
echo "<h2>5. PHP Deserialization Test</h2>";
if (isset($_GET['data'])) {
    $data = $_GET['data'];
    $obj = unserialize(base64_decode($data));
    echo "[VULNERABLE] Object deserialization triggered<br>";
} else {
    echo "Test: Send serialized object via ?data=<b64_data><br>";
}

// Test 6: Session Upload Progress
echo "<h2>6. Session Upload Progress Test</h2>";
echo "upload_progress enabled: " . (ini_get('session.upload_progress.enabled') ? 'YES' : 'NO') . "<br>";
if (ini_get('session.upload_progress.enabled')) {
    echo "[VULNERABLE] Upload progress enabled<br>";
} else {
    echo "[SAFE] Upload progress disabled<br>";
}

// Test 7: File Upload
echo "<h2>7. File Upload Test</h2>";
if ($_FILES && isset($_FILES['upload'])) {
    $file = $_FILES['upload'];
    // VULNERABLE: No type/extension check
    $target = "/tmp/" . $file['name'];
    move_uploaded_file($file['tmp_name'], $target);
    echo "File uploaded: " . htmlspecialchars($file['name']) . "<br>";
    echo "[VULNERABLE] Arbitrary file upload possible<br>";
} else {
    echo "Upload a file via POST<br>";
}

echo "<hr>";
echo "<h2>Summary</h2>";
echo "This page demonstrates common PHP vulnerabilities<br>";
echo "For authorized security testing only<br>";
?>
