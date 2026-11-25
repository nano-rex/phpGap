#!/bin/bash
###############################################################################
# CloudLinux / CageFS Privilege-Escalation ENUMERATION (read-only)
#
# AUTHORIZATION: authorized assessment of your own host only.
# PURPOSE: enumerate realistic local root-escalation surface from an
#          unprivileged shared-hosting account (e.g. a web-RCE foothold).
#
# This script ONLY READS. It does not exploit, write, modify, or drop a
# shell. Run it inside the account (Plesk SSH Terminal / ssh), not through
# the web RCE (the anti-bot layer will challenge automated web traffic).
#
# Usage:
#   bash privesc-enum-cloudlinux.sh [--log FILE]
###############################################################################

LOG_FILE=""
[ "$1" = "--log" ] && LOG_FILE="$2"

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GRN=$'\033[0;32m'; YEL=$'\033[1;33m'; BLU=$'\033[0;34m'; NC=$'\033[0m'
else
    RED=""; GRN=""; YEL=""; BLU=""; NC=""
fi

out() { if [ -n "$LOG_FILE" ]; then echo -e "$1" | tee -a "$LOG_FILE"; else echo -e "$1"; fi; }
hdr()  { out "\n${BLU}==== $1 ====${NC}"; }
good() { out "${GRN}[+]${NC} $1"; }   # potentially useful to an attacker
info() { out "${BLU}[*]${NC} $1"; }
warn() { out "${YEL}[!]${NC} $1"; }
bad()  { out "${RED}[-]${NC} $1"; }   # dead end / hardened
has()  { command -v "$1" >/dev/null 2>&1; }
# run a command safely (never abort the script), truncate noisy output
sh_try() { timeout 20 bash -c "$1" 2>&1; }

CANDIDATES=()
add() { CANDIDATES+=("$1"); }

###############################################################################
hdr "CONTEXT"
info "user:    $(id 2>/dev/null)"
info "host:    $(hostname 2>/dev/null)"
info "kernel:  $(uname -a 2>/dev/null)"
info "date:    $(date 2>/dev/null)"
[ "$(id -u 2>/dev/null)" = "0" ] && good "Already UID 0 (root) — nothing to escalate."

###############################################################################
hdr "1. KERNEL / KernelCare (most likely root path on CloudLinux)"
RUNNING="$(uname -r 2>/dev/null)"
info "running kernel (uname -r): $RUNNING"
if has kcarectl; then
    EFF="$(sh_try 'kcarectl --uname')"
    info "KernelCare present. Effective (live-patched) level:"
    out  "    $EFF"
    info "KernelCare patch info:"
    out  "$(sh_try 'kcarectl --info' | sed 's/^/    /')"
    warn "Compare the EFFECTIVE level (not uname) against known LPEs — live patches"
    warn "may already close bugs that look exploitable by version string alone."
    add "KERNEL: verify effective level '$EFF' against current LPE set (les/linpeas)"
else
    warn "kcarectl not found — either no live patching, or hidden in the cage."
    add "KERNEL: no KernelCare visible; check $RUNNING against known LPEs"
fi
# cheap mitigations snapshot
info "cmdline: $(sh_try 'cat /proc/cmdline')"
info "unprivileged userns: $(sh_try 'cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo n/a')"
info "kptr_restrict=$(sh_try 'cat /proc/sys/kernel/kptr_restrict') dmesg_restrict=$(sh_try 'cat /proc/sys/kernel/dmesg_restrict')"

###############################################################################
hdr "2. CloudLinux / CageFS jail"
out  "$(sh_try 'cat /etc/cloudlinux-release /etc/redhat-release 2>/dev/null' | sed 's/^/    /')"
info "cagefs rpm: $(sh_try 'rpm -q cagefs lve-utils lvemanager 2>&1 | tr "\n" " "')"
VARTMP="$(sh_try 'readlink -f /var/tmp')"
info "/var/tmp -> $VARTMP ; /tmp perms: $(sh_try 'ls -ld /tmp')"
if [ "$VARTMP" = "/tmp" ] || sh_try 'ls -ld /tmp' | grep -q 'drwx------'; then
    warn "CageFS fingerprint present — filesystem is jailed per-account."
    warn "Kernel/SUID/cap bugs still cross CageFS; file-visibility tricks usually do not."
fi
PWENT="$(sh_try 'wc -l < /etc/passwd')"
info "/etc/passwd entries visible: $PWENT (a virtualized cage shows very few)"

###############################################################################
hdr "3. sudo / su"
if has sudo; then
    info "sudo -n -l:"; out "$(sh_try 'sudo -n -l' | sed 's/^/    /')"
    if sh_try 'sudo -n -l' | grep -qiE 'NOPASSWD|\(ALL|/bin/(ba)?sh'; then
        good "sudo rule may be abusable (NOPASSWD / shell)."; add "SUDO: review 'sudo -l' rules (GTFOBins)"
    fi
else
    bad "sudo not installed (typical in CageFS) — no sudo path."
fi

###############################################################################
hdr "4. SUID / SGID binaries (GTFOBins)"
SUID="$(sh_try 'find / -xdev -perm -4000 -type f 2>/dev/null')"
SGID="$(sh_try 'find / -xdev -perm -2000 -type f 2>/dev/null')"
if [ -n "$SUID" ]; then out "SUID:"; out "$(echo "$SUID" | sed 's/^/    /')"; else bad "No SUID binaries visible."; fi
[ -n "$SGID" ] && { out "SGID:"; out "$(echo "$SGID" | sed 's/^/    /')"; }
# flag classic GTFOBins SUIDs
echo "$SUID" | grep -qE '/(find|nmap|vim|less|more|nano|awk|gawk|perl|python|ruby|env|bash|dash|cp|mv|tar|zip|gdb|node|php|socat|busybox)$' \
    && { good "GTFOBins-capable SUID present."; add "SUID: abuse a GTFOBins binary above"; }
# writable SUID = instant win
while read -r b; do [ -n "$b" ] && [ -w "$b" ] && { good "WRITABLE SUID: $b"; add "SUID: writable SUID binary $b"; }; done <<< "$SUID"

###############################################################################
hdr "5. File capabilities"
if has getcap; then
    CAPS="$(sh_try 'getcap -r / 2>/dev/null')"
    if [ -n "$CAPS" ]; then
        out "$(echo "$CAPS" | sed 's/^/    /')"
        echo "$CAPS" | grep -qiE 'cap_setuid|cap_setgid|cap_sys_admin|cap_sys_module|cap_dac_(override|read_search)|cap_sys_ptrace' \
            && { good "Dangerous capability present."; add "CAP: abuse capability above"; }
    else bad "No file capabilities found."; fi
else bad "getcap not available."; fi

###############################################################################
hdr "6. Root cron / timers running account-writable files"
for f in /etc/crontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* ; do
    [ -r "$f" ] && out "    $f:" && out "$(sh_try "grep -vE '^\s*#|^\s*$' '$f'" | sed 's/^/        /')"
done
# writable cron targets
WR="$(sh_try 'find /etc/cron* /var/spool/cron -writable 2>/dev/null')"
[ -n "$WR" ] && { good "Writable cron path(s):"; out "$(echo "$WR" | sed 's/^/    /')"; add "CRON: write to a root-run cron target above"; }
# scripts referenced by cron that we can write
for f in /etc/crontab /etc/cron.d/*; do
    [ -r "$f" ] || continue
    for s in $(grep -oE '/[A-Za-z0-9_./-]+\.(sh|pl|py)' "$f" 2>/dev/null | sort -u); do
        [ -w "$s" ] && { good "Root cron runs writable script: $s"; add "CRON: writable script $s"; }
    done
done
has systemctl && info "systemd timers:" && out "$(sh_try 'systemctl list-timers --all --no-pager 2>/dev/null | head -15' | sed 's/^/    /')"

###############################################################################
hdr "7. Local privileged services / sockets"
if has ss; then out "$(sh_try 'ss -ltnp 2>/dev/null' | sed 's/^/    /')"; elif has netstat; then out "$(sh_try 'netstat -ltnp 2>/dev/null' | sed 's/^/    /')"; fi
info "unix sockets (root-owned daemons may trust local conns):"
out "$(sh_try 'ls -la /run/*.sock /var/run/*.sock /run/mysqld/*.sock /var/lib/mysql/*.sock 2>/dev/null' | sed 's/^/    /')"
info "Try local DB as root if creds leak (see §9): mysql -uadmin -p<psa> / mysql --socket=..."

###############################################################################
hdr "8. Writable sensitive files & PATH hijack"
info "PATH=$PATH"
for d in $(echo "$PATH" | tr ':' ' '); do
    w="$(sh_try "find '$d' -maxdepth 1 -writable -type f 2>/dev/null")"
    [ -n "$w" ] && { good "World/own-writable file in PATH dir $d:"; out "$(echo "$w" | sed 's/^/    /')"; add "PATH: writable binary in PATH"; }
done
for f in /etc/passwd /etc/shadow /etc/sudoers /etc/ld.so.preload /etc/ld.so.conf; do
    [ -w "$f" ] && { good "WRITABLE sensitive file: $f"; add "FILE: writable $f"; }
done
# NFS no_root_squash
sh_try 'cat /etc/exports 2>/dev/null' | grep -q no_root_squash && { good "/etc/exports has no_root_squash"; add "NFS: no_root_squash"; }

###############################################################################
hdr "9. Secrets in this account (lateral pivot, not vertical)"
info "These do not give root directly but can unlock admin/DB/other hosts."
HOME_DIR="${HOME:-$(pwd)}"
info "SSH keys:"; out "$(sh_try "ls -la $HOME_DIR/.ssh 2>/dev/null" | sed 's/^/    /')"
info "App config / env files holding creds:"
out "$(sh_try "grep -rilE 'password|passwd|secret|api[_-]?key|token|DB_PASS' $HOME_DIR --include='*.php' --include='*.env' --include='*.ini' --include='*.conf' --include='*.json' -l 2>/dev/null | head -20" | sed 's/^/    /')"
info "Readable Plesk admin creds (needs root normally): $(sh_try 'ls -la /etc/psa/.psa.shadow 2>/dev/null || echo not-readable')"

###############################################################################
hdr "10. Container / VM / direct-kernel-memory escape"
[ -f /.dockerenv ] && good "/.dockerenv present (container)."
[ -w /proc/sysrq-trigger ] && { good "/proc/sysrq-trigger WRITABLE"; add "ESCAPE: writable sysrq-trigger"; }
{ [ -w /dev/mem ] || [ -w /dev/kmem ]; } && { good "/dev/mem or /dev/kmem WRITABLE"; add "ESCAPE: writable kernel memory"; }
info "uid_map: $(sh_try 'cat /proc/self/uid_map')"

###############################################################################
hdr "SUMMARY — candidate root vectors"
if [ ${#CANDIDATES[@]} -eq 0 ]; then
    bad "No local root-escalation vector found with these read-only checks."
    info "Most probable remaining path on CloudLinux: an LPE the running kernel"
    info "is still vulnerable to — confirm the EFFECTIVE (KernelCare) level in §1"
    info "against linux-exploit-suggester / public advisories. Otherwise the"
    info "realistic finding is: account fully compromised, contained by CageFS."
else
    for c in "${CANDIDATES[@]}"; do good "$c"; done
    warn "These are LEADS to verify by hand — this script does not exploit anything."
fi
out ""
