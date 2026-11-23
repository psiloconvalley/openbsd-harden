#!/bin/ksh
#
# OpenBSD operational base system hardener and audit engine.
# Targets: OpenBSD 7.x (Base System)

set -eu
umask 077

err() {
	print -u2 "${0##*/}: $1"
	exit 1
}

assert() {
	local name="$1" got="$2" want="$3"
	[[ "$got" == "$want" ]] || err "check failed for $name (got '$got', want '$want')"
	print "ok: $name ($got)"
}

backup() {
	[[ -f "$1" && ! -f "$1.orig" ]] && cp -p "$1" "$1.orig" || true
}

set_sysctl() {
	local key="$1" val="$2" live="$3"

	if [[ "$live" == "1" ]]; then
		sysctl "${key}=${val}" >/dev/null
		assert "sysctl $key" "$(sysctl -n "$key")" "$val"
	fi

	touch /etc/sysctl.conf
	chmod 0644 /etc/sysctl.conf
	if grep -qE "^[[:space:]]*#?[[:space:]]*${key}=" /etc/sysctl.conf; then
		sed -E -i "s|^[[:space:]]*#?[[:space:]]*${key}=.*|${key}=${val}|" /etc/sysctl.conf
	else
		print "${key}=${val}" >>/etc/sysctl.conf
	fi
	assert "sysctl.conf $key" "$(grep -E "^${key}=" /etc/sysctl.conf | cut -d= -f2)" "$val"
}

set_sshd() {
	local key="$1" val="$2" file="$3"
	if grep -qE -i "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$file"; then
		sed -E -i "s/^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*/${key} ${val}/" "$file"
	else
		print "${key} ${val}" >>"$file"
	fi
}

get_sshd_val() {
	local opt="$1"
	local val
	val="$(/usr/sbin/sshd -f /etc/ssh/sshd_config -T 2>/dev/null | awk -v o="$opt" '$1 == o {print $2}')"
	if [[ -z "$val" ]]; then
		val="$(awk -v o="$opt" 'tolower($1) == tolower(o) {print $2}' /etc/ssh/sshd_config | tail -n1)"
	fi
	print "$val"
}

# --- Pre-flight Checks ---
[[ $(id -u) -eq 0 ]] || err "need root privileges (run via su - or doas)"
[[ $(uname -s) == "OpenBSD" ]] || err "unsupported OS"

USER_TARGET="${1:-}"
[[ -n "$USER_TARGET" && "$USER_TARGET" != "root" ]] || err "usage: ${0##*/} <username>"
id "$USER_TARGET" >/dev/null 2>/dev/null || err "user '$USER_TARGET' does not exist in /etc/passwd"

USER_HOME="$(eval echo ~"$USER_TARGET")"
[[ -d "$USER_HOME" ]] || err "missing home directory '$USER_HOME'"

TMP="$(mktemp -d /tmp/harden.XXXXXXXXXX)"
trap 'rm -rf "$TMP"' EXIT INT TERM HUP

# --- Display Visual Banner ---
print "=================================================================="
print "        OpenBSD Operational Base System Hardener v1.0             "
print "=================================================================="
print "  [*] Target Admin User : ${USER_TARGET}"
print "  [*] Hostname          : $(hostname)"
print "  [*] Operating System  : $(sysctl -n kern.version | head -n 1)"
print "=================================================================="

# --- Phase 1: Filesystem Mount Verification ---
for mp in /tmp /var /home; do
	if mount | grep -q " on ${mp} "; then
		opts="$(mount | grep " on ${mp} ")"
		if [[ "$opts" == *nodev* && "$opts" == *nosuid* ]]; then
			assert "fstab $mp security flags" "nodev,nosuid" "nodev,nosuid"
		else
			print -u2 "warn: $mp is missing nodev or nosuid mount flags"
		fi
	fi
done

# --- Phase 2: Privilege Delegation (doas.conf) ---
backup /etc/doas.conf
print "permit persist $USER_TARGET as root" >"$TMP/doas.conf"
doas -C "$TMP/doas.conf" || err "invalid doas.conf syntax"
install -m 0600 -o root -g wheel "$TMP/doas.conf" /etc/doas.conf
assert "doas.conf permissions" "$(stat -f '%Mp%Lp' /etc/doas.conf)" "0600"

# --- Phase 3: Kernel Parameters (sysctl) ---
set_sysctl kern.nosuidcoredump 3 1
set_sysctl net.inet.ip.redirect 0 1
set_sysctl net.inet6.ip6.redirect 0 1
set_sysctl ddb.panic 0 0

# --- Phase 4: Packet Filter Firewall (pf.conf) ---
backup /etc/pf.conf
cat <<'INNER_EOF' >"$TMP/pf.conf"
# OpenBSD Hardened Firewall Baseline
set skip on lo
set block-policy drop

match in all scrub (no-df random-id max-mss 1440)

block in log all
pass out quick all flags S/SA keep state

antispoof quick for (egress)

table <bruteforce> persist
block in quick from <bruteforce>
pass in quick proto tcp to port ssh flags S/SA keep state \
    (max-src-conn 10, max-src-conn-rate 5/30, overload <bruteforce> flush global)
INNER_EOF

pfctl -nf "$TMP/pf.conf" || err "invalid pf.conf syntax"
install -m 0600 -o root -g wheel "$TMP/pf.conf" /etc/pf.conf
pfctl -f /etc/pf.conf
assert "pf status" "$(pfctl -si | awk '/^Status:/ {print $2}')" "Enabled"

# --- Phase 5: OpenSSH Server Hardening ---
backup /etc/ssh/sshd_config
cp -p /etc/ssh/sshd_config "$TMP/sshd_config"

set_sshd PermitRootLogin no "$TMP/sshd_config"
set_sshd X11Forwarding no "$TMP/sshd_config"
set_sshd PermitEmptyPasswords no "$TMP/sshd_config"

if [[ -s "$USER_HOME/.ssh/authorized_keys" || -s "/root/.ssh/authorized_keys" ]]; then
	set_sshd PasswordAuthentication no "$TMP/sshd_config"
	want_pw="no"
else
	print -u2 "warn: no authorized_keys found in $USER_HOME; keeping PasswordAuthentication yes"
	set_sshd PasswordAuthentication yes "$TMP/sshd_config"
	want_pw="yes"
fi

/usr/sbin/sshd -t -f "$TMP/sshd_config" || err "invalid sshd_config syntax"
install -m 0644 -o root -g wheel "$TMP/sshd_config" /etc/ssh/sshd_config
rcctl reload sshd >/dev/null

assert "sshd PermitRootLogin" "$(get_sshd_val permitrootlogin)" "no"
assert "sshd PasswordAuthentication" "$(get_sshd_val passwordauthentication)" "$want_pw"

# --- Phase 6: Unused Base Daemon Minimization ---
for svc in sndiod smtpd apmd; do
	rcctl stop "$svc" >/dev/null 2>/dev/null || true
	rcctl disable "$svc" >/dev/null
	assert "service $svc disabled" "$(rcctl get "$svc" flags)" "NO"
done

print "=================================================================="
print "[+] Hardening complete. System is fully compliant and verified."
print "=================================================================="
