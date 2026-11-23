#!/bin/ksh
#
# OpenBSD base system hardening script.

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
	if grep -qE "^${key}=" /etc/sysctl.conf; then
		sed -E -i "s|^${key}=.*|${key}=${val}|" /etc/sysctl.conf
	else
		print "${key}=${val}" >>/etc/sysctl.conf
	fi
	assert "sysctl.conf $key" "$(grep -E "^${key}=" /etc/sysctl.conf | cut -d= -f2)" "$val"
}

[[ $(id -u) -eq 0 ]] || err "need root privileges"
[[ $(uname -s) == "OpenBSD" ]] || err "unsupported OS"

USER_TARGET="${1:-}"
[[ -n "$USER_TARGET" && "$USER_TARGET" != "root" ]] || err "usage: ${0##*/} user"
id "$USER_TARGET" >/dev/null 2>&1 || err "user $USER_TARGET does not exist"

USER_HOME="$(eval echo ~"$USER_TARGET")"
[[ -d "$USER_HOME" ]] || err "missing home directory for $USER_TARGET"

TMP="$(mktemp -d /tmp/harden.XXXXXXXXXX)"
trap 'rm -rf "$TMP"' EXIT INT TERM HUP

# Check mount flags on standard partitions.
for mp in /tmp /var /home; do
	if mount | grep -q " on ${mp} "; then
		opts="$(mount | grep " on ${mp} ")"
		[[ "$opts" == *nodev* && "$opts" == *nosuid* ]] ||
			print -u2 "warn: $mp missing nodev or nosuid"
	fi
done

# Configure doas(1).
backup /etc/doas.conf
print "permit persist $USER_TARGET as root" >"$TMP/doas.conf"
doas -C "$TMP/doas.conf" || err "invalid doas.conf syntax"
install -m 0600 -o root -g wheel "$TMP/doas.conf" /etc/doas.conf
assert "doas.conf mode" "$(stat -f '%Mp%Lp' /etc/doas.conf)" "0600"

# Tune kernel parameters.
set_sysctl kern.nosuidcoredump 3 1
set_sysctl net.inet.ip.redirect 0 1
set_sysctl net.inet6.ip6.redirect 0 1
set_sysctl ddb.panic 0 0

# Configure pf(4).
backup /etc/pf.conf
cat <<'INNER_EOF' >"$TMP/pf.conf"
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

# Configure sshd(8).
backup /etc/ssh/sshd_config
cp -p /etc/ssh/sshd_config "$TMP/sshd_config"

sed -E -i 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$TMP/sshd_config"
sed -E -i 's/^#?X11Forwarding.*/X11Forwarding no/' "$TMP/sshd_config"
sed -E -i 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$TMP/sshd_config"

if [[ -s "$USER_HOME/.ssh/authorized_keys" ]]; then
	sed -E -i 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' "$TMP/sshd_config"
	want_pw="no"
else
	print -u2 "warn: no authorized_keys found; keeping PasswordAuthentication yes"
	sed -E -i 's/^#?PasswordAuthentication.*/PasswordAuthentication yes/' "$TMP/sshd_config"
	want_pw="yes"
fi

/usr/sbin/sshd -t -f "$TMP/sshd_config" || err "invalid sshd_config"
install -m 0644 -o root -g wheel "$TMP/sshd_config" /etc/ssh/sshd_config
rcctl reload sshd >/dev/null

assert "sshd PermitRootLogin" "$(/usr/sbin/sshd -T | awk '$1 == "permitrootlogin" {print $2}')" "no"
assert "sshd PasswordAuthentication" "$(/usr/sbin/sshd -T | awk '$1 == "passwordauthentication" {print $2}')" "$want_pw"

# Disable unused base daemons.
for svc in sndiod smtpd apmd; do
	rcctl stop "$svc" >/dev/null 2>&1 || true
	rcctl disable "$svc" >/dev/null
	assert "service $svc" "$(rcctl get "$svc" flags)" "NO"
done
