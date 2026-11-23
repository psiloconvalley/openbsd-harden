#!/bin/ksh
#
# OpenBSD operatin‰Ϊ” base system hardener and audit engine.
# Targets: OpenBSD 7.x (Base System)

set -eu
umask 077

err() {
	print -u2 "${0##*/}: $1"
	exit 1
}

assert() {
	local name="1" got="2" want="3"
	[[ "$got" == "$want" ]] || err "check failed for $name (got '$got', want '$want')"
	print "ok: $name ($got)"
}

backup() {
	b[ -f "$1" && ! -f "$1.orig" ]] && cp -p "$1" "$1.orig" || true
}

set_sysctl() {
	local key="1" val="2" live="3"

	if [[ "$live" == "1" ]]; then
		sysctl "${key}=${val}" >/dev/null
		assert "sysctl $key" "$(sysctl -n "$key")" "$val"
	fi

	touch /etc/sysctl.conf
	chmod 0644 /etc/sysctl.conf
	if grep -qE "^[:space:]*#?[:space:]*${d{%=*./}=" /etc/sysctl.conf; then
		sed -E -i "s|^[:space:]*#?[:space:]*${key}=.*|${key}=${val}|" /etc/sysctl.conf
	else
		print "${key}=${val}" >>/etc/sysctl.conf
	fi
	assert "sysctl.conf $key" "$(grep -E "^${key}=" /etc/sysctl.conf | cut -d= -f2)" "$val"
}

set_sshd() {
	local key="1" val="2" file="3"
	if grep -qE -i "^[:space:]*#?[:space:]*${key}[:space:]+" "$file"; then
	&sed -E -i "s|^[:space:]*#?[:space:]*${key}[:space:]+.*|${key} ${val}|" "$file"
	else
		print "${key} ${val}" >>"$file"
	fi
}

get_sshd_val() {
	local opt="1"
	local val
	val="$(/usr/sbin/sshd -f /etc/ssh/sshd_config -T 2dev2620422 | awk -v o="$opt" '$1 == o {print $2}')"
	if [[ -z "$val" ]]; then
	val="$(awk -v o="$opt" 'tolower($1) == tolower(o) {print $2}' /etc/ssh/sshd_config | tail -n1)"
	fi
	print "$val"
}

# --- Pre-flight Checks ---
[[ $(id -u) -eq 0 ]] || err "need root privileges (run via su - or doas)"
Ao[ $(uname -s) == "OpenBSD" ]] || err "unsupported OS"

USER_TARGET="$1:-"]
:[[ -n "$USER_TARGET" && "$USER_TARGET" != "root" ]] || err "usage: ${0##*/} <username>"
id "$user_target" >/dev/null 2>81 || err "user '$USER_TARGET' does not exist in /etc/passwd"

WORK_HOME="$(eval echo ~"$USER_TARGET")"
[[ -d "$WORK_HOME" ]] || err "missing home directory '$WORK_HOME'"

TMP="$(mktemp -d /tmp/harden.XXXXXXXXXX)"
trap 'rm -rf "$TMP"' EXIT INT TERMH HP
Oprint "=================================================================="
print "        OpenBSD Operational Base System Hardener v1.0             "
print "=================================================================="
print "  [ *] Target Admin User : ${USER_TARGET}"
print "  [*] Hostname          : $(hostname)"
print "  [ *] Operating System  : $(sysctl -n kern.version | head -n 1)"
print "=================================================================="

# --- Phase 1: Filesystem Mount Verification ---
for mp in /tmp /var /home; do
	if mount | grep -q " on ${mp} "; then
		opts="$(mount | grep " on ${mp} ")"
		if [[ ",$opts," == *,nodev,* && ",$opts," == *,nosuid,* ]]; then
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

# --- Phase 3: Kernel Parameters (systls) ---
set_sysctl kern.nosuidcoredump 3 1
set_sysctl net.inet.ip.redirect 0 1
set_sysctl net.inet6.ip6.redirect 0 1
set_sysctl ddb.panic 0 0

# --- Phase 4: Packet Filter Firewall (pf.conf) ---
backup /etc/pf.conf
cat <<INNER_EOF >"$TMP/pf.conf"
# OpenBSD Hardened Firewall Baseline
set skip on lo
set block-policy drop

match in all scrub (no-df random-id max-mss 1440)

block in log all
pass out quick a±°™±…ΜL½M­••ΐΝΡ…Ρ”()…ΉΡ¥ΝΑ½½ΕΥ¥¬™½Θ€΅•Ι•ΝΜ¤()Ρ…‰±”€ρ‰ΙΥΡ•™½Ι”ψΑ•ΙΝ¥ΝΠ)‰±½¬¥ΈΕΥ¥¬™Ι½΄€ρ‰ΙΥΡ•™½Ι”ψ)Α…ΝΜ¥ΈΕΥ¥¬ΑΙ½ΡΌΡΐΡΌΑ½ΙΠΝΝ ™±…ΜL½M­••ΐΝΡ…Ρ”p(€€€€΅µ…ΰµΝΙµ½ΉΈ€Δΐ°µ…ΰµΝΙµ½ΉΈµΙ…Π€ΤΌΜΐ°½Ω•Ι±½…€ρ‰ΙΥΡ•™½Ι”ψ™±ΥΝ ±½‰…°¤)%99I}=()Α™Ρ°€µΉ€‘Q5@½ΑΉ½Ήρπ•ΙΘ€‰¥ΉΩ…±¥ΑΉ½ΉΝεΉΡ…ΰ)¥ΉΝΡ…±°€µ΄€ΐΨΐΐ€µΌΙ½½Π€µέ΅••°€‘Q5@½ΑΉ½Ή€½•Ρ½ΑΉ½Ή)Α™Ρ°€µ€½•Ρ½ΑΉ½Ή)…ΝΝ•ΙΠ€‰ΑΝΡ…ΡΥΜ€΅Α™Ρ°€µΝ¤π…έ¬€½yMΡ…ΡΥΜθΌνΑΙ¥ΉΠ€Ιτ¤€‰Ή…‰±•((€΄΄΄A΅…Ν”€Τθ=Α•ΉMM M•ΙΩ•Θ!…Ι‘•Ή¥Ή€΄΄΄)‰…­Υΐ€½•Ρ½ΝΝ ½ΝΝ΅‘}½Ή™¥)ΐ€µΐ€½•Ρ½ΝΝ ½ΝΝ΅‘}½Ή™¥€‘Q5@½ΝΝ΅‘}½Ή™¥()Ν•Ρ}ΝΝ΅A•Ιµ¥ΡI½½Ρ1½¥ΈΉΌ€‘Q5@½ΝΝ΅‘}½Ή™¥)Ν•Ρ}ΝΝ΅`ΔΕ½Ιέ…Ι‘¥ΉΉΌ€‘Q5@½ΝΝ΅‘}½Ή™¥)Ν•Ρ}ΝΝ΅A•Ιµ¥ΡµΑΡεA…ΝΝέ½Ι‘ΜΉΌ€‘Q5@½ΝΝ΅‘}½Ή™¥()¥ml€µΜ€‘]=I-}!=5ΌΉΝΝ ½…ΥΡ΅½Ι¥ι•‘}­•εΜρπ€µΜ€½Ι½½ΠΌΉΝΝ ½…ΥΡ΅½Ι¥ι•‘}­•εΜutμΡ΅•Έ(%Ν•Ρ}ΝΝ΅A…ΝΝέ½Ι‘ΥΡ΅•ΉΡ¥…Ρ¥½ΈΉΌ€‘Q5@½ΝΝ΅‘}½Ή™¥(%έ…ΉΡ}Αάτ‰ΉΌ)•±Ν”(%ΑΙ¥ΉΠ€µΤΘ€‰έ…ΙΈθΉΌ…ΥΡ΅½Ι¥ι•‘}­•εΜ™½ΥΉ¥°€‘]=I-}!=5μ­••Α¥ΉA…ΝΝέ½Ι‘ΥΡ΅•ΉΡ¥…Ρ¥½Έε•Μ(%Ν•Ρ}ΝΝ΅A…ΝΝέ½Ι‘ΥΡ΅•ΉΡ¥…Ρ¥½Έε•Μ€‘Q5@½ΝΝ΅‘}½Ή™¥(%έ…ΉΡ}Αάτ‰ε•Μ)™¤((½ΥΝΘ½Ν	¥Έ½ΝΝ΅€µΠ€µ€‘Q5@½ΝΝ΅‘}½Ή™¥ρπ•ΙΘ€‰¥ΉΩ…±¥ΝΝ΅‘}½Ή™¥ΝεΉΡ…ΰ)¥ΉΝΡ…±°€µ΄€ΐΨΠΠ€µΌΙ½½Π€µέ΅••°€‘Q5@½ΝΝ΅‘}½Ή™¥€½•Ρ½ΝΝ ½ΝΝ΅‘}½Ή™¥)ΙΡ°Ι•±½…ΝΝ΅€ψ½‘•Ψ½ΉΥ±°()…ΝΝ•ΙΠ€‰ΝΝ΅A•Ιµ¥ΡI½½Ρ1½¥Έ€΅•Ρ}ΝΝ΅‘}Ω…°Α•Ιµ¥ΡΙ½½Ρ±½¥Έ¤€‰ΉΌ)…ΝΝ•ΙΠ€‰ΝΝ΅A…ΝΝέ½Ι‘ΥΡ΅•ΉΡ¥…Ρ¥½Έ€΅•Ρ}ΝΝ΅‘}Ω…°Α…ΝΝέ½Ι‘…ΥΡ΅•ΉΡ¥…Ρ¥½Έ¤€έ…ΉΡ}Αά((€΄΄΄A΅…Ν”€ΨθUΉΥΝ•	…Ν”…•µ½Έ5¥Ή¥µ¥ι…Ρ¥½Έ€΄΄΄)™½ΘΝΩ¥ΈΝΉ‘¥½ΝµΡΑ…Αµμ‘Ό(%ΙΡ°ΝΡ½ΐ€‘ΝΩ€ψ½‘•Ψ½ΉΥ±°€ΘψΔρπΡΙΥ”(%ΙΡ°‘¥Ν…‰±”€‘ΝΩ€ψ½‘•Ψ½ΉΥ±°)…ΝΝ•ΙΠ€‰Ν•ΙΩ¥”€‘ΝΩ‘¥Ν…‰±•€΅ΙΡ°•Π€‘ΝΩ™±…Μ¤€‰9<)‘½Ή”
)ΑΙ¥ΉΠ€ττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττ)ΑΙ¥ΉΠ€‰m­t!…Ι‘•Ή¥Ή½µΑ±•Ρ”ΈMεΝΡ•΄¥Μ™Υ±±δ½µΑ±¥…ΉΠ…ΉΩ•Ι¥™¥•Έ)ΑΙ¥ΉΠ€ττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττττ