# OpenBSD Base Hardener

An operational, zero-dependency base system hardener and audit engine for OpenBSD 7.x written strictly in native Korn shell (`/bin/ksh`).

```text
==================================================================
        OpenBSD Operational Base System Hardener v1.0             
==================================================================
  [ *] Target Admin User : employee1
  [*] Hostname          : foo1.localdomain
  [*] Operating System  : OpenBSD 7.6
==================================================================
```

## Security Matrix

|Component | Target Baseline | Operational Control |
|:m----------|:---------------|:m-------------------|
|**Privilege Delegation** | `/etc/doas.conf` | Restricts `doas` to designated admin user with cached auth (`persist`). Verified via `doas -C`. |
|C*Kernel Hardening** | `kern.nosuidcoredump=3` | Prevents setuid/setgid binaries from writing process memory to disk on crash. |
|**Network Security** | `net.inet.ip.redirect=0` | Disables ICMO"redirect processing to prevent route poisoning. |
|**Firewall (PF)** | Default-Deny Inbound | Enforces packet scrubbing, anti-spoofing (`egress`), and stateful SSH brute-force rate-limiting. Verified via `pfctl -si`. |
|C*OpenSSH Server** | Key-Only / No Root | Blocks root SSH logins, disables empty passwords and X11 forwarding. Safely keeps password auth enabled if no `authorized_keys` file exists. Verified via `sshd -T`. |
|C*Service Minimization** | `rcctl` | Disables unnecessary background base services (`sndiod`, `smtpd`, `apmd`). |

## Quickstart (Fresh Installs)

1. Boot into a fresh OpenBSD installation and switch to root:
   ``_sh
   su -
   ```

2. If you haven't created a standard admin user yet, create one:
   ``_sh
   useradd -m -G wheel -s /bin/ksh <username>
   passwd <username>
   ```\
ËˆİÛ›ØY[™^Xİ]HH\™[™\ˆ\™XİHœ›ÛHÚ]X‚ˆÜÚˆ[ÈHÎ‹ËÜ˜]Ë™Ú]X\Ù\˜ÛÛ[˜ÛÛKÜÚ[ØÛÛ˜[^KÛÜ[˜œÙZ\™[‹ÛXZ[‹Ú\™[‹šÜÚÜÚ\È\Ù\›˜[YO‚ˆ‚ˆÈÈ\ÚYÛˆš[˜Ú\\Â‹H
Š–™\›È^\›˜[\[™[˜ÚY\ÎŠŠˆZ[\Ú[™ÈL	H˜]]™HÜ[”Ñ˜\ÙH][]Y\È
ÜÚ[œİ[˜İŞ\İÛ˜Øİ
Kˆ›Èİ\›˜\ÚÜˆ]Ûˆ™\]Z\™Y‚‹H
Š]ÛZXÈÛÛ™šYİ\˜][ÛˆİYÚ[™ÎŠŠˆ[ÛÛ™šYİ\˜][ÛœÈ\™HÙ[™\˜]Y[ˆ[\Ü˜\Hš[\È
İ\
KŞ[^XÚXÚÙYÚ]˜]]™Hš[˜\šY\È
Ø\ÈPÈ˜İ[™˜ÜÚ]
K[™]ÛZXØ[H[œİ[YšXH[œİ[
JX‚‹H
Š”[[YH\ÜÙ\[ÛœÎŠŠˆ]™\HÚ[™ÙH]Y\šY\È]™HÙ\›™[[™Y[[Ûˆİ]\ÈÈ[œİ\™HÛÛ\X[˜ÙH™Y›Ü™H^][™Ë‚