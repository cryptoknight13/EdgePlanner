#!/usr/bin/env bash
# Turn this machine into the EdgePlanner box (the Pi; install on ONE box only):
#   - web page as a service on web.port (0.0.0.0, LAN-reachable, login from .env) at http://<name>/
#     for every name in config/settings.yaml web.hostnames: *.local by mDNS (no router change), others by the
#     box's own DNS (devices use it only when their DNS points at this box).
#   - dnsmasq as this box's resolver: box.dns_servers upstream (OpenDNS), LAN reverse lookups to the router.
#   - names follow the default-route NIC: NetworkManager re-publishes on every IP/interface change.
#   - with a network cable plugged in, Wi-Fi is dropped (one LAN address); it reconnects when the cable is out.
#   - setup Wi-Fi (box.setup_wifi): with no cable and no known Wi-Fi wait_seconds after boot, the box starts its
#     own Wi-Fi; its network page then switches the box to the customer's Wi-Fi.
# Values come from config/settings.yaml (web, box) and secrets from .env (EDGEPLANNER_USER, EDGEPLANNER_PASSWORD,
# SETUP_WIFI_PASSWORD); nothing network-specific is written into this script. Idempotent: run again after a change.
#
#   sudo bash scripts/install_box.sh
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OWNER=$(stat -c %U "$ROOT")
# shell-quoted assignments from config/settings.yaml
eval "$("$ROOT/.venv/bin/python" - "$ROOT/config/settings.yaml" <<'PY'
import ipaddress, shlex, sys, yaml
s = yaml.safe_load(open(sys.argv[1]))
w = s["box"]["setup_wifi"]
net = ipaddress.ip_network(w["subnet"])
print(f"NAMES={shlex.quote(' '.join(s['web']['hostnames']))}")
print(f"PORT={int(s['web']['port'])}")
print(f"DNS_SERVERS={shlex.quote(' '.join(str(ipaddress.ip_address(a)) for a in s['box']['dns_servers']))}")
print(f"HOTSPOT={shlex.quote(w['ssid'])}")
print(f"HOTSPOT_IP={net[1]}")
print(f"HOTSPOT_ADDR={net[1]}/{net.prefixlen}")
print(f"WAIT_TRIES={max(1, int(w['wait_seconds']) // 2)}")
PY
)"
env_value() { sed -n "s/^$1=//p" "$ROOT/.env" 2>/dev/null | tail -n 1; }
for k in EDGEPLANNER_USER EDGEPLANNER_PASSWORD SETUP_WIFI_PASSWORD; do
  [ -n "$(env_value $k)" ] || { echo "set $k in $ROOT/.env first" >&2; exit 1; }
done
HOTSPOT_PSK=$(env_value SETUP_WIFI_PASSWORD)
[ ${#HOTSPOT_PSK} -ge 8 ] || { echo "SETUP_WIFI_PASSWORD must be at least 8 characters" >&2; exit 1; }

missing=""
command -v dnsmasq >/dev/null || missing="$missing dnsmasq-base"
command -v avahi-publish >/dev/null || missing="$missing avahi-utils"
command -v avahi-daemon >/dev/null || missing="$missing avahi-daemon"
[ -z "$missing" ] || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $missing
systemctl enable --now avahi-daemon >/dev/null

chown "$OWNER": "$ROOT/.env"; chmod 600 "$ROOT/.env"

mkdir -p /etc/edgeplanner
echo "$NAMES" > /etc/edgeplanner/names

# Current addresses -> /run/edgeplanner/: ip (for mDNS: LAN address, else the setup Wi-Fi's), hosts,
# listen.conf and rev.conf (dnsmasq: LAN only, so it never clashes with the setup Wi-Fi's own DHCP/DNS).
cat > /usr/local/sbin/edgeplanner-net <<'EOF'
#!/bin/sh
set -eu
mkdir -p /run/edgeplanner
cd /run/edgeplanner
dev=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
gw=$(ip -4 route show default | awk '{print $3; exit}')
lan=""; net=""
if [ -n "$dev" ]; then
  lan=$(ip -4 -o addr show dev "$dev" | awk '{split($4, a, "/"); print a[1]; exit}')
  net=$(ip -4 route show dev "$dev" scope link proto kernel | awk '{print $1; exit}')
fi
ip=${lan:-$(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}')}
echo "$ip" > ip
if [ -n "$ip" ]; then echo "$ip $(cat /etc/edgeplanner/names)" > hosts; else : > hosts; fi
echo "listen-address=127.0.0.1" > listen.conf
: > rev.conf
if [ -n "$lan" ]; then
  echo "listen-address=$lan" >> listen.conf
  # Reverse lookups for the LAN still go to the router, which knows the DHCP names discovery labels hosts with.
  echo "rev-server=$net,$gw" > rev.conf
fi
EOF
chmod 755 /usr/local/sbin/edgeplanner-net

cat > /etc/edgeplanner/dnsmasq.conf <<EOF
# EdgePlanner DNS: own names from /run/edgeplanner/hosts, everything else via box.dns_servers.
# Listens on 127.0.0.1 and the LAN address only (a private address behind the router).
port=53
bind-interfaces
conf-file=/run/edgeplanner/listen.conf
domain-needed
no-resolv
no-hosts
$(for s in $DNS_SERVERS; do echo "server=$s"; done)
addn-hosts=/run/edgeplanner/hosts
conf-file=/run/edgeplanner/rev.conf
cache-size=1000
EOF

cat > /etc/systemd/system/edgeplanner-dns.service <<'EOF'
[Unit]
Description=EdgePlanner DNS (dnsmasq, OpenDNS upstream)
After=network-online.target
Wants=network-online.target

[Service]
ExecStartPre=/usr/local/sbin/edgeplanner-net
ExecStart=/usr/sbin/dnsmasq -k --conf-file=/etc/edgeplanner/dnsmasq.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/edgeplanner-mdns.service <<'EOF'
[Unit]
Description=EdgePlanner mDNS names (*.local)
After=avahi-daemon.service network-online.target
Requires=avahi-daemon.service

[Service]
ExecStartPre=/usr/local/sbin/edgeplanner-net
# -R: no reverse record, so the box keeps its own hostname for its IP.
ExecStart=/bin/sh -c 'ip=$(cat /run/edgeplanner/ip); [ -n "$ip" ] || exec sleep infinity; for n in $(cat /etc/edgeplanner/names); do case $n in *.local) avahi-publish -a -R "$n" "$ip" & ;; esac; done; wait'
# always: a name taken by another box ends avahi-publish cleanly; keep retrying so it is claimed once free.
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/edgeplanner-web.service <<EOF
[Unit]
Description=EdgePlanner web page on port $PORT
After=network-online.target

[Service]
User=$OWNER
WorkingDirectory=$ROOT
ExecStart=$ROOT/.venv/bin/python run.py web --host 0.0.0.0 --port $PORT
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# Re-publish whenever the network changes (new IP, Wi-Fi <-> cable, reconnect, setup Wi-Fi up/down).
cat > /etc/NetworkManager/dispatcher.d/50-edgeplanner <<'EOF'
#!/bin/sh
# Cable in: drop Wi-Fi, so the box has one address on the LAN (a scan would list the second one as a device).
# Cable out: Wi-Fi reconnects to its known network.
if [ "$(nmcli -g GENERAL.TYPE dev show "$1" 2>/dev/null)" = ethernet ]; then
  wifi=$(nmcli -t -f DEVICE,TYPE dev | awk -F: '$2 == "wifi" {print $1; exit}')
  if [ -n "$wifi" ]; then
    case "$2" in
      up) nmcli dev disconnect "$wifi" >/dev/null 2>&1 ;;
      down) nmcli dev connect "$wifi" >/dev/null 2>&1 ;;
    esac
  fi
fi
case "$2" in
  up|down|dhcp4-change|connectivity-change) systemctl try-restart edgeplanner-dns.service edgeplanner-mdns.service ;;
esac
EOF
chmod 755 /etc/NetworkManager/dispatcher.d/50-edgeplanner

# This box resolves through its own DNS too (box.dns_servers directly as fallback); NetworkManager leaves resolv.conf alone.
printf '[main]\ndns=none\n' > /etc/NetworkManager/conf.d/50-edgeplanner-dns.conf
printf 'nameserver 127.0.0.1\n%s\n' "$(for s in $DNS_SERVERS; do echo "nameserver $s"; done)" > /etc/resolv.conf
systemctl reload NetworkManager

# ---- Setup Wi-Fi (only when the box has a Wi-Fi radio) ----
WIFI=$(nmcli -t -f DEVICE,TYPE dev | awk -F: '$2 == "wifi" {print $1; exit}')
if [ -n "$WIFI" ]; then
  # Recreated on every run so a changed name, range or password takes effect.
  nmcli -t -f NAME con show | grep -qxF "$HOTSPOT" && nmcli con delete id "$HOTSPOT" >/dev/null
  nmcli con add type wifi ifname "$WIFI" con-name "$HOTSPOT" \
    autoconnect no ssid "$HOTSPOT" mode ap 802-11-wireless.band bg ipv4.method shared ipv4.addresses "$HOTSPOT_ADDR" \
    ipv6.method disabled wifi-sec.key-mgmt wpa-psk wifi-sec.proto rsn wifi-sec.pairwise ccmp wifi-sec.psk "$HOTSPOT_PSK" >/dev/null
  # On the setup Wi-Fi every name points at the box, so a phone's captive-portal check opens the page.
  mkdir -p /etc/NetworkManager/dnsmasq-shared.d
  echo "address=/#/$HOTSPOT_IP" > /etc/NetworkManager/dnsmasq-shared.d/edgeplanner.conf

  cat > /usr/local/sbin/edgeplanner-hotspot <<EOF
#!/bin/sh
# Boot: wait for a cable or a known Wi-Fi; with neither after box.setup_wifi.wait_seconds, list nearby Wi-Fi
# (the radio is busy once it is an access point) and start the setup Wi-Fi.
for i in \$(seq $WAIT_TRIES); do ip -4 route show default | grep -q . && exit 0; sleep 2; done
mkdir -p /run/edgeplanner
nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list --rescan yes > /run/edgeplanner/wifi-scan.txt 2>/dev/null || true
nmcli con up "$HOTSPOT"
EOF
  chmod 755 /usr/local/sbin/edgeplanner-hotspot

  cat > /etc/systemd/system/edgeplanner-hotspot.service <<'EOF'
[Unit]
Description=EdgePlanner setup Wi-Fi when the box has no network
After=NetworkManager.service
Wants=NetworkManager.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/edgeplanner-hotspot

[Install]
WantedBy=multi-user.target
EOF

  # Called by the web page (via sudo, this one command only): network name and password on stdin.
  cat > /usr/local/sbin/edgeplanner-wifi <<EOF
#!/bin/sh
set -eu
IFS= read -r SSID || true
IFS= read -r PSK || true
[ -n "\$SSID" ] && [ \$(printf %s "\$SSID" | wc -c) -le 32 ] || { echo "pick a Wi-Fi network" >&2; exit 1; }
n=\$(printf %s "\$PSK" | wc -c)
[ "\$n" -eq 0 ] || { [ "\$n" -ge 8 ] && [ "\$n" -le 63 ]; } || { echo "a Wi-Fi password is 8 to 63 characters" >&2; exit 1; }
mkdir -p /run/edgeplanner
echo "connecting to \$SSID…" > /run/edgeplanner/wifi-result.txt
# Switch in the background so the page gets its answer before this box leaves the current Wi-Fi.
# The password travels in the environment (root-only), not on a command line.
SSID="\$SSID" PSK="\$PSK" setsid /usr/local/sbin/edgeplanner-wifi-switch >/dev/null 2>&1 </dev/null &
EOF
  cat > /usr/local/sbin/edgeplanner-wifi-switch <<EOF
#!/bin/sh
out=/run/edgeplanner/wifi-result.txt
sleep 2
nmcli con down "$HOTSPOT" >/dev/null 2>&1 || true
# nmcli needs the network in a fresh scan to tell its security type; right after the setup Wi-Fi stops it is not.
for i in 1 2 3 4 5 6 7 8; do
  sleep 3
  nmcli -t -f SSID dev wifi list --rescan yes ifname "$WIFI" 2>/dev/null | grep -qxF "\$SSID" && break
done
known=\$(nmcli -t -f NAME con show | grep -cxF "\$SSID" || true)
old=""
# shortcut: nmcli takes the password as an argument (visible in ps for a moment); a single-user box.
if [ "\$known" -gt 0 ]; then
  if [ -n "\$PSK" ]; then
    old=\$(nmcli -s -g 802-11-wireless-security.psk con show id "\$SSID" 2>/dev/null || true)
    nmcli con modify id "\$SSID" wifi-sec.key-mgmt wpa-psk wifi-sec.psk "\$PSK" >/dev/null 2>&1
  fi
  msg=\$(nmcli -w 60 con up id "\$SSID" ifname "$WIFI" 2>&1)
elif [ -z "\$PSK" ]; then
  msg=\$(nmcli -w 60 dev wifi connect "\$SSID" ifname "$WIFI" 2>&1)
else
  msg=\$(nmcli -w 60 dev wifi connect "\$SSID" password "\$PSK" ifname "$WIFI" 2>&1)
fi
if [ \$? -eq 0 ]; then
  sleep 5
  echo "connected to \$SSID at \$(cat /run/edgeplanner/ip 2>/dev/null)" > \$out
  exit 0
fi
# A failed connect must not leave a wrong password behind: restore a known network's old one, drop a new profile.
if [ "\$known" -gt 0 ]; then
  [ -z "\$old" ] || nmcli con modify id "\$SSID" wifi-sec.psk "\$old" >/dev/null 2>&1 || true
else
  nmcli con delete id "\$SSID" >/dev/null 2>&1 || true
fi
echo "could not join \$SSID: \$(echo "\$msg" | tail -n 1)" > \$out
if ! ip -4 route show default | grep -q .; then
  nmcli -t -f SSID,SIGNAL,SECURITY dev wifi list --rescan yes > /run/edgeplanner/wifi-scan.txt 2>/dev/null || true
  nmcli con up "$HOTSPOT" >/dev/null 2>&1
fi
EOF
  chmod 755 /usr/local/sbin/edgeplanner-wifi /usr/local/sbin/edgeplanner-wifi-switch
  echo "$OWNER ALL=(root) NOPASSWD: /usr/local/sbin/edgeplanner-wifi" > /etc/sudoers.d/edgeplanner
  chmod 440 /etc/sudoers.d/edgeplanner
  visudo -cqf /etc/sudoers.d/edgeplanner
  systemctl daemon-reload
  systemctl enable edgeplanner-hotspot >/dev/null
fi

# Keep the system log across reboots (capped), so an unexpected reset leaves evidence.
mkdir -p /var/log/journal /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nSystemMaxUse=50M\n' > /etc/systemd/journald.conf.d/50-edgeplanner.conf
systemd-tmpfiles --create --prefix /var/log/journal >/dev/null
systemctl restart systemd-journald
journalctl --flush

systemctl daemon-reload
systemctl enable --now edgeplanner-dns edgeplanner-mdns edgeplanner-web >/dev/null
systemctl restart edgeplanner-dns edgeplanner-mdns edgeplanner-web
echo "ok: $NAMES -> $(cat /run/edgeplanner/ip) (web on port $PORT, owner $OWNER, setup Wi-Fi: ${WIFI:+$HOTSPOT on $WIFI})"
