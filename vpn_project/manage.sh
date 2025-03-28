#!/bin/bash

# OpenVPN Client Management Script
# This script simplifies the management of OpenVPN clients, including creating, revoking, and retrieving client configurations.
# It also supports 2FA (Two-Factor Authentication) using Google Authenticator.

# Variables
ACTION=$1          # The action to perform (create, revoke, status, get)
CLIENT=$2          # The client username
CLIENTDIR="/opt/openvpn/clients"  # Directory to store client configurations

# Color codes for terminal output
R="\e[0;91m"  # Red
G="\e[0;92m"  # Green
W="\e[0;97m"  # White
B="\e[1m"     # Bold
C="\e[0m"     # Reset color

# Ensure the client directory exists
[ -d "$CLIENTDIR" ] || mkdir -p "$CLIENTDIR"

# Function: showHelp
# Displays usage information and exits the script.
function showHelp() {
    echo -e "${W}Usage:${C}"
    echo "  ./manage.sh create <username>   Create new VPN user"
    echo "  ./manage.sh revoke <username>   Remove VPN user"
    echo "  ./manage.sh status              List active certificates"
    echo "  ./manage.sh get <username>      Show local credentials"
    exit 1
}

# Function: newClient
# Creates a new OpenVPN client with the specified username.
# Generates certificates, a password, and a 2FA QR code.
function newClient() {
    CLIENT=${1:?}  # Client username (required)
    CLIENTEXISTS=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c -E "/CN=${CLIENT}\$")
    
    # Check if the client already exists
    if [[ $CLIENTEXISTS == '1' ]]; then
        echo -e "${R}User ${CLIENT} already exists${C}"
        exit 1
    fi

    # Verify Easy-RSA directory exists
    if [ ! -d "/etc/openvpn/server/easy-rsa/" ]; then
        echo -e "${R}Easy-RSA directory not found at /etc/openvpn/server/easy-rsa/${C}"
        exit 1
    fi

    # Create client directory
    CLIENTPATH="${CLIENTDIR}/${CLIENT}"
    mkdir -p "$CLIENTPATH"
    
    # Generate a random password
    PW=$(openssl rand -base64 16)
    echo "$PW" > "${CLIENTPATH}/pass.txt"

    # Certificate generation (using existing CA)
    cd /etc/openvpn/server/easy-rsa/ || exit
    echo -e "${PW}\n${PW}" | ./easyrsa --batch build-client-full "$CLIENT" nopass
    
    # Create a system account for the client
    if ! id "$CLIENT" &>/dev/null; then
        useradd -M -d "$CLIENTPATH" -s /bin/bash "$CLIENT"
        echo "$CLIENT:$PW" | chpasswd
        chage -m 0 -M 99999 -I -1 -E -1 "$CLIENT"
    fi

    # Generate 2FA secret and QR code
    if ! command -v google-authenticator &> /dev/null; then
        echo -e "${R}google-authenticator is not installed. Please install it to enable 2FA.${C}"
        exit 1
    fi
    mkdir -p "/opt/openvpn/google-auth"
    google-authenticator -t -d -f -r 3 -R 30 -W -C -s "/opt/openvpn/google-auth/${CLIENT}"
    secret=$(head -n1 "/opt/openvpn/google-auth/${CLIENT}")
    qrencode -t PNG -o "${CLIENTPATH}/${CLIENT}_qrcode.png" \
        "otpauth://totp/${CLIENT}@vpn?secret=${secret}&issuer=VPN"

    # Generate the OVPN configuration file
    {
        echo "client"
        echo "dev tun"
        echo "proto udp"
        echo "remote 192.168.1.181 1194"  # Replace with your server IP
        echo "resolv-retry infinite"
        echo "nobind"
        echo "persist-key"
        echo "persist-tun"
        echo "remote-cert-tls server"
        echo "auth-user-pass"
        echo "auth-nocache"
        echo "cipher AES-256-GCM"
        echo "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305:AES-256-CBC"
        echo "auth SHA256"  
        echo "script-security 2"
        echo "up /etc/openvpn/update-resolv-conf"
        echo "down /etc/openvpn/update-resolv-conf"
        echo -e "verb 3\n\n"
        echo "<ca>"
        cat "/etc/openvpn/server/easy-rsa/pki/ca.crt"  # Embed CA certificate
        echo -e "</ca>\n\n"
        echo "<cert>"
        cat "/etc/openvpn/server/easy-rsa/pki/issued/${CLIENT}.crt"  # Embed client certificate
        echo -e "</cert>\n\n"
        echo "<key>"
        cat "/etc/openvpn/server/easy-rsa/pki/private/${CLIENT}.key"  # Embed client private key
        echo -e "</key>\n\n"
        echo "<tls-crypt>"
        cat "/etc/openvpn/server/easy-rsa/ta.key"  # Embed TLS auth key
        echo "</tls-crypt>"
    } > "${CLIENTPATH}/${CLIENT}.ovpn"

    # Set permissions for security
    chmod 600 -R "$CLIENTPATH"
    chown nobody:nogroup "$CLIENTPATH"/*

    echo -e "${G}User ${CLIENT} created:${C}"
    echo -e "Password: ${PW}"
    echo -e "OVPN Profile: ${CLIENTPATH}/${CLIENT}.ovpn"
    echo -e "QR Code: ${CLIENTPATH}/${CLIENT}_qrcode.png"
}

# Function: revokeClient
# Revokes a client's certificate and removes their configuration files.
function revokeClient() {
    CLIENT=${1:?}  # Client username (required)
    cd /etc/openvpn/server/easy-rsa/ || exit

    # Verify client certificate exists
    if [ ! -f "pki/issued/${CLIENT}.crt" ]; then
        echo -e "${R}Client certificate for ${CLIENT} not found${C}"
        exit 1
    fi

    # Revoke the client certificate
    ./easyrsa --batch revoke "$CLIENT"
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    
    # Remove client certificate files
    rm -f "pki/reqs/${CLIENT}.req*"
    rm -f "pki/private/${CLIENT}.key*"
    rm -f "pki/issued/${CLIENT}.crt*"

    # Remove the client from the PKI index
    sed -i "/CN=${CLIENT}$/d" /etc/openvpn/server/easy-rsa/pki/index.txt

    # Remove the system account
    id "$CLIENT" && userdel -r -f "$CLIENT"
    
    # Remove the client's configuration directory
    rm -rf "${CLIENTDIR:?}/${CLIENT:?}"

    echo -e "${G}VPN access for $CLIENT revoked${C}"
}

# Function: showStatus
# Lists all active certificates.
function showStatus() {
    if [ ! -f "/etc/openvpn/server/easy-rsa/pki/index.txt" ]; then
        echo -e "${R}Certificate index file not found${C}"
        exit 1
    fi
    cat /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | grep -v "server_"
}

# Function: getClient
# Retrieves and displays the credentials for a specific client.
function getClient() {
    CLIENT=${1:?}  # Client username (required)
    CLIENTPATH="${CLIENTDIR}/${CLIENT}"
    
    # Check if the client exists
    if [ ! -d "$CLIENTPATH" ]; then
        echo -e "${R}User ${CLIENT} does not exist${C}"
        exit 1
    fi

    # Display client credentials
    echo -e "${G}Credentials for ${CLIENT}:${C}"
    echo -e "Password: $(cat "${CLIENTPATH}/pass.txt")"
    echo -e "OVPN Profile: ${CLIENTPATH}/${CLIENT}.ovpn"
    echo -e "QR Code: ${CLIENTPATH}/${CLIENT}_qrcode.png"
}

# Main script logic
case "$ACTION" in
    create)
        [ -z "$CLIENT" ] && { echo -e "${R}Provide a username to create${C}"; exit 1; }
        newClient "$CLIENT"
        ;;
    revoke)
        [ -z "$CLIENT" ] && { echo -e "${R}Provide a username to revoke${C}"; exit 1; }
        revokeClient "$CLIENT"
        ;;
    status)
        showStatus
        ;;
    get)
        [ -z "$CLIENT" ] && { echo -e "${R}Provide a username to retrieve${C}"; exit 1; }
        getClient "$CLIENT"
        ;;
    *)
        showHelp
        ;;
esac
