#!/bin/bash
# Author: Greerso https://github.com/greerso
# Steemit:  https://steemit.com/@greerso
#
# BTC 1BzrkEMSF4aXBtZ19DhVf8KMPVkXjXaAPG
# ETH 0x0f64257fAA9E5E36428E5BbB44C9A2aE3A055577
# LTC LRf2oaNjLH18UtfXnr6GG34c3xv6To2XeZ
# ZEC t1QCnCQstdgvZ5v3P9sZbeT9ViJd2pDfNBL
# ZEN zndLiWRo7cYeAKuPArtpQ6HNPi6ZdaTmLFL
# ZEL t1RdEHDboaRwpoBVQDuQ9bEpBmFqU1dFBR6


# ==============================================================================
# Variables
# ==============================================================================
# Project Specific
    PROJECT_NAME="bhash"
    PROJECT_GITHUB_REPO="bhashcoin/bhash"
    GITHUB_BIN_SUFFIX=linux
    PROJECT_STAKE=2000
#
export NEWT_COLORS=''
RPCUSER="${PROJECT_NAME}_user"
RPCPASSWORD="$(head -c 32 /dev/urandom | base64)"
RPC_PORT="17654"
P2P_PORT="17652"
LINUX_USER=$(who -m | awk '{print $1;}')
LINUX_USERPW="$(head -c 32 /dev/urandom | base64)"
PUBLIC_IP="$(dig +short myip.opendns.com @resolver1.opendns.com)"
INTERNALIP="$(hostname -I)"
HOSTNAME="$(cat /etc/hostname)"
SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
WALLET_LOCATION="${HOME}/.${PROJECT_NAME}"
DAEMON_BINARY="${PROJECT_NAME}d"
PROJECT_CLI="${PROJECT_NAME}-cli"
PROJECT_LOGO="          *////////////*                       \n         ///////////////                       \n         *//////////////                       \n         ****//////////                        \n        ********///////                        \n        ***********///*                        \n       /**************////////*,               \n       *******************/////////,           \n       **********************/////////         \n       *************************///////*       \n      ,*************@@@@***%@@@%***//////      \n      *************/@@@&***@@@@/******////     \n      *********@@@@@@@@@@@@@@@@@@@*******//    \n     **********@@@@@@@@@@@@@@@@@@@*********,   \n     *************/@@@@***&@@@**************   \n     *************&@@@#***@@@@*************,   \n    ,**********@@@@@@@@@@@@@@@@@@&*********/   \n    ,,********/@@@@@@@@@@@@@@@@@@**********    \n    ,,,,,********#@@@/***@@@@*************/    \n   ,,,,,,,,*****@@@@***(@@@@************(     \n   ,,,,,,,,,,,**************************       \n   ,,,,,,,,,,,,,,,********************/        \n  .,,,,,,,,,,,,,,,,,,****************          \n  .,,,,,,,,,,,,,/,,,,,,,**********             "
WT_BACKTITLE="$PROJECT_NAME Masternode Installer"
WT_TITLE="Installing the $PROJECT_NAME Masternode..."
declare MN_ALIAS
declare MN_PRIV_KEY
declare COLLATERAL_OUTPUT_TXID
declare COLLATERAL_OUTPUT_INDEX
declare -a BASE_PKGS=(\
    apt-transport-https \
    ca-certificates \
    curl \
    htop \
    jq \
    libevent-dev \
    lsb-release \
    software-properties-common \
    unzip \
    wget)
declare -a PROJECT_PKGS=(\
    libboost-system-dev \
    libboost-filesystem-dev \
    libboost-chrono-dev \
    libboost-program-options-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libdb-dev \
    libdb++-dev
    libzmq3-dev \
    libminiupnpc-dev)
# ------------------------------------------------------------------------------

# ==============================================================================
# Functions
# ==============================================================================

# Silence
# Use 'stfu command args...'
stfu() {
  "$@" >/dev/null 2>&1
}

# Use 'copy_text "text to display"'
text_to_copy() {
    clear
    echo
    echo
    echo "# ===========Start copy text AFTER this line==========="
    echo -e "$@"
    echo "# ===========Stop copy text BEFORE this line==========="
    echo
    echo
    read -n 1 -s -r -p "Press any key to continue..."
    clear
}

# Use 'user_in_group user group'
user_in_group() {
    groups $1 | grep -q "\b$2\b"
}

# infobox TEXT
infobox() {
    BASE_LINES=8
    WT_HEIGHT=$(echo -e "$@" | wc -l)
    (( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
    WT_WIDTH=78
    WT_SIZE="$WT_HEIGHT $WT_WIDTH"
    TERM=ansi whiptail \
    --infobox "$@" \
    --backtitle "$WT_BACKTITLE" \
    --title "$WT_TITLE" \
    $WT_SIZE
}

# msgbox TEXT
msgbox() {
    BASE_LINES=8
    WT_HEIGHT=$(echo -e "$@" | wc -l)
    (( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
    WT_WIDTH=78
    WT_SIZE="$WT_HEIGHT $WT_WIDTH"
    TERM=ansi whiptail \
    --msgbox "$@" \
    --backtitle "$WT_BACKTITLE" \
    --title "$WT_TITLE" \
    $WT_SIZE
}

# inputbox TEXT
inputbox() {
    BASE_LINES=8
    WT_HEIGHT=$(echo -e "$@" | wc -l)
    (( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
    WT_WIDTH=78
    WT_SIZE="$WT_HEIGHT $WT_WIDTH"
    TERM=ansi whiptail \
    --inputbox "$@" \
    --backtitle "$WT_BACKTITLE" \
    --title "$WT_TITLE" \
    --nocancel \
    3>&1 1>&2 2>&3 \
    $WT_SIZE
}

# yesnobox TEXT
yesnobox() {
BASE_LINES=8
WT_HEIGHT=$(echo -e "$@" | wc -l)
(( WT_HEIGHT=WT_HEIGHT+BASE_LINES ))
WT_WIDTH=78
WT_SIZE="$WT_HEIGHT $WT_WIDTH"
TERM=ansi whiptail \
--yesno "$@" \
--backtitle "$WT_BACKTITLE" \
--title "$WT_TITLE" \
3>&1 1>&2 2>&3 \
$WT_SIZE
}

pre_checks() {
    UBUNTU_VER=$(lsb_release -rs)
    if [[ $UBUNTU_VER != 16.04 ]]; then
    msgbox "Ubuntu 16.04 is required, you have $UBUNTU_VER.  Exiting..."
    exit 1
    fi

    if [ "$(id -nu)" != "root" ]; then
    sudo -k
    PASSWORD=$(whiptail --backtitle "$PROJECT_NAME Masternode Installer" --title "Authentication required" --passwordbox "Installing $PROJECT_NAME requires root privilege. Please authenticate to begin the installation.\n\n[sudo] Password for user $USER:" 12 50 3>&2 2>&1 1>&3-)
    exec sudo -S -p '' "$0" "$@" <<< "$PASSWORD"
    exit 1
    fi

    if [ -n "$(pidof $DAEMON_BINARY)" ]; then
    msgbox "The $PROJECT_NAME daemon is already running."
    # check for updates
    exit 1
    fi
}

# install_packages from BASE_PKGS and PROJECT_PKGS array variables in addition to any other packages specified
install_packages() {
apt update
apt-get -y install aptitude
aptitude -yq3 update
aptitude -yq3 full-upgrade
# add an if exists to each of the following
aptitude -yq3 install ${BASE_PKGS[@]} $@
aptitude -yq3 install ${PROJECT_PKGS[@]}

# Add bitcoin repo. *why?
# stfu add-apt-repository -y ppa:bitcoin/bitcoin
# stfu apt update
# stfu aptitude -yq3 install \
#   libdb4.8-dev \
#   libdb4.8++-dev
}

change_hostname() {
HOSTNAME=$(hostname)
if [ -z "$1" ]; then
newHostname=$(inputbox "Your hostname is $HOSTNAME,  please enter a new hostname then press ok.")
else
newHostname="$1"
fi
sed -i "s|$Hostname|$newHostname|1" /etc/hostname
if grep -q "$Hostname" /etc/hosts; then
sed -i "s|$Hostname|$newHostname|1" /etc/hosts
else
echo "127.0.0.1 $newHostname" >> /etc/hosts
fi
}

create_swap() {
TOTAL_MEM=$(free -m | awk '/^Mem:/{print $2}')
TOTAL_SWP=$(free -m | awk '/^Swap:/{print $2}')
TOTAL_M=$(($TOTAL_MEM + $TOTAL_SWP))
if [ $TOTAL_M -lt 4000 ]; then
if ! grep -q '/swapfile' /etc/fstab ; then
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi
fi
}

create_user() {
if [ -z "$1" ]; then
USERNAME=$(inputbox "Please enter the new user name")
else
USERNAME=$1
fi
USER_PASSWORD=$(inputbox "Please enter a password for '${USERNAME}'")
adduser --gecos "" --disabled-password --quiet "$USERNAME"
echo "$USERNAME:$USER_PASSWORD" | chpasswd
# Add user to sudoers
usermod -a -G sudo "$USERNAME"
LINUX_USER=$USERNAME
WALLET_LOCATION="$(eval echo "~$USERNAME")/.${PROJECT_NAME}"
# add option to ask instead of adding to sudoers by default
# add a loop to add more users  
}

unattended-upgrades() {
apt-get -y install unattended-upgrades >/dev/null 2>&1
autoUpdateCommands=(
's|\"\${distro_id}:\${distro_codename}\";|// \"\${distro_id}:\${distro_codename}\";|'
's|\"\${distro_id}ESM:\${distro_codename}\";|// \"\${distro_id}ESM:\${distro_codename}\";|'
)
for autoUpdateCommand in "${autoUpdateCommands[@]}"; do
sed -i "$autoUpdateCommand" /etc/apt/apt.conf.d/50unattended-upgrades
done
if ! grep -q "APT::Periodic::Unattended-Upgrade \"1\" ;" /etc/apt/apt.conf.d/10periodic; then
echo "APT::Periodic::Unattended-Upgrade \"1\" ;" >> /etc/apt/apt.conf.d/10periodic
fi
}

harden_ssh() {
# Set ssh port
SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
if [ $SSH_PORT -eq 22 ] ; then
NEW_SSH_PORT=$(inputbox "SSH is currently running on $NEW_SSH_PORT.  Botnets scan are constantly scanning this port.  Enter a new port or press enter to accept port 2222" )
fi
if grep -q Port /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})Port)( *)?(.*)|Port $NEW_SSH_PORT|1" /etc/ssh/sshd_config
else
echo "Port $NEW_SSH_PORT" >> /etc/ssh/sshd_config
fi
# Disable root user ssh login
# Make sure that you have a normal user before doing this
if grep -q PermitRootLogin /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})PermitRootLogin)( *)?(.*)|PermitRootLogin no|1" /etc/ssh/sshd_config
else
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
fi
# Disable the use of passwords with ssh
# Add ssh-key for remote user to LINUX_USER .ssh/allowed_keys
if grep -q PasswordAuthentication /etc/ssh/sshd_config; then
sed -ri "s|(^(.{0,2})PasswordAuthentication)( *)?(.*)|PasswordAuthentication no|1" /etc/ssh/sshd_config
else
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
fi
# Restart the ssh daemon
systemctl restart sshd
}

setup_ufw() {
    SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
    ALLOWED_PORTS=[$@]
    REMOTE_IP=$(echo -e $SSH_CLIENT | awk '{ print $1}')
    
    if ! [ -f /etc/ufw/ufw.conf ]; then
        apt-get -y install ufw
    fi
    
    # Open all outgoing ports, block all incoming ports then open port $SSH_PORT for ssh.
    ufw default allow outgoing
    ufw default deny incoming
    
    # Open ports
    ufw allow $SSH_PORT/tcp comment 'ssh port'
    ufw allow $P2P_PORT/tcp comment 'mn p2p port'
    # allow $ALLOWED_PORTS
    allow all ports from $REMOTE_IP
    # Enable the firewall
    ufw --force enable
}

setup_fail2ban() {
REMOTE_IP=$(echo -e $SSH_CLIENT | awk '{ print $1}')
FQDN="$(hostname -f)"
SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
JAIL_LOCAL="[blacklist]\nenabled = true\nlogpath  = /var/log/fail2ban.*\nbanaction = blacklist\nbantime  = 31536000   \; 1 year\nfindtime = 31536000   \; 1 year\nmaxretry = 10\n\n[Definition]\nloglevel = INFO\nlogtarget = /var/log/fail2ban.log\nsyslogsocket = auto\nsocket = /var/run/fail2ban/fail2ban.sock\npidfile = /var/run/fail2ban/fail2ban.pid\ndbfile = /var/lib/fail2ban/fail2ban.sqlite3\ndbpurgeage = 86400"
JAIL_LOCAL=$(echo -e $JAIL_LOCAL)

if [ ! -f /etc/fail2ban/jail.local ]; then
apt -y install fail2ban
cat <<EOF > /etc/fail2ban/jail.local
$JAIL_LOCAL
EOF
fi

sed -i -e 's|ignoreip = 127.0.0.1/8|ignoreip = $REMOTE_IP|g' /etc/fail2ban/jail.local
# jail.local:
# [sshd]
# action = %(action_)s
# smtp.py[host="host:25", user="my-account", password="my-pwd", sender="sender@example.com", dest="example@example.com", name="%(__name__)s"]
# sed -i -e 's|destemail = root@localhost|destemail = me@myemail.com |g' /etc/fail2ban/jail.local
# sed -i -e 's|sender = root@localhost|sender = fail2ban@$FQDN\nsendername = Fail2Ban|g' /etc/fail2ban/jail.local
# sed -i -e 's|mta = sendmail|mta = mail|g' /etc/fail2ban/jail.local
sed -i -e 's|action = %(action_)s|action = %(action_mwl)s|g' /etc/fail2ban/jail.local
sed -i -e 's|= ssh|= $SSH_PORT|g' /etc/fail2ban/jail.local

#create an action for repeat offenders from mitchellkrogza/Fail2Ban-Blacklist

cat <<EOF >> /etc/fail2ban/action.d/blacklist.conf
# /etc/fail2ban/action.d/blacklist.conf
# Fail2Ban Blacklist for Repeat Offenders (action.d)
# Version: 1.0
# GitHub: https://github.com/mitchellkrogza/Fail2Ban-Blacklist-JAIL-for-Repeat-Offenders-with-Perma-Extended-Banning
# Tested On: Fail2Ban 0.91
# Server: Ubuntu 16.04
# Firewall: IPTables
#

[INCLUDES]
before = iptables-common.conf


[Definition]
# Option:  actionstart
# Notes.:  command executed once at the start of Fail2Ban.
# Values:  CMD
#

actionstart = <iptables> -N f2b-<name>
              <iptables> -A f2b-<name> -j <returntype>
              <iptables> -I <chain> -p <protocol> -j f2b-<name>
              # Sort and Check for Duplicate IPs in our text file and Remove Them
              sort -u /etc/fail2ban/ip.blacklist -o /etc/fail2ban/ip.blacklist
              # Persistent banning of IPs reading from our ip.blacklist text file
              # and adding them to IPTables on our jail startup command
              cat /etc/fail2ban/ip.blacklist | while read IP; do iptables -I f2b-<name> 1 -s $IP -j DROP; done

# Option:  actionstop
# Notes.:  command executed once at the end of Fail2Ban
# Values:  CMD
#

actionstop = <iptables> -D <chain> -p <protocol> -j f2b-<name>
             <iptables> -F f2b-<name>
             <iptables> -X f2b-<name>

# Option:  actioncheck
# Notes.:  command executed once before each actionban command
# Values:  CMD
#

actioncheck = <iptables> -n -L <chain> | grep -q 'f2b-<name>[ \t]'

# Option:  actionban
# Notes.:  command executed when banning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#

actionban = <iptables> -I f2b-<name> 1 -s <ip> -j DROP
# Add the new IP ban to our ip.blacklist file
echo '<ip>' >> /etc/fail2ban/ip.blacklist

# Option:  actionunban
# Notes.:  command executed when unbanning an IP. Take care that the
#          command is executed with Fail2Ban user rights.
# Tags:    See jail.conf(5) man page
# Values:  CMD
#
actionunban = <iptables> -D f2b-<name> -s <ip> -j DROP
# Remove IP from our ip.blacklist file
sed -i -e '/<ip>/d' /etc/fail2ban/ip.blacklist

[Init]
EOF

cat <<EOF >> /etc/fail2ban/filter.d/blacklist.conf
# /etc/fail2ban/filter.d/blacklist.conf
# Fail2Ban Blacklist for Repeat Offenders (filter.d)
#
# Version: 1.0
# GitHub: https://github.com/mitchellkrogza/Fail2Ban-Blacklist-JAIL-for-Repeat-Offenders-with-Perma-Extended-Banning
# Tested On: Fail2Ban 0.91
# Server: Ubuntu 16.04
# Firewall: IPTables
#

[INCLUDES]

# Read common prefixes. If any customizations available -- read them from
# common.local
before = common.conf

[Definition]

_daemon = fail2ban\.actions\s*

# The name of the jail that this filter is used for. In jail.conf, name the 
# jail using this filter 'blacklist', or change this line!
_jailname = blacklist

failregex = ^(%(__prefix_line)s| %(_daemon)s%(__pid_re)s?:\s+)NOTICE\s+\[(?!%(_jailname)s\])(?:.*)\]\s+Ban\s+<HOST>\s*$

ignoreregex = 

[Init]

journalmatch = _SYSTEMD_UNIT=fail2ban.service PRIORITY=5
EOF

#
# Secure shared memory
#

cat <<EOF >> /etc/fstab

tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0
EOF

# Harden the networking layer

# Prevent source routing of incoming packets
# enable Spoof protection
if grep -q net.ipv4.conf.default.rp_filter /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.rp_filter)( *)?(.*)|net.ipv4.conf.default.rp_filter = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.all.rp_filter /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.rp_filter)( *)?(.*)|net.ipv4.conf.all.rp_filter=1|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf
fi

# enable TCP/IP SYN cookies
if grep -q net.ipv4.tcp_syncookies /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.tcp_syncookies)( *)?(.*)|net.ipv4.tcp_syncookies=1|1" /etc/sysctl.conf
else
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
fi

# Ignore ICMP broadcat requests
if grep -q net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.icmp_echo_ignore_broadcasts)( *)?(.*)|net.ipv4.icmp_echo_ignore_broadcasts=1|1" /etc/sysctl.conf
else
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
fi

# Disable source packet routing
if grep -q net.ipv4.conf.all.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.accept_source_route)( *)?(.*)|net.ipv4.conf.all.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.all.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.all.accept_source_route)( *)?(.*)|net.ipv6.conf.all.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.default.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.accept_source_route)( *)?(.*)|net.ipv4.conf.default.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.default.accept_source_route /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.default.accept_source_route)( *)?(.*)|net.ipv6.conf.default.accept_source_route = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
fi

# Ignore send redirects
if grep -q net.ipv4.conf.all.send_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.send_redirects)( *)?(.*)|net.ipv4.conf.all.send_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.default.send_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.send_redirects)( *)?(.*)|net.ipv4.conf.default.send_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
fi

# Log Martians
if grep -q net.ipv4.conf.all.log_martians /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.log_martians)( *)?(.*)|net.ipv4.conf.all.log_martians = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
fi

# Bogus error responses
if grep -q net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.icmp_ignore_bogus_error_responses)( *)?(.*)|net.ipv4.icmp_ignore_bogus_error_responses = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
fi

# Ignore ICMP redirects
if grep -q net.ipv4.conf.all.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.all.accept_redirects)( *)?(.*)|net.ipv4.conf.all.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.all.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.all.accept_redirects)( *)?(.*)|net.ipv6.conf.all.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv4.conf.default.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.conf.default.accept_redirects)( *)?(.*)|net.ipv4.conf.default.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

if grep -q net.ipv6.conf.default.accept_redirects /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv6.conf.default.accept_redirects)( *)?(.*)|net.ipv6.conf.default.accept_redirects = 0|1" /etc/sysctl.conf
else
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
fi

# Ignore Directed pings
if grep -q net.ipv4.icmp_echo_ignore_all /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})net.ipv4.icmp_echo_ignore_all)( *)?(.*)|net.ipv4.icmp_echo_ignore_all = 1|1" /etc/sysctl.conf
else
echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
fi

# restart the service
sysctl -p.

# Prevent IP spoofing
if grep -q order /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})order)( *)?(.*)|order bind,hosts|1" /etc/host.conf
else
echo "order bind,hosts" >> /etc/host.conf
fi

if grep -q multi /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})multi)( *)?(.*)|#multi on|1" /etc/host.conf
else
echo "#multi on" >> /etc/host.conf
fi

if grep -q nospoof /etc/sysctl.conf; then
sed -ri "s|(^(.{0,2})nospoof)( *)?(.*)|nospoof on|1" /etc/host.conf
else
echo "nospoof on" >> /etc/host.conf
fi

systemctl restart fail2ban

}

# download_binaries PROJECT_NAME PROJECT_GITHUB_REPO
download_binaries() {
GITHUB_BIN_URL="$(curl -sSL https://api.github.com/repos/${PROJECT_GITHUB_REPO}/releases/latest | jq -r ".assets[] | select(.name | test(\"$GITHUB_BIN_SUFFIX\")) | .browser_download_url")"
    
    curl -sSL "$GITHUB_BIN_URL" | tar xvz -C /usr/local/bin/
}

wallet_configs() {
mkdir -p $WALLET_LOCATION
cat <<EOF > $WALLET_LOCATION/masternode.conf
$MASTERNODE_CONF
EOF
SERVER_WALLET_CONF=$(echo -e $SERVER_WALLET_CONF)
cat <<EOF > $WALLET_LOCATION/${PROJECT_NAME}.conf
$SERVER_WALLET_CONF
EOF
chown -R $LINUX_USER $WALLET_LOCATION
}

daemon_service() {
DAEMON_SERVICE=$(echo -e $DAEMON_SERVICE)
cat <<EOF > /etc/systemd/system/$DAEMON_BINARY.service
$DAEMON_SERVICE
EOF
systemctl daemon-reload
systemctl enable $DAEMON_BINARY
systemctl restart $DAEMON_BINARY
}
# ------------------------------------------------------------------------------

# ==============================================================================
# Pre-checks
# ==============================================================================
# pre_checks
# ------------------------------------------------------------------------------

# ==============================================================================
# Setup dialogs
# ==============================================================================
declare -a INSTALL_OPTIONS=(
#    "Change Hostame"
Base server install
#- Setting a hostname
# - Create swap space for a low ram vps
# - Add a non-root user
 - Configure automatic security updates for Ubuntu
 - Install and configure UFW Firewall
  - Allow all outbound traffic
  - Deny all inbound traffic
  - Allow inbound P2P for Masternode and SSH
  - Whitelist installer ip address
 - Install and configure Fail2Ban IDS
 - Autoblock repeat offenders from public blacklist
#- Harden SSH security
#  - Change SSH from port 22
#  - Disable root logon
#  - Require ssh-keys

Masternode install
- Prompted install
- Automatically detect Client and Host ip addresses
- Automatically generate RPC User and secure password.
- Download latest version from Github API
)
declare -A INSTALL_STEPS=(
    [installing]="Installing packages required for setup..."
    [install_dependencies]="This script will walk you through the following:\n\n${INSTALL_OPTIONS}\n\nYou will need:\n- A QT wallet with at least $PROJECT_STAKE coins and to know how to copy/paste."
    [create_key]="Start the qt wallet.\n - Go to Settings->Debug console and paste the following command:\n\ncreatemasternodekey\n\nThe result will look something like this \"y0uRm4st3rn0depr1vatek3y\".  Enter it here"
    [choose_alias]="Choose an alias for your masternode, for example MN1, then enter it here"
    [stake_address]="While still in the Debug console type the following command to get a public address to send the stake to:\n\ngetaccountaddress ${MN_ALIAS}\n\nThe result will look similar to this \"mA7fXSTe23RNoD83Esx6or4uYLxLqunDm5\".  Send exactly $PROJECT_STAKE HASH to that address making sure that any tx fee is covered."
    [mn_outputs]="Back in the Debug console Execute the command:\n\nmasternode outputs\n\nThis will output TX and output pairs of numbers, for example:\n{\n\"a9b31238d062ccb5f4b1eb6c3041d369cc014f5e6df38d2d303d791acd4302f2\": \"0\"\n}\nPaste just the first, long, number without any punctuation, here and the second number in the next screen."
    [mn_outputs_txin]="Enter the second, single digit number from the previous step (usually 0 or 1) here."
    [mn_conf]="On the QT wallet, open the masternode.conf file via the menu Tools->Open Masternode Configuration File.\n\nPaste the string that will appear on the next screen then save and close the file."
    [bash_conf]="On the QT wallet, open the bash.conf file via the menu Tools->Open Wallet Configuration File.\n\nPaste the lines that will appear on the next screen then save and close the file"
    [get_binaries]="Installing binaries to /usr/local/bin..."
    [vps_configs]="Creating configs in $WALLET_LOCATION..."
    [vps_systemd]="Creating and installing the $PROJECT_NAME systemd service..."
    [start_alias]="Restart the wallet.  You should see your Masternode listed in the Masternodes tab.\n\nGo to Settings->Debug console and paste the following command:\n\nstartmasternode alias lockwallet ${MN_ALIAS}\n\nto start your alias.\n\nIt may take up to 24 hours for your masternode to fully propagate"
)
# ------------------------------------------------------------------------------

# ==============================================================================
msgbox "${INSTALL_STEPS[install_dependencies]}"
WT_TITLE="Installing dependencies..."
infobox "${INSTALL_STEPS[installing]}"
# ==============================================================================
stfu install_packages
# ------------------------------------------------------------------------------

# ==============================================================================
WT_TITLE="Server Config"
# ==============================================================================
infobox "Configuring automatic security upgrades..."
stfu unattended-upgrades
# change_hostname
# stfu create_swap

if [ "$LINUX_USER" == "root" ]; then
	WT_TITLE="I AM ROOT" 
	if (yesnobox "You logged into your server as root.\n\nIt is not reccomended to install and run your masternode as root. Would you like to create a normal user?"); then
	create_user
	fi
fi

# harden_ssh #Needs work
infobox "Configuring firewall..."
stfu setup_ufw
infobox "Configureing Fail2Ban..."
stfu setup_fail2ban
# ------------------------------------------------------------------------------

# ==============================================================================
WT_TITLE="Masternode Config"
# ==============================================================================
MN_PRIV_KEY=$(inputbox "${INSTALL_STEPS[create_key]}")
MN_ALIAS=$(inputbox "${INSTALL_STEPS[choose_alias]}")
    # note:  --default-item is not working here.  need fix.
msgbox "${INSTALL_STEPS[stake_address]}"
COLLATERAL_OUTPUT_TXID=$(inputbox "${INSTALL_STEPS[mn_outputs]}")
COLLATERAL_OUTPUT_INDEX=$(inputbox "${INSTALL_STEPS[mn_outputs_txin]}")
msgbox "${INSTALL_STEPS[mn_conf]}"
    MASTERNODE_CONF="$MN_ALIAS $PUBLIC_IP:$P2P_PORT $MN_PRIV_KEY $COLLATERAL_OUTPUT_TXID $COLLATERAL_OUTPUT_INDEX"
    text_to_copy $MASTERNODE_CONF
msgbox "${INSTALL_STEPS[bash_conf]}"
LOCAL_WALLET_CONF="rpcuser=$RPCUSER\nrpcpassword=$RPCPASSWORD\nrpcallowip=127.0.0.1\nlisten=0\nserver=1\ndaemon=1\nlogtimestamps=1\nmaxconnections=256"
    text_to_copy $LOCAL_WALLET_CONF
infobox "${INSTALL_STEPS[get_binaries]}"
    stfu download_binaries
infobox "${INSTALL_STEPS[vps_configs]}"
SERVER_WALLET_CONF="rpcuser=${RPCUSER}\nrpcpassword=${RPCPASSWORD}\nrpcallowip=127.0.0.1\nlisten=1\nserver=1\ndaemon=1\nlogtimestamps=1\nmaxconnections=256\nmasternode=1\nexternalip=${PUBLIC_IP}\nmasternodeaddr=${PUBLIC_IP}\nmasternodeprivkey=${MN_PRIV_KEY}\nmnconf=${WALLET_LOCATION}/masternode.conf\ndatadir=${WALLET_LOCATION}"
    stfu wallet_configs
infobox "${INSTALL_STEPS[vps_systemd]}"
DAEMON_SERVICE="[Unit]\nDescription=$PROJECT_NAME daemon\nAfter=network.target\n\n[Service]\nExecStart=/usr/local/bin/$DAEMON_BINARY --daemon --conf=$WALLET_LOCATION/$PROJECT_NAME.conf -pid=/run/$DAEMON_BINARY/$DAEMON_BINARY.pid\nRuntimeDirectory=$DAEMON_BINARY\nUser=$LINUX_USER\nType=forking\nWorkingDirectory=$WALLET_LOCATION\nPIDFile=/run/$DAEMON_BINARY/$DAEMON_BINARY.pid\nRestart=on-failure\n\nPrivateTmp=true\nProtectSystem=full\nNoNewPrivileges=true\nPrivateDevices=true\nMemoryDenyWriteExecute=true\n\n[Install]\nWantedBy=multi-user.target"
    stfu daemon_service
msgbox "${INSTALL_STEPS[start_alias]}"
# ==============================================================================
# Display logo
# ==============================================================================
clear
echo -e "${PROJECT_LOGO}\n\nUseful commands:\n'${PROJECT_CLI} masternode status'   #Get the status of your masternode\n'${PROJECT_CLI} --help'              #Get a list of things that ${PROJECT_CLI} can do\n'sudo systemctl stop ${DAEMON_BINARY}'    #Stop the ${PROJECT_NAME} Daemon\n'sudo systemctl start ${DAEMON_BINARY}'   #Start the ${PROJECT_NAME} Daemon\n'sudo systemctl restart ${DAEMON_BINARY}' #Restart the ${PROJECT_NAME} Daemon\n'sudo systemctl status ${DAEMON_BINARY}'  #Get the status ${PROJECT_NAME} Daemon\n\nFor a beginners quick start for linux see https://steemit.com/tutorial/@greerso/linux-cli-command-line-interface-primer-for-beginners"
# ------------------------------------------------------------------------------

# ==============================================================================
# TODO
# ==============================================================================
#	Validation on user input
#	Make Base Installs optional
#   Fail2Ban email reports of hacking activity
#   Harden SSH security
#       Change port 22
#       Disable root logon
#       Require ssh-keys
##Masternode install
#   Check for already installed
#       Check daemon up-to-date
#           install update
#	NTP and timezone
# ------------------------------------------------------------------------------