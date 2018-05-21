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
	GITHUB_REPO="bhashcoin/bhash"
#
RPCUSER="$PROJECT_NAME_user"
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
LOCAL_WALLET_CONF="rpcpassword=$RPCUSER\nrpcpassword=$RPCPASSWORD\nrpcallowip=127.0.0.1\nlisten=0\nserver=1\ndaemon=1\nlogtimestamps=1\nmaxconnections=256\nmasternode=1"
${PROJECT_NAME}_OS=linux
WT_BACKTITLE="$PROJECT_NAME Masternode Installer"
declare WT_TITLE
declare WT_SIZE
# ------------------------------------------------------------------------------

# ==============================================================================
# Setup helper functions
# ==============================================================================
export NEWT_COLORS=''

# Silence
# Use 'stfu command args...'
stfu() {
  "$@" >/dev/null 2>&1
}

# Use 'print_status "text to display"'
print_status() {
    echo
    echo "## $1"
    echo
}

# Use 'user_in_group user group'
user_in_group() {
    groups $1 | grep -q "\b$2\b"
}

infobox() {
	TERM=ansi whiptail \
	--infobox "$@" \
	--backtitle "$WT_BACKTITLE" \
	--title "$WT_TITLE" \
	$WT_SIZE
}

msgbox() {
	TERM=ansi whiptail \
	--msgbox "$@" \
	--backtitle "$WT_BACKTITLE" \
	--title "$WT_TITLE" \
	$WT_SIZE
}

inputbox() {
	TERM=ansi whiptail \
	--inputbox "$@" \
	--backtitle "$WT_BACKTITLE" \
	--title "$WT_TITLE" \
	--nocancel \
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
	password=$(whiptail --backtitle "$PROJECT_NAME Masternode Installer" --title "Authentication required" --passwordbox "Installing $PROJECT_NAME requires root privilege. Please authenticate to begin the installation.\n\n[sudo] Password for user $USER:" 12 50 3>&2 2>&1 1>&3-)
	exec sudo -S -p '' "$0" "$@" <<< "$password"
	exit 1
	fi

	if [ -n "$(pidof $DAEMON_BINARY)" ]; then
	msgbox "The $PROJECT_NAME daemon is already running."
	# check for updates
	exit 1
	fi
}

change_hostname() {
    inputbox "Your hostname is $Hostname,  please enter a new hostname then press ok."
        sed -i "s|$Hostname|$newHostname|1" /etc/hostname
        if grep -q "$Hostname" /etc/hosts; then
            sed -i "s|$Hostname|$newHostname|1" /etc/hosts
        else
            echo "127.0.0.1 $newHostname" >> /etc/hosts
        fi
    esac
}

create_swap() {
	totalmem=$(free -m | awk '/^Mem:/{print $2}')
	totalswp=$(free -m | awk '/^Swap:/{print $2}')
	totalm=$(($totalmem + $totalswp))
	if [ $totalm -lt 4000 ]; then
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
	USERNAME=$(inputbox "Please enter the new user name")
	USER_PASSWORD=$(inputbox "Please enter the password for '${username}'")
	adduser --gecos "" --disabled-password --quiet "$USERNAME"
	echo "$USERNAME:$USER_PASSWORD" | chpasswd
	# Add user to sudoers
	usermod -a -G sudo "$USERNAME"
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
		
	if grep -q "APT::Periodic::Unattended-Upgrade \"1\" ;" /etc/apt/apt.conf.d/10periodic; then
	    # "Already configured"
	else
	    echo "APT::Periodic::Unattended-Upgrade \"1\" ;" >> /etc/apt/apt.conf.d/10periodic
	fi
}

setup_ufw() {
	SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
	ALLOWED_PORTS=[$@]
	REMOTE_IP=$(echo -e $SSH_CLIENT | awk '{ print $1}')
	
	if [ -f /etc/ufw/ufw.conf ]; then
	    # echo "ufw already exists!"
	    # exit $?
	    else apt-get -y install ufw
	fi
	
	# Open all outgoing ports, block all incoming ports then open port $SSH_PORT for ssh.
	ufw default allow outgoing
	ufw default deny incoming
	
	# Open ports
	ufw allow $SSH_PORT/tcp comment 'ssh port'
	# allow $ALLOWED_PORTS
	# allow all ports from $REMOTE_IP
	# Enable the firewall
	ufw enable
}

setup_fail2ban() {
	REMOTE_IP=$(echo -e $SSH_CLIENT | awk '{ print $1}')
	FQDN="$(hostname -f)"
	SSH_PORT=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
	if [ -f /etc/fail2ban/jail.conf /etc/fail2ban/jail.local ]; then
	    # echo "jail.local already exists!"
	    else apt -y install fail2ban
		cat <<EOF >> /etc/fail2ban/jail.local
		[nginx-noscript]
		port     = http,https
		logpath  = /var/log/nginx/*access.log*
		
		[blacklist]
		enabled = true
		logpath  = /var/log/fail2ban.*
		banaction = blacklist
		bantime  = 31536000   ; 1 year
		findtime = 31536000   ; 1 year
		maxretry = 10
		
		[Definition]
		loglevel = INFO
		logtarget = /var/log/fail2ban.log
		syslogsocket = auto
		socket = /var/run/fail2ban/fail2ban.sock
		pidfile = /var/run/fail2ban/fail2ban.pid
		dbfile = /var/lib/fail2ban/fail2ban.sqlite3
		dbpurgeage = 86400
		EOF
	fi
	
	sed -i -e 's|ignoreip = 127.0.0.1/8|ignoreip = $REMOTE_IP|g' /etc/fail2ban/jail.local
	# sed -i -e 's|destemail = root@localhost|destemail = me@myemail.com |g' /etc/fail2ban/jail.local
	# sed -i -e 's|sender = root@localhost|sender = fail2ban@$FQDN\nsendername = Fail2Ban|g' /etc/fail2ban/jail.local
	# sed -i -e 's|mta = sendmail|mta = mail|g' /etc/fail2ban/jail.local
	sed -i -e 's|action = %(action_)s|action = %(action_mwl)s|g' /etc/fail2ban/jail.local
	sed -i -e 's|= ssh|= $SSH_PORT|g' /etc/fail2ban/jail.local
	
	cat <<EOF >> /etc/fail2ban/filter.d/nginx-noscript.conf
		[Definition]
		failregex = ^<HOST> -.*GET.*(\.asp|\.exe|\.pl|\.cgi|\.scgi)
		ignoreregex =
		EOF
	
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
		
		systemctl restart fail2ban
		
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
}

# ------------------------------------------------------------------------------

# ==============================================================================
# Pre-checks
# ==============================================================================
pre_checks
# ------------------------------------------------------------------------------

# ==============================================================================
# 'Required Packages...'
# ==============================================================================
declare -a BASE_PKGS=(\
	apt-transport-https \
	ca-certificates \
	curl \
	htop \
	jq \
	libevent-dev \
	lsb-release \
	software-properties-common \
	unattended-upgrades \
	unzip \
	wget)
declare -a OPT_PKGS=(\
	fail2ban \
	ufw)
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
WT_TITLE="Installing dependencies..."
infobox "$installing"
# ==============================================================================
stfu apt update
stfu apt-get -y install aptitude
aptitude -yq3 update
aptitude -yq3 full-upgrade
aptitude -yq3 install ${BASE_PKGS[@]}
aptitude -yq3 install ${PROJECT_PKGS[@]}

# Add bitcoin repo
# stfu add-apt-repository -y ppa:bitcoin/bitcoin
# stfu apt update
# stfu aptitude -yq3 install \
#	libdb4.8-dev \
#	libdb4.8++-dev
# ------------------------------------------------------------------------------

# ==============================================================================
# Firewall port
# ==============================================================================
ufw allow $P2P_PORT/tcp comment '$PROJECT_NAME P2P'
ufw allow $$SSH_PORT/tcp comment 'SSH'
ufw --force enable
# ------------------------------------------------------------------------------

# ==============================================================================
# Setup dialogs
# ==============================================================================
installing="Installing packages required for setup..."
# ------------------------------------------------------------------------------

# ==============================================================================
WT_BACKTITLE="$PROJECT_NAME Masternode Installer"
WT_SIZE="8 78"
WT_TITLE="Installing the $PROJECT_NAME Masternode..."
# ==============================================================================
step0="You will need:\n\n-A qt wallet with at least 2000 coins\n-An Ubuntu 16.04 64-bit server with a static public ip."
msgbox "$step0"

step1="Start the qt wallet. Go to Settings→Debug console and enter the following command:\n\n\"createmasternodekey\"\n\nThe result will look something like this \"y0uRm4st3rn0depr1vatek3y\".  Enter it here"
MN_PRIV_KEY=$(inputbox $step1)

step2="Choose an alias for your masternode, for example MN1, then enter it here"
MN_ALIAS=$(inputbox $step2)
	# note:  --default-item is not working here.  need fix.

step3"While still in the Debug console type the following command to get a public address to send the stake to:\n\n\"getaccountaddress $MN_ALIAS\"\n\nThe result will look similar to this \"mA7fXSTe23RNoD83Esx6or4uYLxLqunDm5\".  Send exactly 2000 HASH to that address making sure that any tx fee is covered."
msgbox $step3

step4="Back in the Debug console Execute the command:\n\n\"masternode outputs\"\n\nThis will output TX and output pairs of numbers, for example:\n\"{\n\"a9b31238d062ccb5f4b1eb6c3041d369cc014f5e6df38d2d303d791acd4302f2\": \"0\"\n}\"\nPaste just the first number, long number, here and the second number in the next screen."
COLLATERAL_OUTPUT_TXID=$(inputbox $step4)

step5="Paste the second, single digit number from the previous step (usually \"0\" here."
COLLATERAL_OUTPUT_INDEX=$(inputbox $step5)
	MASTERNODE_CONF="$MN_ALIAS $PUBLIC_IP:$P2P_PORT $MN_PRIV_KEY $COLLATERAL_OUTPUT_TXID $COLLATERAL_OUTPUT_INDEX"

step6="Open the masternode.conf file via the menu Tools→Open Masternode Configuration File. Without any blank lines type in a space-delimited single line paste the following string:\n\n${MASTERNODE_CONF}\n\nSave and close the file."
msgbox $step6

step7="Open the bash.conf file via the menu Tools→Open Wallet Configuration File and paste the following text:\n\n${LOCAL_WALLET_CONF}\n\nSave and close the file."
msgbox $step7

step8="Installing binaries to /usr/local/bin..."
msgbox $step8
	${PROJECT_NAME}_URL=$(curl -s https://api.github.com/repos/${GITHUB_REPO}/releases/latest | jq -r ".assets[] | select(.name | test(\"${PROJECT_NAME}_OS\")) | .browser_download_url")

	curl -sSL "${PROJECT_NAME}_URL" | tar xvz -C /usr/local/bin/
	sleep .5

step9="Creating configs in $WALLET_LOCATION..."
infobox $step9
	mkdir -p $WALLET_LOCATION
	cat <<EOF > $WALLET_LOCATION/masternode.conf
	$MASTERNODE_CONF
	EOF

step10="Creating the bhash configuration..."
infobox $step10
	LOCAL_WALLET_CONF=$(echo -e $LOCAL_WALLET_CONF)
	cat <<EOF > $WALLET_LOCATION/$PROJECT_NAME.conf
	RPCUSER=$RPCUSER
	RPCPASSWORD=$RPCPASSWORD
	rpcallowip=127.0.0.1
	listen=1
	server=1
	daemon=1
	logtimestamps=1
	maxconnections=256
	masternode=1
	externalip=$PUBLIC_IP
	bind=$PUBLIC_IP:$P2P_PORT
	masternodeaddr=$PUBLIC_IP
	masternodeprivkey=$MN_PRIV_KEY
	mnconf=$WALLET_LOCATION/masternode.conf
	datadir=$WALLET_LOCATION
	EOF
	stfu chown -R $LINUX_USER $WALLET_LOCATION

step11="Installing the $PROJECT_NAME service..."
infobox $step11
# ==============================================================================
	cat <<EOF > /etc/systemd/system/$DAEMON_BINARY.service
	[Unit]
	Description=$PROJECT_NAME daemon
	After=network.target
	
	[Service]
	ExecStart=/usr/local/bin/$DAEMON_BINARY --daemon --conf=$WALLET_LOCATION/$PROJECT_NAME.conf -pid=/run/$DAEMON_BINARY/$DAEMON_BINARY.pid
	RuntimeDirectory=$DAEMON_BINARY
	User=$LINUX_USER
	Type=forking
	WorkingDirectory=$WALLET_LOCATION
	PIDFile=/run/$DAEMON_BINARY/$DAEMON_BINARY.pid
	Restart=on-failure
	
	# Hardening measures
	####################
	# Provide a private /tmp and /var/tmp.
	PrivateTmp=true
	# Mount /usr, /boot/ and /etc read-only for the process.
	ProtectSystem=full
	# Disallow the process and all of its children to gain
	# new privileges through execve().
	NoNewPrivileges=true
	# Use a new /dev namespace only populated with API pseudo devices
	# such as /dev/null, /dev/zero and /dev/random.
	PrivateDevices=true
	# Deny the creation of writable and executable memory mappings.
	MemoryDenyWriteExecute=true
	
	[Install]
	WantedBy=multi-user.target
	EOF
# ------------------------------------------------------------------------------



# ==============================================================================
infobox "Enabling and starting $PROJECT_NAME service..."
# ==============================================================================
stfu systemctl daemon-reload
stfu systemctl enable $DAEMON_BINARY
stfu systemctl restart $DAEMON_BINARY
# ------------------------------------------------------------------------------


msgbox "Restart the wallet.  You should see your Masternode listed in the Masternodes tab.

If you get errors, you may have made a mistake in either the $PROJECT_NAME.conf or masternodes.conf files.

Use the buttons to start your alias.  It may take up to 24 hours for your masternode to fully propagate"
# ==============================================================================
# Display logo
# ==============================================================================
clear
echo -e "$PROJECT_LOGO\n\nUseful commands:\n'$PROJECT_CLI masternode status'   #Get the status of your masternode\n'${PROJECT_CLI} --help'              #Get a list of things that $PROJECT_CLI can do\n'sudo systemctl stop $DAEMON_BINARY'    #Stop the $PROJECT_NAME Daemon\n'sudo systemctl start ${DAEMON_BINARY}'   #Start the $PROJECT_NAME Daemon\n'sudo systemctl restart $DAEMON_BINARY' #Restart the $PROJECT_NAME Daemon\n'sudo systemctl status $DAEMON_BINARY'  #Get the status $PROJECT_NAME Daemon\n\nFor a beginners quick start for linux see https://steemit.com/tutorial/@greerso/linux-cli-command-line-interface-primer-for-beginners"
# ------------------------------------------------------------------------------

# ==============================================================================
# Install Steps
# ==============================================================================
#Base Server Options
	Set Hostname
	Create Swap for low ram vps
	Add non-root user
	Automatic security updates
	Install and configure UFW Firewall
		Allow all outbound traffic
		Deny all inbound traffic
		Allow inbound P2P for Masternode and SSH
		Whitelist installer ip address
	Install and configure Fail2Ban IDS
		Email reports of hacking activity
		Autoblock repeat offenders from public blacklist
	Harden SSH security
		Change port 22
		Disable root logon
		Require ssk-keys
#Masternode install
	Check for already installed
		Check daemon update
			install update
#	Simple Q&A process
	Secure install (no root user)
	Prompts with instructions
	Automatic generation of secure RPC passwords
			

# ------------------------------------------------------------------------------


