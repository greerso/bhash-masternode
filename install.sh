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
# =======================================================================================
# Setup alias and helper functions
# =======================================================================================
export NEWT_COLORS=''

# Silence
# Use 'command args...'
stfu() {
  "$@" >/dev/null 2>&1
}

# Use 'print_status "text to display"'
print_status() {
    echo
    echo "## $1"
    echo
}

# Use 'echo "Please enter some information: (Default value)"'
#    'variableName=$(inputWithDefault value)'
inputWithDefault() {
    read -r userInput
    userInput=${userInput:-$@}
    echo "$userInput"
}

# Use 'user_in_group user group'
user_in_group() {
    groups $1 | grep -q "\b$2\b"
}
# ---------------------------------------------------------------------------------------

# =======================================================================================
# Run as root
# =======================================================================================
if [[ $(whoami) != "root" ]]; then
    print_status Please run this script as root user.
    exit 1
fi
# ---------------------------------------------------------------------------------------

# =======================================================================================
# 'Switch to Aptitude...'
# =======================================================================================
stfu apt update
stfu apt-get -y install aptitude
# ---------------------------------------------------------------------------------------

# =======================================================================================
TERM=ansi whiptail --infobox "Installing packages required for setup..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Installing dependencies..." \
	8 78
# =======================================================================================
stfu aptitude -yq3 update
stfu aptitude -yq3 full-upgrade
stfu aptitude -yq3 install \
	apt-transport-https \
	ca-certificates \
	curl \
	htop \
	fail2ban \
	jq \
	libboost-system-dev \
	libboost-filesystem-dev \
	libboost-chrono-dev \
	libboost-program-options-dev \
	libboost-test-dev \
	libboost-thread-dev \
	libzmq3-dev \
	libminiupnpc-dev \
	libevent-dev \
	lsb-release \
	software-properties-common \
	unattended-upgrades \
	unzip \
	ufw \
	wget

# Add bitcoin repo
stfu add-apt-repository -y ppa:bitcoin/bitcoin
stfu apt update
stfu aptitude -yq3 install \
	libdb4.8-dev \
	libdb4.8++-dev
# ---------------------------------------------------------------------------------------

# =======================================================================================
# Installation variables
# =======================================================================================
rpcuser="bhashuser"
rpcpassword="$(head -c 32 /dev/urandom | base64)"
rpcport="5567"
bhashuserpw="$(head -c 32 /dev/urandom | base64)"
publicip="$(dig +short myip.opendns.com @resolver1.opendns.com)"
internalip="$(hostname -I)"
Hostname="$(cat /etc/hostname)"
sshPort=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
bhashuser=$(who -m | awk '{print $1;}')
bhashwallet=$HOME/.bhash
sshPort=$(cat /etc/ssh/sshd_config | grep Port | awk '{print $2}')
# ---------------------------------------------------------------------------------------

# =======================================================================================
TERM=ansi whiptail --infobox "Installing the bhash Masternode..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Installing the B-Hash Masternode..." \
	8 78
# =======================================================================================
# What you need.
TERM=ansi whiptail --msgbox "You will need:

-A qt wallet with at least 2000 coins
-An Ubuntu 16.04 64-bit server with a static public ip." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Before you start" \
	24 78

# Step 1
masternodeprivkey=$(TERM=ansi whiptail --inputbox \
"Start the qt wallet. Go to Settings→Debug console and enter the following command:

\"createmasternodekey\"

The result will look something like this \"y0uRm4st3rn0depr1vatek3y\".  Enter it here" \
	--backtitle "Installing B-Hash Masternode" \
	--title "Step 1" \
	--nocancel \
	3>&1 1>&2 2>&3 \
	24 78)
	
# Step 2
masternodealias=$(TERM=ansi whiptail --inputbox \
"Choose an alias for your masternode, for example MN1, then enter it here" \
	--default-item MN1 \
	--backtitle "Installing B-Hash Masternode" \
	--title "Step 2" \
	--nocancel \
	3>&1 1>&2 2>&3 \
	24 78)
# note:  --default-item is not working here.  need fix.

# Step 3
TERM=ansi whiptail --msgbox \
"While still in the Debug console type the following command to get a public address to send the stake to:

\"getaccountaddress $masternodealias\"

The result will look similar to this \"mA7fXSTe23RNoD83Esx6or4uYLxLqunDm5\".  Send exactly 2000 HASH to that address making sure that any tx fee is covered.
" \
	--backtitle "Installing B-Hash Masternode" \
	--title "Step 3" \
	24 78

# Step 4
collateral_output_txid=$(TERM=ansi whiptail --inputbox "Back in the Debug console Execute the command:

\"masternode outputs\"

This will output TX and output pairs of numbers, for example:
\"{
 \"a9b31238d062ccb5f4b1eb6c3041d369cc014f5e6df38d2d303d791acd4302f2\": \"0\"
}\"
Paste just the first number, long number, here and the second number in the next screen." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Step 4" \
	--nocancel \
	3>&1 1>&2 2>&3 \
	24 78)

# Step 5
collateral_output_index=$(TERM=ansi whiptail --inputbox "Paste the second, single digit number from the previous step (usually \"0\" here." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Step 5" \
	--nocancel \
	3>&1 1>&2 2>&3 \
	24 78)

# Step 6
TERM=ansi whiptail --msgbox "Open the masternode.conf file via the menu Tools→Open Masternode Configuration File. Without any blank lines type in a space-delimited single line paste the following string:

$masternodealias $publicip:17652 $masternodeprivkey $collateral_output_txid $collateral_output_index

Save and close the file." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Step 6" \
	24 78
	
# Step 7
TERM=ansi whiptail --msgbox "Open the bash.conf file via the menu Tools→Open Wallet Configuration File and paste the following text:

rpcuser=$rpcuser
rpcpassword=$rpcpassword
rpcallowip=127.0.0.1
listen=0
server=1
daemon=1
logtimestamps=1
maxconnections=256
masternode=1

Save and close the file." \
	--title "Step 7" \
	24 78
# ---------------------------------------------------------------------------------------

# =======================================================================================
TERM=ansi whiptail --infobox "Installing binaries to /usr/local/bin..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Install binaries" \
	8 78
# =======================================================================================
bhashOS=linux
bhashURL=$(curl -s https://api.github.com/repos/bhashcoin/bhash/releases/latest | jq -r ".assets[] | select(.name | test(\"${bhashOS}\")) | .browser_download_url")
curl -sSL "$bhashURL" | tar xvz -C /usr/local/bin/
sleep .5
# ---------------------------------------------------------------------------------------

# =======================================================================================
TERM=ansi whiptail --infobox "Creating configs in $bhashwallet..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Create config files" \
	8 78
# =======================================================================================
mkdir -p $bhashwallet
# ---------------------------------------------------------------------------------------

# =======================================================================================
# 'Creating the B-Hash Masternode configuration...'
# =======================================================================================
cat <<EOF > $bhashwallet/masternode.conf
$masternodealias $publicip:$rpcport $masternodeprivkey $collateral_output_txid $collateral_output_index
EOF
# ---------------------------------------------------------------------------------------

# =======================================================================================
TERM=ansi whiptail --infobox "Creating the B-Hash configuration..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Creating configs" \
	8 78
# =======================================================================================
cat <<EOF > $bhashwallet/bhash.conf
rpcuser=$rpcuser
rpcpassword=$rpcpassword
rpcallowip=127.0.0.1
listen=1
server=1
daemon=1
logtimestamps=1
maxconnections=256
masternode=1
externalip=$publicip
bind=$publicip:17652
masternodeaddr=$publicip
masternodeprivkey=$masternodeprivkey
mnconf=$bhashwallet/masternode.conf
datadir=$bhashwallet
EOF
# ---------------------------------------------------------------------------------------

# =======================================================================================
# Fix wallet permissions...
# =======================================================================================
stfu chown -R $bhashuser $bhashwallet
# ---------------------------------------------------------------------------------------

# =======================================================================================
TERM=ansi whiptail --infobox "Installing the bhash service..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Installing B-Hash service" \
	8 78
# =======================================================================================
cat <<EOF > /etc/systemd/system/bhashd.service
[Unit]
Description=B-Hash daemon
After=network.target

[Service]
ExecStart=/usr/local/bin/bhashd --daemon --conf=$bhashwallet/bhash.conf -pid=/run/bhashd/bhashd.pid
RuntimeDirectory=bhashd
User=$bhashuser
Type=forking
WorkingDirectory=$bhashwallet
PIDFile=/run/bhashd/bhashd.pid
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
# ---------------------------------------------------------------------------------------

# =======================================================================================
# Firewall port
# =======================================================================================
ufw allow 17652/tcp comment 'bhash daemon'
ufw allow $sshPort/tcp comment 'ssh port'
ufw --force enable
# ---------------------------------------------------------------------------------------


# =======================================================================================
TERM=ansi whiptail --infobox "Enabling and starting B-Hash service..." \
	--backtitle "Installing B-Hash Masternode" \
	--title "Enabling service..." \
	8 78
# =======================================================================================
stfu systemctl daemon-reload
stfu systemctl enable bhashd
stfu systemctl restart bhashd
# ---------------------------------------------------------------------------------------


TERM=ansi whiptail --msgbox "Restart the wallet.  You should see your Masternode listed in the Masternodes tab.

If you get errors, you may have made a mistake in either the bhash.conf or masternodes.conf files.

Use the buttons to start your alias.  It may take up to 24 hours for your masternode to fully propagate" \
	--backtitle "Installing B-Hash Masternode" \
	--title "Restart qt Wallet" \
	24 78
# =======================================================================================
# Display logo
# =======================================================================================
clear
cat << EOF                                               
          *////////////*                       
         ///////////////                       
         *//////////////                       
         ****//////////                        
        ********///////                        
        ***********///*                        
       /**************////////*,               
       *******************/////////,           
       **********************/////////         
       *************************///////*       
      ,*************@@@@***%@@@%***//////      
      *************/@@@&***@@@@/******////     
      *********@@@@@@@@@@@@@@@@@@@*******//    
     **********@@@@@@@@@@@@@@@@@@@*********,   
     *************/@@@@***&@@@**************   
     *************&@@@#***@@@@*************,   
    ,**********@@@@@@@@@@@@@@@@@@&*********/   
    ,,********/@@@@@@@@@@@@@@@@@@**********    
    ,,,,,********#@@@/***@@@@*************/    
   *,,,,,,,,*****@@@@***(@@@@************(     
   ,,,,,,,,,,,**************************       
   ,,,,,,,,,,,,,,,********************/        
  .,,,,,,,,,,,,,,,,,,****************          
  .,,,,,,,,,,,,,/,,,,,,,**********             

Useful commands:
'bhash-cli masternode status'	#Get the status of your masternode
'bhash-cli --help'				#Get a list of things that bhash-cli can do
'sudo systemctl stop bhashd'	#Stop the B-Hash Daemon
'sudo systemctl start bhashd'	#Start the B-Hash Daemon
'sudo systemctl restart bhashd' #Restart the B-Hash Daemon
'sudo systemctl status bhashd'	#Get the status B-Hash Daemon

For a beginners quick start for linux see https://steemit.com/tutorial/@greerso/linux-cli-command-line-interface-primer-for-beginners
EOF
# ---------------------------------------------------------------------------------------
