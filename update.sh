#!/usr/bin/env bash

# 
# 3CX DEBIAN 10 TO 12 UPGRADE SCRIPT
# DO NOT MODIFY THE SCRIPT
# IT IS HIGHLY RECOMMENDED TO TAKE A SNAPSHOT OF THE INSTANCE/SERVER BEFORE PROCEEDING
# AS WELL AS A FULL 3CX BACKUP, STORED OFFLINE OUTSIDE OF THE INSTANCE.
# https://www.3cx.com
#

# Initial Config
SCRIPT=$(/bin/readlink -f $0)
VERSION_BEFORE=`/usr/bin/lsb_release -r | cut -f2`
ARCHITECTURE=`dpkg --print-architecture`
LOG_UPDATE="/tmp/UPDATE.log"
LOG_TCX_BACKUP="/tmp/BACKUP.log"
FLAG_UPDATE_SUCCESS="/tmp/UPDATE_SUCCESSFULL"
FLAG_UPDATE_FAIL="/tmp/UPDATE_FAILED"
FLAG_UPDATE_RUNNING="/tmp/UPDATE_RUNNING"
WORKING_DIRECTORY="/tmp"
WEBAPI_URL="https://webapi.3cx.com/upgrade"
REPO_URL="http://repo.3cx.com"
DEBIAN_REPO_URL="http://deb.debian.org"
SCRIPT_VERSION="f3eaf417288d6435d00a4a7d7814ea8c37c76f375cee71a69be7da84508daf4e"
HOSTNAME=`hostname`
HYPERVISOR=`virt-what`
TCX_VERSION_INSTALLED=""
REMOVED_BACKPORTS=("")
RESTORE_BACKPORTS_CHECKER=0
RESTORE_3CX_CHECKER=0
PREFLIGHT_CHECK=0


# Execute the script in non-interactive mode
export DEBIAN_FRONTEND=noninteractive
{

# Logging function
function log {
	/bin/echo -e "\e[33m====== [`date +"%H:%M:%S"`] $1: $2\e[39m"
}

# Send the upgrade result to the API
function sendStatusAPI {
	/usr/bin/wget --post-file=$LOG_UPDATE $WEBAPI_URL 2> /dev/null > /dev/null
}

# Upgrade result function
function upgrade_result {
	# Success, Aborted, Unsupported and Failed
	STATUS=$1
	ERROR=$2
	REMEDIATION=$3
	RES_TIME=`date +"%d-%m-%Y %H:%M:%S"`
	UPGRADE_RESULT=`jq -n --arg res "$STATUS" --arg tit "$ERROR" --arg msg "$REMEDIATION" --arg tim "$RES_TIME" '{result: $res, time: $tim, title: $tit, message: $msg}'`

	/bin/echo $UPGRADE_RESULT > /var/lib/3cxpbx/OS_UPGRADE_RESULT
	/bin/chown phonesystem: /var/lib/3cxpbx/OS_UPGRADE_RESULT

	if [ -f /var/lib/3cxpbx/OS_UPGRADE_RESULT ];then
	    log "Upgrade Result" "*******************************************"
		/bin/cat /var/lib/3cxpbx/OS_UPGRADE_RESULT | jq '.' -r
	fi
}

# Success function
function success {
	upgrade_result "success" "Upgrade successfully completed" "The upgrade has been successfully completed. Your system is now running Debian 12 (Bookworm)."
	/bin/cp $LOG_UPDATE $FLAG_UPDATE_SUCCESS
	/bin/rm -f $FLAG_UPDATE_RUNNING
	/bin/echo "::SUCCESS::"
	sendStatusAPI
}

# Install package function
function apt_command {

  # Attempt to handle apt locked at all times 
  check_apt_lock

  for command in "$@"
  do
    /bin/echo "> Execute apt command simulation on \""$command"\"";
    if [ "$command" != "update" ]; then
      # simulate an update (dependency check)
      /usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Acquire::ForceIPv4=true -o Dpkg::Options::="--force-confold" -y --allow-downgrades --allow-remove-essential --allow-change-held-packages --simulate $command  || { check_fail "Upgrade" "Package Update Simulation Failed" "An error occurred while simulating package upgrade: $1"; }

	  # download packages (check network)
      /usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --allow-downgrades --allow-remove-essential --allow-change-held-packages --download-only $command  || { check_fail "Upgrade" "Package Download Failed" "An error occurred while downloading package: $1"; }
    fi
  done
  # simulation succeeded and all packages are downloaded
  for command in "$@"
  do
    /bin/echo "> Execute apt command on \""$command"\"";
    /usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --allow-downgrades --allow-remove-essential --allow-change-held-packages $command  || { check_fail "Upgrade" "Package Update Failed" "An error occurred while upgrading package: $1"; }
  done
}

# Fix google pub key
function google_pub_key {
	dpkg -l | grep google-cloud-sdk
  	if [ "$?" = "0" ]; then
		curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg| gpg --yes -o /usr/share/keyrings/google-archive-keyring.gpg --dearmor
		curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
		curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo tee /usr/share/keyrings/cloud.google.asc
	fi
}

# Add bullseye debian key (ls)
function bullseye_apt_key {
	wget -qO /etc/apt/trusted.gpg.d/bullseye-ls.asc https://ftp-master.debian.org/keys/release-11.asc
	wget -qO /etc/apt/trusted.gpg.d/bullseye-archive-ls.asc https://ftp-master.debian.org/keys/archive-key-11.asc
	wget -qO /etc/apt/trusted.gpg.d/bullseye-security-ls.asc https://ftp-master.debian.org/keys/archive-key-11-security.asc
}

# Check if the system is up to date
function check_system_up_to_date {
	PACKAGES_PENDING_UPDATE=`apt-get -s upgrade | grep "^Inst" | wc -l`
	if [ $PACKAGES_PENDING_UPDATE -gt 0 ];then
	    log "$PACKAGES_PENDING_UPDATE packages are pending update"
		/bin/false
		check_fail "aborted" "Pending updates found" "Packages with pending updates have been detected. Please enable security updates in 3CX for all packages to be automatically installed and then try again."
	fi
}

# Check minimum specs
function check_specs {
	# Check cpu
	AVAILABLE_CPU=`nproc`
	if [ $AVAILABLE_CPU -lt 1 ]; then
		log "Preparation" "Not enough CPU cores. At least 2 CPU cores are required for a smooth upgrade."
		PREFLIGHT_CHECK=1
		upgrade_result "aborted" "Insufficient CPU cores" "There are not enough CPU cores. Please make sure there are at least 2 CPU cores before upgrading."
		fail;
	fi
	# Check memory
	AVAILABLE_MEMORY=`cat /proc/meminfo | grep MemTotal | awk '{print $2}'`
	if [ $AVAILABLE_MEMORY -lt 1900000 ]; then
		log "Preparation" "Not enough memory. At least 2GB of memory is required for a smooth upgrade."
		PREFLIGHT_CHECK=1
		upgrade_result "aborted" "Insufficient memory" "There is not enough memory. Please make sure there is at least 2GB of memory before upgrading."
		fail;
	fi
}

# Check whether the 3CX and Debian repositories are reachable
function check_connectivity {

	IS_REPO_REACHABLE=`curl -Is -m 10 $REPO_URL | head -n 1 | awk '{print $2}'`
	if [ "$IS_REPO_REACHABLE" == "200" ]; then
		log "Preparation" "$REPO_URL is reachable"
	else 
	    PREFLIGHT_CHECK=1
		false
		check_fail "aborted" "3CX Repository is unreachable" "Ensure that the server can reach $REPO_URL. Try using 8.8.8.8 or 1.1.1.1 as nameservers."
	fi

	IS_DEBIAN_REPO_REACHABLE=`curl -Is -m 10 $DEBIAN_REPO_URL | head -n 1 | awk '{print $2}'`
	if [ "$IS_DEBIAN_REPO_REACHABLE" == "200" ]; then
		log "Preparation" "$DEBIAN_REPO_URL is reachable"
	else 
	    PREFLIGHT_CHECK=1
		false
		check_fail "aborted" "Debian Repository is unreachable" "Ensure that the server can reach $DEBIAN_REPO_URL. Try using 8.8.8.8 or 1.1.1.1 as nameservers."
	fi
}

# Check whethere there is a known monitoring software running which may interfere with the upgrade
function disable_monitoring_software {
	log "Preparation" "Checking for monitoring software."
	MONITORING_SOFTWARE=("monit zabbix-agent nagios datadog-agent snmpd cmk-agent-ctl icinga2 cactid smartmontools monitorix munin-node newrelic-infra cmk-agent-ctl-daemon");
	for monitoring in $MONITORING_SOFTWARE; do
		service $monitoring status
		if [ "$?" == "0" ]; then
			service $monitoring stop
			log "Preparation" "Found $monitoring. Stopping service to avoid interference with the upgrade."
		fi
	done
}

# Check whether XFS filesystem is used with the barrier/nobarrier mount options ~ Debian 11
function check_xfs {
	XFS_MOUNT_CHCK=`cat /etc/fstab | grep " xfs " | grep -iE "barrier|nobarrier"`
	if [ "$?" == "0" ]; then
	    PREFLIGHT_CHECK=1
		false
		check_fail "aborted" "Deprecated XFS mount option used" "A disk running XFS is mounted with the 'barrier' option set. This is deprecated in Debian 11. Please remove it in /etc/fstab, otherwise the disk will fail to mount."
	fi
}

function firewall_save_old_iptables {
	log "Upgrade" "Replacing IPTables with NFTables"
	log "Upgrade" "Installing NFTables package with apt-get"
	apt_command "install nftables"
	log "Upgrade" "Install iptables compat package"
	/usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --allow-downgrades --allow-remove-essential --allow-change-held-packages install iptables-nftables-compat 2> /dev/null > /dev/null
	log "Firewall" "Saving the old iptables to convert them to NFTables"
	/sbin/iptables-save > /tmp/iptables-old-4.txt
	/sbin/ip6tables-save > /tmp/iptables-old-6.txt
	log "Upgrade" "Converting ipgrables to NFTables"
	iptables-restore-translate -f /tmp/iptables-old-4.txt > /tmp/nftables-new.nft
	ip6tables-restore-translate -f /tmp/iptables-old-6.txt >> /tmp/nftables-new.nft
	log "Upgrade" "Removing comments from NFTables file"
	/bin/sed -i.bak -E "s/comment \"(.*)\"//" /tmp/nftables-new.nft
}

function firewall_convert_old_iptables_to_new_nftables {
	# log "Upgrade" "Execute new NFTables rules"
	# /usr/sbin/nft -f /tmp/nftables-new.nft
	log "Upgrade" "Preparing /etc/nftables.conf for next reboot"
	/bin/cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f

# Flush the rule set
flush ruleset

EOF
	/bin/cat /tmp/nftables-new.nft >> /etc/nftables.conf
	/bin/chmod +x /etc/nftables.conf
	log "Upgrade" "Enable NFTables in systemctl"
	/bin/systemctl enable nftables
}


function flag_if_dphys_swapfile_installed {
	/bin/systemctl status dphys-swapfile 
	if [ $? -eq 0 ]; then
		touch /tmp/TCX_UPGRADE_DPHYS_IS_ENABLED
	fi
}

function stop_3cx_services {
	/usr/sbin/3CXStopServices
}

function start_3cx_services {
		systemctl start 3CXEventNotificationManager 3CXCfgServ01 3CXMediaServer 3CXPhoneSystemMC01 3CXPhoneSystem01 3CXIVR01 3CXQueueManager01 3CXCallFlow01 3CXSystemService01 3CXAudioProvider01 3CXGatewayService nginx
}

function disable_apt_daily_timer {
	/bin/systemctl stop apt-daily.timer
}

function enable_apt_daily_timer {
	/bin/systemctl start apt-daily.timer
}

function disable_dphys_swapfile {
	if [ -f /tmp/TCX_UPGRADE_DPHYS_IS_ENABLED ]; then
		/sbin/dphys-swapfile uninstall
		/bin/systemctl disable dphys-swapfile.service
		apt_command "remove dphys-swapfile"
	fi
}

function enable_dphys_swapfile {
	if [ -f /tmp/TCX_UPGRADE_DPHYS_IS_ENABLED ]; then
		apt_command "update"
		apt_command "install dphys-swapfile"
		/bin/systemctl enable dphys-swapfile.service
	fi
}

function disable_3cx_update {
	mv /usr/sbin/3CXServicePackVersion /tmp/3CXServicePackVersion.backup
}

function activate_3cx_update {
	if [ ! -f /usr/sbin/3CXServicePackVersion ]; then
		mv /tmp/3CXServicePackVersion.backup /usr/sbin/3CXServicePackVersion
	fi
}

function check_apt_lock {
	x=1
	APT_LOCKED=0
	DPKG_LOCKED=0
	while [ $x -le 5 ]
	do
		x=$(( $x + 1 ))

		/bin/fuser /var/lib/apt/lists/lock > /dev/null 2> /dev/null
		if [ $? -eq 0 ]; then
			log "APT is currently locked by another process. Retrying in 45 seconds..."
			APT_LOCKED=1
			sleep 45
		else 
			APT_LOCKED=0
			break
		fi

	done
	
	if [ "$APT_LOCKED" == "1" ]; then
		/bin/fuser /var/lib/apt/lists/lock > /dev/null 2> /dev/null
		if [ $? -eq 0 ]; then
			/bin/fuser /var/lib/apt/lists/lock
			log "Failed" "Output of ps aux (apt lock)"
			AS=`/bin/fuser /var/lib/apt/lists/lock | /usr/bin/cut -d ":" -f2`
			/bin/ps aux --forest | grep $AS
			false
			check_fail "aborted" "APT is locked" "APT is currently locked by a process. Make sure that the server is not installing any updates and try again."
		fi
	fi

	x=1
	while [ $x -le 5 ]
	do
		x=$(( $x + 1 ))

		/bin/fuser /var/lib/dpkg/lock > /dev/null 2> /dev/null
		if [ $? -eq 0 ]; then
			log "DPKG is currently locked by another process. Retrying in 45 seconds..."
			DPKG_LOCKED=1
			sleep 45
		else 
			DPKG_LOCKED=0
			break
		fi
	done

	if [ "$DPKG_LOCKED" == "1" ]; then
		/bin/fuser /var/lib/dpkg/lock > /dev/null 2> /dev/null
		if [ $? -eq 0 ]; then
			/bin/fuser /var/lib/dpkg/lock
			false
			check_fail "aborted" "DPKG is locked" "DPKG is currently locked by a process. Make sure that the server is not installing any updates and try again."
		fi
	fi
}

function restore_source_lists {
	if [ -d "/etc/apt/upgrade_sources_bk" ]; then
		rm -rf /etc/apt/sources.list.d/*
		/bin/cp -f /etc/apt/upgrade_sources_bk/* /etc/apt/sources.list.d/ 	
	fi
	if [ -f "/tmp/sources.list.backup" ]; then
		/bin/cp /tmp/sources.list.backup /etc/apt/sources.list
	fi
}

function reinstate_3cx {
	apt list --installed | grep 3cxpbx 2> /dev/null > /dev/null
	if [ "$?" != "0" ]; then
		RESTORE_3CX_CHECKER=1
		sleep 5
		apt_command "update"
		apt_command "install 3cxpbx"
	fi
}

function fail {
	/bin/cp $LOG_UPDATE $FLAG_UPDATE_FAIL
	/bin/rm -f $FLAG_UPDATE_RUNNING
	if [ "$PREFLIGHT_CHECK" = "0" ]; then
		restore_source_lists
		# if [ $RESTORE_BACKPORTS_CHECKER -eq 0 ]; then
		# 	restore_backports
		# fi
		if [ $RESTORE_3CX_CHECKER -eq 0 ]; then
			reinstate_3cx
		fi
		activate_3cx_update
		start_3cx_services
		enable_apt_daily_timer
		enable_dphys_swapfile
		log "Failed" "Output of ps aux"
		/bin/ps aux 2>&1
		log "Failed" "Output of journalctl"
		/bin/journalctl -xe 2>&1
		log "Failed" "Output of /var/log/nginx/error.log"
		/bin/cat /var/log/nginx/error.log 2>&1 | /usr/bin/tail -1000
		log "Failed" "Output of /var/log/nginx/access.log"
		/bin/cat /var/log/nginx/access.log 2>&1 | /usr/bin/tail -1000
		log "Failed" "Output of /var/log/syslog.log"
		/bin/cat /var/log/syslog 2>&1 | /usr/bin/tail -1000
		if [ -f "/var/log/postgresql/postgresql-11-main.log" ];then
			log "Failed" "Output of /var/log/postgresql/postgresql-11-main.log"
			/bin/cat /var/log/postgresql/postgresql-11-main.log 2>&1 | /usr/bin/tail -100
		fi
		if [ -f "/var/log/postgresql/postgresql-13-main.log" ];then
			log "Failed" "Output of /var/log/postgresql/postgresql-13-main.log"
			/bin/cat /var/log/postgresql/postgresql-13-main.log 2>&1 | /usr/bin/tail -100
		fi
		if [ -f "/var/log/postgresql/postgresql-15-main.log" ];then
			log "Failed" "Output of /var/log/postgresql/postgresql-15-main.log"
			/bin/cat /var/log/postgresql/postgresql-15-main.log 2>&1 | /usr/bin/tail -100
		fi
	fi
	/bin/echo "::FAIL::"
	sendStatusAPI
	exit -1;
}


function check_fail {
	if [ "x$?" != "x0" ]; then
		upgrade_result "$1" "$2" "$3"
		/bin/echo -e "\e[31m[`date +"%H:%M"`] $1: $2 - $?\e[39m"
		/bin/cp $LOG_UPDATE $FLAG_UPDATE_FAIL
		/bin/rm -f $FLAG_UPDATE_RUNNING
		fail
	fi
}

function check_if_3cx_is_installed {
	dpkg -l | grep 3cxpbx 2> /dev/null > /dev/null
	check_fail "aborted" "3CX is not installed." "3CX is not installed on this system."

	TCX_VERSION_INSTALLED=`apt-cache policy 3cxpbx | grep Installed | awk '{print $2}'`
	if [ "${TCX_VERSION_INSTALLED:0:2}" -lt "18" ];then
		/bin/false
		check_fail "aborted" "3CX Version not supported" "The system is running 3CX V16 on Debian 10 which is not officially supported. Please upgrade to V18 and try again."
	fi
}


function check_locale_problem {
	/usr/bin/pg_lsclusters 2>&1 | /bin/grep "perl: warning"
	if [ $? -eq 0 ]; then
		/bin/cat /etc/default/locale
		/usr/bin/locale
		/usr/bin/locale -a
		/bin/false
		check_fail "aborted" "Invalid Locales for PostgreSQL" "Run 'sudo dpkg-reconfigure locales' and enable 'en_US.UTF-8'."
	else
		log "Preparation" "Checking locales"
	fi
}

function check_hold_packages {
	dpkg --get-selections | grep 'hold$'
	if [ "x$?" != "x0" ]; then
		log "Workaround" "Unholding packages to avoid issues during the upgrade";
		dpkg --get-selections | grep 'hold$' | awk '{print $1}' | while read line; do apt-mark unhold $line; done
	fi
}

function check_misconfigured_packages {
	dpkg --audit
	if [ "x$?" != "x0" ]; then
		log "Workaround" "Attempting to fix misconfigured or broken packages";
		apt_command "--fix-broken install"
		if [ "x$?" != "x0" ]; then
			PREFLIGHT_CHECK=1
			false
			check_fail "aborted" "Misconfigured packages detected" "The system has misconfigured or packages in a broken state. Prin run 'dpkg --audit' to identify and manually fix them."
		fi
	fi
}

# Check for known third party software known for breaking the upgrade
function check_third_party_software {
	log "Preparation" "Checking for third party software hat may interfere with the upgrade."
	INSTALLED_SOFTWARE=`apt list --installed | cut -d "/" -f1`
	PROHIBITED=("php lighttpd rkhunter apache2");
	for installed in $INSTALLED_SOFTWARE; do
		if [[ "${PROHIBITED[@]}" =~ "$INSTALLED_SOFTWARE" ]]; then
		    PREFLIGHT_CHECK=1
			/bin/false
			check_fail "aborted" "Third party software found" "A third party software which is known to interfere with the upgrade was found: $installed. Please remove or disable it and retry."
		fi
	done
}

# Check if the achitecture is supported
function check_architecture {
	log "Preparation" "Checking if the architecture is supported"
	if [ "x$ARCHITECTURE" == "xarmhf" ] || [ "x$ARCHITECTURE" == "xarm64" ]; then
		log "Preparation" "Non supported architecture detected $ARCHITECTURE."
		PREFLIGHT_CHECK=1
		upgrade_result "unsupported" "Unsupported Architecture" "The upgrade script does not support $ARCHITECTURE."
		fail;
	fi
}

# Check disk space
function check_disk_space {

	# Clean up partial downloads
	apt_command "clean"

	TCX_SPACE=`du -hs /var/lib/3cxpbx | awk '{print $1}'`
	log "Preparation" "3CX installation takes $TCX_SPACE of space"

	# Check if at least 5GB of disk space is available
	AVAILABLE_DISK_SPACE=`/bin/echo $(($(stat -f --format="%a*%S" /)))`
	if [ $AVAILABLE_DISK_SPACE -lt 5006870912 ]; then
		log "Preparation" "Not enough disk space available. At least 5GB of free disk space is required for a smooth upgrade."
		PREFLIGHT_CHECK=1
		upgrade_result "aborted" "Insufficient disk space" "There is not enough disk space available. Please make sure at least 5GB is free before upgrading."
		fail;
	fi
}


# Workaround
# apt-utils : Depends: apt (= 1.4.X) but 1.4.11 is installed
function apt_utils_workaround_check {
	/usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --allow-downgrades --allow-remove-essential --allow-change-held-packages --simulate upgrade | grep -E "apt-utils : .*: apt \(= 1\.4\.[0-9]+\) .* 1.4.11.*"
	if [ "x$?" = "x0" ]; then
		log "Workaround" "Try to fix apt-utils dependency problem";
		apt_command "install apt-utils"
	fi
}

function switch_ethernet_scheme {
  if [ "x$BLOCK_DOWNGRADE" == "x1" ]; then return; fi;

	# check if network inetface is old scheme
	/sbin/ifconfig | /bin/grep eth0
	if [ "x$?" == "x0" ]; then
  	# backup for rollback
  	/bin/cp /etc/default/grub /tmp/grub.backup
  	/bin/sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT/ {/net.ifnames=0/! s/\(.*\)"/\1 net.ifnames=0"/}' /etc/default/grub
  	/bin/ln -s /dev/null /etc/systemd/network/99-default.link
	fi
}

function switch_googld_sdk {
  # unhold package if it is on hold
  if [ "x$GOOGLE_SDK" == "x1" ]; then
    /usr/bin/apt-mark unhold google-cloud-sdk
	log "Post Install" "Upgrading Google Cloud SDK if needed"
	apt_command "install google-cloud-sdk"
    return;
  fi
  # check if Google Cloud SDK is installed
  GOOGLE_SDK=0
  /usr/bin/dpkg -s google-cloud-sdk
  if [ $? -eq 0 ]; then
    GOOGLE_SDK=1
    /usr/bin/apt-mark hold google-cloud-sdk
  fi
}

# Set 3CX Debian Bullseye repos
function switch_package_sources {

	if [ ! -f /usr/share/keyrings/3cx-archive-keyring.gpg ]; then
		wget -O- $REPO_URL/key.pub | gpg --dearmor | sudo tee /usr/share/keyrings/3cx-archive-keyring.gpg > /dev/null
	fi

	rm /etc/apt/sources.list.d/3cx*

  	if [ "x$BLOCK_DOWNGRADE" == "x1" ]; then return; fi;
	/bin/echo "deb http://deb.debian.org/debian bullseye main"  	> /etc/apt/sources.list
	/bin/echo "deb http://deb.debian.org/debian-security/ bullseye-security main"  	>> /etc/apt/sources.list
	/bin/echo "deb http://deb.debian.org/debian bullseye-updates main"  	>> /etc/apt/sources.list
	
	# Replace all occurrences of buster in the /etc/apt/sources.list.d/ 3cxpbx.list
	/bin/sed -i s/buster/bullseye/g /etc/apt/sources.list.d/*
	/bin/sed -i s/10/11/g /etc/apt/sources.list.d/*
}

# Check sources integrity
function check_sources {
	echo "Preparation" "Checking sources"
	cat /etc/apt/sources.list
	ls /etc/apt/sources.list.d/
	cat /etc/apt/sources.list.d/*
	apt update
	if [ "$?" != "0" ]; then
	    PREFLIGHT_CHECK=1
		/bin/false
		check_fail "aborted" "Apt issue detected" "There seems to be an issue with the system's sources. Please run apt update manually and see what needs to be fixed."	
	fi
}

# Check for third party source lists/repositories
function check_third_party_sources {
	test_folder=("google-cloud.list google-cloud-sdk.list backports.list gce_sdk.list 3cxpbx.list 3cxpbx-testing.list rasp.list digitalocean-agent.list  google_osconfig_managed.list google-cloud-monitoring.list google.list google-cloud-logging.list droplet-agent.list nightly.list vultr-apprepo.list zabbix.list microsoft-prod.list");
	ls /etc/apt/sources.list.d/
	for found_list in `ls /etc/apt/sources.list.d/`; do
		if [[ "${test_folder[@]}" =~ "$found_list" ]]; then
    		log "Preparation" "Source list found: $found_list"
		else
			/bin/false
			check_fail "aborted" "Third party source list found" "A third party source list was found in /etc/apt/sources.list.d/: $found_list. Please remove it and retry."
		fi
	done
}

# Backup existing source lists
function backup_sources {
	if [ ! -d "/etc/apt/upgrade_sources_bk" ]; then
		mkdir /etc/apt/upgrade_sources_bk
	fi

	/bin/cp -f /etc/apt/sources.list.d/* /etc/apt/upgrade_sources_bk

	# Backup old debian package sources (in case we need to switch back)
	/bin/cp -f /etc/apt/sources.list /tmp/sources.list.backup
}


# Fix for grub-pc
function check_for_grub {
 DEVICE_FOUND=""
 for i in `lsblk -rndbo SIZE,NAME,TRAN`; do
  /bin/echo $i
  DEVICE=`/bin/echo $i | cut -d" " -f2;`
  dd if=/dev/$DEVICE bs=512 count=1 2> /dev/null | grep -q GRUB && /bin/echo "GRUB partition found $DEVICE"
  GRUB_FOUND=$?
  if [ "x$GRUB_FOUND" == "x0" ]; then
		DEVICE_FOUND=$DEVICE
   return
  fi
 done;
}

# Check for sources/repositories problems
function check_upgradeability {
	log "Preparation" "Switching to Debian 11 sources to check upgradeability of the current sources/repositories to Debian $1"
	switch_package_sources
	/usr/bin/apt-get update
	check_fail "aborted" "Source/repository problem detected" "A preflight check of the current sources/repositories indicated that there is an issue upgrading to Debian 11. The upgrade aborted to prevent failure."

	log "Preparation" "Upgreadability status seems OK"
	restore_source_lists
}

# Check if there are any packages installed from backports as they will probably interfere with the upgrade
function check_backports {
	BACKPORTS_PACKAGES=`dpkg-query -l | grep '~bpo' | grep ^ii`
	if [ "$?" == "0" ]; then
		log "Preparation" "Packages installed from packports detected."
		for BACKPORT_PACKAGE in `dpkg-query -l | grep '~bpo' | grep ^ii | awk '{print $2}'`
		do
			log "Preparation" "Removing backport package $BACKPORT_PACKAGE"
			REMOVED_BACKPORTS+=("$BACKPORT_PACKAGE")
			# Backup the package's configuration in case the user wants to use it post-ugprade
			if [ -f /var/lib/dpkg/info/$BACKPORT_PACKAGE.conffiles ]; then
				CONF_FILES=`cat /var/lib/dpkg/info/$BACKPORT_PACKAGE.conffiles`
				if [ "$?" == "0" ];then
					log "Preparation" "Backing up the configuration files of the backport packages that will be removed"
					if [ ! -d  /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup ]; then
						log "Preparation" "Creating /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup directory"
						mkdir -p /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup
					fi
					
					for conf_file in $CONF_FILES
					do
						if [ -f  $conf_file ]; then
							CONF_FILE_DIR=`dirname "$conf_file"`
							if [ ! -d  /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$CONF_FILE_DIR ]; then
								log "Preparation" "Creating /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$CONF_FILE_DIR directory"
								mkdir -p /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$CONF_FILE_DIR
							fi
							log "Preparation" "Copying $conf_file to /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup"
							cp -p $conf_file /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$CONF_FILE_DIR
						fi
						
					done
				fi
			fi
			apt_command "remove --purge $BACKPORT_PACKAGE"
			check_fail "aborted" "Cannot remove backport package" "There was an error removing package $BACKPORT_PACKAGE. Please remove it manually and try again."
		done
	fi
}


# Restore removed backported packages if the script fails/aborts before any packages are upgraded to Debian 11
function restore_backport_packages_config {
	# Ensure that the system has not upgraded
	if [ `/usr/bin/lsb_release -r | cut -f2` == "10" ]; then
		BACKPORT_PACKAGE=$1
		if [ -f /var/lib/dpkg/info/$BACKPORT_PACKAGE.conffiles ]; then
			CONF_FILES=`cat /var/lib/dpkg/info/$BACKPORT_PACKAGE.conffiles`
			if [ "$?" == "0" ];then
				if [ -d  /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup ]; then
					log "Restore" "Attempting to restore the configuration files of backport package $BACKPORT_PACKAGE"
					for conf_file in $CONF_FILES
					do
						CONF_FILE_DIR=`dirname "$conf_file"`
						if [ -f  /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$conf_file ]; then
							log "Restore" "Restoring /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$conf_file to $conf_file"
							cp -p /etc/3CX-UPGRADE-CONF-BACKUPS/$BACKPORT_PACKAGE-configuration-backup$conf_file $conf_file
						fi
					done
				fi
			fi
		fi
	fi
}

# Restore any packages from backports we removed if they are available in the repository
function restore_backports {
	sleep 10
	RESTORE_BACKPORTS_CHECKER=1
	apt_command "update"
	if [ ${#REMOVED_BACKPORTS[@]} -gt 0 ]; then
		log "Post-Upgrade" "Attempting to restore removed backport packages"
		for package in  ${REMOVED_BACKPORTS[@]}
		do
			log "Post-Upgrade" "Checking if $package is available.."
			apt-cache policy $package | grep "Candidate: \([0-9\.~_+-]\)"
			if [ "$?" == "0" ]; then
				log "Post-Upgrade" "Restoring $package"
				apt_command "install $package"
				restore_backport_packages_config $package
			else
				log "Post-Upgrade" "$package is not available to restore"
			fi
		done
	fi
}


# Get current PostgresSQL version to be used later
function get_postgresql_version {
	log "Preparation" "Fetching current PostgreSQL version, requesting cluster version $1"
	log "Preparation" "Fetch postgresql information"
	dpkg -l | grep postgresql
	PSQL_FROM_CLUSTER=`pg_lsclusters --no-header`
	log "Preparation" "Fetch postgresql cluster: $PSQL_FROM_CLUSTER"
	PSQL_VERSION_FULL=`sudo -u postgres psql -tAq -c "SELECT current_setting('cluster_name'), current_setting('server_version');"`
	if [ "$?" != "0" ];then
		log "Preparation" "Cannot get PostgreSQL version."
		systemctl is-active --quiet postgresql
		if [ "$?" != "0" ];then
			log "Preparation" "Postgresql is not running. Attempting to start it. "
			systemctl start postgresql
			if [ "$?" != "0" ];then
				/bin/false
				check_fail "aborted" "Cannot start PostgreSQL" "Postgresql service cannot be started."
			else 
				get_postgresql_version
			fi
		fi
	fi
	PSQL_VERSION=`echo $PSQL_VERSION_FULL |  cut -d "/" -f1`
	if [ -z $PSQL_VERSION ] || [ "$PSQL_VERSION" != "$1"  ];then
		log "Preparation" "Could not get postgresql cluster version from the settings database. Got: $PSQL_VERSION. Trying from pg_lsclusters result..."
		PSQL_VERSION=`echo $PSQL_FROM_CLUSTER | awk '{print $1}'`
	fi

	if [ -z $PSQL_VERSION ] || [ "$PSQL_VERSION" != "$1"  ];then
	    log "Preparation" "Unable to determine postgresql cluster version. Got: $PSQL_VERSION. Aborting..."
		/bin/false
		check_fail "aborted" "Unable to determine the PostgreSQL cluster version" "The script was unable to determine PostgreSQL cluster version. This may be a result of postgresql misconfiguration or service problem."
	fi
}

function check_nginx_permissions {
	NGINX_FILES_USER=`find /var/lib/3cxpbx/Bin/nginx/conf ! -user phonesystem`
	NGINX_FILES_GROUP=`find /var/lib/3cxpbx/Bin/nginx/conf ! -group phonesystem`
	if [ ! -z "$NGINX_FILES_USER" ] || [ ! -z "$NGINX_FILES_GROUP" ];then
		/bin/false
		check_fail "aborted" "File ownership problem" "There are files under /var/lib/3cxpbx/Bin/nginx/conf with the wrong user and/or group ownership. Please make sure the files are owner by the user: phonesystem"
	fi
}


# Detach script if necessary
if [ "x$1" != "xdetach" ]; then
	if [ "x$1" != "xrunstandalone" ]; then
		log "Preparation" "Detach script"
	  /usr/bin/setsid sh -c "exec $SCRIPT 'runstandalone' 2>&1 < /dev/null | tee -a $LOG_UPDATE 2>&1" &
	  exit 0;
	else
		log "Preparation" "Script is now running standalone"
	fi
fi

# The parent script might be there still. Wait 3 seconds for exiting.
/bin/sleep 1
log "Preparation" "Script path is $SCRIPT"
for pid in $(/bin/pidof -x $(/usr/bin/basename $SCRIPT)); do
    if [ $pid != $$ ]; then
				log "Preparation" "Upgrade script $(/usr/bin/basename $SCRIPT) seeems to be already running with PID $pid"
        exit 1
    fi
done

if [ -f $FLAG_UPDATE_RUNNING ]; then
	log "Preparation" "Upgrade script $(/usr/bin/basename $SCRIPT) seeems to be already running. Found $FLAG_UPDATE_RUNNING"
	exit 1
fi



# Starting script
cd $WORKING_DIRECTORY
touch $FLAG_UPDATE_RUNNING

log "Starting" "Backup script $SCRIPT"
log "Starting" "Backup script version: $SCRIPT_VERSION"
log "Starting" "Current directory: `pwd`"
log "Starting" "Current user: `whoami`"
log "Starting" "Current date: `date`"
log "Starting" "Current version: $VERSION_BEFORE"
log "Starting" "Architecture: $ARCHITECTURE"
log "Starting" "Hostname: $HOSTNAME"
log "Starting" "Hypervisor: $HYPERVISOR"

# Stop nginx to prevent interference by the user while the upgrade is running
#/bin/systemctl stop nginx


apt_command "update"

# Install required software
/usr/bin/dpkg -s jq
if [ "$?" != "0" ]; then
    log "Prepare" "Installing JQ..."
	apt_command "install jq"
	if [ "x$?" != "x0" ]; then
		check_fail "aborted" "Unable to install jq" "Installation of the jq package has failed."
	fi
fi

/usr/bin/dpkg -s curl
if [ "$?" != "0" ]; then
    log "Prepare" "Installing Curl..."
	apt_command "install curl"
	if [ "x$?" != "x0" ]; then
		check_fail "aborted" "Unable to install curl" "Installation of the curl package has failed."
	fi
fi

/usr/bin/dpkg -s wget
if [ "$?" != "0" ]; then
    log "Prepare" "Installing Wget..."
	apt_command "install wget"
	if [ "x$?" != "x0" ]; then
		check_fail "aborted" "Unable to install wget" "Installation of the wget package has failed."
	fi
fi

/usr/bin/dpkg -s sudo
if [ "$?" != "0" ]; then
    log "Prepare" "Installing Sudo..."
	apt_command "install sudo"
	if [ "x$?" != "x0" ]; then
		check_fail "aborted" "Unable to install Sudo" "Installation of the sudo package has failed."
	fi
fi

/usr/bin/dpkg -s apt-transport-https
if [ "$?" != "0" ]; then
    log "Prepare" "Installing apt-transport-https..."
	apt_command "install apt-transport-https"
	if [ "x$?" != "x0" ]; then
		check_fail "aborted" "Unable to install apt-transport-https" "Installation of the apt-transport-https package has failed."
	fi
fi

/usr/bin/dpkg -s gpg
if [ "$?" != "0" ]; then
	apt_command "install gpg"
	if [ "x$?" != "x0" ]; then
		check_fail "aborted" "Unable to install GPG" "Installation of the gpg package suite has failed."
	fi
fi


# Remove old repositories
if [ -f /etc/apt/sources.list.d/saltstack.list ]; then
	log "Pre-Upgrade" "Removing salt repository if available"
	rm -f /etc/apt/sources.list.d/saltstack.list 2> /dev/null > /dev/null
fi

# Remove custom repos
if [ -f /etc/apt/sources.list.d/custom_debian.list ]; then
	log "Pre-Upgrade" "Removing custom debian sources"
	rm -f /etc/apt/sources.list.d/custom_debian.list 2> /dev/null > /dev/null
fi

# Preflight system checks
google_pub_key
bullseye_apt_key
check_sources
#check_system_up_to_date
check_specs
check_disk_space
backup_sources
check_architecture
check_apt_lock
check_if_3cx_is_installed
check_third_party_software
check_connectivity
check_third_party_sources
check_upgradeability "11"
check_locale_problem
check_hold_packages
check_misconfigured_packages
check_xfs
check_nginx_permissions
#check_backports

log "Preparation" "Preflight check completed successfully"

log "Reparation" "Checking backport packages"
dpkg-query -l | grep '~bpo' | grep ^ii

# Disable certain configuration/services that might interfere with the upgrade
log "Preparation" "Disabling services that might interfere with the upgrade"
flag_if_dphys_swapfile_installed
disable_3cx_update
disable_apt_daily_timer
disable_dphys_swapfile
disable_monitoring_software

# Get currently installed PostgresSQL version
get_postgresql_version "11"

# Check if iptables is installed in order to run migration to nftables
IPTABLES_INSTALLED=`dpkg -l | grep iptables  2> /dev/null > /dev/null`
if [ "x$IPTABLES_INSTALLED" == "x0" ]; then
	firewall_save_old_iptables
fi

log "Preparation" "Checking Debian version"

# Check LSB Release
/bin/echo $VERSION_BEFORE | grep -e "^10.*" 2> /dev/null > /dev/null
IS_VERSION_10=`/bin/echo $?`
if [ "x0" != "x$IS_VERSION_10" ]; then
	log "Preparation" "The system version is not 10 (Buster): Found version $VERSION_BEFORE"
	exit -1
else
	log "Preparation" "System is Buster ($VERSION_BEFORE). Go ahead."
fi

# Backup 3CX configuration
log "Preparation" "Preparing 3CX Backup: /var/lib/3cxpbx/Instance1/Data/Backups/rescueBackupUpgrade.zip"
/usr/bin/sudo -u phonesystem /usr/sbin/3CXBackupCmd --cfg=/var/lib/3cxpbx/Instance1/Bin/RestoreCmd.exe.config --log=$LOG_TCX_BACKUP --file=/var/lib/3cxpbx/Instance1/Data/Backups/rescueBackupUpgrade.zip --options=LIC,FQDN
check_fail "Preparation" "3CX backup failed" "An error occured while backing up 3CX. Please make sure that all 3CX services are running and that your system has sufficient disk space."

# Check the available disk space after the 3CX backup
check_disk_space

# Stop 3CX services
log "Preparation" "Stopping 3CX Services"
stop_3cx_services


# Fixing dphys-swapfile configuration
if [ -f /etc/dphys-swapfile ]; then
	log "Preparation" "Adjusting dphys configuration"
	sed -i '/CONF_SWAPSIZE.*$/d' /etc/dphys-swapfile
	sed -i '/CONF_MAXSWAP.*$/d' /etc/dphys-swapfile
	echo "CONF_MAXSWAP=2048" >> /etc/dphys-swapfile
	echo 3 > /proc/sys/vm/drop_caches
	sleep 10
	echo 1 > /proc/sys/vm/drop_caches
fi


# Backup the old pinning files (in case we need to switch back)
mkdir /tmp/pinning_files
/bin/cp /etc/apt/preferences.d/* /tmp/pinning_files

# Delete pinning file
log "Preparation" "Removing pinning files"
/bin/rm -rf /etc/apt/preferences.d/*

log "Preparation" "Switching locales to en_US and UTF-8 en_US.UTF-8 (necessary for PostgreSQL and other packages)"
if [ -z "$LANG" ]; then
	LANG="en_US.UTF-8"
	/usr/bin/localedef -i en_US -f UTF-8 en_US.UTF-8
fi


# Generate locales and set environment variables
log "Preparation" "Exporting systme language variables"
export LANGUAGE=$LANG
export LANG=$LANG
export LC_ALL=$LANG
export LANGUAGE=$LANG
export LC_ADDRESS=$LANG
export LC_IDENTIFICATION=$LANG
export LC_MEASUREMENT=$LANG
export LC_MONETARY=$LANG
export LC_NAME=$LANG
export LC_NUMERIC=$LANG
export LC_PAPER=$LANG
export LC_TELEPHONE=$LANG
export LC_TIME=$LANG


# Fix environment for i18n
TERM=linux
unset LC_CTYPE


# Prepare system for Network interface naming
log "Preparation" "Switching ethernet scheme if necessary (eth0)"
switch_ethernet_scheme

# Check if Google Cloud SDK is installed
log "Preparation" "Set Google SDK package on hold for upgrade"
switch_googld_sdk

# log start time
log "Pre-Upgrade" "Initiate upgrade `/bin/date -u +"%Y-%m-%dT%H:%M:%SZ"`"

# Added cache cleanup command
log "Pre-Upgrade" "Executing apt-get clean before upgrading"
apt_command "clean"

export TCX_NO_START_SERVICES=1

# Force system to update to latest 10.x minor release
log "Pre-Upgrade" "Executing apt-get upgrade to upgrade to the latest Debian 10"
apt_command "update"
apt_utils_workaround_check
apt_command "upgrade"

# Remove 3CX before upgrade
log "Upgrade" "REACHING POINT OF NO RETURN - STARTING DEBIAN 11 UPGRADE AND REMOVING 3CX"
log "Upgrade" "Removing 3CX"
apt_command "remove 3cxpbx"


# Add Debian bullseye package sources
log "Upgrade" "Switching package sources from buster to bullseye in /etc/apt/sources.list and /etc/apt/sources.list.d/"
switch_package_sources

# Force system to upgrade to latest 11.x major release
log "Upgrade" "apt-get update for the latest Debian 11 repositories"
apt_command "clean"

# Initiate APT_FAILED
APT_FAILED=0

# Trying to execute apt-get update manually to catch problems
/usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y update
if [ "x$?" != "x0" ]; then
	APT_FAILED=1
fi


# Checking downloaded packages
/usr/bin/apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y --download-only upgrade
if [ "x$?" != "x0" ]; then
	APT_FAILED=1
fi

if [ "x$APT_FAILED" != "x0" ]; then
	# Restore the old pinning files
	/bin/cp /tmp/pinning_files/* /etc/apt/preferences.d

	# Restore the source files
	restore_source_lists

	# Executing apt-get update
	apt_command "clean"
	apt_command "update"

	# Re-install 3cxpbx
	apt_command "install 3cxpbx=$TCX_VERSION_INSTALLED"

	# Start 3CX services
	start_3cx_services


	# The next line "false" will ensure that check_fail will really fail
	false
	check_fail "aborted" "Unable to download package" "A package couldn't be download. Please make sure there are no third party broken repositories on the system."
fi



log "Upgrade" "Grub preparation - Installing debconf-utils to handle necessary grub input"
apt_command "install debconf-utils"
log "Upgrade" "Grub preparation - Checking for grub partition"
check_for_grub
if [ "x$DEVICE_FOUND" != "x" ]; then
	log "Upgrade" "Grub preparation - Grub device found. Removing grub to reinstall it again"
	apt_command "purge grub-pc grub-common"
	log "Upgrade" "Grub preparation - Preparing grub configuration for reinstallation"
cat <<EOL | debconf-set-selections
grub-pc grub-pc/install_devices multiselect /dev/$DEVICE_FOUND
grub-pc grub-pc/install_devices_empty boolean false
EOL
	log "Upgrade" "Grub preparation - Installing grub-pc and grub-common with prepared configuration"
	apt_command "install grub-pc grub-common"
	log "Upgrade" "Grub preparation - Updating grub partition"
	update-grub
fi


# Upgrade the system
log "Upgrade" "Dist-Upgrade to the latest Debian 11. This may take a while."
apt_command "upgrade" "dist-upgrade"


# If the upgrade was successfull we shouldn't allow a downgrade from this point
export BLOCK_DOWNGRADE=1


log "Post-Upgrade" "PostgreSQL version: $PSQL_VERSION_FULL"
log "Post-Upgrade" "PostgreSQL version number: $PSQL_VERSION"

# Update PostgreSQL to latest version
log "Post-Upgrade" "PostgreSQL - Installing latest PostreSQL 13 database"
apt_command "install postgresql-13 postgresql-client-13"
log "Post-Upgrade" "PostgreSQL - Dropping newly generated empty 13 cluster"
/usr/bin/pg_dropcluster --stop 13 main
log "Post-Upgrade" "PostgreSQL - Stopping PostreSQL for upgrade"
/bin/systemctl stop postgresql # Stop all open connections
log "Post-Upgrade" "PostgreSQL - Wait 60 seconds to settle"
/bin/sleep 60 # Wait a few seconds
log "Post-Upgrade" "PostgreSQL - Upgrade old 11 database to 13 (with old 3cxpbx data)"
/usr/bin/pg_upgradecluster $PSQL_VERSION main

if [ "x$?" != "x0" ]; then
	# Wait gracefully if the PostgreSQL database is not available
	log "Post-Upgrade" "PostgreSQL - Upgrade failed. Trying again"
	log "Post-Upgrade" "PostgreSQL - Wait 60 seconds to settle"
	/bin/systemctl stop postgresql # Stop all open connections
	log "Post-Upgrade" "PostgreSQL - Wait 120 seconds to settle"
	sleep 120
	log "Post-Upgrade" "PostgreSQL - Upgrade old 11 database to 13 (with old 3cxpbx data)"
	/usr/bin/pg_upgradecluster $PSQL_VERSION main
fi

if [ "x$?" != "x0" ]; then
	# Wait gracefully if the PostgreSQL database is not available
	log "Post-Upgrade" "PostgreSQL - Upgrade failed. Trying again"
	log "Post-Upgrade" "PostgreSQL - Wait 60 seconds to settle"
	/bin/systemctl stop postgresql # Stop all open connections
	log "Post-Upgrade" "PostgreSQL - Wait 240 seconds to settle"
	sleep 240
	log "Post-Upgrade" "PostgreSQL - Upgrade old 11 database to 13 (with old 3cxpbx data)"
	/usr/bin/pg_upgradecluster $PSQL_VERSION main
fi

check_fail "Post-Upgrade" "PostgreSQL Upgrade cluster failed failed... exiting"

# Remove old database
log "Post-Upgrade" "PostgreSQL - Drop old 13 database (with old 3cxpbx data)"
/usr/bin/pg_dropcluster --stop $PSQL_VERSION main

check_fail "Post-Upgrade" "PostgreSQL Dropping old cluster failed... exiting"

log "Post-Upgrade" "PostgreSQL - Removing old PostreSQL 13 package"
apt_command "--purge remove postgresql-client-$PSQL_VERSION postgresql-$PSQL_VERSION"

# Reindex database
log "Post-Upgrade" "PostgreSQL - Starting new PostgreSQL"
/bin/systemctl start postgresql
log "Post-Upgrade" "PostgreSQL - Waiting 30 seconds to settle"
/bin/sleep 30 # Wait a few seconds
log "Post-Upgrade" "PostgreSQL - Reindexing new database"
/usr/bin/sudo -u postgres reindexdb --all
check_fail "Post-Upgrade" "PostgreSQL Reindexing failed"


log "Upgrade" "Switching package sources from bullseye to bookworm in /etc/apt/sources.list and /etc/apt/sources.list.d/"

# Switch to Debian 12 sources
/bin/echo "deb http://deb.debian.org/debian bookworm main"  	> /etc/apt/sources.list
/bin/echo "deb http://deb.debian.org/debian-security/ bookworm-security main"  	>> /etc/apt/sources.list
/bin/echo "deb http://deb.debian.org/debian bookworm-updates main"  	>> /etc/apt/sources.list

# Include 3CX Debian 12 sources
/bin/echo "deb [arch=$ARCHITECTURE by-hash=yes signed-by=/usr/share/keyrings/3cx-archive-keyring.gpg] $REPO_URL/debian/2004 bookworm main"  	>> /etc/apt/sources.list
/bin/echo "deb [arch=$ARCHITECTURE by-hash=yes signed-by=/usr/share/keyrings/3cx-archive-keyring.gpg] $REPO_URL/debian-security/2004 bookworm-security main" >> /etc/apt/sources.list
/bin/echo "deb [arch=$ARCHITECTURE by-hash=yes signed-by=/usr/share/keyrings/3cx-archive-keyring.gpg] $REPO_URL/3cx bookworm main"  			> /etc/apt/sources.list.d/3cxpbx.list


# Switch any other sources.
/bin/sed -i s/bullseye/bookworm/g /etc/apt/sources.list.d/*
/bin/sed -i s/11/12/g /etc/apt/sources.list.d/*

# Adjust MS files
microsoft_files=()
while IFS="" read -r -d '' file; do
  if  grep -E "https?://packages.microsoft.com" "$file" > /dev/null; then
    microsoft_files+=("$file")
  fi
done < <(find "/etc/apt/sources.list.d" -type f -name 'microsoft*' -print0)

if [ ! -f "/usr/share/keyrings/microsoft-prod.gpg" ];then
	curl -s https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
fi

for file in "${microsoft_files[@]}"; do
  /bin/echo "Adjusting MS file: $file"
  sed -i "s/\[arch=amd64,arm64,armhf\]/[arch=amd64,arm64,armhf signed-by=\/usr\/share\/keyrings\/microsoft-prod.gpg]/" "$file"
done


apt_command "update"

apt_command "install zstd usrmerge"
if [ "x$?" != "x0" ]; then
	check_fail "aborted" "Unable to install zstd usrmerge" "Installation of the zstd usrmerge packages has failed."
fi

log "Upgrade" "Dist-Upgrade to the latest Debian 12. This may take a while."
apt_command "upgrade" "dist-upgrade"

get_postgresql_version "13"

log "Post-Upgrade" "PostgreSQL version: $PSQL_VERSION_FULL"
log "Post-Upgrade" "PostgreSQL version number: $PSQL_VERSION"

# Update PostgreSQL to latest version
log "Post-Upgrade" "PostgreSQL - Installing latest PostreSQL 15 database"
apt_command "install postgresql-15 postgresql-client-15"
log "Post-Upgrade" "PostgreSQL - Dropping newly generated empty 15 cluster"
/usr/bin/pg_dropcluster --stop 15 main
log "Post-Upgrade" "PostgreSQL - Stopping PostreSQL for upgrade"
/bin/systemctl stop postgresql # Stop all open connections
log "Post-Upgrade" "PostgreSQL - Wait 60 seconds to settle"
/bin/sleep 60 # Wait a few seconds
log "Post-Upgrade" "PostgreSQL - Upgrade old 13 database to 15 (with old 3cxpbx data)"
/usr/bin/pg_upgradecluster $PSQL_VERSION main

if [ "x$?" != "x0" ]; then
	# Wait gracefully if the PostgreSQL database is not available
	log "Post-Upgrade" "PostgreSQL - Upgrade failed. Trying again"
	log "Post-Upgrade" "PostgreSQL - Wait 60 seconds to settle"
	/bin/systemctl stop postgresql # Stop all open connections
	log "Post-Upgrade" "PostgreSQL - Wait 120 seconds to settle"
	sleep 120
	log "Post-Upgrade" "PostgreSQL - Upgrade old 13 database to 15 (with old 3cxpbx data)"
	/usr/bin/pg_upgradecluster $PSQL_VERSION main
fi

if [ "x$?" != "x0" ]; then
	# Wait gracefully if the PostgreSQL database is not available
	log "Post-Upgrade" "PostgreSQL - Upgrade failed. Trying again"
	log "Post-Upgrade" "PostgreSQL - Wait 60 seconds to settle"
	/bin/systemctl stop postgresql # Stop all open connections
	log "Post-Upgrade" "PostgreSQL - Wait 240 seconds to settle"
	sleep 240
	log "Post-Upgrade" "PostgreSQL - Upgrade old 13 database to 15 (with old 3cxpbx data)"
	/usr/bin/pg_upgradecluster $PSQL_VERSION main
fi

check_fail "Post-Upgrade" "PostgreSQL Upgrade cluster failed failed... exiting"

# Remove old database
log "Post-Upgrade" "PostgreSQL - Drop old 11 database (with old 3cxpbx data)"
/usr/bin/pg_dropcluster --stop $PSQL_VERSION main

check_fail "Post-Upgrade" "PostgreSQL Dropping old cluster failed... exiting"

log "Post-Upgrade" "PostgreSQL - Removing old PostreSQL 13 package"
apt_command "--purge remove postgresql-client-$PSQL_VERSION postgresql-$PSQL_VERSION"

# Reindex database
log "Post-Upgrade" "PostgreSQL - Starting new PostgreSQL"
/bin/systemctl start postgresql
log "Post-Upgrade" "PostgreSQL - Waiting 30 seconds to settle"
/bin/sleep 30 # Wait a few seconds
log "Post-Upgrade" "PostgreSQL - Reindexing new database"
/usr/bin/sudo -u postgres reindexdb --all
check_fail "Post-Upgrade" "PostgreSQL Reindexing failed"


# Reinstall 3CX
log "Post-Upgrade" "Installing the latest 3cxpbx package for Debian 12 (v20)"
apt_command "update"
/bin/sleep 5
# Remove un-needed sql functions
sudo -u postgres /usr/bin/psql -tAq --dbname database_single -c "DROP FUNCTION IF EXISTS get_chat_messages(integer,integer,character varying);"
apt_command "install 3cxpbx"
check_fail "Post-Upgrade" "The 3cxpbx package installation failed"


# Clear old packages
log "Cleaning up" "Remove old packages"
apt_command "autoremove"

# Added cache cleanup command
log "Cleaning up" "Executing apt-get clean"
apt_command "clean"


# Remove old iptables in favour of nftables
if [ -f /usr/sbin/waagent ]; then
	# WALinuxAgent can be installed without the package management system. That is why the binary is checked directly.
	log "Cleaning up" "NOT purging iptables because it's an Azure installation"
	/bin/echo "Seems to be an Azure installation. Keeping iptables"
fi


if [ -f /etc/systemd/system/multi-user.target.wants/prometheus-node-exporter.service ]; then
	log "Cleaning up" "Prometheus - Fixing systemctl pathes"
	# Move service for unknown reason
	mv /etc/systemd/system/multi-user.target.wants/prometheus-node-exporter.service /etc/systemd/system/prometheus-node-exporter.service
	log "Cleaning up" "Prometheus - Enable prometheus-node-exporter.service"
	systemctl enable prometheus-node-exporter.service
fi

log "Finish" "Upgrade completed on `/bin/date -u +"%Y-%m-%dT%H:%M:%SZ"`"

if [ "x$IPTABLES_INSTALLED" == "x0" ]; then
	firewall_convert_old_iptables_to_new_nftables
fi

# Reactivate services which were disabled earlier in the script
activate_3cx_update
enable_apt_daily_timer
enable_dphys_swapfile

# Check whether the system has been upgraded to the expected version
VERSION_AFTER=`/usr/bin/lsb_release -r | cut -f2`
TCX_VERSION_AFTER=`apt-cache policy 3cxpbx | grep Installed | awk '{print $2}'`
if [ ${VERSION_AFTER:0:2} == "12" ]; then
  	success
	log "Finish" "The new Debian version is $VERSION_AFTER"
	log "Finish" "The new 3CX version is $TCX_VERSION_AFTER"
else
  fail
fi

log "Post Upgrade" "Running final scripts"
#restore_backports

# Debriefing
log "Cleaning up" "Set Google SDK package to unhold and update"
switch_googld_sdk

# Cater for dhcp-client-identifier
DHCPCHK=`cat /etc/dhcp/dhclient.conf | grep -e '^send dhcp-client-identifier'`
if [ "$?" != "0" ];then
	log "Post-Upgrade" "Restoring the old dhcp-client-identifier setup"
	echo "send dhcp-client-identifier = hardware;" >> /etc/dhcp/dhclient.conf
fi


log "Finish" "Rebooting now"

/sbin/reboot
} 2>&1 | tee -a "$LOG_UPDATE"
