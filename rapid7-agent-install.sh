#!/bin/bash
#Created by Lucas Esmeraldino
#27-06-2024

#Colors
RedColor='\033[0;31m'
GreenColor='\033[0;32m'
YellowColor='\033[0;33m'
BlueColor='\033[0;34m'
PurpleColor='\033[0;35m'
CyanColor='\033[0;36m'
WhiteColor='\033[0;37m'
OrangeColor='\033[0;33m'
ResetColor='\033[0m'
bold='\033[1m'

tokenPar="$1"
scriptLog=".scriptlog"
statusLog=".statuslog"
checked="${GreenColor}${bold}[\xE2\x9C\x93]${normal}"
notChecked="${RedColor}${bold}[-]${ResetColor}"
infoCheck="${CyanColor}${bold}[i]${ResetColor}"
errorCheck="${RedColor}${bold}[!]${ResetColor}"
systemUpdate="System Update"
dependenciesInstalled="Dependencies Installed"
auditdConfigured="Auditd Configured"
auditdRuleConfigured="Auditd Rules"
auditdAfunixConfigured="Auditd AfUnix"
auditdConfConfigured="Setting up Rapid7 Agent"
agentInstalled="Rapid7 Agent"
audispdConfigure="Audispd Configuration"
hashFile="$(md5sum -b "$0" | sed 's/\*.\/rapid7-agent-install.sh//' | sed 's/*rapid7-agent-install.sh//' )"
linuxVersion="$(cat /etc/os-release | grep NAME | sed 's/NAME="//' | sed 's/"//' | sed 's/PRETTY_//g' | sed 's/ GNU*.*//g' | head -1)"
agentPath="./rapid7-insight-agent_4.0.9.38-1_amd64.deb"
certPath="/opt/rapid7/ir_agent/components/insight_agent/4.0.9.38/autoinstall.cert"




writeLogChecked()
{
	date >> $scriptLog
	echo -e "$checked ${ResetColor}$1 $2 $3 $4 $5 $6 $7 $8 $9 ${ResetColor}" | tee -a $scriptLog $statusLog
	clear
	banner
	cat $statusLog
}

writeLogNotChecked()
{
	echo -e "$notChecked ${ResetColor}$1 $2 $3 $4 $5 ${ResetColor}" | tee -a $scriptLog
}

writeLogProgress()
{
	echo -e "$infoCheck ${ResetColor}$1 $2 $3 $4 $5 ${ResetColor}" | tee -a $scriptLog
}

banner()
{
	echo -e "\
	${RedColor}${bold}
       _____                   ___   
      (, /   )         ,   /) /   /  
        /__ / _  __      _(/     /   
     ) /   \_(_(_/_)__(_(_(_    /    
    (_/       .-/              /     
             (_/                     
                                     ${ResetColor}${bold}
	IDR Agent + Enhanced logs v4.0.9
	Git: https://github.com/esmeraldino-lk/Rapid7LinuxAutoInstall
	Created by: 𝐿𝑢𝑐𝑎𝑠 𝐸𝑠𝑚𝑒𝑟𝑎𝑙𝑑𝑖𝑛𝑜${CyanColor}${bold}
	\xF0\x9F\x94\x91 Hash: ${hashFile}
	\xF0\x9F\x90\xA7 Version: ${linuxVersion}
	Hostname: $(hostname)
	Token: ${tokenPar}${bold}${ResetColor}
	" | tr -d "	"
}

sudoCheck()
{
	if [ "$EUID" -ne 0 ]
  		then echo -e "${RedColor}Please run as root${ResetColor}"
  		exit
	fi
}

updateSystem()
{
	writeLogNotChecked $systemUpdate

	if command -v yum &> /dev/null; 
	then
		apt update -y > /dev/null 2>&1
	else
		yum update -y > /dev/null 2>&1
	fi

	writeLogChecked $systemUpdate
}

installDepend()
{
	writeLogNotChecked $dependenciesInstalled

	if command -v yum &> /dev/null; 
	then
		yum install audit -y
		yum install md5sum -y
	else
		apt install auditd -y
		apt install md5sum -y
	fi
	writeLogChecked $dependenciesInstalled
}

centOSConfigure()
{
	writeLogNotChecked "CentOS Configure"
	/opt/rapid7/ir_agent/components/insight_agent/4.0.9.38/configure_agent.sh --token $tokenPar -v --start

	writeLogNotChecked $audispdConfigure
	echo -e "${YellowColor}[*] CentOS Detected.${ResetColor}"
	echo "\
	#
	# This file controls the configuration of the audit event
	# dispatcher daemon, audispd.
	#
	q_depth = 8192
	overflow_action = SYSLOG
	priority_boost = 4
	max_restarts = 10
	name_format = HOSTNAME
	" | tr -d "	" > "/etc/audisp/audispd.conf"
	writeLogChecked $audispdConfigure

	writeLogNotChecked "CentOS Configure"
}

debOSConfigure()
{
	writeLogNotChecked "Deb Configure"
	/opt/rapid7/ir_agent/components/insight_agent/4.0.9.38/configure_agent.sh --token $tokenPar -v --start
	writeLogNotChecked "Deb Configure"
}

installAgent()
{
	if [[ -a "/opt/rapid7/ir_agent/ir_agent" && -a "$certPath" ]]; then
		#writeLogChecked $agentInstalled
		echo -e "${GreenColor}[*] Rapid7 Already Installed${ResetColor}"

		agentVersion="$(service ir_agent status | grep "/opt/rapid7/ir_agent/components/insight_agent/" | sed "s/.*\/opt\/rapid7\/ir_agent\/components\/insight_agent\///" | head -1 | sed "s/\/ir_agent//")"
		agentTenant="$(cat /opt/rapid7/ir_agent/components/insight_agent/$agentVersion/config.json | grep cmsgpack://NS | head -1 | sed "s/\"cmsgpack:\/\///" | sed "s/\",//" | sed "s/    //")"

		echo -e "$checked ${ResetColor}Agent Tenant: $agentTenant ${ResetColor}" | tee -a $scriptLog $statusLog

    else
		writeLogNotChecked $agentInstalled
		
		if [ -a $agentPath ]; then
		    echo -e "${GreenColor}[!] Agent detected in folder${ResetColor}"
		else
		    if [[ $(uname -m) == *"x86_64"* ]]; then
				
				writeLogProgress Processor: amd64
				
				if [[ $linuxVersion == *"Debian"* ]] || [[ $linuxVersion == *"Ubuntu"* ]]; then
					writeLogProgress Downloading .deb package
				    wget https://us3.storage.endpoint.ingress.rapid7.com/public.razor-prod-6.us-west-2.insight.rapid7.com/endpoint/agent/1718655850/linux/x86_64/rapid7-insight-agent_4.0.9.38-1_amd64.deb --progress=bar:force -P ./
					apt install $agentPath
					debOSConfigure
					writeLogChecked $agentInstalled
				elif [[ $linuxVersion == *"CentOS"* ]] || [[ $linuxVersion == *"Oracle"* ]]; then
					writeLogProgress Downloading .rpm package
				    wget https://us3.storage.endpoint.ingress.rapid7.com/public.razor-prod-6.us-west-2.insight.rapid7.com/endpoint/agent/1718655850/linux/x86_64/rapid7-insight-agent-4.0.9.38-1.x86_64.rpm --progress=bar:force -P ./
					rpm -i $agentPath
					centOSConfigure
					writeLogChecked $agentInstalled
				fi
				
		    elif [[ $(uname -m) == *"aarch64"* ]]; then

				writeLogProgress Processor: arm64
				if [[ $linuxVersion == *"Debian"* ]] || [[ $linuxVersion == *"Ubuntu"* ]]; then
					writeLogProgress Downloading .deb package
				    wget https://us3.storage.endpoint.ingress.rapid7.com/public.razor-prod-6.us-west-2.insight.rapid7.com/endpoint/agent/1718655850/linux/arm64/rapid7-insight-agent_4.0.9.38-1_arm64.deb --progress=bar:force -P ./
					apt install $agentPath
					debOSConfigure
					writeLogChecked $agentInstalled
				elif [[ $linuxVersion == *"CentOS"* ]] || [[ $linuxVersion == *"Oracle"* ]]; then
					writeLogProgress Downloading .rpm package
				    wget https://us3.storage.endpoint.ingress.rapid7.com/public.razor-prod-6.us-west-2.insight.rapid7.com/endpoint/agent/1718655850/linux/arm64/rapid7-insight-agent-4.0.9.38-1.aarch64.rpm --progress=bar:force -P ./
					rpm -i $agentPath
					centOSConfigure
					writeLogChecked $agentInstalled
				fi
			else
				writeLogChecked AGENTERROR
				exit
			fi
			
		fi
		
		writeLogProgress "Installing..."
    fi
}
auditRules()
{
	#write log
	writeLogNotChecked $auditdRuleConfigured

	auditRulePath="/etc/audit/rules.d/audit.rules"
	auditRulePath2="/etc/audit/audit.rules"
	mv $auditRulePath /etc/audit/rules.d/audit.rules.backup #rename previous file to backup
	mv $auditRulePath2 /etc/audit/audit.rules.backup #rename previous file to backup

    auditRuleList=$(printf "%s\n" "\
		-D
		-b 8192
		-i 1

		-a always,exit -F arch=b64 -S execve -F key=execve
		-w /etc/cron.allow -p wa -k cron
		-w /etc/cron.deny -p wa -k cron
		-w /etc/cron.d/ -p wa -k cron
		-w /etc/cron.daily/ -p wa -k cron
		-w /etc/cron.hourly/ -p wa -k cron
		-w /etc/cron.monthly/ -p wa -k cron
		-w /etc/cron.weekly/ -p wa -k cron
		-w /etc/crontab -p wa -k cron
		-w /var/spool/cron/ -p wa -k cron
		-w /etc/group -p wa -k etcgroup
		-w /etc/passwd -p wa -k etcpasswd
		-w /etc/gshadow -k etcgroup
		-w /etc/shadow -k etcpasswd
		-w /etc/security/opasswd -k opasswd
		-w /etc/sudoers.d/ -p wa -k sudoers.d
		-w /etc/sudoers -p wa -k actions
		-w /etc/sudoers.d/ -p wa -k actions
		-w /usr/bin/passwd -p x -k passwd_modification
		-w /etc/login.defs -p wa -k login
		-w /etc/securetty -p wa -k login
		-w /var/log/faillog -p wa -k login
		-w /var/log/lastlog -p wa -k login
		-w /var/log/tallylog -p wa -k login
		-a always,exit -F arch=b64 -F exe=/bin/bash -F success=1 -S connect -k "remote_shell"
		-a always,exit -F arch=b64 -F exe=/usr/bin/bash -F success=1 -S connect -k "remote_shell"
		-w /etc/pam.d/ -p wa -k pam
		-w /etc/security/limits.conf -p wa  -k pam
		-w /etc/security/limits.d -p wa  -k pam
		-w /etc/security/pam_env.conf -p wa -k pam
		-w /etc/security/namespace.conf -p wa -k pam
		-w /etc/security/namespace.d -p wa -k pam
		-w /etc/security/namespace.init -p wa -k pam
		-a always,exit -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
		-a always,exit -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess
		-w /usr/bin/whoami -p x -k recon
		-w /usr/bin/id -p x -k recon
		-w /bin/hostname -p x -k recon
		-w /bin/uname -p x -k recon
		-w /etc/issue -p r -k recon
		-w /etc/hostname -p r -k recon
		-w /usr/bin/wget -p x -k susp_activity
		-w /usr/bin/curl -p x -k susp_activity
		-w /usr/bin/base64 -p x -k susp_activity
		-w /bin/nc -p x -k susp_activity
		-w /bin/netcat -p x -k susp_activity
		-w /usr/bin/ncat -p x -k susp_activity
		-w /usr/bin/ss -p x -k susp_activity
		-w /usr/bin/netstat -p x -k susp_activity
		-w /usr/bin/ssh -p x -k susp_activity
		-w /usr/bin/scp -p x -k susp_activity
		-w /usr/bin/sftp -p x -k susp_activity
		-w /usr/bin/ftp -p x -k susp_activity
		-w /usr/bin/socat -p x -k susp_activity
		-w /usr/bin/wireshark -p x -k susp_activity
		-w /usr/bin/tshark -p x -k susp_activity
		-w /usr/bin/rawshark -p x -k susp_activity
		-w /usr/bin/rdesktop -p x -k susp_activity
		-w /usr/local/bin/rdesktop -p x -k susp_activity
		-w /usr/bin/wlfreerdp -p x -k susp_activity
		-w /usr/bin/xfreerdp -p x -k susp_activity
		-w /usr/local/bin/xfreerdp -p x -k susp_activity
		-w /usr/bin/nmap -p x -k susp_activity
		-w /usr/bin/uftp -p x -k susp_activity
		-w /usr/sbin/uftp -p x -k susp_activity
		-w /lib/systemd/system/uftp.service -k susp_activity
		-w /usr/lib/systemd/system/uftp.service -k susp_activity
		-w /usr/bin/atftpd -p x -k susp_activity
		-w /usr/sbin/atftpd -p x -k susp_activity
		-w /usr/bin/in.tftpd -p x -k susp_activity
		-w /usr/sbin/in.tftpd -p x -k susp_activity
		-w /lib/systemd/system/atftpd.service -k susp_activity
		-w /usr/lib/systemd/system/atftpd.service -k susp_activity
		-w /lib/systemd/system/atftpd.socket -k susp_activity
		-w /usr/lib/systemd/system/atftpd.socket -k susp_activity
		-a always,exit -F path=/usr/libexec/sssd/p11_child -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/libexec/sssd/krb5_child -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/libexec/sssd/ldap_child -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/libexec/sssd/selinux_child -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/libexec/sssd/proxy_child -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/lib64/vte-2.91/gnome-pty-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/lib64/vte-2.91/gnome-pty-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-w /usr/bin/zip -p x -k Data_Compressed
		-w /usr/bin/gzip -p x -k Data_Compressed
		-w /usr/bin/tar -p x -k Data_Compressed
		-w /usr/bin/bzip2 -p x -k Data_Compressed
		-w /usr/bin/lzip -p x -k Data_Compressed
		-w /usr/local/bin/lzip -p x -k Data_Compressed
		-w /usr/bin/lz4 -p x -k Data_Compressed
		-w /usr/local/bin/lz4 -p x -k Data_Compressed
		-w /usr/bin/lzop -p x -k Data_Compressed
		-w /usr/local/bin/lzop -p x -k Data_Compressed
		-w /usr/bin/plzip -p x -k Data_Compressed
		-w /usr/local/bin/plzip -p x -k Data_Compressed
		-w /usr/bin/pbzip2 -p x -k Data_Compressed
		-w /usr/local/bin/pbzip2 -p x -k Data_Compressed
		-w /usr/bin/lbzip2 -p x -k Data_Compressed
		-w /usr/local/bin/lbzip2 -p x -k Data_Compressed
		-w /usr/bin/pixz -p x -k Data_Compressed
		-w /usr/local/bin/pixz -p x -k Data_Compressed
		-w /usr/bin/pigz -p x -k Data_Compressed
		-w /usr/local/bin/pigz -p x -k Data_Compressed
		-w /usr/bin/unpigz -p x -k Data_Compressed
		-w /usr/local/bin/unpigz -p x -k Data_Compressed
		-w /usr/bin/zstd -p x -k Data_Compressed
		-w /usr/local/bin/zstd -p x -k Data_Compressed
		-w /bin/nc.openbsd -p x -k susp_activity
		-w /bin/nc.traditional -p x -k susp_activity
		-w /sbin/iptables -p x -k sbin_susp
		-w /sbin/ip6tables -p x -k sbin_susp
		-w /sbin/ifconfig -p x -k sbin_susp
		-w /usr/sbin/arptables -p x -k sbin_susp
		-w /usr/sbin/ebtables -p x -k sbin_susp
		-w /sbin/xtables-nft-multi -p x -k sbin_susp
		-w /usr/sbin/nft -p x -k sbin_susp
		-w /usr/sbin/tcpdump -p x -k sbin_susp
		-w /usr/sbin/traceroute -p x -k sbin_susp
		-w /usr/sbin/ufw -p x -k sbin_susp
		-a always,exit -F path=/usr/libexec/kde4/kpac_dhcp_helper -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/libexec/kde4/kdesud -F perm=x -F auid>=1000 -F auid!=4294967295 -k T1078_Valid_Accounts
		-w /usr/bin/dbus-send -p x -k dbus_send
		-w /usr/bin/gdbus -p x -k gdubs_call
		-a always,exit -F path=/usr/bin/setfiles -F perm=x -F auid>=500 -F auid!=4294967295 -k -F T1078_Valid_Accounts
		-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=500 -F auid!=4294967295 -k -F T1078_Valid_Accounts
		-a always,exit -F path=/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-a always,exit -F path=/usr/lib64/dbus-1/dbus-daemon-launch-helper -F perm=x -F auid>=500 -F auid!=4294967295 -k T1078_Valid_Accounts
		-w /usr/bin/pkexec -p x -k pkexec
		-w /bin/ash -p x -k susp_shell
		-w /bin/csh -p x -k susp_shell
		-w /bin/fish -p x -k susp_shell
		-w /bin/tcsh -p x -k susp_shell
		-w /bin/tclsh -p x -k susp_shell
		-w /bin/xonsh -p x -k susp_shell
		-w /usr/local/bin/xonsh -p x -k susp_shell
		-w /bin/open -p x -k susp_shell
		-w /bin/rbash -p x -k susp_shell
		-w /bin/wish -p x -k susp_shell
		-w /usr/bin/wish -p x -k susp_shell
		-w /bin/yash -p x -k susp_shell
		-w /usr/bin/yash -p x -k susp_shell
		-a always,exit -F arch=b64 -S execve -F euid=33 -k detect_execve_www
		-a always,exit -F arch=b64 -S execve -F euid=48 -k detect_execve_www
		-w /bin/clush -p x -k susp_shell
		-w /usr/local/bin/clush -p x -k susp_shell
		-w /etc/clustershell/clush.conf -p x -k susp_shell
		-w /bin/tmux -p x -k susp_shell
		-w /usr/local/bin/tmux -p x -k susp_shell
		-w /etc/profile.d/ -p wa -k shell_profiles
		-w /etc/profile -p wa -k shell_profiles
		-w /etc/shells -p wa -k shell_profiles
		-w /etc/bashrc -p wa -k shell_profiles
		-w /etc/csh.cshrc -p wa -k shell_profiles
		-w /etc/csh.login -p wa -k shell_profiles
		-w /etc/fish/ -p wa -k shell_profiles
		-w /etc/zsh/ -p wa -k shell_profiles
		-w /usr/local/bin/xxh.bash -p x -k susp_shell
		-w /usr/local/bin/xxh.xsh -p x -k susp_shell
		-w /usr/local/bin/xxh.zsh -p x -k susp_shell
		-a always,exit -F arch=b64 -S ptrace -F a0=0x4 -k code_injection
		-a always,exit -F arch=b64 -S ptrace -F a0=0x5 -k data_injection
		-a always,exit -F arch=b64 -S ptrace -F a0=0x6 -k register_injection
		-a always,exit -F arch=b64 -S ptrace -k tracing
		-a always,exit -F arch=b64 -S memfd_create -F key=anon_file_create
		-a always,exit -F dir=/home -F auid=0 -F auid>=1000 -F auid!=-1 -C auid!=obj_uid -k power_abuse
		-a always,exit -F arch=b32 -S socket -F a0=2  -k network_socket_created
		-a always,exit -F arch=b64 -S socket -F a0=2  -k network_socket_created
		-a always,exit -F arch=b32 -S socket -F a0=10 -k network_socket_created
		-a always,exit -F arch=b64 -S socket -F a0=10 -k network_socket_created
		-w /var/log/audit/ -k auditlog
		-w /etc/audit/ -p wa -k auditconfig
		-w /etc/libaudit.conf -p wa -k auditconfig
		-w /etc/audisp/ -p wa -k audispconfig
		-w /sbin/auditctl -p x -k audittools
		-w /sbin/auditd -p x -k audittools
		-w /etc/apparmor/ -p wa -k apparmor
		-w /etc/apparmor.d/ -p wa -k apparmor
		-w /sbin/apparmor_parser -p x -k apparmor_tools
		-w /usr/sbin/aa-complain -p x -k apparmor_tools
		-w /usr/sbin/aa-disable -p x -k apparmor_tools
		-w /usr/sbin/aa-enforce -p x -k apparmor_tools
		-w /etc/systemd/ -p wa -k systemd
		-w /lib/systemd/ -p wa -k systemd
		-w /bin/systemctl -p x -k systemd_tools
		-w /bin/journalctl -p x -k systemd_tools
		-a always,exit -F arch=b32 -S mknod -S mknodat -k specialfiles
		-a always,exit -F arch=b64 -S mknod -S mknodat -k specialfiles
		-a always,exit -F arch=b32 -S mount -S umount -S umount2 -k mount
		-a always,exit -F arch=b64 -S mount -S umount2 -k mount 
		-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
		-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
		-w /usr/sbin/stunnel -p x -k stunnel
		-w /etc/cron.allow -p wa -k cron
		-w /etc/cron.deny -p wa -k cron
		-w /etc/cron.d/ -p wa -k cron
		-w /etc/cron.daily/ -p wa -k cron
		-w /etc/cron.hourly/ -p wa -k cron
		-w /etc/cron.monthly/ -p wa -k cron
		-w /etc/cron.weekly/ -p wa -k cron
		-w /etc/crontab -p wa -k cron
		-w /var/spool/cron/crontabs/ -k cron
		-w /etc/group -p wa -k etcgroup
		-w /etc/passwd -p wa -k etcpasswd
		-w /etc/gshadow -k etcgroup
		-w /etc/shadow -k etcpasswd
		-w /etc/security/opasswd -k opasswd
		-w /usr/bin/passwd -p x -k passwd_modification
		-w /usr/sbin/groupadd -p x -k group_modification
		-w /usr/sbin/groupmod -p x -k group_modification
		-w /usr/sbin/addgroup -p x -k group_modification
		-w /usr/sbin/useradd -p x -k user_modification
		-w /usr/sbin/usermod -p x -k user_modification
		-w /usr/sbin/adduser -p x -k user_modification
		-w /etc/login.defs -p wa -k login
		-w /etc/securetty -p wa -k login
		-w /var/log/faillog -p wa -k login
		-w /var/log/lastlog -p wa -k login
		-w /var/log/tallylog -p wa -k login
		-w /etc/hosts -p wa -k hosts
		-w /etc/network/ -p wa -k network
		-w /etc/inittab -p wa -k init
		-w /etc/init.d/ -p wa -k init
		-w /etc/init/ -p wa -k init
		-w /etc/ld.so.conf -p wa -k libpath
		-w /etc/localtime -p wa -k localtime
		-w /etc/timezone -p wa -k timezone
		-w /etc/sysctl.conf -p wa -k sysctl
		-w /etc/modprobe.conf -p wa -k modprobe
		-w /etc/modprobe.d/ -p wa -k modprobe
		-w /etc/modules -p wa -k modprobe
		-a always,exit -S init_module -S delete_module -k modules
		-w /etc/pam.d/ -p wa -k pam
		-w /etc/security/limits.conf -p wa  -k pam
		-w /etc/security/pam_env.conf -p wa -k pam
		-w /etc/security/namespace.conf -p wa -k pam
		-w /etc/security/namespace.init -p wa -k pam
		-w /etc/puppet/ssl -p wa -k puppet_ssl
		-w /etc/aliases -p wa -k mail
		-w /etc/postfix/ -p wa -k mail
		-w /etc/ssh/sshd_config -k sshd
		-a exit,always -F arch=b32 -S sethostname -k hostname
		-a exit,always -F arch=b64 -S sethostname -k hostname
		-w /etc/issue -p wa -k etcissue
		-w /etc/issue.net -p wa -k etcissue
		-w /etc/ipsec.conf -p wa -k ipsec
		-w /etc/ipsec.d/ -p wa -k ipsec
		-w /etc/ipsec.secrets -p wa -k ipsec
		-w /etc/strongswan.conf -p wa -k strongswan
		-w /etc/strongswan.d/ -p wa -k strongswan
		-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileaccess
		-a exit,always -F arch=b64 -S open -F dir=/tmp -F success=0 -k unauthedfileaccess
		-w /bin/su -p x -k priv_esc
		-w /usr/bin/sudo -p x -k priv_esc
		-w /etc/sudoers -p rw -k priv_esc
		-w /sbin/shutdown -p x -k power
		-w /sbin/poweroff -p x -k power
		-w /sbin/reboot -p x -k power
		-w /sbin/halt -p x -k power
		-a always,exit -F dir=/home/ -F uid=0 -C auid!=obj_uid -k admin_user_home
		-w /tmp/ -p wxa -k tmp
		-w /var/tmp/ -p wxa -k tmp
    ")

	echo "$auditRuleList"| tr -d "	" > $auditRulePath
	echo "$auditRuleList"| tr -d "	" > $auditRulePath2

    writeLogChecked $auditdRuleConfigured Rules: $(cat $auditRulePath | wc -l)
}

configureAfunix()
{
	writeLogNotChecked $auditdAfunixConfigured

	mkdir /etc/audit/plugins.d
	mkdir /etc/audisp/plugins.d

	auditAfList=$(printf "%s\n" "\
	# This file controls the configuration of the
	# af_unix socket plugin. It simply takes events
	# and writes them to a unix domain socket. This
	# plugin can take 2 arguments, the path for the
	# socket and the socket permissions in octal.
	active = yes
	direction = out
	path = builtin_af_unix
	type = builtin
	args = 0600 /var/run/audispd_events
	format = binary
	")

	echo "$auditAfList"| tr -d "	" > "/etc/audisp/plugins.d/af_unix.conf"
	echo "$auditAfList"| tr -d "	" > "/etc/audit/plugins.d/af_unix.conf"
	writeLogChecked $auditdAfunixConfigured Lines: $(cat '/etc/audit/plugins.d/af_unix.conf' | wc -l)

}

configureAuditConf()
{
	writeLogNotChecked $auditdConfConfigured

	auditConfPath="/opt/rapid7/ir_agent/components/insight_agent/common/audit.conf"
	echo '{"auditd-compatibility-mode":true}' > $auditConfPath

    service auditd stop 
    service auditd start
	systemctl restart ir_agent
	systemctl restart auditd

	writeLogChecked $auditdConfConfigured "Lines: $(cat $auditConfPath | wc -l)"
}
certificate()
{
	writeLogNotChecked "Certificate"

	echo "\
	07b5aa44dd2513b7de51f72adb05a87f64b6d5762525dce3f335119f4601136a
	Certificate
	" | tr -d "	" > $certPath

	writeLogChecked "Certificate"
}

main()
{
	trap 'rm .statusLog .scriptLog; exit 1' SIGINT # CTRL + C escape manipulation	
	if [[ -z $tokenPar ]]; then
		banner
		echo -e "$errorCheck Usage: $0 <token>"
		echo -e "$errorCheck Token: $1"
		exit 1
	fi

	banner
    sudoCheck
    updateSystem
    installDepend
    installAgent
    auditRules
    configureAfunix
	configureAuditConf
    certificate

	rm .statuslog
	echo -e "$checked ${GreenColor}${bold}Success!${ResetColor}"

}
main
