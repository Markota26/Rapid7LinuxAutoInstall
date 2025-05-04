#!/bin/bash
#created by lucas esmeraldino

URL="https://raw.githubusercontent.com/esmeraldino-lk/Rapid7LinuxAutoInstall/refs/heads/main/rapid7-agent-install.sh"
SCRIPT="/opt/rapid7i/rapid7install.sh"
HOSTNAME=$(hostname)
DATE=$(date '+%d/%m/%Y %H:%M:%S')
CRONTAB=$(crontab -l)
CRON_HORARIO="1 * * * *"
CRON_CMD="$CRON_HORARIO bash /opt/rapid7i/rapid7rotine.sh"
ROTINECOMMAND="bash /opt/rapid7i/rapid7i.sh"
OSVERSION="$(cat /etc/os-release | grep NAME | sed 's/NAME="//' | sed 's/"//' | sed 's/PRETTY_//g' | sed 's/ GNU*.*//g' | head -1)"

if [[ -z $3 ]]; then
    echo -e "$errorCheck Usage: $0 <token> <region> <api-key>"
    echo -e "$errorCheck Token: $1"
    echo -e "$errorCheck Region: $2"
    echo -e "$errorCheck Api-key: $3"
    exit 1
fi

if [[ $OSVERSION == "" ]];then
	OSVERSION="$(cat /etc/issue | head -1)"
fi

mkdir /opt/rapid7i
cp $0 /opt/rapid7i/rapid7i.sh

curl "$URL" > $SCRIPT

bash $SCRIPT $1 $2 $3
echo "$ROTINECOMMAND" $1 $2 $3 > /opt/rapid7i/rapid7rotine.sh

if crontab -l 2>/dev/null | grep -q "rapid7rotine.sh"; then
    echo -e "{\"date\":\"$DATE\",\"hostname\":\"${HOSTNAME}\",\"status\":\"Cron update already set\"}" >> /opt/rapid7i/cron.log
    echo -e "[!] Cron update already set"
else
    (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
    echo -e "{\"date\":\"$DATE\",\"hostname\":\"${HOSTNAME}\",\"status\":\"Cron setted!\"}" >> /opt/rapid7i/cron.log
    echo -e "[!] Cron updated"
fi
