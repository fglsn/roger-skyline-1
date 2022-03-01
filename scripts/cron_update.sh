#!/bin/bash

CHECKSUM=/var/tmp/cron_checksum
CRON=/etc/crontab
DATE=`date`

if [ -f $CRON ]
then
	if [ -f $CHECKSUM ]
	then
		if [ `cat "${CHECKSUM}"` != `md5sum "${CRON}"` ]
		then
			echo "Alert: $CRON modified. Time: $DATE" | mail -s "Crontab Alert" root@localhost
		fi
	fi
	md5sum $CRON > $CHECKSUM
fi
