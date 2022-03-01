#!/bin/bash
UPDFILE="/var/log/update_script.log"

date >> $UPDFILE
apt update -y >> $UPDFILE
apt upgrade -y >> $UPDFILE