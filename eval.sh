shasum < Debian.vdi

vboxmanage internalcommands sethduuid eval3.vdi

change eval3 interface adapters to Host-Only

# The VM runs well on a Linux OS:

cat /etc/os-release
echo "Debian version: "
cat /etc/debian_version


# Technos such as Traefik as well as that Docker/Vagrant/etc.
#containers are not used in this project.

dpkg -l


# The size of the VM disk is 8 GB.
# There is at least one 4.2 GB partition.

sudo dmesg | grep blocks
sudo fdisk -x
sudo apt install parted
sudo parted
#unit GB 
#print list


# From the shell of the VM, run the command that lets you
#know if the OS and packages are up to date.
#If you discover that the OS or packages are not up to date,
#this test has failed.

sudo apt update


# From the shell of the VM, run the command that allows
#to know which packages are installed. If you discover that
#docker/vagrant/traefik type packages are installed,
#this test has failed.
#Already done with dpkg -l

apt list --installed


# NETWORK AND SECURITY:

#-----
# Ask the evaluated person to create a user with SSH key to be able to
#connect to the VM. He must be part of the sudo group. If it's not
#in this case, this test is failed.

sudo bash /root/create_sudouser.sh
groups test
	#now can login on host with: ssh test@10.11.142.143 -p 50042


#-----
# Check that the DHCP service of the VM is deactivated If
#not, this test is failed.

ip r

	#One can use ip r 
	#Linux command to list default route which act as the DHCP Server on most home networks
	#https://www.cyberciti.biz/faq/linux-find-out-dhcp-server-ip-address/



#-----
# Choose a different netmask than /30, ask the evaluated person to
# configure a network connection with this netmask on the host and guest side.
# The evaluated person will choose the IPs. If it is not successful, this test is failed.
# Netmask notation: https://www.pawprint.net/designresources/netmask-converter.php

sudo nano /etc/network/interfaces
	#insert mask
sudo service networking restart
sudo ip link set enp0s3 up


#-----
# From a shell on the VM, check that the port of the SSH has been successfully
#been modified. SSH access MUST be done with publickeys.
#The root user should not be able to connect in SSH. If this is not
#the case, this test is failed.

sudo cat /etc/ssh/sshd_config
	#Port 50042
	#PermitRootLogin no
	#PubkeyAuthentication yes
	#PasswordAuthentication no 
	
	#can try to connect 
	# ssh root@10.11.142.143 -p 50042



#-----
# From a shell on the VM, run the command that lists all firewall rules.
#If no rules are in place or that it is not sufficient in relation to the
#request from the subject, then this test is failed.

sudo iptaples -L -v -n
sudo ufw status verbose

#-----
#From a shell on your computer, run the command that allows you to
#to test a DOS (Slowloris or other). Check that everything is still working.
#In addition, make sure that a Fail2Ban service (or similar service) is installed on the VM.
#If this is not the case, this test is failed.

#nmap 10.11.142.143
#nc -z -v 10.11.142.143 50042

#on  Mac or another VM:
	#	ab -k -c 350 -n 20000 http://10.11.142.143/
#on VM:
	sudo tail -F /var/log/fail2ban.log
	sudo iptables -S
	sudo fail2ban-client status
	sudo fail2ban-client status http-get-dos


#-----
#From a shell on the VM, run the command that
#lists the open ports. Check that the open ports
#correspond to the subject's request. If not, this
#test is failed.
# There are 80, 443, 50042. May be 25for SMTP mailing

netstat -lntu
sudo lsof -i -P

#-----
#Check if the active services of the machine are only those
#necessary for its proper functioning. If not, this test
#has failed.

systemctl --type=service --state=active
sudo service --status-all
systemctl list-unit-files --type=service


#-----
#Check that there is a script to update all sources
#of package, packages, which log into the right file and that it is in cron.
#If this is not the case, this test is failed.

sudo ls /root/
sudo cat /root/update_packages.sh

sudo crontab -e

#-----
# Check that there is a script to monitor the changes in the file
# /etc/crontab and sends an email to root if it has been modified.
#You must therefore receive an email showing that the file has changed, either locally with
#the mail order, either in your own mailbox. If not, this test
#has failed.

sudo cat /root/crontab_alert.sh
sudo /bin/bash -c '(echo "#" >> /etc/crontab )'
sudo sh /root/crontab_alert.sh
sudo cat /var/spool/mail/user | grep cron


#-----
#Check that there is self-signed SSL on all services. If this is not
#the case, this test is failed.

ls /etc/ssl/certs
sudo cat apache-selfsigned.crt
sudo apachectl configtest

#WEB PART:
#From a shell of the VM, check that the package of a Web server
#is installed. If this is not the case, this test is failed.

sudo apt list --installed | grep apache

cd /var/www/html/
sudo git pull 

