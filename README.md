# roger-skyline-1

This subject follows Init where we have learn some of basics commands and first
reflexes in system and network administration. This project is a concrete exemple of
the use of those commands and will let you start your own first web server. 

This file describes my steps of this project completion.

## # Install Debian on VirtualBox to goinfre folder:

VDI 8.00 GB Fixed size
https://www.debian.org/distrib/

Partition:
Create three partitions on SCSI2
1.	4.2GB, primary, beggining, ext4, /
2.	500MB, swap
3.	Rest memory, logical, ext4, home/

In software installation:
	No desktop interfaces,
	SSH services - check,
	Utilities - check,
	Grub - ok,
	install to disk (goinfre)

To check partition table in GB later:
	`sudo apt install parted`
	`sudo parted` -> `unit GB` -> `print all`


## # Update system:
Install sudo with:
	`apt install sudo`
 
Update packages:
	`sudo apt update`
	`sudo apt upgrade`

note, if you get error:
"Release file for .... is not valid yet (invalid for another *h * *min *s). 
	Updates for this repository will not be applied"  
Run:  `sudo hwclock --hctosys` This is a timezone error.  
https://askubuntu.com/questions/1096930/sudo-apt-update-error-release-file-is-not-yet-valid

#### Add user and give sudo rights:
	sudo adduser username
	sudo usermod -aG username
	su - user

## # Add static IP address:  
Set static IP on one VM machine with NAT & Host-Only interfaces.  
https://www.codesandnotes.be/2018/10/16/network-of-virtualbox-instances-with-static-ip-addresses-and-internet-access/

Create a host in VirtualBox:  
&emsp; File -> Host Network Manager -> Create -> Configure Adapter Manually  
&emsp; Set IP address of host, set mask 255.255.255.252  
  
In Network Preferences of your VM:  
&emsp; Set 1st interface as NAT, Second as Host-Only Adapter and choose a host that you've just created.  
  
Calculate possible IP that you can use considering that netmask 30 doesn't provide you with many options.  
Netmask notation: https://www.pawprint.net/designresources/netmask-converter.php  

Inside /etc/network/interfaces file add:  
```console
iface enp0s8 inet static  
	address 192.168.56.2  
	netmask 255.255.255.252  
```
Save file and restart networking daemon with:  
&emsp; `sudo service networking restart`   
  
&emsp; Netmask can be also set by:  
&emsp; `sudo ifconfig enp0s8 netmask 255.255.255.252` (but only until reboot)

## # Modify default ssh port:
https://www.linuxlookup.com/howto/change_default_ssh_port  
Change PORT 22 from default to for example 50042, save, reboot SHH:  
```console
sudo nano/etc/ssh/sshd_config 
sudo /etc/init.d/ssh restart
```
Now should be able to connect via ssh on host computer with:
ssh username@192.168.56.2 -p 50042

Disable SSH Root Login:  
https://www.tecmint.com/disable-or-enable-ssh-root-login-and-limit-ssh-access-in-linux/#:~:text=For%20security%20reasons%2C%20it's%20not,gain%20access%20to%20your%20system  

`sudo nano /etc/ssh/sshd_config` : set #PermitRootLogin to no and uncomment it  

Restart sshd service:
&emsp;`sudo systemctl restart sshd`  


## # Configure SSH to be accessable with pub.key:

https://kb.iu.edu/d/aews
https://www.linode.com/docs/guides/use-public-key-authentication-with-ssh/

1. Create rsa key on a local Mac:  
  `ssh-keygen -t rsa`
2. Redirect PUBLIC key to VM. It will be authomatically added to /home/user/.ssh as authorized_keys  
  `ssh-copy-id -i /Users/ishakuro/.ssh/id_rsa.pub user@192.168.56.2 -p 50042`  
Change /etc/ssh/sshd_config:  
&emsp;set #PasswordAuthentication to no, uncomment
3. Try login to VM 

<em>If accidentely deleted host-keys in /etc/ssh do this:  
	https://www.cyberciti.biz/faq/howto-regenerate-openssh-host-keys/  
	sudo dpkg-reconfigure openssh-server  
	sudo systemctl restart ssh</em>

## # Firewall:
https://opensource.com/article/18/9/linux-iptables-firewalld
https://help.ubuntu.com/community/UFW

##### Install and set up UFW Firewall:
```console
sudo apt install ufw -y 
sudo systemctl enable ufw --now
sudo systemctl status ufw
sudo ufw enable
```
<em>In the future, if you need to disable UFW for a temporary period:
  `sudo ufw disable`  
To remove UFW altogether from your Debian system:
  `sudo apt remove ufw --purge`  
Do not remove UFW unless you have a solid option or know how to use IPTables, especially when running a server environment connected to the public.`</em>  
  
https://www.linuxcapable.com/how-to-setup-and-configure-ufw-firewall-on-debian-11-bullseye/  
https://www.digitalocean.com/community/tutorials/how-to-set-up-a-firewall-with-ufw-on-ubuntu-18-04  

Check status of firewall:  
&emsp;`sudo ufw status numbered`  

Set the rules of your firewall on your server only with the services used outside the VM:  
&emsp;`sudo ufw default deny incoming`  
&emsp; `sudo ufw default allow outgoing`  
  
Enable UFW Ports to SSH, HTTPS, HTTP:  
&emsp;`sudo ufw allow 50042/tcp` #SSH  
&emsp;`sudo ufw allow 443` #HTTPS  
&emsp;`sudo ufw allow 80/tcp` #HTTP  

To check UFW status:  
&emsp;`sudo ufw status verbose`  
&emsp;`sudo ufw show added`  

To delete rules:  
https://www.cyberciti.biz/faq/how-to-delete-a-ufw-firewall-rule-on-ubuntu-debian-linux/  

&emsp;`sudo ufw status numbered`  
&emsp;`sudo ufw delete <rule-number-here>`  

To check open ports:  
https://www.freecodecamp.org/news/what-is-nmap-and-how-to-use-it-a-tutorial-for-the-greatest-scanning-tool-of-all-time  
&emsp;`sudo apt update`  
&emsp;`sudo apt install nmap -y`  
&emsp;`nmap -A 192.168.56.2`  

`netstat -lntu` for opened Network ports

## # DOS:

http://lepepe.github.io/sysadmin/2016/01/19/ubuntu-server-ufw.html  
https://wiki.archlinux.org/title/Uncomplicated_Firewall#Rate_limiting_with_ufw  

ufw has the ability to deny connections from an IP address that has attempted to initiate 6 or more connections in the last 30 seconds. Users should consider using this option for services such as SSH:  
&emsp;`sudo ufw limit SSH`  

#### Fail2Ban:  
https://wiki.archlinux.org/title/Fail2ban  
https://www.the-art-of-web.com/system/fail2ban/  
https://itstorage.net/index.php/ldce/islme/238-slau-5  
https://pipo.blog/articles/20210915-fail2ban-apache-dos  
https://serverfault.com/questions/639923/fail2ban-jail-local-vs-jail-conf  

Useful at the end:  
https://smeretech.com/how-to-ban-http-dos-attacks-with-fail2ban/  
https://serverfault.com/questions/949636/fail2ban-not-working-on-http-get-dos-filter  

Install:  
&emsp;`sudo apt-get install fail2ban`  

Copy jail.conf to jail.local:  
&emsp;`sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`  

Set rules in jail.local:  
&emsp;`sudo nano /etc/fail2ban/jail.local`  

```console
	[sshd]

	enabled = true
	port = 50042
	findtime  = 600
	maxretry  = 5
	bantime   = 900
	logpath = %(sshd_log)s
	backend = %(sshd_backend)s
```  
*add this after setting up and running apache2:

```console
	[http-get-dos] 

	enabled = true
	port = http,https
	filter = http-get-dos
	findtime  = 300
	maxretry  = 300
	bantime   = 300
	logpath = /var/log/apache2/access.log
	action = iptables[name=HTTP, port=http, protocol=tcp]
```  
^ https://smeretech.com/how-to-ban-http-dos-attacks-with-fail2ban/  

- maxretry is how many GETs we can have in the findtime period before getting narky  
- findtime is the time period in seconds in which we're counting "retries" (300 seconds = 5 mins)  
- bantime is how long we should drop incoming GET requests for a given IP for, in this case it's 5 minutes  

Configure filters:   
&emsp;`sudo nano /etc/fail2ban/filter.d/http-get-dos.conf` to add filter:  
```console
	[Definition]
	failregex = ^<HOST> -.*"(GET|POST).*
	ignoreregex =
```

`sudo ufw reload`
`sudo service fail2ban restart`
`sudo systemctl enable fail2ban`
 ##### Check if f2b configured well:
	Attack from your mac: ab -k -c 350 -n 20000 http://192.168.56.2/
	Check if f2b rule for attacker IP has appeared in iptables: sudo iptables -S  

sudo tail -f /var/log/apache2/access.log  
sudo cat /var/log/ufw.log  
sudo cat /var/log/syslog  

## # Psad:
https://www.unixmen.com/how-to-block-port-scan-attacks-with-psad-on-ubuntu-debian/

	sudo apt-get update 
	sudo apt-get install psad

	sudo echo -e ’kern.info\t|/var/lib/psad/psadfifo’ >> /etc/syslog.conf
	sudo /etc/init.d/rsyslog restart

	sudo nano /etc/psad/psad.conf
		paste config (see files/psad.conf file)

	sudo /etc/init.d/psad restart

Update Firewall Rules for ipv4 and ipv6:  
	`sudo iptables -A INPUT -j LOG`  
	`sudo iptables -A FORWARD -j LOG`  
	`sudo ip6tables -A INPUT -j LOG`  
	`sudo ip6tables -A FORWARD -j LOG`  

Restart:
	`sudo psad -R`  
	`sudo psad --sig-update`  
	`sudo psad -H`  

To checkopen ports:  
`sudo lsof -P -i`  
https://linuxhint.com/how_to_list_open_ports_on_linux/  

You may have lost your SSH connection, no problem!  
&emsp;Remove rule from iptables with:  
&emsp;`sudo iptables -D <line to delete from iptables>`  

Then check  
`sudo nano /etc/hosts.deny`  
&emsp;and delete banned ip from list  
https://phoenixnap.com/kb/fix-connection-reset-by-peer-ssh-error
You can also add any IP to /etc/hosts.allow  

## # Services:
https://linuxhint.com/disable_unnecessary_services_debian_linux/
	sudo systemd-analyze blame

	systemctl --type=service --state=active
	sudo service --status-all

	sudo systemctl stop apparmore
	sudo systemctl stop keyboard-setup
	sudo systemctl stop console-setup
	sudo systemctl stop rsyslog.service  or  sudo systemctl disable rsyslog
	sudo systemctl disable systemd-pstore.service

	systemctl list-unit-files --type=service


###### services left for me:  
&emsp;	apache2.service  
&emsp;	cron.service  
&emsp;	e2scrub_reap.service (tried to disasble, lost connection to vm) mailing service  
&emsp;	fail2ban.service  
&emsp;	getty@.service  
&emsp;	networking.service  
&emsp;	ssh.service  
&emsp;	systemd-timesyncd.service (for packages)  
&emsp;	ufw.service  

`sudo apt purge <service>` to delete unnesessary service 


## # Scripts:
https://serverfault.com/questions/310098/how-to-add-a-timestamp-to-bash-script-log
https://askubuntu.com/questions/672892/what-does-y-mean-in-apt-get-y-install-command
https://unix.stackexchange.com/questions/153911/when-does-linux-send-a-root-mail-and-how-to-force-it-for-testing-purposes

From root:
```console
touch /root/update_packages.sh
chmod 755 update_packages.sh
chown root /root/update_packages.sh
nano /root/update_packages.sh
	paste your script and save

touch /root/crontab_alert.sh
chmod 755 crontab_alert.sh
chown root /root/crontab_alert.sh
	paste script and save

crontab -e

paste:
	@reboot /root/update_packages.sh &
	0 4 * * wed /root/update_packages.sh &
	0 0 * * * /root/crontab_alert.sh &

```
Check if scripts are functioning well by modifying crontab and checking mail alert: 

	sudo echo "#" >> /etc/crontab  
	sudo sh /root/crontab_alert.sh  
	sudo cat /var/spool/mail/user | grep cron  


## # Your Git:

	sudo apt install git  
	ssh-keygen -t rsa  
	sudo cat /home/user/.ssh/id_rsa.pub  

paste to https://github.com/settings/keys  


## # Apache:
https://ubuntu.com/tutorials/install-and-configure-apache#2-installing-apache

	sudo apt update
	sudo apt install apache2
	cd /var/www/
	sudo mv html html2
	sudo git clone repo html


## # Create Self-Signed SSL Certificate for Apache:
https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-ubuntu-16-04

Create the SSL Certificate:

		sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/myrogerskyline.fi.key -out /etc/ssl/certs/myrogerskyline.fi.crt

		**	Common Name (e.g. server FQDN or YOUR name) []:192.168.56.2
			Email Address []:root@debian.lan

Create strong Diffie-Hellman group, which is used in negotiating Perfect Forward Secrecy with clients (/etc/ssl/certs/dhparam.pem):  

		sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048  

Configure Apache to Use SSL:  
		`sudo nano /etc/apache2/conf-available/ssl-params.conf`  
		*make changes*
	
Modify the Default Apache SSL Virtual Host File:  

1. Back up the original SSL Virtual Host file:  
		`sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.bak`

2. Open the SSL Virtual Host file to make adjustments:  
		`sudo nano /etc/apache2/sites-available/default-ssl.conf`
```console
	Add:  
		ServerAdmin root@debian.lan
		ServerName 192.168.56.2
		SSLCertificateFile		/etc/ssl/certs/myrogerskyline.fi.crt
		SSLCertificateKeyFile /etc/ssl/private/myrogerskyline.fi.key

	Uncomment:  
			BrowserMatch "MSIE [2-6]" \
							nokeepalive ssl-unclean-shutdown \
							 downgrade-1.0 force-response-1.0
```  	
3. Modify the Unencrypted Virtual Host File to Redirect to HTTPS:
&emsp; `sudo nano /etc/apache2/sites-available/000-default.conf`
&emsp; to "VirtualHost *:80" block add:

		Redirect "/" "https://your_domain_or_IP/"

4. Adjust the Firewall:
		sudo ufw app list
		
		if no Apache in application list:
		https://stackoverflow.com/questions/51537084/i-installed-apache-2-but-in-sudo-ufw-app-list-there-is-no-apache-applications-in
	
		sudo nano /etc/ufw/applications.d/apache2-utils.ufw.profile

		[Apache]
		title=Web Server
		description=Apache v2 is the next generation of the omnipresent Apache web server.
		ports=80/tcp

		[Apache Secure]
		title=Web Server (HTTPS)
		description=Apache v2 is the next generation of the omnipresent Apache web server.
		ports=443/tcp

		[Apache Full]
		title=Web Server (HTTP,HTTPS)
		description=Apache v2 is the next generation of the omnipresent Apache web server.
		ports=80,443/tcp

	Enabling the Changes in Apache: 
		sudo a2enmod ssl  
		sudo a2enmod headers  
		sudo a2ensite default-ssl  
		sudo a2enconf ssl-params  
		sudo apache2ctl configtest  
		sudo systemctl restart apache2  
