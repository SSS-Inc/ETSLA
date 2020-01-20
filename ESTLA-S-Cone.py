#!/usr/bin/env python3
# S-Cone.py
# Strategic Service Solutions, Inc.

#############################################################
# Usage:                                                   #
# /path/to/S-Cone.py <FLASH_OPTION> <WWAN_IP_ADDRESS>      #
# FLASH_OPTION                                             #
#    noflash                                               #
#       do not flash the Laguna board                      #
#    flash                                                 #
#       flash the Laguna board                             #
#                                                          #
# WWAN_IP_ADDRESS                                          #
#    - enter the ip address to be used by the wireless     #
#      adapter (external IP address)                       #
#                                                          #
# This program configures the gateworks GW2391 board.      #
# 1) flash                                                 #
# 2) ssh                                                   #
#    i. key setup                                          #
#   ii. ssh connect                                        #
# 3) scripts setup                                         #
#    i. make scripts directory                             #
#   ii. transfer scripts                                   #
#  iii. set up scripts                                     #
# 4) configure settings                                    #
#    i. password                                           #
#   ii. system                                             #
#  iii. wireless                                           #
#   iv. network                                            #
#    v. firewall                                           #
# 5) create user                                           #
# 6) serial authentication setup                           #
#                                                          #
############################################################

############################################################
######################## Modules ###########################
############################################################
import paramiko
import os
import subprocess
import time
import sys

############################################################
####################### Variables ##########################
############################################################
#S-Cone
host = '192.168.1.1'    #default ip
host_after = '192.168.1.254'
user = 'root'           #default username
passwrd = None          #default password
#Host Linux machine
homedir = os.getenv("HOME")
sconedir = os.getcwd()
#paths
dropbear_path = "/etc/dropbear"
scripts_path = "/etc/scripts"
initd_path = "/etc/init.d"
jtag_path = homedir + "/jtag/jtag_usbv4"
binary_path = sconedir + "/binaries/wpa_cli__login.bin"
privatekey_path = homedir + "/.ssh/id_rsa"
publickey_path = homedir + "/.ssh/id_rsa.pub"
authkeys_path = homedir + "/.ssh/authorized_keys"
roamingsh_path = sconedir + "/scripts/roaming.sh"
roaming_path = sconedir + "/scripts/roaming"
temperaturesh_path = sconedir + "/scripts/temperature.sh"
temperature_path = sconedir + "/scripts/temperature"
monitorsh_path = sconedir + "/scripts/monitor.sh"
monitor_path = sconedir + "/scripts/monitor"
login_path = sconedir + "/scripts/S-Cone_login.sh"
firewall_path = sconedir + "/configfiles/firewall1"
network_path = sconedir + "/configfiles/network1"
system_path = sconedir + "/configfiles/system1"
wireless_path = sconedir + "/configfiles/wireless1"
inventory_path = sconedir + "/S-ConeInventory.csv"

############################################################
####################### Functions ##########################
############################################################
def ping(host):
    """
    wait until S-Cone can be pinged
    """
    print('[*] Pinging S-Cone ({})...'.format(host))
    time.sleep(2)
    #stay in while loop until you can ping S-Cone LAN NIC
    response = os.system('ping -c 1 ' + host + ' > /dev/null')
    while response != 0:
        response = os.system('ping -c 1 ' + host + ' > /dev/null')

def JTAG_detected():
    """
    check if the JTAG programmer is detected
    """
    command = "ls /dev/ttyUSB1"
    command_list = command.split()
    p = subprocess.Popen(command_list, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    stdout, stderr = p.communicate()
    
    if stdout:
        return True
    else:
        print("!! Could not detect the JTAG programmer. !!")
        time.sleep(2)
        return False

def isLinuxMachine():
    """
    check if the OS running the S-Cone.py program can flash
    """
    command = "cat /proc/sys/kernel/osrelease"
    #command = "cat /proc/version"
    command_list = command.split()
    p = subprocess.Popen(command_list, stdout = subprocess.PIPE, stderr = subprocess.PIPE)
    stdout, stderr = p.communicate()
    
    if b"Microsoft" not in stdout:
        return True
    else:
        print("!! This machine is NOT suitable to flash the S-Cone. !!")
        time.sleep(2)
        return False

def exec_command(command):
    """
    executes ssh commands with a time delay
    """
    global ssh
    ssh.exec_command(command)
    time.sleep(2)

def clear():
    command = "clear"
    subprocess.Popen(command)
    time.sleep(0.01)
    
def is_valid_ip(ip):
    ip_list = ip.split('.')
    if len(ip_list) < 4 or '' in ip_list:
        return False
    ip_list = [ int(x) for x in ip_list ]
    for i in range(4):
        if ip_list[i] < 0 or ip_list[i] > 255:
            return False
            break
        else:
            return True
        
def getSConeIP():
    while True:
        ip = input("Enter IP address to assign to wireless NIC: ")
        if ip != '':
            if not is_valid_ip(ip):
                print("not a valid ip address")
            else:
                break
    return ip
        
def wannaFlash():
    flash_option = 'N'
    if isLinuxMachine() and JTAG_detected():
        flash_option = input("flash? [y/N]: ")
    return flash_option

def selectProfile():
    profile = input("Enter profile [ets/tti/etsla]: ")
    if profile == "ets":
        SSID = "ETS_Yard"
        SSID_KEY = "Ets2lake"
        NETMASK = "255.255.252.0"
        GATEWAY = "192.168.7.254"
    elif profile == "etsla":
        SSID = "ETS_Yard"
        SSID_KEY = "Ets2lake"
        NETMASK = "255.255.252.0"
        GATEWAY = "192.168.7.254"
    elif profile == "tti":
        SSID = "EPS"
        SSID_KEY = "c@rg0t3c!"
        NETMASK = "255.255.254.0"
        GATEWAY = "10.200.224.10"
    return profile, SSID, SSID_KEY, NETMASK, GATEWAY

############################################################
###################### User Prompt #########################
############################################################
clear()
ping(host)
profile, SSID, SSID_KEY, NETMASK, GATEWAY = selectProfile()
wwan_ip_address = getSConeIP()
flash_option = wannaFlash()
   
############################################################
####################### 1. Flash ###########################
############################################################
if (flash_option == 'y'):
    print('[*] Removing ftdi_sio module')
    rmmod_command = "sudo rmmod ftdi_sio"
    rmmod_command__list = rmmod_command.split()
    rmm_process = subprocess.Popen(rmmod_command__list)
    rmm_process.communicate()

    print('[*] Flashing Laguna board')
    jtag_command = "sudo " + jtag_path + " -p " + binary_path
    jtag_command__list = jtag_command.split()
    jtag_process = subprocess.Popen(jtag_command__list)
    time.sleep(200)
    input("[*] Flashing complete. PRESS ENTER")

    print('[*] Probing for ftdi_sio module')
    modprobe_command = "sudo modprobe ftdi_sio"
    modprobe_command__list = modprobe_command.split()
    mp_process = subprocess.Popen(modprobe_command__list)
    time.sleep(2)

    #print('[*] Waiting 60 seconds for S-Cone bootup')
    print('[*] type "sudo screen /dev/ttyUSB1 115200" in another terminal window')
    time.sleep(2)

    ping(host)

############################################################
######################### 2. SSH ###########################
############################################################

####################### Key Setup ##########################
print('[*] Setting up keys')
removeknownhosts_command = "rm " + homedir + "/.ssh/known_hosts"
removeknownhosts_command__list = removeknownhosts_command.split()
rkh_process = subprocess.Popen(removeknownhosts_command__list)

touchknownhosts_command = "touch " + homedir + "/.ssh/known_hosts"
touchknownhosts_command__list = touchknownhosts_command.split()
tkh_process = subprocess.Popen(touchknownhosts_command__list)

removeprivatekey_command = "rm " + privatekey_path
removeprivatekey_command__list = removeprivatekey_command.split()
rprk_process = subprocess.Popen(removeprivatekey_command__list)

removepublickey_command = "rm " + publickey_path
removepublickey_command__list = removepublickey_command.split()
rpuk_process = subprocess.Popen(removepublickey_command__list)

keygen_command = "ssh-keygen -m pem -t rsa -b 4096"
keygen_command__list = keygen_command.split()
kg_process = subprocess.Popen(keygen_command__list, stdin = subprocess.PIPE)
kg_process.communicate(input = "\n".encode())

copypubtoauth_command = "cp " + publickey_path + " " + authkeys_path
copypubtoauth_command__list = copypubtoauth_command.split()
cpta_process = subprocess.Popen(copypubtoauth_command__list)

print('[*] Transferring authorized_keys file')
copyauthkeyfile_command = "scp " + authkeys_path + " " + user + "@" + host + ":" + dropbear_path
copyauthkeyfile_command__list = copyauthkeyfile_command.split()
cakf_process = subprocess.Popen(copyauthkeyfile_command__list, stdin = subprocess.PIPE)
cakf_process.communicate(input = "yes\n".encode())
time.sleep(1)

mykey = paramiko.RSAKey.from_private_key_file(privatekey_path)

###################### SSH Connect #########################
try:
    print('[*] Connecting to S-Cone via SSH')
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, pkey = mykey)

    print('[*] Connected successfully')
    time.sleep(1)

except:
    print('[*] Could NOT connect via SSH. Check your connectivity to the S-Cone.')
    sys.exit()

############################################################
##################### 3. Scripts Setup #####################
############################################################

################### Make Scripts Directory##################
print('[*] Making scripts directory')
ssh.exec_command("mkdir " + scripts_path)
print('[*] Changing permissions for scripts directory')
ssh.exec_command("chmod 700 " + scripts_path)
time.sleep(1)

################### Transfer Login Script ##################
print('[*] Transferring S-Cone_login.sh script')
copylogin_command = "scp " + login_path + " " + user + "@" + host + ":" + "/bin/"
copylogin_command__list = copylogin_command.split()
cl_process = subprocess.Popen(copylogin_command__list)
time.sleep(1)

################# Transfer Roaming Scripts #################
print('[*] Transferring roaming.sh script')
copyroamingsh_command = "scp " + roamingsh_path + " " + user + "@" + host + ":" + scripts_path
copyroamingsh_command__list = copyroamingsh_command.split()
crsh_process = subprocess.Popen(copyroamingsh_command__list)
time.sleep(1)

print('[*] Transferring roaming script')
copyroaming_command = "scp " + roaming_path + " " + user + "@" + host + ":" + initd_path
copyroaming_command__list = copyroaming_command.split()
cr_process = subprocess.Popen(copyroaming_command__list)
time.sleep(1)

############### Transfer Temperature Scripts ###############
print('[*] Transferring temperature.sh script')
copytemperaturesh_command = "scp " + temperaturesh_path + " " + user + "@" + host + ":" + scripts_path
copytemperaturesh_command__list = copytemperaturesh_command.split()
ctsh_process = subprocess.Popen(copytemperaturesh_command__list)
time.sleep(1)

print('[*] Transferring temperature script')
copytemperature_command = "scp " + temperature_path + " " + user + "@" + host + ":" + initd_path
copytemperature_command__list = copytemperature_command.split()
ct_process = subprocess.Popen(copytemperature_command__list)
time.sleep(1)

################# Transfer Monitor Scripts #################
print('[*] Transferring monitor.sh script')
copymonitorsh_command = "scp " + monitorsh_path + " " + user + "@" + host + ":" + scripts_path
copymonitorsh_command__list = copymonitorsh_command.split()
cmsh_process = subprocess.Popen(copymonitorsh_command__list)
time.sleep(1)

print('[*] Transferring monitor script')
copymonitor_command = "scp " + monitor_path + " " + user + "@" + host + ":" + initd_path
copymonitor_command__list = copymonitor_command.split()
cm_process = subprocess.Popen(copymonitor_command__list)
time.sleep(1)

#################### Set up Login Script ###################
print('[*] Setting up login script')
ssh.exec_command("chmod 700 /bin/S-Cone_login.sh")
time.sleep(1)

################## Set up Roaming Scripts ##################
print('[*] Setting up roaming scripts')
ssh.exec_command("chmod 700 " + initd_path + "/roaming")
time.sleep(1)
ssh.exec_command(initd_path + "/roaming enable")
time.sleep(1)
ssh.exec_command("chmod 700 " + scripts_path + "/roaming.sh")
time.sleep(1)
if profile == "tti":
    ssh.exec_command("sed -i s/ETS_Yard/EPS/g " + scripts_path + "/roaming.sh")

################ Set up Temperature Scripts ################
print('[*] Setting up temperature scripts')
ssh.exec_command("chmod 700 " + initd_path + "/temperature")
time.sleep(1)
ssh.exec_command(initd_path + "/temperature enable")
time.sleep(1)
ssh.exec_command("chmod 700 " + scripts_path + "/temperature.sh")
time.sleep(2)

################## Set up Monitor Scripts ##################
print('[*] Setting up monitor scripts')
ssh.exec_command("chmod 700 " + initd_path + "/monitor")
time.sleep(1)
ssh.exec_command(initd_path + "/monitor enable")
time.sleep(1)
ssh.exec_command("chmod 700 " + scripts_path + "/monitor.sh")
time.sleep(1)

# change permissions on system, wireless, network and firewall files
    # chmod -R 664 /etc/config
# change group on system, wireless, network and firewall files
    # chgrp -R users /etc/config

############################################################
################### 4. Config Settings #####################
############################################################

#################### Password Config #######################
print('[*] Updating root password')
stdin, stdout, stderr = ssh.exec_command('passwd')
stdin.write('Strategic3!@#$\n')
stdin.write('Strategic3!@#$\n')

##################### System Config ########################
print('[*] Configuring System File')
ssh.exec_command("uci set system.@system[0].hostname=S-Cone")
ssh.exec_command("uci set system.@system[0].log_file=/var/log/S-Cone.log")
exec_command("uci set system.@system[0].ttylogin=1")

ssh.exec_command("uci commit system")

##################### Wireless Config ######################
print('[*] Configuring Wireless File')
#radio0
ssh.exec_command("uci del wireless.radio0.disabled")

#wifi-iface[0]
ssh.exec_command("uci set wireless.@wifi-iface[0].network=wwan")
ssh.exec_command("uci set wireless.@wifi-iface[0].mode=sta")
ssh.exec_command("uci set wireless.@wifi-iface[0].ssid=" + SSID)
ssh.exec_command("uci set wireless.@wifi-iface[0].encryption=psk2")
exec_command("uci set wireless.@wifi-iface[0].key=" + SSID_KEY)

ssh.exec_command("uci commit wireless")

##################### Network Config #######################
print('[*] Configuring Network File')
#loopback : unchanged

#lan
ssh.exec_command("uci del network.lan.type")
#this command has been moved to the end of the program
#ssh.exec_command("uci set network.lan.ipaddr=192.168.1.254")

#wwan
exec_command("uci set network.wwan=interface")
ssh.exec_command("uci set network.wwan.proto=static")
ssh.exec_command("uci set network.wwan.ipaddr=" + wwan_ip_address)
ssh.exec_command("uci set network.wwan.netmask=" + NETMASK)
ssh.exec_command("uci set network.wwan.gateway=" + GATEWAY)
exec_command("uci set network.wwan.dns=8.8.8.8")

ssh.exec_command("uci commit network")

ssh.exec_command("/etc/init.d/network restart")
print('[*] Network service restarted')

time.sleep(1)

ping(host)

###################### Firewall Config #####################
print('[*] Configuring Firewall File')

#zone[1] = wwan : wan -> wwan
ssh.exec_command("uci set firewall.@zone[1].network=wwan")

if profile == 'ets':
    #port forwarding for ETS
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[0].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[0].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[0].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[0].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[0].src_dport='10022'")
    ssh.exec_command("uci set firewall.@redirect[0].dest_ip='192.168.1.10'")
    ssh.exec_command("uci set firewall.@redirect[0].dest_port='22'")
    ssh.exec_command("uci set firewall.@redirect[0].name='CCXA_ssh'")

    time.sleep(2)
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[1].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[1].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[1].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[1].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[1].src_dport='4803'")
    ssh.exec_command("uci set firewall.@redirect[1].dest_ip='192.168.1.10'")
    ssh.exec_command("uci set firewall.@redirect[1].dest_port='4803'")
    ssh.exec_command("uci set firewall.@redirect[1].name='CCXA_spread'")

    time.sleep(2)
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[2].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[2].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[2].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[2].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[2].src_dport='20022'")
    ssh.exec_command("uci set firewall.@redirect[2].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[2].dest_port='22'")
    ssh.exec_command("uci set firewall.@redirect[2].name='GPS_ssh'")

    time.sleep(2)
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[3].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[3].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[3].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[3].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[3].src_dport='3044'")
    ssh.exec_command("uci set firewall.@redirect[3].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[3].dest_port='3044'")
    ssh.exec_command("uci set firewall.@redirect[3].name='GPS_rtcm-correction'")

elif profile == "etsla":
    # port forwarding for ETSLA
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[0].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[0].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[0].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[0].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[0].src_dport='10022'")
    ssh.exec_command("uci set firewall.@redirect[0].dest_ip='192.168.1.10'")
    ssh.exec_command("uci set firewall.@redirect[0].dest_port='22'")
    ssh.exec_command("uci set firewall.@redirect[0].name='CCXA_ssh'")

    time.sleep(2)
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[1].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[1].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[1].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[1].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[1].src_dport='4803'")
    ssh.exec_command("uci set firewall.@redirect[1].dest_ip='192.168.1.10'")
    ssh.exec_command("uci set firewall.@redirect[1].dest_port='4803'")
    ssh.exec_command("uci set firewall.@redirect[1].name='CCXA_spread'")

    time.sleep(2)
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[2].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[2].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[2].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[2].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[2].src_dport='20022'")
    ssh.exec_command("uci set firewall.@redirect[2].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[2].dest_port='22'")
    ssh.exec_command("uci set firewall.@redirect[2].name='GPS_ssh'")

    time.sleep(2)
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[3].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[3].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[3].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[3].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[3].src_dport='3044'")
    ssh.exec_command("uci set firewall.@redirect[3].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[3].dest_port='3044'")
    ssh.exec_command("uci set firewall.@redirect[3].name='GPS_rtcm-correction'")


elif profile == 'tti':
    #port forwarding for TTI
    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[0].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[0].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[0].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[0].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[0].src_dport='8022'")
    ssh.exec_command("uci set firewall.@redirect[0].dest_ip='192.168.1.11'")
    ssh.exec_command("uci set firewall.@redirect[0].dest_port='22'")
    ssh.exec_command("uci set firewall.@redirect[0].name='CCXA_ssh'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[1].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[1].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[1].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[1].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[1].src_dport='3044'")
    ssh.exec_command("uci set firewall.@redirect[1].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[1].dest_port='3044'")
    ssh.exec_command("uci set firewall.@redirect[1].name='Correction_Data'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[2].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[2].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[2].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[2].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[2].src_dport='1022'")
    ssh.exec_command("uci set firewall.@redirect[2].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[2].dest_port='22'")
    ssh.exec_command("uci set firewall.@redirect[2].name='GPS_ssh'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[3].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[3].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[3].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[3].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[3].src_dport='7777'")
    ssh.exec_command("uci set firewall.@redirect[3].dest_ip='192.168.1.99'")
    ssh.exec_command("uci set firewall.@redirect[3].dest_port='7777'")
    ssh.exec_command("uci set firewall.@redirect[3].name='GPS_7777'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[4].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[4].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[4].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[4].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[4].src_dport='1080'")
    ssh.exec_command("uci set firewall.@redirect[4].dest_ip='192.168.1.2'")
    ssh.exec_command("uci set firewall.@redirect[4].dest_port='80'")
    ssh.exec_command("uci set firewall.@redirect[4].name='Screen_80'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[5].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[5].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[5].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[5].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[5].src_dport='5900'")
    ssh.exec_command("uci set firewall.@redirect[5].dest_ip='192.168.1.2'")
    ssh.exec_command("uci set firewall.@redirect[5].dest_port='5900'")
    ssh.exec_command("uci set firewall.@redirect[5].name='GPS_5900'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[6].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[6].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[6].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[6].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[6].src_dport='445'")
    ssh.exec_command("uci set firewall.@redirect[6].dest_ip='192.168.1.11'")
    ssh.exec_command("uci set firewall.@redirect[6].dest_port='445'")
    ssh.exec_command("uci set firewall.@redirect[6].name='CCXA_445'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[7].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[7].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[7].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[7].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[7].src_dport='139'")
    ssh.exec_command("uci set firewall.@redirect[7].dest_ip='192.168.1.11'")
    ssh.exec_command("uci set firewall.@redirect[7].dest_port='139'")
    ssh.exec_command("uci set firewall.@redirect[7].name='CCXA_139'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[8].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[8].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[8].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[8].proto='tcp'")
    ssh.exec_command("uci set firewall.@redirect[8].src_dport='137'")
    ssh.exec_command("uci set firewall.@redirect[8].dest_ip='192.168.1.11'")
    ssh.exec_command("uci set firewall.@redirect[8].dest_port='137'")
    ssh.exec_command("uci set firewall.@redirect[8].name='CCXA_137'")

    exec_command("uci add firewall redirect")
    ssh.exec_command("uci set firewall.@redirect[9].target='DNAT'")
    ssh.exec_command("uci set firewall.@redirect[9].src='wan'")
    ssh.exec_command("uci set firewall.@redirect[9].dest='lan'")
    ssh.exec_command("uci set firewall.@redirect[9].proto='tcp udp'")
    ssh.exec_command("uci set firewall.@redirect[9].src_dport='138'")
    ssh.exec_command("uci set firewall.@redirect[9].dest_ip='192.168.1.11'")
    ssh.exec_command("uci set firewall.@redirect[9].dest_port='138'")
    ssh.exec_command("uci set firewall.@redirect[9].name='CCXA_138'")
    time.sleep(3)

#allow ssh on wwan interface
exec_command("uci add firewall rule")
ssh.exec_command("uci set firewall.@rule[9].target='ACCEPT'")
ssh.exec_command("uci set firewall.@rule[9].src='wan'")
ssh.exec_command("uci set firewall.@rule[9].proto='tcp'")
ssh.exec_command("uci set firewall.@rule[9].dest_port='22'")
ssh.exec_command("uci set firewall.@rule[9].name='ALLOW-SSH-WAN'")

#allow http on wwan interface
exec_command("uci add firewall rule")
ssh.exec_command("uci set firewall.@rule[10]=rule")
ssh.exec_command("uci set firewall.@rule[10].target='ACCEPT'")
ssh.exec_command("uci set firewall.@rule[10].src='wan'")
ssh.exec_command("uci set firewall.@rule[10].proto='tcp'")
ssh.exec_command("uci set firewall.@rule[10].dest_port='80'")
exec_command("uci set firewall.@rule[10].name='ALLOW-HTTP-WAN'")

ssh.exec_command("uci commit firewall")

time.sleep(3)

############################################################
############### Write outputs to files #####################
############################################################
#firewall1
stdin, stdout, stderr = ssh.exec_command("cat /etc/config/firewall")
output = stdout.read().decode()

with open(firewall_path, "w") as f:
    for letter in output:
        f.write(letter)
        
#network1
stdin, stdout, stderr = ssh.exec_command("cat /etc/config/network")
output = stdout.read().decode()

with open(network_path, "w") as f:
    for letter in output:
        f.write(letter)
        
#system1
stdin, stdout, stderr = ssh.exec_command("cat /etc/config/system")
output = stdout.read().decode()

with open(system_path, "w") as f:
    for letter in output:
        f.write(letter)
        
#wireless1
stdin, stdout, stderr = ssh.exec_command("cat /etc/config/wireless")
output = stdout.read().decode()

with open(wireless_path, "w") as f:
    for letter in output:
        f.write(letter)

############################################################
################### 5. User Config #########################
############################################################
print('[*] Configuring User account')
ssh.exec_command("echo 'ets:x:99:100:ets:/etc/config:/bin/ash' >> /etc/passwd")
ssh.exec_command("echo 'ets::0:0:99999:7:::' >> /etc/shadow")
stdin, stdout, stderr = ssh.exec_command('passwd ets')
stdin.write('ets\n')
stdin.write('ets\n')

time.sleep(1)

############################################################
################ 6. Serial Authentication ##################
############################################################
print('[*] Enabling serial authentication')
exec_command("mv /etc/inittab /etc/inittab.orig")
exec_command("head -n2 /etc/inittab.orig > /etc/inittab")
exec_command("echo '::askconsole:/bin/S-Cone_login.sh' >> /etc/inittab")

#note that ttylogin was enabled in the system config settings

#/etc/inittab.orig
'''
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K shutdown
::askconsole:/bin/ash --login
'''
#/etc/inittab
'''
::sysinit:/etc/init.d/rcS S boot
::shutdown:/etc/init.d/rcS K shutdown
::askconsole:/bin/S-Cone_login.sh
'''

time.sleep(1)

############################################################
#################### Get Inventory #########################
############################################################
#get ID, IPs and MACs
stdin, stdout, stderr = ssh.exec_command('ifconfig eth0')
output_eth0 = stdout.read().decode()
l = output_eth0.splitlines()
tmp=[]
tmp.append(l[0])
tmp.append(l[1])
l = tmp
l1 = l[0].split()
l2 = l[1].split()
mac_eth0 = l1[4]
ip_eth0 = l2[1]
ip_eth0 = ip_eth0[5:]
ip_eth0 = "192.168.1.254"

stdin, stdout, stderr = ssh.exec_command('ifconfig wlan0')
output_wlan0 = stdout.read().decode()
l = output_wlan0.splitlines()
tmp=[]
tmp.append(l[0])
tmp.append(l[1])
l = tmp
l1 = l[0].split()
l2 = l[1].split()
mac_wlan0 = l1[4]
ip_wlan0 = l2[1]
ip_wlan0 = ip_wlan0[5:]
ip_wlan0_list = ip_wlan0.split('.')
ip_wlan0_lastOctet = ip_wlan0_list[-1]
SCone_ID = ip_wlan0_lastOctet[-3:]

print('ID: {}'.format(SCone_ID))
print('IP (LAN): {}'.format(ip_eth0))
print('MAC (LAN): {}'.format(mac_eth0))
print('IP (WWAN): {}'.format(ip_wlan0))
print('MAC (WWAN): {}'.format(mac_wlan0))

if profile == 'ets':
    inventory_path = sconedir + "/S-ConeInventory_ETS.csv"
elif profile == 'tti':
    inventory_path = sconedir + "/S-ConeInventory_TTI.csv"
elif profile == 'etsla':
    inventory_path = sconedir + "/S-ConeInventory_ETSLA.csv"

#create file if it doesn't exist
command = "touch " + inventory_path
command__list = command.split()
process = subprocess.Popen(command__list)
#append to .csv file
with open(inventory_path, "a") as f:
    f.write(SCone_ID)
    f.write(', ')
    f.write(ip_eth0)
    f.write(', ')
    f.write(mac_eth0)
    f.write(', ')
    f.write(ip_wlan0)
    f.write(', ')
    f.write(mac_wlan0)
    f.write('\n')

############################################################
#################### LAN Network IP ########################
############################################################
print('[*] Setting LAN IP address')
exec_command("uci set network.lan.ipaddr=192.168.1.254")
exec_command("uci commit network")

############################################################
################### Config Complete ########################
############################################################
print('[*] Configuration Complete')

time.sleep(1)

print('[*] Rebooting S-Cone')
time.sleep(2)
ssh.exec_command("reboot")
time.sleep(1)

ssh.close()