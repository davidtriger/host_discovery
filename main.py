#!/usr/bin/env python3

from Passive import P0f_client 
from Host import Host
from Report import XML
import Recog
from nmap import PortScanner
from elevate import elevate
import netifaces
import argparse

# Convert ip mask to a number of 1's in it's binary representation
def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])


# Get default network address and mask
def get_network_parameters():
    default_gw_device = netifaces.gateways()['default'][netifaces.AF_INET][1]
    addresses = netifaces.ifaddresses(default_gw_device)[netifaces.AF_INET][0]
    
    return addresses["addr"] + "/" + str(netmask_to_cidr(addresses["netmask"]))


def parse_args():
    parser = argparse.ArgumentParser(description="Simple utility to scan network and detect operating system and device fingerprints. If no arguments are passed, detects the subnet automatically")
    parser.add_argument("target_spec", type=str, nargs="?", help="Can pass hostnames, IP addresses, networks, etc. Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254")
    args = parser.parse_args()
    return args.target_spec


def main():
    target_spec = parse_args()

    # Require superuser for nmap OS scan and MAC resolution
    elevate(graphical=False)

    # Enable p0f passive scan while nmap is scanning
    with P0f_client("p0f.socket") as p0f_client:
        nm = PortScanner() 

        if target_spec is None:
            target_spec = get_network_parameters()
            print("Using automatic target_spec: ", target_spec)

        print("Starting scan")
        #nm.scan(target_spec, arguments="-A -T4")

        """
        try:
            nm.scan(target_spec, arguments="-F")
        except KeyboardInterrupt as e: 
            print("nmap scan interrupted.")
        """
        nm.scan("192.168.1.1", arguments="-p 22 -sV -O -T4 --script=banner")

        #nm.scan("192.168.1.1", arguments="-O -F -sS -sU")
        #nm.scan("192.168.1.1", arguments="-O --osscan-limit --max-os-tries 1")
        hosts = dict()

        for host in nm.all_hosts():
            hosts[host] = Host(host, nm, p0f_client)
            print(host)
            print(nm[host].hostnames())
            
            for key, value in nm[host].items():
                print(key, " ", value)

            for protocol in nm[host].all_protocols():
                print(protocol)
                lport = nm[host][protocol].keys()

                for port in sorted(lport):
                    print('port : %s\tstate : %s' % (port, nm[host][protocol][port]['state']))

        print(len(hosts), " hosts scanned with target spec: ", target_spec)

        #xml = XML(hosts)
        #print(xml.get_xml())
        

if __name__ == "__main__":
    main()
