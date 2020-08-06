#!/usr/bin/env python3

from Passive import P0f_client 
from Host import Host
from Report import XML
from nmap import PortScanner
from elevate import elevate
import netifaces
import argparse
import os

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

    # Stealth scan, OS scan, and MAC resolution require superuser priveleges
    elevate(graphical=False)

    # Enable p0f passive scan while nmap is scanning
    with P0f_client("p0f.socket") as p0f_client:
        nm = PortScanner() 

        if target_spec is None:
            target_spec = get_network_parameters()
            print("Using automatic target_spec: ", target_spec)

        print("Starting scan")

        """
        try:
            nm.scan(target_spec, arguments="-F")
        except KeyboardInterrupt as e: 
            print("nmap scan interrupted.")
        """
        nm.scan("192.168.1.1", arguments="-sS -sU -p 22 -sV -O -T4 --script=banner")

        hosts = dict()

        for host in nm.all_hosts():
            try:
                hosts[host] = Host(host, nm, p0f_client)
                
                for key, value in nm[host].items():
                    print(key, " ", value)
    
            except Exception as e:
                print("Error parsing host ", host, " ", e)
                raise e
    
        print(len(hosts), " hosts scanned with target spec: ", target_spec)

        #xml = XML(hosts)
        #print(xml.get_xml())
        

if __name__ == "__main__":
    main()
