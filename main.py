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
    parser = argparse.ArgumentParser(description=\
            "Simple utility to scan network and detect operating system and device"\
            "fingerprints. If no arguments are passed, detects the subnet automatically"\
            )
    parser.add_argument("target_spec", type=str, nargs="?", help=\
            "Can pass hostnames, IP addresses, networks, etc. Ex: scanme.nmap.org,"\
            "microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254"\
            )
    args = parser.parse_args()
    
    return args.target_spec


def main():
    target_spec = parse_args()

    # Stealth scan, OS scan, and MAC resolution require superuser priveleges
    elevate(graphical=False, show_console=False)

    # Enable p0f passive scan while nmap is scanning
    with P0f_client("p0f.socket") as p0f_client:
        nm = PortScanner() 

        # If no target spec specified, detect subnet automatically
        if target_spec is None:
            target_spec = get_network_parameters()
            print("Using automatic target_spec: ", target_spec)

        # Invoke nmap scanner
        print("Starting scan")

        try:
            nm.scan(target_spec, arguments="-sS -sU -p 5353 -sV -O -T4 --script=banner,dns-service-discovery,smb-os-discovery.nse")
        except KeyboardInterrupt as e: 
            print("nmap scan interrupted.")

        # Process hosts
        hosts = dict()

        for host in nm.all_hosts():
            try:
                hosts[host] = Host(host, nm, p0f_client)
            except Exception as e:
                print("Error parsing host ", host, " ", e)
                raise e # TODO - REMOVE
    
        print(len(hosts), " hosts scanned with target spec: ", target_spec)

        # Create XML output
        xml = XML(hosts)

        with open("host_report.xml", "w") as out_file:
            out_file.write(xml.get_xml())


if __name__ == "__main__":
    main()
