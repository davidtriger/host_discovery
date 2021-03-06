#!/usr/bin/env python3

from Passive import P0f_client 
from Host import Host
from Report import XML
from nmap import PortScanner
from elevate import elevate
import netifaces
import argparse
from argparse import RawTextHelpFormatter
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
            "fingerprints.\n If no arguments are passed, detects the subnet automatically,"\
            "and uses default nmap ports.",
            formatter_class=RawTextHelpFormatter
            )
    parser.add_argument("target_spec", type=str, nargs="?", help=\
            "Can pass hostnames, IP addresses, networks, etc.\n"\
            "Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0.0-255.1-254"
            )
    parser.add_argument("-i", "--interface", type=str, help=\
            "Specify interface to run tool on. If omitted, runs on default interface."
            )
    parser.add_argument("-a", "--args", type=str, help=\
            "Additional arguments for nmap. See nmap -h."
            )

    parser.add_argument("-sU", action="store_true", help=\
            "Scan UDP. Makes execution slow, low amount of ports recommended.\n"\
            "Consider using with:\n"\
            "\t--args \"--min-parallelism 10 --max-retries 2\""
            )

    ports_group = parser.add_mutually_exclusive_group()
    ports_group.add_argument("-p", "--ports", type=str, help=\
            "Only scan specified ports. Mutually exclusive with --top_ports.\n"\
            "Ex: -p 22; -p 1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9"
            )
    ports_group.add_argument("-t", "--top_ports", type=str, help=\
            "Scan top <number> most common ports. Mutually exclusive with --ports." 
            )
    
    args = parser.parse_args()
    
    return args.target_spec, args.interface, args.ports, args.top_ports, args.sU, args.args


def main():
    # Stealth scan, OS scan, and MAC resolution require superuser priveleges
    elevate(graphical=False, show_console=False)

    target_spec, interface, ports, top_ports, sU, args= parse_args()

    STEALTH_SCAN = "-sS"
    SCAN_SERVICES = "-sV --version-intensity 2"
    SCAN_OS = "-A"
    TIMING_TEMPLATE = "-T4"
    SCRIPTS = ["banner" , "dns-service-discovery", "ssl-cert"]
    SCRIPT_ARG = "--script=" + ",".join(SCRIPTS)
    MAX_OS_TRIES = "--max-os-tries 2"

    nmap_arguments = [STEALTH_SCAN, SCAN_SERVICES, SCAN_OS, TIMING_TEMPLATE, SCRIPT_ARG, MAX_OS_TRIES]

    if interface is not None:
        nmap_arguments.append("-e " + interface)
    
    if sU or args is not None and "-sU" in args:
        nmap_arguments.append("-sU")
        print("Warning: UDP scan enabled, which may slow scan. See help for more info.")
        print("Large amount of UDP ports to scan may drastically impede performance.")

    if ports is not None:
        nmap_arguments.append("-p " + ports)
        
        if top_ports is not None:
            print("--ports specified, --top-ports ignored")
    else:
        if top_ports is not None:
            nmap_arguments.append("--top-ports " + top_ports)

    if args is not None:
        nmap_arguments.append(args)

    # Enable p0f passive scan while nmap is scanning
    with P0f_client("p0f.socket", interface) as p0f_client:
        nm = PortScanner() 

        # If no target spec specified, detect subnet automatically
        if target_spec is None:
            target_spec = get_network_parameters()
            print("Using automatic target_spec: ", target_spec)

        # Invoke nmap scanner
        print("Starting scan")
        print("Target spec: ", target_spec)
        print("nmap args:\n", " ".join(nmap_arguments))

        try:
            nm.scan(target_spec, arguments = " ".join(nmap_arguments))
        except KeyboardInterrupt as e: 
            print("nmap scan interrupted.")

        # Process hosts
        hosts = dict()

        for host in nm.all_hosts():
            try:
                hosts[host] = Host(host, nm, p0f_client)
            except Exception as e:
                print("Error parsing host ", host, " ", e)
    
        print(len(hosts), " hosts scanned with target spec: ", target_spec)

        # Create XML output
        xml = XML(hosts)

        with open("host_report.xml", "w") as out_file:
            out_file.write(xml.get_xml())
            print("Results stored to host_report.xml")


if __name__ == "__main__":
    main()
