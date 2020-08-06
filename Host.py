import requests
import json
import getmac
import Recog
import re


class Host():
    def __init__(self, hostname, nmap_data, p0f_client):
        self.hostname = hostname
        self.nmap_data = nmap_data[hostname]
        self.p0f_data = p0f_client.get_data(hostname)

        # Get fields as requested in assignment spec
        addresses = self.nmap_data["addresses"]

        self.mac_address = None

        if "mac" in addresses.keys() and len(addresses["mac"]) > 0:
            self.mac_address = addresses["mac"]

        if "ipv4" in addresses.keys():
            self.ip_address = addresses["ipv4"]

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(ip=self.ip_address)
        elif "ipv6" in addresses.keys():
            self.ip_address = addresses["ipv6"]

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(ip6=self.ip_address)
        else:
            self.ip_address = hostname 

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(hostname=self.ip_address)
       
        self.vendor = None
        self.get_vendor()

        status = self.nmap_data["status"]
        self.state = status["state"]
        
        if "reason" in status.keys():
            self.state += " (" + status["reason"] + ")"


        # Process services
        self.tcp_services = dict()
        if "tcp" in self.nmap_data.keys():
            print("tcp")
            for port in sorted(self.nmap_data["tcp"].keys()):
                # Ignore empty fields
                self.tcp_services[port] = {k: v for k, v in self.nmap_data["tcp"][port].items() if v is not None and v != ""}
                print(port, " ", self.tcp_services[port])

                if "script" in self.tcp_services[port]:
                    if port == 22:
                        banner = self.tcp_services[port]["script"]["banner"]
                        for word in re.split(r"\\x\w\w+|\n", banner):
                            if len(word) > 2:
                                match = Recog.match(word, "ssh_banners")
                                """
                                if match.startswith("FAIL:"):
                                    for part_word in re.split(r"\W+", word):
                                        if len(part_word) > 2 and not part_word.isdigit():
                                            match = Recog.match(part_word, "ssh_banners")
                                            print(match)
                                else:
                                    print(match)
                                """

        self.udp_services = dict()
        if "udp" in self.nmap_data.keys():
            print("udp")
            for port in sorted(self.nmap_data["udp"].keys()):
                # Ignore empty fields
                self.udp_services[port] = {k: v for k, v in self.nmap_data["udp"][port].items() if v is not None and v != ""}
                print(port, " ", self.udp_services[port])

        print(self.p0f_data)

        

    def get_vendor(self):
        # macvendors.co is more reliable than nmap vendor
        MACVENDOR_URL = "http://macvendors.co/api/" + self.mac_address

        try:
            response = requests.get(MACVENDOR_URL).json()
            
            if "error" in response["result"].keys(): 
                raise Exception("No vendor found")
            else:
                self.vendor = response
        except:
            # macvendors failed, use nmap vendor
            self.vendor = self.nmap_data["vendor"]
            
