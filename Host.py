import requests
import json
import getmac


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

        print(self.p0f_data)

        

    def get_vendor(self):
        # nmap vendor is less reliable than macvendors.co
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
            
