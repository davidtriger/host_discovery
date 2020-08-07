import requests
import json
import getmac
import Recog


class Host():
    def __init__(self, hostname, nmap_data, p0f_client):
        self.hostname = hostname
        self.nmap_data = nmap_data[hostname]
        self.p0f_data = p0f_client.get_data(hostname)

        # Get fields as requested in assignment spec
        addresses = self.nmap_data["addresses"]

        self.mac_address = None

        # MAC address
        if "mac" in addresses.keys() and len(addresses["mac"]) > 0:
            self.mac_address = addresses["mac"]

        # IP Address
        if "ipv4" in addresses.keys():
            # IPv4
            self.ip_address = addresses["ipv4"]

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(ip=self.ip_address)
        elif "ipv6" in addresses.keys():
            # IPv6
            self.ip_address = addresses["ipv6"]

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(ip6=self.ip_address)
        else:
            self.ip_address = hostname 

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(hostname=self.ip_address)
       
        # Vendor
        self.vendor = self.get_vendor() 

        # State 
        status = self.nmap_data["status"]
        self.state = status["state"]
        
        if "reason" in status.keys():
            self.state += " (" + status["reason"] + ")"


        # Process services
        self.tcp_services = dict()
        if "tcp" in self.nmap_data.keys():
            # TCP Services
            for port in sorted(self.nmap_data["tcp"].keys()):
                # Ignore empty fields
                self.tcp_services[port] = { key: value for key, value in self.nmap_data["tcp"][port].items() if value is not None and value != "" }

                # Try to match banners grabbed 
                if "script" in self.tcp_services[port] and "banner" in self.tcp_services[port]["script"]:
                    match = None

                    # FTP
                    if port in [20, 21]:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "ftp_banners", Recog.MatchLevel.SPLIT_HEX)

                    # SSH
                    if port == 22:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "ssh_banners", Recog.MatchLevel.SPLIT_HEX)

                    # Telnet
                    if port == 23:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "telnet_banners", Recog.MatchLevel.SPLIT_HEX)

                    # SMTP
                    if port in [25, 465, 587, 2525]:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "smtp_banners", Recog.MatchLevel.SPLIT_HEX)

                    # HTTP
                    if port in [80, 443, 8000, 8008, 8080, 8888]:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "html_title", Recog.MatchLevel.SPLIT_HEX)

                    # POP3
                    if port in [110, 995]:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "pop_banners", Recog.MatchLevel.SPLIT_HEX)

                    # NNTP
                    if port == 119:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "nntp_banners", Recog.MatchLevel.SPLIT_HEX)

                    # IMAP
                    if port in [143, 993]:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "imap_banners", Recog.MatchLevel.SPLIT_HEX)

                    # MySQL TCP
                    if port == 3306: 
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "mysql_banners", Recog.MatchLevel.SPLIT_HEX)
                        
                    # SIP TCP
                    if port in [5060, 5061]:
                        match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "sip_banners", Recog.MatchLevel.SPLIT_HEX)

                    if match is not None:
                        self.tcp_servies[port]["recog_match"] = match

                                                        
        self.udp_services = dict()
        if "udp" in self.nmap_data.keys():
            # UDP Services
            for port in sorted(self.nmap_data["udp"].keys()):
                # Ignore empty fields
                self.udp_services[port] = { key: value for key, value in self.nmap_data["udp"][port].items() if value is not None and value != "" }

                # Try to match banners grabbed 
                if "script" in self.udp_services[port] and "banner" in self.udp_services[port]["script"]:
                    match = None

                    # NTP
                    if port == 123:
                        match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "ntp_banners", Recog.MatchLevel.SPLIT_HEX)

                    # MySQL UDP 
                    if port == 3306: 
                        match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "mysql_banners", Recog.MatchLevel.SPLIT_HEX)

                    #SIP UDP
                    if port in [5060, 5061]:
                        match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "sip_banners", Recog.MatchLevel.SPLIT_HEX)

                    if match is not None:
                        self.udp_servies[port]["recog_match"] = match

    def get_report_data(self):
        report = {
                    "Host" : self.hostname,
                    "IP" : self.ip_address,
                    "State" : self.state,
                    "MAC" : self.mac_address,
                    "Vendor" : self.vendor,
                    "Services" : { 
                        "TCP" : self.tcp_services,
                        "UDP" : self.udp_services
                        },
                    "Nmap data" : self.nmap_data,
                    "P0f data" : self.p0f_data
                }

        return report
        
    def get_vendor(self):
        if self.mac_address is None:
            return ""

        try:
            # macvendors.co is more reliable than nmap vendor
            macvendor_url = "http://macvendors.co/api/" + self.mac_address
            response = requests.get(macvendor_url).json()
            
            if "error" in response["result"].keys(): 
                raise Exception("No vendor found")
            else:
                return response
        except:
            # macvendors failed, use nmap vendor
            return self.nmap_data["vendor"]
         
