import requests
import json
import getmac
import Recog


class Host():
    def __init__(self, hostname, nmap_data, p0f_client, default_match_level=Recog.MatchLevel.SPLIT_HEX):
        self.hostname = hostname
        self.nmap_data = nmap_data[hostname]
        self.p0f_data = p0f_client.get_data(hostname)

        # Get fields as requested in assignment spec
        self.hardware = dict() 
        addresses = self.nmap_data["addresses"]
        self.mac_address = None

        # MAC address
        if "mac" in addresses and len(addresses["mac"]) > 0:
            self.mac_address = addresses["mac"]

        # IP Address
        if "ipv4" in addresses:
            # IPv4
            self.ip_address = addresses["ipv4"]

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(ip=self.ip_address)
        elif "ipv6" in addresses:
            # IPv6
            self.ip_address = addresses["ipv6"]

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(ip6=self.ip_address)
        else:
            # Use hostname
            self.ip_address = hostname 

            if self.mac_address is None:
                self.mac_address = getmac.get_mac_address(hostname=self.ip_address)
       
        # Vendor
        self.vendor = self.get_vendor() 

        # Hostname
        if "hostnames" in self.nmap_data and len(self.nmap_data["hostnames"]) > 0:
            self.hostname_list = self.nmap_data["hostnames"]
        
        # State 
        if "status" in self.nmap_data and "state" in self.nmap_data["status"]:
            status = self.nmap_data["status"]
            self.state = status["state"]
            
            if "reason" in status:
                self.state += " (" + status["reason"] + ")"

        # Process services
        self.tcp_services = dict()
        if "tcp" in self.nmap_data:
            # TCP Services
            for port in sorted(self.nmap_data["tcp"].keys()):
                # Ignore empty fields
                self.tcp_services[port] = { key: value for key, value in self.nmap_data["tcp"][port].items() if value is not None and value != "" }
                match = None

                # Try to match banners grabbed 
                if "script" in self.tcp_services[port]:
                    # HTTPS
                    if port == 443:
                        if "ssl-cert" in self.tcp_services[port]["script"]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["ssl-cert"], "x509_subjects", Recog.MatchLevel.SPLIT_NON_ALPHABETIC)

                            if match is None:
                                match = Recog.match_nmap(self.tcp_services[port]["script"]["ssl-cert"], "x509_issuers", Recog.MatchLevel.SPLIT_NON_ALPHABETIC)

                    if "banner" in self.tcp_services[port]["script"]:
                        # FTP
                        if port in [20, 21]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "ftp_banners", default_match_level)

                        # SSH
                        if port == 22:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "ssh_banners", default_match_level)

                        # Telnet
                        if port == 23:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "telnet_banners", default_match_level)

                        # SMTP
                        if port in [25, 465, 587, 2525]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "smtp_banners", default_match_level)

                        # HTTP
                        if port in [80, 8000, 8008, 8080, 8888]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "html_title", default_match_level)

                            # Try match server string if title did not yield results
                            if match is None:
                                match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "http_servers", default_match_level)
                        
                        # POP3
                        if port in [110, 995]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "pop_banners", default_match_level)

                        # NNTP
                        if port == 119:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "nntp_banners", default_match_level)

                        # IMAP
                        if port in [143, 993]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "imap_banners", default_match_level)

                        # SMB TCP
                        if port in [137, 138, 139, 445]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "smb_native_os", default_match_level)

                        # MySQL TCP
                        if port == 3306: 
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "mysql_banners", default_match_level)
                            
                        # SIP TCP
                        if port in [5060, 5061]:
                            match = Recog.match_nmap(self.tcp_services[port]["script"]["banner"], "sip_banners", default_match_level)

                    if "dns_service_discovery" in self.tcp_services[port]["script"]:
                        # MDNS TCP 
                        if port == 5353: 
                            match = Recog.match_nmap(
                                    self.tcp_services[port]["script"]["dns_service_discovery"],
                                    "mdns_device-info_txt",
                                    Recog.MatchLevel.SPLIT_NON_ALPHABETIC
                                    )

                if match is not None:
                    self.tcp_services[port]["recog_match"] = match

                    # Detect hardware
                    if "os.device" in match:
                        self.hardware["tcp_" + str(port)] = match["os.device"]
                    elif "hw.device" in match:
                        self.hardware["tcp_" + str(port)] = match["hw.device"]

        self.udp_services = dict()
        if "udp" in self.nmap_data:
            # UDP Services
            for port in sorted(self.nmap_data["udp"].keys()):
                # Ignore empty fields
                self.udp_services[port] = { key: value for key, value in self.nmap_data["udp"][port].items() if value is not None and value != "" }
                match = None

                # Try to match banners grabbed 
                if "script" in self.udp_services[port]:
                    if "banner" in self.udp_services[port]["script"]:
                        # NTP
                        if port == 123:
                            match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "ntp_banners", default_match_level)

                        # SMB UDP 
                        if port in [137, 138, 139, 445]:
                            match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "smb_native_os", default_match_level)

                        # MySQL UDP 
                        if port == 3306: 
                            match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "mysql_banners", default_match_level)

                        #SIP UDP
                        if port in [5060, 5061]:
                            match = Recog.match_nmap(self.udp_services[port]["script"]["banner"], "sip_banners", default_match_level)
                        
                    if "dns_service_discovery" in self.udp_services[port]["script"]:
                        # MDNS UDP 
                        if port == 5353: 
                            match = Recog.match_nmap(self.udp_services[port]["script"]["dns_service_discovery"], "mdns_device-info_txt", default_match_level)

                if match is not None:
                    self.udp_services[port]["recog_match"] = match

                    # Detect hardware
                    if "os.device" in match:
                        self.hardware["udp_" + str(port)] = match["os.device"]
                    elif "hw.device" in match:
                        self.hardware["udp_" + str(port)] = match["hw.device"]

        self.operating_system = dict() 

        # OS Detection
        if "osmatch" in self.nmap_data:
            # Nmap
            osmatch = self.nmap_data["osmatch"]
            
            if len(osmatch) > 0:
                # Assume the first suggestion is correct
                nmap_os = osmatch[0]["name"]
                self.operating_system["Nmap match"] = nmap_os
                match = Recog.match_nmap(nmap_os, "operating_system", Recog.MatchLevel.SPLIT_NON_ALPHABETIC)
                
                if match is not None:
                    self.operating_system["Recog match"] = match
                    
                    # Detect hardware
                    if "os.device" in match:
                        self.hardware["OS match"] = match["os.device"]
                    elif "hw.device" in match:
                        self.hardware["OS match"] = match["hw.device"]
        
        # Use P0f results to improve detection
        try:
            if self.p0f_data is not None:
                # P0f
                # Detect OS
                p0f_os = self.p0f_data["os_name"].replace(b"\x00", b"").decode("ascii") + " " + self.p0f_data["os_flavor"].replace(b"\x00", b"").decode("ascii")
                
                if len(p0f_os) > 1:
                    self.operating_system["P0f match"] = p0f_os
                
                    if "Recog match" not in self.operating_system or self.operating_system["Recog match"] is None:
                        self.operating_system["Recog match"] = Recog.match_nmap(p0f_os, "operating_system", Recog.MatchLevel.SPLIT_NON_ALPHABETIC)

                # Detect HTTP
                p0f_http = self.p0f_data["http_name"].replace(b"\x00", b"").decode("ascii") + " " + self.p0f_data["http_flavor"].replace(b"\x00", b"").decode("ascii")

                if len(p0f_http) > 1:
                    match = Recog.match_nmap(p0f_http, "html_title", default_match_level)

                    # Try match server string if title did not yield results
                    if match is None:
                        match = Recog.match_nmap(p0f_http, "http_servers", default_match_level)

                    if match is not None:
                        self.tcp_services["P0f HTTP"] = match

                        # Detect hardware
                        if "os.device" in match:
                            self.hardware["P0f HTTP mmatch"] = match["os.device"]
                        elif "hw.device" in match:
                            self.hardware["P0f HTTP match"] = match["hw.device"]
        except Exception as e:
            print("Error processing p0f results for ", host, ", omitting. ", e)

        self.hardware["String match guess"] = \
        find_pattern(
            self.nmap_data, 
            [
                "Printer", "Phone", "Fax", "Firewall", "Bridge", "Router", "Switch", "Gateway", "Hub",
                "Modem", "Macbook", "Ipad", "Alexa", "VPN", "Laptop", "MBP", "Scanner", "Server", "IPS",
                "IDS", "KVM", "Media", "TV", "Tablet", "Android", "iOS", "VoIP", "Camera", "Cam", "PC",
                "Computer", "Car", "Speaker", "Headphone", "Streamer", "Huawei", "Xiaomi", "Mi", "Galaxy",
                "Vivo", "Samsung", "Watch", "Apple", "Nokia", "Motorola", "LG", "Playstation", "Sony",
                "Xbox", "Amazon", "HTC", "VMware", "Virtual", "HP", "Cisco", "Checkpoint", "Netgear"
            ]
        )


    def get_report_data(self):
        hostname = self.hostname.strip().replace(" ", "_")

        report = {
                    self.hostname : {
                        "Host" : self.hostname,
                        "Hostnames" : self.hostname_list,
                        "IP" : self.ip_address,
                        "State" : self.state,
                        "MAC" : self.mac_address,
                        "Vendor" : self.vendor,
                        "Hardware" : self.hardware,
                        "Operating System" : self.operating_system,
                        "Services" : { 
                            "TCP" : self.tcp_services,
                            "UDP" : self.udp_services
                        },
                        "Nmap data" : self.nmap_data,
                        "P0f data" : self.p0f_data
                    }
                }

        return report
        
    def get_vendor(self):
        if self.mac_address is None:
            return ""

        try:
            # macvendors.co is more reliable than nmap vendor
            macvendor_url = "http://macvendors.co/api/" + self.mac_address
            response = requests.get(macvendor_url).json()
            
            if "error" in response["result"]: 
                raise Exception("No vendor found")
            else:
                return response
        except:
            # macvendors failed, use nmap vendor
            if "vendor" in self.nmap_data:
                return self.nmap_data["vendor"]
            else:
                return "Unknown"
         

# Find a pattern from a list of given pattern in an object
def find_pattern(obj, pattern_list):
    try:
        if isinstance(obj, dict):
            for key, value in obj.items():
                pattern = find_pattern(value, pattern_list) 

                if pattern != "Unidentified":
                    return pattern
        elif isinstance(obj, list):
            for element in obj:
                pattern = find_pattern(element, pattern_list) 

                if pattern != "Unidentified":
                    return pattern
        else:
            for pattern in pattern_list:
                if pattern.lower() in str(obj).lower():
                    return pattern + " - " + str(obj)

    except Exception as e:
        # Ignore errors as this is only for enrichment
        pass

    return "Unidentified"
    
