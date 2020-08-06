class Host():
    def __init__(self, hostname, nmap_data, p0f_client):
        self.hostname = hostname
        self.nmap_data = nmap_data[hostname]
        self.p0f_data = p0f_client.get_data(hostname)

