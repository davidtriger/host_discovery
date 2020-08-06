from yattag import Doc


class XML():
    def __init__(self, hosts):
        self.doc, self.tag, self.text = Doc().tagtext()

        for host in hosts.values():
            self.add_host(host)

    def add_value(self, value):
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    insert_key = str(inner_key)

                    # Assert XML tag rules
                    if len(insert_key) == 0 or insert_key.lower().startswith("xml") or not insert_key[0].isalpha():
                        insert_key = "_" + insert_key

                    with self.tag(insert_key):
                        self.add_value(inner_value)
            elif isinstance(value, list):
                for element in value:
                    self.add_value(element)
            else:
                self.text(value)


    
    def add_host(self, host):
        with self.tag("device"):
            self.add_value(host.nmap_data)
        
    def get_xml(self):
        return self.doc.getvalue()
