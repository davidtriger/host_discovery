from yattag import Doc
import re


class XML():
    def __init__(self, hosts):
        self.doc, self.tag, self.text = Doc().tagtext()

        with self.tag("report"):
            for host in hosts.values():
                self.add_value(host.get_report_data())

    # Recursively add values, expanding dictionaries and lists
    def add_value(self, value):
            if isinstance(value, dict):
                for inner_key, inner_value in value.items():
                    insert_key = str(inner_key)

                    # Special characters are not allowed in tag key
                    insert_key = re.sub("\W+", "_", insert_key)

                    # Assert XML tag key rules
                    if len(insert_key) == 0 or insert_key.lower().startswith("xml") or not insert_key[0].isalpha():
                        insert_key = "_" + insert_key
                    
                    with self.tag(insert_key):
                        self.add_value(inner_value)
            elif isinstance(value, list):
                for element in value:
                    self.add_value(element)
            elif value is not None:
                # Don't print tabs and newlines
                self.text(re.sub(r"\s+", " ", str(value)))
            else:
                self.text("None")
        
    def get_xml(self):
        return self.doc.getvalue()
