from cvss_search.driver import MongoDriver


class CVSSSearch:
    def __init__(self, server=None, port=None):
        self.driver = MongoDriver(server, port)

    def find_by_cve(self):
        return None

    def search(self, filter):
        return None
