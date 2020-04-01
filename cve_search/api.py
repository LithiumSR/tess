from cve_search.driver import MongoDriver
from cve_search.update import Updater


class CVESearch:
    def __init__(self, server=None, port=None):
        self.driver = MongoDriver(server, port)

    def update(self):
        Updater(driver=self.driver).update()

    def query(self, *argv):
        self._connect()
        return list(self.driver.get(*argv))

    def find_by_cve(self, cve_id):
        return list(self.query({"_id": cve_id}))[0]

    def get_all(self):
        return self.query({}, {})

    def _connect(self):
        if not self.driver.is_connected():
            self.driver.connect()

    def close(self):
        self.driver.close_connection()
