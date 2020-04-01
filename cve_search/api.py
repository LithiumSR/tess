from cve_search.capec_updater import CAPECUpdater
from cve_search.cve_updater import CVEUpdater
from cve_search.driver import MongoDriver


class CVESearch:
    def __init__(self, server=None, port=None):
        self.driver = MongoDriver(server, port)

    def update(self, force_update=False):
        CAPECUpdater(driver=self.driver, force_update=force_update).update()
        CVEUpdater(driver=self.driver, force_update=force_update).update()

    def query_cve(self, *argv):
        self._connect()
        return self.driver.get_cve(*argv)

    def find_cve_by_id(self, cve_id):
        return list(self.query_cve({"_id": cve_id}))[0]

    def get_all(self):
        return self.query_cve({}, {})

    def _connect(self):
        if not self.driver.is_connected():
            self.driver.connect()

    def close(self):
        self.driver.close_connection()
