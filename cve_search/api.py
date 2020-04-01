from cve_search.capec_updater import CAPECUpdater
from cve_search.crossref_updater import CrossReferenceUpdater
from cve_search.cve_updater import CVEUpdater
from cve_search.driver import MongoDriver


class CVESearch:
    def __init__(self, server=None, port=None):
        self.driver = MongoDriver(server, port)

    def update(self, force_update=False):
        capec_updated = CAPECUpdater(driver=self.driver, force_update=force_update).update()
        cve_updated = CVEUpdater(driver=self.driver, force_update=force_update).update()
        cross_updater = CrossReferenceUpdater(driver=self.driver)
        cross_updater.update_capec(force_update, capec_updated, cve_updated)

    def query_cve(self, *argv):
        self._connect()
        return self.driver.get_cve(*argv)

    def find_cve_by_id(self, cve_id):
        return list(self.query_cve({"_id": cve_id}))[0]

    def get_all_cve(self):
        return self.query_cve({}, {})

    def query_capec(self, *argv):
        self._connect()
        return self.driver.get_capec(*argv)

    def find_capec_by_id(self, capec_id):
        return list(self.query_capec({"_id": capec_id}))[0]

    def get_all_capec(self):
        return self.query_capec({}, {})

    def _connect(self):
        if not self.driver.is_connected():
            self.driver.connect()

    def close(self):
        self.driver.close_connection()
c = CVESearch().update()