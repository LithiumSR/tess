import os
from os.path import join

from tqdm import tqdm

from cve_search.driver import MongoDriver
from cve_search.via4_ref_updater import VIA4RefUpdater


class CrossReferenceUpdater:
    def __init__(self, server=None, port=None, driver=None):
        self.path = join(os.path.dirname(join(os.path.abspath(__file__))), 'data')
        self.driver = driver
        if self.driver is None:
            self.driver = MongoDriver(server=server, port=port)
        if not self.driver.is_connected():
            self.driver.connect()

    def update_capec(self, force_update=False, capec_updated=True, cve_updated=True):
        print('Starting crossreference updater for CAPEC entries...')
        cursor_cve = self.driver.get_cve({})
        cursor_capec = self.driver.get_capec({})
        count_cve = self.driver.get_collection('cve_details').count_documents({})
        count_capec = self.driver.get_collection('capec_details').count_documents({})
        with tqdm(desc='Stage 1', total=count_cve) as pbar:
            for item in cursor_cve:
                cwe = []
                problems = item['cve']['problemtype']['problemtype_data']
                if 'capec' in item.keys() and not capec_updated and not force_update:
                    pbar.update(1)
                    continue
                for problem in problems:
                    details = problem['description']
                    for el in details:
                        if el['value'].startswith('CWE'):
                            cwe.append(el['value'])
                cwe = list(set(cwe))
                capec_ids = []
                for weakness in cwe:
                    capec_by_weakness = self.driver.get_capec({'weaknesses': weakness})
                    capec_ids.extend([item['id'] for item in capec_by_weakness])
                capec_ids = list(set(capec_ids))
                to_add = []
                for entry in capec_ids:
                    capec = list(self.driver.get_capec({'_id': entry}))[0]
                    to_add.append({'id': entry, 'name': capec['name']})
                item['capec'] = to_add
                self.driver.write_details_cve(item)
                pbar.update(1)
        with tqdm(desc='Stage 2', total=count_capec) as pbar:
            for item in cursor_capec:
                if 'cve' in item.keys() and not cve_updated and not force_update:
                    pbar.update(1)
                    continue
                cve_by_capec = self.driver.get_cve({'capec.id': item['id']})
                ids = list(set([el['_id'] for el in cve_by_capec]))
                item['cve'] = ids
                self.driver.write_entry_capec(item)
                pbar.update(1)

    def update_via4(self, force_update=True, cve_updated=True):
        VIA4RefUpdater(driver=self.driver, force_update=force_update, cve_updated=cve_updated).update()
