import os
from os.path import join

from cve_search.driver import MongoDriver
from tqdm import tqdm

class CrossReferenceUpdater:
    def __init__(self, server=None, port=None, driver=None):
        self.path = join(os.path.dirname(join(os.path.abspath(__file__))), 'data')
        self.url = 'https://capec.mitre.org/data/xml/capec_v3.2.xml'
        self.driver = driver
        if self.driver is None:
            self.driver = MongoDriver(server=server, port=port)
        if not self.driver.is_connected():
            self.driver.connect()

    def update_capec(self, force_update = False, skip_existing = True):
        print('Updating CAPEC cross references')
        cursor_cve = self.driver.get_cve({})
        count = self.driver.get_collection('cve_details').count_documents({})
        with tqdm(total=count) as pbar:
            for item in cursor_cve:
                cwe = []
                problems = item['cve']['problemtype']['problemtype_data']
                if 'capec' in item.keys() and skip_existing and not force_update:
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
                    cursor_capec = self.driver.get_capec({ 'weaknesses':  weakness })
                    capec_ids.extend([item['id'] for item in cursor_capec])
                capec_ids = list(set(capec_ids))
                to_add = []
                for entry in capec_ids:
                    capec = list(self.driver.get_capec({'_id': entry}))[0]
                    to_add.append({'id': entry, 'name': capec['name']})
                item['capec'] = to_add
                self.driver.write_details_cve(item)
                pbar.update(1)

