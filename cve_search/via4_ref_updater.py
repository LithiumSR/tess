import datetime
import hashlib
import json
import os
from os.path import join
from pathlib import Path

import requests
from tqdm import tqdm

from cve_search.driver import MongoDriver


class VIA4RefUpdater:
    def __init__(self, server=None, port=None, driver=None, force_update=False, cve_updated=True):
        self.path = join(os.path.dirname(join(os.path.abspath(__file__))), 'data')
        self.last_year = datetime.datetime.now().year
        self.url = 'https://www.cve-search.org/feeds/via4.json'
        self.driver = driver
        self.force_update = force_update
        self.cve_updated = cve_updated
        if self.driver is None:
            self.driver = MongoDriver(server=server, port=port)
        if not self.driver.is_connected():
            self.driver.connect()
        Path(self.path).mkdir(parents=True, exist_ok=True)

    def update(self):
        print('Starting VIA4 references updater...')
        json_file = join(self.path, self.url.rsplit('/', 1)[-1])
        json_content = requests.get(self.url).content
        json_hash = hashlib.sha256(json_content).hexdigest()
        with open(json_file, 'wb') as f:
            f.write(json_content)
        ignore = False
        try:
            ignore = json_hash == self.driver.get_info_via4()['hash']
        except:
            print("Can't find hash of previous update. Updating nonetheless...")
        if ignore and not self.force_update:
            return False
        self._update_db(json_file, json_hash)
        self._cleanup_files()
        return True

    def _update_db(self, json_file, json_hash):
        with open(json_file) as f:
            data = json.load(f)
            keys = data['cves'].keys()
            with tqdm(total=len(keys)) as pbar:
                for el in keys:
                    if el.startswith('VE'):
                        el = el.replace('VE', 'CVE', 1)
                    details = list(self.driver.get_cve({'_id': el}))
                    if len(details) == 0:
                        pbar.update(1)
                        continue
                    details = details[0]
                    details['via4'] = data['cves'][el]
                    self.driver.write_details_cve(details)
                    pbar.update(1)
            self.driver.write_info_via4(json_hash)

    def _cleanup_files(self):
        os.remove(join(self.path, self.url.rsplit('/', 1)[-1]))
