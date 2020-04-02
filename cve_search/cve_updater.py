import datetime
import gzip
import hashlib
import json
import os
import shutil
from os.path import isfile, join
from pathlib import Path

import requests

from cve_search.driver import MongoDriver


class CVEUpdater:
    def __init__(self, server=None, port=None, driver=None, force_update=False):
        self.path = join(os.path.dirname(join(os.path.abspath(__file__))), 'data')
        self.last_year = datetime.datetime.now().year
        self.url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{0}.{1}'
        self.starting_year = 2002
        self.force_update = force_update
        self.driver = driver
        if self.driver is None:
            self.driver = MongoDriver(server=server, port=port)
        if not self.driver.is_connected():
            self.driver.connect()
        Path(self.path).mkdir(parents=True, exist_ok=True)

    def update(self):
        print("Starting CVE updater...")
        year = self.starting_year
        modified = False
        while year <= self.last_year:
            meta_url = self.url.format(year, 'meta')
            meta_file = join(self.path, meta_url.rsplit('/', 1)[-1])
            meta_content = requests.get(meta_url).content
            meta_hash = hashlib.sha256(meta_content).hexdigest()
            try:
                ignore = meta_hash == self.driver.get_info_cve(year)['hash']
            except:
                print("Can't find hash of previous update for year {}. Updating nonetheless...".format(year))
                ignore = False
            if ignore and not self.force_update:
                year += 1
                print("CVE Entries for year {} already updated. Skipping...".format(year))
                continue
            json_file_url = self.url.format(year, 'json.gz')
            json_gz_file = join(self.path, json_file_url.rsplit('/', 1)[-1])
            json_file = join(self.path, self.url.format(year, 'json').rsplit('/', 1)[-1])
            with open(json_gz_file, 'wb') as f:
                r = requests.get(json_file_url)
                f.write(r.content)
            with gzip.open(json_gz_file, 'rb') as f_in:
                with open(json_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    success = True
            if not success:
                print("Download failed for year {}, skipping...".format(year))
                year += 1
                continue
            modified = True
            self._update_db(json_file, year, meta_hash)
            with open(meta_file, 'wb') as f:
                f.write(meta_content)
            year += 1
        self._cleanup_files()
        return modified

    def _cleanup_files(self):
        to_delete = [f for f in os.listdir(self.path) if
                     isfile(join(self.path, f)) and f.startswith('nvdcve') and (
                             f.endswith('.json.gz') or f.endswith('.json') or f.endswith('.meta'))]
        for file in to_delete:
            os.remove(join(self.path, file))

    def _update_db(self, json_file, year, meta_hash):
        with open(json_file) as f:
            data = json.load(f)
            cve_entries = data['CVE_Items']
            info = dict(data)
            del info['CVE_Items']
            self.driver.write_info_cve(info, year, meta_hash)
            for entry in cve_entries:
                self.driver.write_details_cve(entry)
            print('CVE Entries for year {} updated successfully'.format(year))
