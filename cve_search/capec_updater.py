import datetime
import hashlib
import os
from os.path import join
from pathlib import Path

import requests
import xmltodict

from cve_search.driver import MongoDriver


class CAPECUpdater:
    def __init__(self, server=None, port=None, driver=None, force_update=False):
        self.path = join(os.path.dirname(join(os.path.abspath(__file__))), 'data')
        self.last_year = datetime.datetime.now().year
        self.url = 'https://capec.mitre.org/data/xml/capec_v3.2.xml'
        self.driver = driver
        self.force_update = force_update
        if self.driver is None:
            self.driver = MongoDriver(server=server, port=port)
        if not self.driver.is_connected():
            self.driver.connect()
        Path(self.path).mkdir(parents=True, exist_ok=True)

    def update(self):
        print("Starting CAPEC updater...")
        xml_file = join(self.path, self.url.rsplit('/', 1)[-1])
        xml_content = requests.get(self.url).content
        xml_hash = hashlib.sha256(xml_content).hexdigest()
        try:
            if xml_hash == self.driver.get_info_capec()['hash'] and not self.force_update:
                print("CAPEC already updated. Aborting...")
                return False
        except:
            print("Can't find hash of previous CAPEC update. Updating nonetheless...")
        with open(xml_file, 'wb') as f:
            f.write(xml_content)
        self._update_db(xml_file, xml_hash)
        self._cleanup_files()
        return True

    def _update_db(self, xml_file, xml_hash):
        with open(xml_file) as f:
            data = xmltodict.parse(f.read())
            data = data['Attack_Pattern_Catalog']['Attack_Patterns']['Attack_Pattern']
            i = 0
            while i < len(data):
                prerequisites = []
                mitigations = []
                consequences = []
                related_cwe = []
                likelihood = None
                typical_severity = None
                id_capec = data[i]['@ID']
                name = data[i]['@Name']
                description = data[i]['Description']
                if 'Prerequisites' in data[i].keys():
                    prerequisites = data[i]['Prerequisites']['Prerequisite']
                    if not isinstance(prerequisites, list):
                        prerequisites = [prerequisites]
                    prerequisites = [item for item in prerequisites]
                if 'Mitigations' in data[i].keys():
                    mitigations = data[i]['Mitigations']['Mitigation']
                    if isinstance(mitigations, dict):
                        mitigations = mitigations['xhtml:p']
                if 'Likelihood_Of_Attack' in data[i].keys():
                    likelihood = data[i]['Likelihood_Of_Attack']
                if 'Typical_Severity' in data[i].keys():
                    typical_severity = data[i]['Typical_Severity']
                if 'Consequences' in data[i].keys():
                    consequences = data[i]['Consequences']['Consequence']
                    if type(consequences) == list:
                        consequences = [dict(item) for item in consequences]
                    else:
                        consequences = dict(consequences)
                if 'Related_Weaknesses' in data[i].keys():
                    related_weaknesses = data[i]['Related_Weaknesses']['Related_Weakness']
                    if isinstance(related_weaknesses, dict):
                        related_weaknesses = [related_weaknesses]
                    related_cwe = ['CWE-' + item['@CWE_ID'] for item in related_weaknesses]
                info = {'id': id_capec, 'name': name, 'description': description, 'likelihood': likelihood,
                        'typical_severity': typical_severity,
                        'prerequisites': prerequisites, 'mitigations': mitigations, 'consequences': consequences,
                        'weaknesses': related_cwe}
                self.driver.write_entry_capec(info)
                i += 1
            self.driver.write_info_capec(xml_hash)

    def _cleanup_files(self):
        os.remove(join(self.path, self.url.rsplit('/', 1)[-1]))
