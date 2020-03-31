import csv

import dateparser
from RAKE import RAKE
from vulnerability import VulnerabilityEvent, Vulnerability
from pycvesearch import CVESearch


class HistoryParser:
    def __init__(self, path):
        self.path = path
        self.data = None
        self.exceptions = None

    def load(self):
        if self.data is not None:
            return self.data
        self.data = []
        self.exceptions = []
        with open('data/exceptions.csv', mode='r') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                row = [el.lower() for el in row]
                self.exceptions.append(row)
        cve = CVESearch()
        rake = RAKE.Rake("./data/stopwords.csv")
        with open(self.path, mode='r') as csv_file:
            csv_reader = csv.DictReader(csv_file, delimiter=',')
            for row in csv_reader:
                info = cve.id(row['id'])
                print(info)
                vuln_event = VulnerabilityEvent(row['id'], row['data'], row['outcome'])
                vuln_event.published = dateparser.parse(info['Published'])
                keywords = rake.run(info['summary'])
                keywords = [item[0] for item in keywords if item[1] > 1.0]
                keywords = self._transform_keywords(keywords)
                capec = [item['name'] for item in info['capec']]
                vuln_details = Vulnerability(keywords, capec, None, None, len(info['references']))
                vuln_event.vuln_details = vuln_details
                print(keywords)
                self.data.append(vuln_event)

    def _transform_keywords(self, keywords):
        ret = []
        for keyword in keywords:
            low_keyword = keyword.lower()
            to_append = None
            ignore = False
            for ex in self.exceptions:
                type_ex = ex[0]
                lcheck = ex[1].lower()
                if type_ex == 'm' and low_keyword == lcheck:
                    if len(ex) == 2:
                        ignore = True
                    else:
                        to_append = ex[2].lower()
                elif type_ex == 'c' and lcheck in low_keyword:
                    if len(ex) == 2:
                        ignore = True
                    else:
                        to_append = low_keyword.replace(lcheck, ex[2].lower())

                if ignore:
                    break
                if to_append is not None:
                    to_append = to_append.strip()
                    while '  ' in to_append:
                        to_append = to_append.replace('  ', ' ')
                    ret.append(to_append)
                    break
            if to_append is None and not ignore:
                ret.append(keyword.lower())
        return ret

HistoryParser("data/dataset.csv").load()
