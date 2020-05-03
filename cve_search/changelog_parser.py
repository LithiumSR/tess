import time

import dateparser
import requests as requests
from bs4 import BeautifulSoup


class CVEChangelogScraper:

    def __init__(self, max_attempts=5, delay_attempt=0):
        self.base_url = "https://nvd.nist.gov/vuln/detail/"
        self.max_tries = max_attempts
        self.delay = delay_attempt

    def get_history(self, cve_id):
        url = self.base_url + cve_id
        status_code = -1
        attempts = 0
        while status_code != 200:
            page = requests.get(url)
            status_code = page.status_code
            if attempts > self.max_tries:
                raise IOError("Can't obtain NVD page")
            if status_code != 200:
                time.sleep(self.delay)
                attempts += 1
            else:
                try:
                    ret = CVEChangelogScraper._parse_html(page.text)
                except:
                    ret = None
                return ret


    @staticmethod
    def _parse_html(html_text):
        soup = BeautifulSoup(html_text, 'html.parser')
        containers = soup.find_all('div', class_='vuln-change-history-container')
        history = {}
        for i in range(len(containers)):
            container = containers[i]
            date = dateparser.parse(
                container.find(attrs={"data-testid": "vuln-change-history-date-" + str(i)}).getText())
            table = container.find('table', attrs={"data-testid": "vuln-change-history-table"})
            if table is None:
                continue
            list_dict_entries = []
            table_body = table.find('tbody')
            entries = table_body.findChildren('tr')
            for k in range(len(entries)):
                prefix = "vuln-change-history-" + str(k) + "-"
                entry = entries[k]
                dict_entry = {'action': entry.find(attrs={"data-testid": prefix + 'action'}).getText(),
                              'type': entry.find(attrs={"data-testid": prefix + 'type'}).getText(),
                              'old': CVEChangelogScraper.cleanup_text(entry.find(attrs={"data-testid": prefix + 'old'}).getText()),
                              'new': CVEChangelogScraper.cleanup_text(entry.find(attrs={"data-testid": prefix + 'new'}).getText())}
                list_dict_entries.append(dict_entry)
            history[str(date)] = list_dict_entries
        return history

    @staticmethod
    def cleanup_text(text):
        text = text.replace('OR\r\n', '')
        return text.strip()
