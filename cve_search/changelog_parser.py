import time

import dateparser
import requests as requests
from bs4 import BeautifulSoup


class CVEChangelogScraper:

    def __init__(self, max_attempts=5, delay_attempt=10, expand=False):
        self.base_url = "https://nvd.nist.gov/vuln/detail/"
        self.domain = "https://nvd.nist.gov"
        self.max_tries = max_attempts
        self.delay = delay_attempt
        self.expand = expand

    def get_history(self, cve_id):
        url = self.base_url + cve_id
        return self._handle_history_url(url, expanded=False)

    def _handle_history_url(self, url, expanded=False):
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
                if expanded:
                    ret = self._parse_expanded_html(page.text)
                else:
                    ret = self._parse_html(page.text)
                return ret

    def _parse_html(self, html_text):
        soup = BeautifulSoup(html_text, 'html.parser')
        containers = soup.find_all('div', class_='vuln-change-history-container')
        history = {}
        if len(containers) == 0:
            return history
        for i in range(len(containers)):
            container = containers[i]
            date = dateparser.parse(
                container.find(attrs={"data-testid": "vuln-change-history-date-" + str(i)}).getText())
            table = container.find('table', attrs={"data-testid": "vuln-change-history-table"})
            if table is None:
                continue
            list_dict_entries = []
            entries = table.find('tbody').findChildren('tr')
            for k in range(len(entries)):
                prefix = "vuln-change-history-" + str(k) + "-"
                entry = entries[k]
                old = entry.find(attrs={"data-testid": prefix + 'old'})
                new = entry.find(attrs={"data-testid": prefix + 'new'})
                exp_link = None
                if new.find(attrs={"data-testid": prefix + 'showing'}) is not None:
                    exp_link = new.find('a')['href']
                    new_list = new.getText().split('View Entire Change Record')
                    if len(new_list) > 1:
                        new_list.pop(0)
                        new = ''.join(new_list).strip()
                if old.find(attrs={"data-testid": prefix + 'showing'}) is not None:
                    exp_link = old.find('a')['href']
                    old_list = old.getText().split('View Entire Change Record')
                    if len(old_list) > 1:
                        old_list.pop(0)
                        old = ''.join(old_list).strip()
                if self.expand and exp_link is not None:
                    exp_link = self.domain + exp_link
                    list_dict_entries = self._handle_history_url(exp_link, expanded=True)
                    break

                if not isinstance(old, str):
                    old = old.getText().strip()
                if not isinstance(new, str):
                    new = new.getText().strip()

                dict_entry = {'action': entry.find(attrs={"data-testid": prefix + 'action'}).getText(),
                              'type': entry.find(attrs={"data-testid": prefix + 'type'}).getText(),
                              'old': old,
                              'new': new}
                list_dict_entries.append(dict_entry)
            history[str(date)] = list_dict_entries
        return history

    def _parse_expanded_html(self, html_text):
        soup = BeautifulSoup(html_text, 'html.parser')
        container = soup.find(id='vulnChangeHistoryShown')
        entries = container.find('tbody').findChildren('tr')
        list_dict_entries = []
        for i in range(len(entries)):
            entry = entries[i]
            action, type_change, old, new = [x.getText().strip() for x in entry.findChildren('td')]
            list_dict_entries.append({'action': action,
                                      'type': type_change,
                                      'old': old,
                                      'new': new})
        return list_dict_entries
