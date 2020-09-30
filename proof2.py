import datetime
import functools

import dateparser
import matplotlib.pyplot as plt
import numpy as np

from cve_search.api import CVESearch
from cvsslib import calculate_vector
from cvsslib.vector import VectorError
from proof import cleanup_vector


def compare(item1, item2):
    if item1['date'] < item2['date']:
        return -1
    elif item1['date'] > item2['date']:
        return 1
    else:
        if item1['type'] == 'vendor' and item2['type'] == 'cvss':
            return -1
        elif item1['type'] == 'cvss' and item2['type'] == 'vendor':
            return 1
        elif item1['type'] == 'cvss' and item2['type'] == 'cvss' and item1['subtype'] == 'added' and item2[
            'subtype'] == 'changed':
            return -1
        elif item1['type'] == 'cvss' and item2['type'] == 'cvss' and item2['subtype'] == 'added' and item1[
            'subtype'] == 'changed':
            return 1
        else:
            return 0


def getData(start_y, end_y, nvd_cvss=True):
    search = CVESearch()
    cursor = search.get_all_cve()
    items = []

    for el in list(cursor):
        id = el['_id']
        if int(id.split('-')[1]) < start_y or int(id.split('-')[1]) > end_y:
            continue
        el = search.find_cve_by_id(id)
        if len(el['history'].keys()) == 0:
            continue
        start = datetime.datetime(day=1, month=1, year=start_y)
        end = datetime.datetime(day=31, month=12, year=end_y)
        date = datetime.datetime.strptime(el['publishedDate'], '%Y-%m-%dT%H:%MZ')
        date = date.replace(tzinfo=None)
        if start <= date <= end:
            events = []
            first_ref_found = False
            skip = False
            for key in el['history'].keys():
                if skip:
                    break
                entries = el['history'][key]
                for entry in entries:
                    if entry['type'].lower() == 'reference type' and 'vendor advisory' in entry['new'].lower():
                        if not first_ref_found:
                            events.append(
                                {'id': id, 'type': 'vendor', 'subtype': None, 'value': None, 'value_old': None,
                                 'date': (dateparser.parse(key) - date).days, })
                            first_ref_found = True
                    if 'cvss v3' in entry['type'].lower():
                        subtype = entry['action'].lower()
                        if subtype == 'removed':
                            skip = True
                            break
                        if nvd_cvss and not entry['new'].startswith('NIST') and not entry['new'].startswith('AV:'):
                            continue
                        if not nvd_cvss and (entry['new'].startswith('NIST') or entry['new'].startswith('AV:')):
                            continue
                        try:
                            value = calculate_vector(cleanup_vector(entry['new'], entry['type']))
                            value_old = None
                            if entry['old'].strip() is not '':
                                value_old = calculate_vector(cleanup_vector(entry['old'], entry['type']))

                            events.append(
                                {'id': id, 'type': 'cvss', 'subtype': subtype, 'value': value, 'value_old': value_old,
                                 'date': (dateparser.parse(key) - date).days, })
                        except VectorError:
                            skip = True
                            print("skipped", entry)

            if len(events) > 0 and not skip:
                items.append(events)

    return items


def convert_to_strings(data):
    i = 0
    words = []
    while i < len(data):
        data[i] = sorted(data[i], key=functools.cmp_to_key(compare))
        i += 1
    max_date = -1
    for el in data:
        for event in el:
            if event['date'] > max_date:
                max_date = event['date']

    for el in data:
        word = ''
        i = 0
        while i < len(el):
            event = el[i]
            if i != 0:
                diff = int((event['date'] - el[i - 1]['date']) / 1)
                app = ['-'] * diff
                app = ''.join(app)
                word = word + app

            if event['type'] == 'vendor':
                word = word + 'V'
            elif event['type'] == 'cvss' and event['subtype'] == 'added':
                word = word + 'C'
                k = 0
                skip = False
                while k < i - 1:
                    event2 = el[k]
                    if skip:
                        break
                    if event2['type'] == 'cvss' and event2['subtype'] == 'added' and event2['new'] == event['new']:
                        skip = True
                    k += 1

                if skip:
                    i += 1
                    continue

            elif event['type'] == 'cvss' and event['subtype'] == 'changed':
                if event['value'] < event['value_old']:
                    word = word + 'D'
                elif event['value'] > event['value_old']:
                    word = word + 'I'
                else:
                    word = word + 'S'

            if i == len(el) - 1:
                diff = int((max_date - event['date']) / 1)
                app = ['-'] * diff
                app = ''.join(app)
                word = word + app
            i += 1

        words.append(word)
    return words


def get_data_processed(year1, year2, only_nvd=True):
    data = getData(year1, year2, nvd_cvss=only_nvd)
    after_seven = []
    data_vendor = []
    data_first_cvss = []
    max_diff_date = -1
    for el in data:
        stop_vendor = False
        stop_first_cvss = False

        for event in el:
            if not stop_vendor and event['type'] == 'vendor' and event['date'] > 7:
                after_seven.append(el)
                data_vendor.append(event['date'])
                stop_vendor = True
            if event['date'] > max_diff_date:
                max_diff_date = event['date']
            if not stop_first_cvss and event['type'] == 'cvss' and event['subtype'] == 'changed':
                data_first_cvss.append(event['date'])
                stop_first_cvss = True

    B = plt.boxplot(data_vendor, showfliers=False)
    # plt.yticks(np.arange(0, max(first_increase) + 100, 100))
    plt.show()
    median = np.median(data_vendor)
    upper_quartile = np.percentile(data_vendor, 75)
    lower_quartile = np.percentile(data_vendor, 25)
    values = {'median': median, 'upper_quartile': upper_quartile, 'lower_quartile': lower_quartile}
    print(values)
    print([item.get_ydata() for item in B['whiskers']])
    return after_seven


def main():
    after_seven1 = get_data_processed(2016, 2019)
    words = convert_to_strings(after_seven1)
    entries = {}
    for word in words:
        new_word = word.replace("-", "")
        if new_word in entries.keys():
            entries[new_word] += 1
        else:
            entries[new_word] = 1
    print(entries)
    print("----------------------")
    after_seven2 = get_data_processed(2016, 2019, only_nvd=False)
    words2 = convert_to_strings(after_seven2)
    entries = {}
    for word in words2:
        new_word = word.replace("-", "")
        if new_word in entries.keys():
            entries[new_word] += 1
        else:
            entries[new_word] = 1
    print(entries)
    first_increase = []
    first_decrease = []
    for word in words:
        if "I" in word:
            first_increase.append(word.find('I'))
        if "D" in word:
            first_decrease.append(word.find('D'))
    print("first", first_increase)
    print("first_d", first_decrease)
    distance_cvss = []
    i = 0
    while i < len(after_seven1):
        after_seven1[i] = sorted(after_seven1[i], key=functools.cmp_to_key(compare))
        i += 1
    for el in after_seven1:
        i = 0
        while i < len(el):
            entry = el[i]
            if entry['type'] == 'cvss':
                k = i + 1
                while k < len(el):
                    entry2 = el[k]
                    print(entry2)
                    if entry2['type'] == 'cvss':
                        distance_cvss.append(entry2['date'] - entry['date'])
                        break
                    k += 1
            i += 1

    '''
    B = plt.boxplot(first_increase, showfliers=False)
    # plt.yticks(np.arange(0, max(first_increase) + 100, 100))
    plt.show()
    median = np.median(first_increase)
    upper_quartile = np.percentile(first_increase, 75)
    lower_quartile = np.percentile(first_increase, 25)
    values = {'median': median, 'upper_quartile': upper_quartile, 'lower_quartile': lower_quartile}
    print(values)
    print([item.get_ydata() for item in B['whiskers']])


    B = plt.boxplot(first_decrease, showfliers=False)
    # plt.yticks(np.arange(0, max(first_increase) + 100, 100))
    plt.show()
    median = np.median(first_decrease)
    upper_quartile = np.percentile(first_decrease, 75)
    lower_quartile = np.percentile(first_decrease, 25)
    values = {'median': median, 'upper_quartile': upper_quartile, 'lower_quartile': lower_quartile}
    print(values)
    print([item.get_ydata() for item in B['whiskers']])



    def lev_metric(x, y):
        i, j = int(x[0]), int(y[0])  # extract indices
        return levenshtein(words[i], words[j])
    X = np.arange(len(words)).reshape(-1, 1)
    clustering = DBSCAN(metric=lev_metric, eps=5).fit(X)
    X_pred = clustering.fit_predict(X)

    labels = []
    for item in clustering.labels_:
        if item not in labels:
            labels.append(item)

    print(labels)
    print(len(labels))
'''


if __name__ == "__main__":
    main()
