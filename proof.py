import datetime

import dateparser
from cvss import CVSS3, CVSS2
from cvsslib import cvss3, calculate_vector
from cve_search.api import CVESearch
from tess.model.feature_selection import FeatureSelection
from tess.parser import HistoryParser
from tess.utils import Utils
from tess.validator import PerformanceValidator, ValidationMethod


def cleanup_vector(vector, cvss_type):
    vector = vector.strip().replace("(", "")
    vector = vector.replace(")", "").strip()
    vector = vector.split(" ")
    for el in vector:
        if el.startswith('AV:'):
            vector = el
            break
    if "v3.1" in cvss_type.lower():
        return 'CVSS:3.1/' + vector
    elif "v3" in cvss_type.lower():
        return 'CVSS:3.0/' + vector
    else:
        return vector


def makeDataset(case):
    search = CVESearch()
    cursor = search.get_all_cve()
    items = []
    all_items = []
    matched = 0
    start_y = 2016
    end_y = 2019
    microsoft = 0

    for el in list(cursor):
        target = None
        id = el['_id']
        is_microsoft = False
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
            valid = False
            if case == 'ref':
                vendor_advisory = []
                for key in el['history'].keys():
                    entries = el['history'][key]
                    for entry in entries:
                        if entry['type'].lower() == 'reference type' and 'vendor advisory' in entry['new'].lower():
                            vendor_advisory.append(dateparser.parse(key))

                min_valid_adv = None
                min_adv = None
                for adv in vendor_advisory:
                    if min_valid_adv is None and (adv - date).days > 7:
                        min_valid_adv = adv
                    if min_valid_adv is not None and adv < min_valid_adv and (adv - date).days > 7:
                        min_valid_adv = adv

                for adv in vendor_advisory:
                    if min_adv is None and (adv - date).days <= 7:
                        min_adv = adv
                    if min_adv is not None and adv < min_adv and (adv - date).days <= 7:
                        min_adv = adv

                valid = min_valid_adv is not None and min_adv is None
                if min_valid_adv is not None:
                    target = (min_valid_adv - date).days

            elif 'cvss' in case:
                cvss = []
                if 'v3' in case:
                    cvss_type = 'cvss v3'
                else:
                    cvss_type = 'cvss v2'

                for key in el['history'].keys():
                    entries = el['history'][key]
                    for entry in entries:
                        if entry['action'].lower() == 'changed' and cvss_type in entry['type'].lower():
                            if 'v3' in case:
                                score_old = None
                                score_new = calculate_vector(cleanup_vector(entry['new'], entry['type']))[1]
                                if entry['old'] != '':
                                    score_old = calculate_vector(cleanup_vector(entry['old'], entry['type']))[1]
                            else:
                                print("no")
                                score_old = None
                                score_new = CVSS2(cleanup_vector(entry['new'], entry['type'])).scores()[1]
                                if entry['old'] != '':
                                    score_old = CVSS2(cleanup_vector(entry['old'], entry['type'])).scores()[1]
                            cvss.append([dateparser.parse(key), score_old, score_new])
                max_score = None
                min_score = None
                for score in cvss:
                    if max_score is None:
                        max_score = score
                    elif score[0] > max_score[0]:
                        max_score = score
                for score in cvss:
                    if min_score is None:
                        min_score = score
                    elif score[0] < min_score[0]:
                        min_score = score
                if max_score is None or min_score is None:
                    valid = False
                else:

                    max_score = max_score[2]
                    if min_score[1] == '':
                        min_score = min_score[2]
                    else:
                        min_score = min_score[1]
                    if min_score is not None and max_score is not None:
                        target = min_score - max_score
                        valid = target <= 0
                if 'date' in case:
                    min_valid_cvss = None
                    min_cvss = None
                    for score in cvss:
                        if min_valid_cvss is None and (score[0] - date).days > 7:
                            min_valid_cvss = score[0]
                        if min_valid_cvss is not None and score[0] < min_valid_cvss and (score[0] - date).days > 7:
                            min_valid_cvss = score[0]

                    for score in cvss:
                        if min_cvss is None and (score[0] - date).days <= 7:
                            min_cvss = score[0]
                        if min_cvss is not None and score[0] < min_cvss and (score[0] - date).days <= 7:
                            min_cvss = score[0]
                    valid = min_valid_cvss is not None and min_cvss is None and valid
                    if min_valid_cvss is not None:
                        target = (min_valid_cvss - date).days

            if valid:
                matched += 1
                for node in el['configurations']['nodes']:
                    if 'cpe_match' not in node.keys():
                        continue
                    for conf in node['cpe_match']:
                        if 'microsoft' in conf['cpe23Uri'].lower():
                            is_microsoft = True
                            microsoft += 1
                            break
                    if is_microsoft:
                        break
                items.append((el['_id'], target))
            all_items.append((el['_id'], target))

    print(len(all_items))
    print(len(items))
    print(microsoft)
    with open(case + '.csv', "w") as fout:
        fout.write('id,data,outcome,target\n')
        for el in items:
            fout.write(el[0] + ',,,' + str(el[1]))
            fout.write('\n')


def test(case):
    parser = HistoryParser(case + '.csv', skip_keywords=False, skip_capec=False, skip_cwe=False)
    parser.load()
    schema = Utils.get_available_feature_schema(parser.data, force_base_entries=False)
    print("o_schema: " + str(len(schema)))
    print("schema: " + str(len(schema)))
    print("nitems: " + str(len(parser.data)))
    print(PerformanceValidator.get_perf(parser.data, schema, selection_method=ValidationMethod.ShuffleSplit, n_splits=3,
                                        is_nn=False))


if __name__ == "__main__":
    makeDataset('cvss v3')
    test('cvss v3')
