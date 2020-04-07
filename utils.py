class Utils:

    @staticmethod
    def get_available_feature_schema(data):
        capec_entries = []
        keywords_entries = []
        for el in data:
            capec_entries.extend([item[0].lower() for item in el.details.capec])
            keywords_entries.extend([item.lower() for item in el.details.keywords])
        return list(set(keywords_entries)) + list(set(capec_entries)) + ['__cvss_expl', '__ref_number', '__days_diff']

    @staticmethod
    def get_element_feature(schema, el):
        features = [0] * len(schema)
        for feature in (el.details.keywords + [item[0] for item in el.details.capec]):
            try:
                index = schema.index(feature.lower())
                features[index] = 1
            except ValueError:
                pass
        features[schema.index('__days_diff')] = (el.date - el.details.published_date.replace(tzinfo=None)).days
        features[schema.index('__ref_number')] = el.details.references_number
        features[schema.index('__cvss_expl')] = el.details.e_score
        return features

    @staticmethod
    def get_target_function_value(data, el):
        valid_events = []
        for item in data:
            if el.id != item.id:
                continue
            diff = (el.date - item.date).days
            if 0 <= diff <= 31 and item != el:
                valid_events.append(item)
        pos = len([item.outcome for item in valid_events if item.outcome == True])
        if len(valid_events) == 0:
            return el.details.e_score
        return el.details.e_score * (pos / (len(valid_events)))

    @staticmethod
    def get_filtered_schema(schema, filter):
        ret = []
        for i in range(len(schema)):
            if filter[i]:
                ret.append(schema[i])
        return ret


"""
    @staticmethod
    def batch(iterable, size):
        it = iter(iterable)
        while item := list(itertools.islice(it, size)):
            yield item
"""
