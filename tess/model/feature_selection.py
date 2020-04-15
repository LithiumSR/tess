from enum import Enum

import lightgbm as lgb

from tess.utils import Utils


class SelectorMode(Enum):
    fromModel = 0
    RFECV = 1


class FeatureSelection:

    def __init__(self, data, mode, threshold=1):
        self.data = data
        self.mode = mode
        self.threshold = threshold

    def select(self):
        schema = Utils.get_available_feature_schema(self.data)
        X = [Utils.get_element_feature(schema, event.details, event.date) for event in self.data]
        Y = [Utils.get_target_function_value(self.data, event) for event in self.data]
        gbm = lgb.LGBMRegressor(boosting_type='gbdt', num_leaves=31, max_depth=-1, learning_rate=0.1,
                                n_estimators=100, objective='regression')
        gbm.fit(X, Y)
        features = gbm.feature_importances_
        for i in range(len(features)):
            if features[i] >= self.threshold:
                features[i] = True
            else:
                features[i] = False

        features[schema.index('__days_diff')] = True
        features[schema.index('__ref_number')] = True
        features[schema.index('__cvss_expl')] = True
        return Utils.get_filtered_schema(schema, features)
