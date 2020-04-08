from enum import Enum

from sklearn.feature_selection import SelectFromModel, RFECV
from sklearn.linear_model import LinearRegression

from tess.utils import Utils


class SelectorMode(Enum):
    fromModel = 0
    RFECV = 1


class FeatureSelection:

    def __init__(self, data, mode):
        self.data = data
        self.mode = mode

    def select(self):
        schema = Utils.get_available_feature_schema(self.data)
        X = [Utils.get_element_feature(schema, event.details, event.date) for event in self.data]
        Y = [Utils.get_target_function_value(self.data, event) for event in self.data]
        if self.mode == SelectorMode.fromModel:
            selector = SelectFromModel(estimator=LinearRegression())
        else:
            selector = RFECV(estimator=LinearRegression(), step=1, cv=5)
        selector.fit(X, Y)
        features = selector.get_support()
        features[schema.index('__days_diff')] = True
        return Utils.get_filtered_schema(schema, features)
