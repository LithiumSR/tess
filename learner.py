from enum import Enum

from joblib import dump, load
from sklearn.feature_selection import SelectFromModel, RFECV
from sklearn.linear_model import LinearRegression

from utils import Utils


class SelectorMode(Enum):
    fromModel = 0
    RFECV = 1


class FeatureSelection:

    def __init__(self, data, mode):
        self.data = data
        self.mode = mode

    def select(self):
        schema = Utils.get_available_feature_schema(self.data)
        X = [Utils.get_element_feature(schema, item) for item in self.data]
        Y = [Utils.get_target_function_value(self.data, item) for item in self.data]
        if self.mode == SelectorMode.fromModel:
            selector = SelectFromModel(estimator=LinearRegression())
        else:
            selector = RFECV(estimator=LinearRegression(), step=1, cv=5)
        selector.fit(X, Y)
        features = selector.get_support()
        features[schema.index('__days_diff')] = True
        return Utils.get_filtered_schema(schema, features)


class LinearModel:

    def __init__(self, data=None, schema=None):
        self.data = data
        self.schema = schema
        self.model = LinearRegression()

    def learn_by_data(self):
        if self.data is None or self.schema is None:
            raise ValueError("You can't fit the model without having a data and schema")
        schema = Utils.get_available_feature_schema(self.data)
        X = [Utils.get_element_feature(schema, item) for item in self.data]
        Y = [Utils.get_target_function_value(self.data, item) for item in self.data]
        self.model.fit(X, Y)

    def learn(self, X, Y):
        self.model.fit(X, Y)

    def predict(self, input):
        return self.model.predict(input)

    def save(self, filename_model, filename_schema):
        dump(self.model, filename_model)
        dump(self.schema, filename_schema)

    def load(self, filename_model, filename_schema):
        self.model = load(filename_model)
        self.schema = load(filename_schema)
        return self.model, self.schema
