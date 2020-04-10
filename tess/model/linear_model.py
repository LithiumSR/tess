from joblib import dump, load
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import PolynomialFeatures
from sklearn.svm import SVR

from tess.utils import Utils


class TessLinearModel:

    def __init__(self, data=None, schema=None, degree=5):
        self.data = data
        self.schema = schema
        if len(data) > 10000:
            self.model = SVR()
        else:
            self.model = LinearRegression()
            self.poly_features = PolynomialFeatures(degree)

    def learn_by_data(self):
        if self.data is None or self.schema is None:
            raise ValueError("You can't fit the model without having a data and schema")
        schema = Utils.get_available_feature_schema(self.data)
        X = [Utils.get_element_feature(schema, event.details, event.date) for event in self.data]
        Y = [Utils.get_target_function_value(self.data, event) for event in self.data]
        if self.poly_features is not None:
            X = self.poly_features.fit_transform(X)
        self.model.fit(X, Y)

    def learn(self, X, Y):
        if self.poly_features is not None:
            X = self.poly_features.fit_transform(X)
        self.model.fit(X, Y)

    def predict(self, elem):
        return self.model.predict(self.poly_features.fit_transform(elem))

    def get_exploitability(self, vulnerability, time):
        return vulnerability.e_score * self.model.predict([Utils.get_element_feature(self.schema, vulnerability, time)])

    def save(self, filename_model, filename_schema):
        dump(self.model, filename_model)
        with open(filename_schema, 'w') as f:
            for elem in self.schema:
                f.write(elem+'\n')

    def load(self, filename_model, filename_schema):
        self.model = load(filename_model)
        self.schema = []
        with open(filename_schema, 'r') as f:
            for line in f:
                self.schema.append(line.strip())
        return self.model, self.schema

    def get_coeff(self):
        return self.model.coef_
