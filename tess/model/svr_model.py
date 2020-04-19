from joblib import dump, load
from sklearn.decomposition import IncrementalPCA, PCA
from sklearn.svm import SVR

from tess.utils import Utils


class TessSVRModel:

    def __init__(self, data=None, schema=None, n_components=-1):
        self.data = data
        self.schema = schema
        self.model = SVR()
        self.use_reduction = n_components > 0
        if self.use_reduction:
            self.pca = PCA(n_components=n_components)

    def learn_by_data(self):
        if self.data is None or self.schema is None:
            raise ValueError("You can't fit the model without having a data and schema")
        X = [Utils.get_element_feature(self.schema, event.details, event.date) for event in self.data]
        if self.use_reduction:
            self.pca.fit(X)
            X = self.pca.transform(X)
        Y = [Utils.get_target_function_value(self.data, event) for event in self.data]
        self.model.fit(X, Y)

    def learn(self, X, Y):
        if self.use_reduction:
            self.pca.fit(X)
            X = self.pca.transform(X)
        self.model.fit(X, Y)

    def predict(self, elem):
        if self.use_reduction:
            elem = self.pca.transform(elem)
        return self.model.predict(elem)

    def get_exploitability(self, vulnerability, time):
        return vulnerability.e_score * self.model.predict([Utils.get_element_feature(self.schema, vulnerability, time)])

    def save(self, filename_model, filename_schema):
        dump(self.model, filename_model)
        with open(filename_schema, 'w') as f:
            for elem in self.schema:
                f.write(elem + '\n')

    def load(self, filename_model, filename_schema):
        self.model = load(filename_model)
        self.schema = []
        with open(filename_schema, 'r') as f:
            for line in f:
                self.schema.append(line.strip())
        return self.model, self.schema

    def get_coeff(self):
        return self.model.coef_
