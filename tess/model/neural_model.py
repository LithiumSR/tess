import numpy as np
from keras.layers import Dense
from keras.models import Sequential
from keras.optimizers import RMSprop
from sklearn.decomposition import IncrementalPCA

from tess.data.tess_file_format import TessFileUtils
from tess.utils import Utils


class TessNeuralModel:

    def __init__(self, data=None, schema=None, epochs=50, batch_size=1, n_components=-1):
        self.data = data
        self.schema = schema
        self.epochs = epochs
        self.batch_size = batch_size
        self.use_reduction = n_components > 0
        if self.use_reduction:
            self.pca = IncrementalPCA(n_components=n_components, batch_size=batch_size)
        if schema is not None:
            self.model = Sequential()
            if self.use_reduction:
                self.model.add(Dense(units=50, activation='relu', input_dim=n_components))
            else:
                self.model.add(Dense(units=50, activation='relu', input_dim=len(schema)))
            self.model.add(Dense(units=30, activation='relu', kernel_initializer='uniform'))
            self.model.add(Dense(units=1, activation='linear'))
            opt = RMSprop(learning_rate=0.001, rho=0.9)
            self.model.compile(loss='mse', optimizer=opt)

    def learn_by_data(self):
        if self.data is None or self.schema is None:
            raise ValueError("You can't fit the model without having a data and schema")
        steps = len(self.data) // self.batch_size
        X = [Utils.get_element_feature(self.schema, event.details, event.date) for event in self.data]
        if self.use_reduction:
            self.pca.fit(X)
            X = self.pca.transform(X)
        Y = [Utils.get_target_function_value(self.data, event) for event in self.data]
        self.model.fit_generator(generator=self._get_generator((X, Y)), epochs=self.epochs, steps_per_epoch=steps)

    def learn(self, X, Y):
        if self.model is None:
            raise ValueError("Model is not set")
        steps = len(X) // self.batch_size
        if self.use_reduction:
            self.pca.fit(X)
            X = self.pca.transform(X)
        self.model.fit_generator(generator=self._get_generator((X, Y)), epochs=self.epochs, steps_per_epoch=steps)

    def predict(self, elem):
        if self.model is None:
            raise ValueError("Model is not set")
        if self.use_reduction:
            elem = self.pca.transform(elem)
        return self.model.predict(elem)

    def get_exploitability(self, vulnerability, time):
        if self.model is None:
            raise ValueError("Model is not set")
        return vulnerability.e_score * self.model.predict([Utils.get_element_feature(self.schema, vulnerability, time)])

    def save(self, filename):
        if self.model is None or self.schema is None:
            raise ValueError("Both model and schema must be set")
        TessFileUtils.save(filename, self)

    def load(self, filename):
        TessFileUtils.load(filename, self)

    def _get_generator(self, data_gen):
        import random
        if isinstance(data_gen, tuple):
            X = data_gen[0]
            Y = data_gen[1]
        else:
            X = [np.array(Utils.get_element_feature(self.schema, event.details, event.date)) for event in data_gen]
            Y = [Utils.get_target_function_value(self.data, event) for event in data_gen]
        gen_data = list(zip(X, Y))
        random.shuffle(gen_data)
        X, Y = zip(*gen_data)
        i = 0
        while True:
            samples_X = []
            samples_Y = []
            for b in range(self.batch_size):
                if i == len(data_gen):
                    i = 0
                    gen_data = list(zip(X, Y))
                    random.shuffle(gen_data)
                    X, Y = zip(*gen_data)
                samples_X.append(X[i])
                samples_Y.append(Y[i])
                i += 1
            yield np.array(samples_X), np.array(samples_Y)
