from enum import Enum

import numpy as np
from sklearn.metrics import explained_variance_score, max_error, mean_absolute_error, mean_squared_error, \
    mean_squared_log_error, median_absolute_error, r2_score
from sklearn.model_selection import ShuffleSplit, KFold

from tess.model.neural_model import TessNeuralModel
from tess.model.svr_model import TessSVRModel
from tess.utils import Utils


class ValidationMethod(Enum):
    KFold = 0
    ShuffleSplit = 1


class PerformanceValidator:

    @staticmethod
    def get_perf(data, schema, n_splits=5, selection_method=ValidationMethod.ShuffleSplit, is_nn=False, epochs=100,
                 batch_size=1):
        ret = {'exp_var': 0, 'max_error': 0, 'mean_abs_error': 0, 'mean_squared_error': 0,
               'mean_squared_log_error': 0, 'median_abs_error': 0, 'r2': 0}
        X = [np.array(Utils.get_element_feature(schema, event.details, event.date)) for event in data]
        Y = [Utils.get_target_function_value(data, event) for event in data]
        X = np.array(X)
        Y = np.array(Y)

        if selection_method == ValidationMethod.KFold:
            selector = KFold(n_splits=n_splits, shuffle=True)
        else:
            selector = ShuffleSplit(n_splits=n_splits, test_size=.25, random_state=0)

        for train_index, test_index in selector.split(X):
            X_train, X_test = X[train_index.astype(int)], X[test_index.astype(int)]
            y_train, y_test = Y[train_index.astype(int)], Y[test_index.astype(int)]
            if is_nn:
                model = TessNeuralModel(schema=schema, epochs=epochs, batch_size=batch_size)
            else:
                model = TessSVRModel(schema=schema)
            model.learn(X_train, y_train)
            partial_res = PerformanceValidator.get_perf_model(model, X_test, y_test)
            ret = {k: ret.get(k, 0) + partial_res.get(k, 0) for k in ret.keys()}
        for key in ret.keys():
            ret[key] = ret[key] / 5
        return ret

    @staticmethod
    def get_perf_model(model, X_test, y_true):
        ret = {}
        y_true = y_true.astype(np.float)
        y_pred = model.predict(X_test)
        try:
            ret['exp_var'] = explained_variance_score(y_true, y_pred)
        except ValueError:
            print("exp_var error")
        try:
            ret['max_error'] = max_error(y_true, y_pred)
        except ValueError:
            print("max_error error")
        try:
            ret['mean_abs_error'] = mean_absolute_error(y_true, y_pred)
        except ValueError:
            print("mean_abs_error error")
        try:
            ret['mean_squared_error'] = mean_squared_error(y_true, y_pred)
        except ValueError:
            print("mean_squared_error error")
        try:
            ret['mean_squared_log_error'] = mean_squared_log_error(y_true, y_pred)
        except ValueError:
            print("mean_squared_log_error error")
        try:
            ret['median_abs_error'] = median_absolute_error(y_true, y_pred)
        except ValueError:
            print("median_abs_error error")
        try:
            ret['r2'] = r2_score(y_true, y_pred)
        except ValueError:
            print("r2 error")
        return ret
