from enum import Enum

import numpy as np
from sklearn.metrics import explained_variance_score, max_error, mean_absolute_error, mean_squared_error, \
    mean_squared_log_error, median_absolute_error, r2_score
from sklearn.model_selection import ShuffleSplit, KFold

from learner import TessModel
from utils import Utils


class SelectionMethod(Enum):
    KFold = 0
    ShuffleSplit = 1


class PerformanceValidator:

    @staticmethod
    def get_perf(data, schema, n_splits=5, selection_method=SelectionMethod.ShuffleSplit):
        ret = {'exp_var': 0, 'max_error': 0, 'mean_abs_error': 0, 'mean_squared_error': 0,
               'mean_squared_log_error': 0, 'median_abs_error': 0, 'r2': 0}
        X = [Utils.get_element_feature(schema, event.details, event.date) for event in data]
        Y = [Utils.get_target_function_value(data, event) for event in data]
        X = np.array(X)
        Y = np.array(Y)

        if selection_method == SelectionMethod.KFold:
            selector = KFold(n_splits=n_splits, shuffle=True)
        else:
            selector = ShuffleSplit(n_splits=n_splits, test_size=.25, random_state=0)

        for train_index, test_index in selector.split(X):
            X_train, X_test = X[train_index.astype(int)], X[test_index.astype(int)]
            y_train, y_test = Y[train_index.astype(int)], Y[test_index.astype(int)]
            model = TessModel(X_train, schema)
            model.learn(X_train, y_train)
            partial_res = PerformanceValidator.get_perf_model(model, X_test, y_test)
            ret = {k: ret.get(k, 0) + partial_res.get(k, 0) for k in ret.keys()}
        for key in ret.keys():
            ret[key] = ret[key] / 5
        return ret

    @staticmethod
    def get_perf_model(model, X_test, y_true):
        ret = {}
        y_pred = model.predict(X_test)
        ret['exp_var'] = explained_variance_score(y_true, y_pred)
        ret['max_error'] = max_error(y_true, y_pred)
        ret['mean_abs_error'] = mean_absolute_error(y_true, y_pred)
        ret['mean_squared_error'] = mean_squared_error(y_true, y_pred)
        ret['mean_squared_log_error'] = mean_squared_log_error(y_true, y_pred)
        ret['median_abs_error'] = median_absolute_error(y_true, y_pred)
        ret['r2'] = r2_score(y_true, y_pred)
        return ret
