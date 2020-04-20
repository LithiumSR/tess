import os
import tempfile

import keras
from joblib import dump, load


class TessFileUtils:

    @staticmethod
    def save(filename, model):
        model_tmp, schema_tmp, pca_tmp = [tempfile.NamedTemporaryFile(delete=False, prefix='tesstmp_') for x in
                                          range(3)]
        from tess.model.neural_model import TessNeuralModel
        from tess.model.svr_model import TessSVRModel
        if isinstance(model, TessNeuralModel):
            mode = 0
            model.model.save(model_tmp.name)
        elif isinstance(model, TessSVRModel):
            mode = 1
            dump(model.model, model_tmp.name)
        else:
            raise AttributeError('Invalid model class')
        dump(model.schema, schema_tmp.name)
        if model.use_reduction:
            dump(model.pca, pca_tmp.name)
        tmp_files = [model_tmp, schema_tmp, pca_tmp]
        with open(filename, 'wb') as fo:
            fo.write(int.to_bytes(mode, 8, 'little'))
            for el in tmp_files:
                fo.write(int.to_bytes(os.stat(el.name).st_size, 8, 'little'))
            for el in tmp_files:
                fi = open(el.name, 'rb')
                b = fi.read(256)
                while b:
                    fo.write(b)
                    b = fi.read(256)
                fi.close()
            if isinstance(model, TessNeuralModel):
                fo.write(int.to_bytes(model.epochs, 8, 'little'))
                fo.write(int.to_bytes(model.batch_size, 8, 'little'))

        for el in tmp_files:
            os.remove(el.name)

    @staticmethod
    def load(filename, model):
        with open(filename, 'rb') as fi:
            mode, model_len, schema_len, pca_len = [int.from_bytes(fi.read(x), 'little') for x in [8, 8, 8, 8]]
            from tess.model.neural_model import TessNeuralModel
            from tess.model.svr_model import TessSVRModel
            if (mode == 0 and not isinstance(model, TessNeuralModel)) or (
                    mode == 1 and not isinstance(model, TessSVRModel) or mode not in [0, 1]):
                raise AttributeError("Model mismatch when restoring")
            model.use_reduction = pca_len > 0
            model_tmp, schema_tmp, pca_tmp = [tempfile.NamedTemporaryFile(delete=False, prefix='tesstmp_') for x
                                              in range(3)]
            tmp_files = [(model_len, model_tmp), (schema_len, schema_tmp), (pca_len, pca_tmp)]
            for el in tmp_files:
                with open(el[1].name, 'wb') as fo:
                    written_bytes = 0
                    while written_bytes < el[0]:
                        fo.write(fi.read(1))
                        written_bytes += 1
            if isinstance(model, TessNeuralModel):
                model.epochs = int.from_bytes(fi.read(8), 'little')
                model.batch_size = int.from_bytes(fi.read(8), 'little')
                model.model = keras.models.load_model(model_tmp)
            elif mode == 1:
                model.model = load(model_tmp)
            model.schema = load(schema_tmp)
            if model.use_reduction:
                model.pca = load(pca_tmp)
            for el in tmp_files:
                os.remove(el[1].name)
