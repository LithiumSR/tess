import argparse
import sys
from os.path import abspath

from tess.model.feature_selection import FeatureSelection
from tess.model.svr_model import TessSVRModel
from tess.model.neural_model import TessNeuralModel
from tess.parser import HistoryParser
from tess.validator import PerformanceValidator, ValidationMethod


def main():
    if len(sys.argv) < 2 or (sys.argv[1] != 'evaluate' and sys.argv[1] != 'learn'):
        usage()
        sys.exit(1)
    mode = sys.argv[1]
    sys.argv.remove(mode)
    parser = getparser(mode)
    args = parser.parse_args()
    if mode == 'evaluate':
        if args.cm.lower() == 'shuffle':
            cross_mode = ValidationMethod.ShuffleSplit
        else:
            cross_mode = ValidationMethod.KFold
        print('Parsing data...')
        parser = HistoryParser(abspath(args.d))
        parser.load()
        print('Selecting features...')
        filtered_schema = FeatureSelection(parser.data, threshold=args.ts).select()
        print('Starting validation...')
        print(PerformanceValidator.get_perf(parser.data, filtered_schema, selection_method=cross_mode, n_splits=5,
                                            is_nn=args.nn, epochs=args.e, batch_size=args.bs))
    elif mode == 'learn':
        parser = HistoryParser(abspath(args.d))
        parser.load()
        filtered_schema = FeatureSelection(parser.data, threshold=args.ts).select()
        if args.nn:
            model = TessNeuralModel(parser.data, filtered_schema, epochs=args.e, batch_size=args.bs)
        else:
            model = TessSVRModel(parser.data, filtered_schema)
        model.learn_by_data()
        model.save(abspath(args.o + '_model.tess'), abspath(args.o + '_schema.tess'))


def getparser(mode):
    parser = argparse.ArgumentParser(prog="python3 tess.py " + mode)
    if mode == 'evaluate':
        parser.add_argument('-d', '-dataset', help='Dataset used to fit and test model through  cross validation')
        parser.add_argument('-n', '-n_split', help='Number of split when cross validating')
        parser.add_argument('-e', '-epochs', help='Number of epochs used when fitting the neural network', default=500)
        parser.add_argument('-bs', '-batch_size', help='Size of the batch passed to the model', default=1)
        parser.add_argument('-ts', '-threshold', help='Threshold for feature selection', default=1)
        parser.add_argument('-nn', action='store_true', help='Use a neural network as a model instead of SVR',
                            default=True)
        parser.add_argument('-cm', '-cross_mode', help='Cross validation mode [kfold|shuffle]', default='kfold')
    else:
        parser.add_argument('-d', '-dataset', help='Dataset used to fit the model')
        parser.add_argument('-o', '-output',
                            help='Prefix of the file name of the dump of the model and the feature schema')
        parser.add_argument('-e', '-epochs', help='Number of epochs used when fitting the neural network', default=500)
        parser.add_argument('-bs', '-batch_size', help='Size of the batch passed to the model', default=1)
        parser.add_argument('-ts', '-threshold', help='Threshold for feature selection', default=1)
        parser.add_argument('-nn', action='store_true', help='Use a neural network as a model instead of SVR',
                            default=True)

    return parser


def usage():
    print("Usage:")
    print("  python3 tess.py [learn|evaluate]")
    print("")
    print("Options:")
    print("  learn                      Fit a linear model")
    print("  evaluate                   Evaluate performance on a dataset through cross validation")
    print("")
    sys.exit(1)


if __name__ == '__main__':
    main()
