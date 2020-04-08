import argparse
import sys
from os.path import abspath

from learner import FeatureSelection, SelectorMode, TessModel
from parser import HistoryParser
from validator import PerformanceValidator, ValidationMethod


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
        if args.sm.lower() == 'rfecv':
            sel_mode = SelectorMode.RFECV
        else:
            sel_mode = SelectorMode.fromModel
        print('Parsing data...')
        parser = HistoryParser(abspath(args.d))
        parser.load()
        print('Selecting features...')
        filtered_schema = FeatureSelection(parser.data, sel_mode).select()
        print('Starting validation...')
        print(PerformanceValidator.get_perf(parser.data, filtered_schema, selection_method=cross_mode, n_splits=5))
    elif mode == 'learn':
        if args.sm.lower() == 'rfecv':
            sel_mode = SelectorMode.RFECV
        else:
            sel_mode = SelectorMode.fromModel
        parser = HistoryParser(abspath(args.d))
        parser.load()
        filtered_schema = FeatureSelection(parser.data, sel_mode).select()
        model = TessModel(parser.data,filtered_schema)
        model.save(abspath(args.o+'_model.tess'), abspath(args.o+'_schema.tess'))

def getparser(mode):
    parser = argparse.ArgumentParser(prog="python3 tess.py " + mode)
    if mode == 'evaluate':
        parser.add_argument('-d', '-dataset', help='Dataset used to fit and test model through  cross validation')
        parser.add_argument('-n', '-n_split', help='Number of split when cross validating')
        parser.add_argument('-cm', '-cross_mode', help='Cross validation mode [kfold|shuffle]', default='kfold')
        parser.add_argument('-sm', '-sel_mode', help='Feature selection mode [model|RFECV]', default='model')
    else:
        parser.add_argument('-d', '-dataset', help='Dataset used to fit the model')
        parser.add_argument('-o', '-output', help='Prefix of the file name of the dump of the model and the feature schema')
        parser.add_argument('-sm', '-sel_mode', help='Feature selection mode [model|RFECV]', default='model')
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