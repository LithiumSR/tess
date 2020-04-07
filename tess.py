from learner import FeatureSelection, SelectorMode, TessModel
from parser import HistoryParser
from validator import PerformanceValidator

if __name__ == '__main__':
    parser = HistoryParser("data/dataset.csv")
    parser.load()
    filtered_schema = FeatureSelection(parser.data, SelectorMode.fromModel).select()
    model = TessModel(parser.data, filtered_schema)
    model.learn_by_data()
    model.save('test_model.tess', 'test_schema.tess')
    print(PerformanceValidator.get_perf(parser.data, filtered_schema))
