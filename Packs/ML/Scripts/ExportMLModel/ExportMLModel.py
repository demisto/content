from CommonServerPython import *


def get_ml_model_data(model_name):
    res = demisto.executeCommand("getMLModel", {"modelName": model_name})
    res = res[0]
    if is_error(res):
        return_error("error reading model %s from Demisto" % model_name)
    return res['Contents']


def main():
    model_data = get_ml_model_data(model_name=demisto.args()['modelName'])
    file_result = fileResult('model.data', json.dumps(model_data))
    demisto.results(file_result)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
