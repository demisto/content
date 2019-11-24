from CommonServerPython import *


# import json

# Python template - reading arguments, calling a command, handling errors and returning results


def read_file_content(input_entry_or_string):
    res = demisto.getFilePath(input_entry_or_string)
    if not res:
        return_error("Entry {} not found".format(input_entry_or_string))
    file_path = res['path']
    with open(file_path, 'r') as f:
        file_content = f.read()
    return file_content


def main():
    entry_id = demisto.args()['entryID']
    model_name = demisto.args()['modelName']
    encoded_file_content = read_file_content(entry_id)
    file_content = json.loads(encoded_file_content)
    args = {'modelData': file_content['modelData'],
            'modelName': model_name,
            'modelLabels': file_content['model']['labels'],
            'modelOverride': True}
    res = demisto.executeCommand('createMLModel', args)
    if is_error(res):
        return_error(get_error(res))
    confusion_matrix = file_content['model']['evaluation']['confusionMatrix']
    res = demisto.executeCommand('evaluateMLModel',
                                 {'modelConfusionMatrix': confusion_matrix,
                                  'modelName': model_name})
    if is_error(res):
        return_error(get_error(res))
    demisto.results("done")


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
