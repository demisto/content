from CommonServerPython import *


def main():
    get_incidents_by_query_args = dict(demisto.args())
    get_incidents_by_query_args['NonEmptyFields'] = demisto.args()['tagField']
    res = demisto.executeCommand("GetIncidentsByQuery", get_incidents_by_query_args)
    if is_error(res):
        return_error(get_error(res))
    incidents = res[-1]['Contents']

    text_pre_process_args = dict(demisto.args())
    text_pre_process_args['inputType'] = 'json_b64_string'
    text_pre_process_args['input'] = base64.b64encode(incidents.encode('utf-8'))
    text_pre_process_args['preProcessType'] = 'nlp'
    text_pre_process_args['textFields'] = text_pre_process_args['emailContentFields']
    text_pre_process_args['whitelistFields'] = "{0},{1}".format('dbot_processed_text', text_pre_process_args['tagField'])
    res = demisto.executeCommand("DBotPreProcessTextData", text_pre_process_args)
    if is_error(res):
        return_error(get_error(res))

    processed_text_data = res[0]['Contents']
    demisto.results(res)
    train_model_args = dict(demisto.args())
    train_model_args['inputType'] = 'json_b64_string'
    train_model_args['input'] = base64.b64encode(processed_text_data.encode('utf-8'))
    train_model_args['overrideExistingModel'] = 'true'
    res = demisto.executeCommand("DBotTrainTextClassifierV2", train_model_args)
    demisto.results(res)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
