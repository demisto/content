from CommonServerPython import *


def main():
    args = dict(demisto.args())
    args['NonEmptyFields'] = demisto.args()['tagField']
    res = demisto.executeCommand("GetIncidentsByQuery", args)
    if is_error(res):
        return_error(get_error(res))
    incidents = res[-1]['Contents']

    args = dict(demisto.args())
    args['inputType'] = 'json_b64_string'
    args['input'] = base64.b64encode(incidents.encode('utf-8'))
    args['preProcessType'] = 'nlp'
    args['textFields'] = args['emailContentFields']
    args['whitelistFields'] = ",".join(['dbot_processed_text', args['tagField']])
    res = demisto.executeCommand("DBotPreProcessTextData", args)
    if is_error(res):
        return_error(get_error(res))
    processed_text_data = res[0]['Contents']

    args = dict(demisto.args())
    args['inputType'] = 'json_b64_string'
    args['input'] = base64.b64encode(processed_text_data.encode('utf-8'))
    args['overrideExistingModel'] = 'true'
    res = demisto.executeCommand("DBotTrainTextClassifierV2", args)
    demisto.results(res)


if __name__ in ['__builtin__', '__main__']:
    main()
