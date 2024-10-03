from CommonServerPython import *

''' STANDALONE FUNCTION '''


def get_group_incidents(args: dict) -> dict:
    model_name = 'xdr_clustering'
    field_for_grouping = 'xdralerts'
    field_for_name = 'xdralerts.causalityactorprocessimagename'

    return_type = args['returnWidgetType']
    demisto.debug(f'DBotGroupXDRIncidents: {return_type=}')

    if return_type == 'incidents':
        res = demisto.executeCommand('DBotShowClusteringModelInfo', {
            'searchQuery': demisto.args().get('searchQuery'),
            'modelName': model_name,
            'returnType': 'incidents',
            'fieldsToDisplay': demisto.args().get('fieldsToDisplay')
        })
        return res
    elif return_type == 'summary':
        res = demisto.executeCommand('DBotShowClusteringModelInfo', {
            'modelName': model_name
        })
        return res
    else:
        res = demisto.executeCommand('DBotTrainClustering', {
            'modelName': model_name,
            'type': args.get('incidentType'),
            'fromDate': args.get('fromDate'),
            'limit': args.get('limit'),
            'fieldsForClustering': field_for_grouping,
            'fieldForClusterName': field_for_name,
            'storeModel': 'True',
            'searchQuery': args.get('searchQuery'),
            'forceRetrain': args.get('forceRetrain'),
            'numberOfFeaturesPerField': 500
        })
        if not res[-1].get('EntryContext', {}):
            demisto.debug(f"DBotGroupXDRIncidents: there are 0 incidents fetched. {res[-1].get('Contents', '')=} "
                          f"{res[-1].get('EntryContext', {})=}")
            res[-1]['Contents'] = {'data': []}
        # we need only the last entry because it's a widget script, and only the widget info should be return
        return res[-1]


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        return_results(get_group_incidents(args))
    except Exception as ex:
        return_error(f'Failed to execute DBotGroupXDRIncidents. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
