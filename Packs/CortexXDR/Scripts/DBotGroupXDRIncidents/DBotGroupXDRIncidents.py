from CommonServerPython import *

model_name = 'xdr_clustering'
field_for_grouping = 'xdralerts'
field_for_name = 'xdralerts.causalityactorprocessimagename'

return_type = demisto.args()['returnWidgetType']

if return_type == 'incidents':
    res = demisto.executeCommand('DBotShowClusteringModelInfo', {
        'searchQuery': demisto.args().get('searchQuery'),
        'modelName': model_name,
        'returnType': 'incidents',
        'fieldsToDisplay': demisto.args().get('fieldsToDisplay')
    })
    demisto.results(res)
elif return_type == 'summary':
    res = demisto.executeCommand('DBotShowClusteringModelInfo', {
        'modelName': model_name
    })
    demisto.results(res)
else:
    args = demisto.args()
    res = demisto.executeCommand('DBotTrainClustering', {
        'modelName': model_name,
        'type': demisto.args().get('incidentType'),
        'fromDate': demisto.args().get('fromDate'),
        'limit': demisto.args().get('limit'),
        'fieldsForClustering': field_for_grouping,
        'fieldForClusterName': field_for_name,
        'storeModel': 'True',
        'searchQuery': demisto.args().get('searchQuery'),
        'forceRetrain': demisto.args().get('forceRetrain'),
        'numberOfFeaturesPerField': 500
    })
    if not res[-1].get('EntryContext', {}):
        demisto.debug(f"DBotGroupXDRIncidents: there are 0 incidents fetched. {res[-1].get('Contents', '')=} "
                      f"{res[-1].get('EntryContext', {})=}")
        res[-1]['Contents'] = {'data': []}
    # we need only the last entry because it's a widget script, and only the widget info should be return
    demisto.results(res[-1])
