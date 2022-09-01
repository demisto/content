from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
import json
from datetime import datetime
import demistomock as demisto


def _get_incident():
    return demisto.incidents()[0]


def displayAnalyticalFeatures():
    incident = _get_incident()
    entityValue = ''
    anomalyName = ''
    riskDate = ''
    entityTypeId = 0
    analyticalFeaturesObj = []
    displayData = []
    for label in incident['labels']:
        if label['value'] is not None and label['type'] == 'entityTypeId':
            entityTypeId = label['value']
        if label['value'] is not None and label['type'] == 'riskDate':
            riskDate = datetime.strptime(label['value'], "%m/%d/%Y %H:%M:%S").strftime("%Y-%m-%d")
        if label['value'] is not None and label['type'] == 'entity':
            entityValue = label['value']
        if label['value'] is not None and label['type'] == 'anomalies':
            anomalies = str(label['value']).replace("null", "\"\"")

    if int(entityTypeId) == 1:
        anomaliesDetailString = json.loads(anomalies)
        for anomalyDetailString in anomaliesDetailString:
            anomalyName = ''
            for key in anomalyDetailString:
                if key is not None and key == 'anomalyName':
                    anomalyName = anomalyDetailString[key]

            fromDate = riskDate
            toDate = riskDate

            res = execute_command('gra-analytical-features-entity-value',
                                  {
                                      'entityValue': entityValue,
                                      'modelName': anomalyName,
                                      'fromDate': fromDate,
                                      'toDate': toDate
                                  }
                                  )
            if res is not None:
                for analyticalFeaturesObj in res:
                    if analyticalFeaturesObj is not None:
                        for analyticalObj in analyticalFeaturesObj:
                            if analyticalObj is not None:
                                for key1 in analyticalObj:
                                    if key1 == 'analyticalFeatureValues':
                                        analyticalFeatures = analyticalObj[key1]
                                        if analyticalFeatures is not None:
                                            for feature in analyticalFeatures:
                                                displayData.append({'Anomaly Name': anomalyName,
                                                                    'Analytical Feature': feature,
                                                                    'Count': len(analyticalFeatures[feature]),
                                                                    'Values': analyticalFeatures[feature]})

        if len(displayData) > 0:
            data = {
                'Type': entryTypes['note'],
                'ContentsFormat': formats['markdown'],
                'Contents': displayData,
                'HumanReadable': tableToMarkdown(None, displayData, headers=["Anomaly Name",
                                                                             "Analytical Feature", "Count", "Values"])
            }
            return_results(data)


def main():
    try:
        displayAnalyticalFeatures()
    except Exception as ex:
        return_error(f'Failed to execute gra-analytical-feature-display. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
