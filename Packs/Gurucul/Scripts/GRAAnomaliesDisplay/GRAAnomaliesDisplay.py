import demistomock as demisto
from CommonServerPython import *


def getAnomaliesByCaseId():
    incident = demisto.incident()

    graCaseId = incident['CustomFields']['gracase']
    oldAnomalies = incident['CustomFields']['gracaseanomalydetails']

    caseId = graCaseId.split('-')[-1]
    if caseId != '':
        # make rest api call
        res = execute_command('gra-cases-anomaly', {'caseId': caseId, 'using': incident['sourceInstance']})
        anomaliesChangedCount = 0

        if res is not None:
            updatedAnomalies = []
            for anomaly in res:
                if anomaly is not None:
                    newAnomaly = {
                        'anomalyname': anomaly['anomalyName'],
                        'riskaccepteddate': anomaly['riskAcceptedDate'],
                        'resourcename': anomaly['resourceName'],
                        'riskscore': anomaly['riskScore'],
                        'assignee': anomaly['assignee'],
                        'assigneetype': anomaly['assigneeType'],
                        'status': anomaly['status'],
                    }
                    updatedAnomalies.append(newAnomaly)

                    for oldAnomaly in oldAnomalies:
                        if oldAnomaly['anomalyname'] == anomaly['anomalyName'] and \
                                (oldAnomaly['status'] != anomaly['status'] or oldAnomaly['assignee'] != anomaly['assignee']):
                            anomaliesChangedCount += 1
                            break

            if anomaliesChangedCount == 0 and len(oldAnomalies) != len(updatedAnomalies):
                anomaliesChangedCount = len(updatedAnomalies) - len(oldAnomalies)

            if anomaliesChangedCount != 0:
                execute_command("setIncident", {"id": incident['id'], "gracaseanomalydetails": updatedAnomalies})
                if anomaliesChangedCount == 1:
                    return_results('There is 1 anomaly update identified for this case. '
                                   'Refresh Analytical Features for updated attributes list.')
                else:
                    return_results(f'There are {anomaliesChangedCount} anomaly updates identified for this '
                                   f'case. Refresh Analytical Features for updated attributes list.')
            else:
                return_results('There are no anomaly changes identified for this case.')


def main():
    try:
        getAnomaliesByCaseId()
    except Exception as ex:
        return_error(f'Failed to execute gra-cases-anomaly. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
