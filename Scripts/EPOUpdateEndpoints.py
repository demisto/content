res = []

endpoints = demisto.get(demisto.args(), 'endpoints')
if not endpoints:
    res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "Received empty endpoints list!"})
else:
    endpoints = ','.join(endpoints) if isinstance(endpoints, list) else endpoints
    eposerver = demisto.get(demisto.args(), 'eposerver')
    # Find the VSEContentUpdateDemisto Client Task
    dArgsFind = {"using": eposerver,
                 "command": "clienttask.find",
                 "params": "searchText=VSEContentUpdateDemisto"
                 }
    repoVersions = {}
    resCmdFind = demisto.executeCommand('epo-command', dArgsFind)
    try:
        for entry in resCmdFind:
            if isError(entry):
                res = resCmdFind
                break
            else:
                taskId = demisto.get(entry, 'Contents.response')[0]['objectId']
                dArgsUpdate = {"using": eposerver,
                               "command": "clienttask.run",
                               "params": "names=" + endpoints + "&productId=EPOAGENTMETA&taskId=%d" % taskId
                               }
                for optarg in ['retryAttempts', 'retryIntervalInSeconds', 'abortAfterMinutes', 'stopAfterMinutes', 'randomizationInterval']:
                    v = None
                    v = demisto.get(demisto.args(), optarg)
                    if v:
                        dArgsUpdate["params"] += ('&' + optarg + '=' + v)

                demisto.log(dArgsUpdate["params"])
                resCmdUpdate = demisto.executeCommand('epo-command', dArgsUpdate)
                demisto.setContext('agentupdateresults', json.dumps(resCmdUpdate[0]['Contents']))
                res += resCmdUpdate

    except Exception as ex:
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": "Error occurred while parsing output from command. Exception info:\n" + str(ex) + "\n\nInvalid output:\n" + str(resCmdFind)})

demisto.results(res)
