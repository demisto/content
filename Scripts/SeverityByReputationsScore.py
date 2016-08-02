for k in demisto.args():
    if demisto.args()[k] == '':
        demisto.results({'Type': entryTypes['error'], 'ContentsFormat': formats['text'], 'Contents': 'Please provide non-empty value for arg ' + k})
        sys.exit(0)

badWeights = {"bad_urls": demisto.args()['bad_url_weight'],
              "bad_ips": demisto.args()['bad_ip_weight'],
              "bad_hashes": demisto.args()['bad_hash_weight']}
tCritical = demisto.args()['threshold_critical']
tHigh = demisto.args()['threshold_high']
tMed = demisto.args()['threshold_medium']

score = demisto.get(demisto.context(), 'score')
# Must explicitly compare to None since 0 is a valid score
if score is None:
    # Setting initial score based on severity. Severity "Unknown" yields score 0.
    score = i['severity'] * 25

for badKey in badWeights:
    v = demisto.get(demisto.context(), badKey)
    v = [v] if isinstance(v, list) else v
    score += len(v) * badWeights[badKey]

demisto.setContext('score', score)
if score >= tMed:
    if score >= tHigh:
        if score >= tCritical:
            demisto.executeCommand('IncidentSet', {'severity': 4})
        else:
            demisto.executeCommand('IncidentSet', {'severity': 3})
    else:
        demisto.executeCommand('IncidentSet', {'severity': 2})
else:
    demisto.executeCommand('IncidentSet', {'severity': 1})
