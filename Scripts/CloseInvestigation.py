dArgs = {}
if demisto.get(demisto.args(), 'reason'):
    dArgs['reason_What-happened'] = demisto.args()['reason']
demisto.results(demisto.executeCommand('closeInvestigation', dArgs))
