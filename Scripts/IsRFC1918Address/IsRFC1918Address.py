import demistomock as demisto

ADDRESS = demisto.args()['value']
RANGES = '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16'

res = demisto.executeCommand('IsInCidrRanges', {'value': ADDRESS, 'cidr_ranges': RANGES})[0]

demisto.results(res['Contents'])
