import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

domains = argToList(demisto.getArg('domain'))
threshold = int(demisto.getArg('threshold'))
emails = demisto.getArg('email')

if not isinstance(emails, list):
    emails = [emails]

for email in emails:
    emailParts = email.split('@', 2)

    if len(emailParts) < 2:
        demisto.results({
            'ContentsFormat': formats.text,
            'Type': entryTypes.error,
            'Contents':
                email.toString() + " - is not a valid email address"
        })

    emailObj = {
        'Username': emailParts[0],
        'Domain': emailParts[1],
        'Address': email,
        'Distance': []
    }

    for domain in domains:
        resp = demisto.executeCommand(
            "GetStringsDistance",
            {
                'inputString': emailObj.get('Domain'),
                'compareString': domain
            }
        )

        if isError(resp[0]):
            demisto.results(resp)

        data = [demisto.get(resp[0], "Contents.Distances")]
        for entry in data:
            emailObj['Distance'].append(
                {
                    'Domain': demisto.get(entry, "StringB"),
                    'Value': demisto.get(entry, "LevenshteinDistance")
                }
            )
    ec = {}
    suspicious = demisto.get(emailObj, "Distance(val.Value > 0 && val.Value < {0}).Value".format(threshold))
    dbotScore = 0
    malicious = None

    if suspicious:
        DBotScore = {
            'Indicator': email,
            'Type': 'email',
            'Vendor': 'DomainSquatting',
            'Score': 2
        }
        malicious = {
            'Vendor': "DomainSquatting",
            'Description': "The email address domain is suspicious at domain squatting"
        }
    account = {'Email': emailObj}
    if malicious:
        account['Malicious'] = malicious
    ec["Account(val.Email && val.Email.Address && val.Email.Address === obj.Email.Address)"] = account
    md = tableToMarkdown("Domain squatting reputation for {0}".format(email), emailObj['Distance'])

    demisto.results(
        {
            'Type': entryTypes.note,
            'Contents': emailObj,
            'ContentsFormat': formats.json,
            'HumanReadable': md,
            'EntryContext': ec
        }
    )