from CommonServerPython import *

domaintools_data = demisto.args().get('domaintools_data', None)

human_readable_str = "No context data for domain."
if domaintools_data:
    create_date = str(datetime.now().date()) if domaintools_data['Registration']['CreateDate'] is None else \
        domaintools_data['Registration']['CreateDate']
    response = demisto.executeCommand("CalculateAge", {"create_date": create_date})
    domain_age = response[0]['Contents'].get('age')
    threat_profile_score = domaintools_data['Analytics']['ThreatProfileRiskScore'].get('RiskScore')
    threat_profile_score = 0 if threat_profile_score is None else threat_profile_score
    proximity_risk_score = domaintools_data['Analytics'].get('ProximityRiskScore')
    proximity_risk_score = 0 if proximity_risk_score is None else proximity_risk_score
    response = demisto.executeCommand('CalculateIndicatorReputation', {"create_date": create_date,
                                                                       "proximity_score": proximity_risk_score,
                                                                       "threat_profile_score": threat_profile_score,
                                                                       "domain_name": domaintools_data['Name']})
    reputation = response[0]['Contents'].get('reputation')
    demisto_indicator = {
        'type': "Domain",
        'value': domaintools_data['Name'],
        'source': 'DomainTools',
        'reputation': reputation,
        'seenNow': 'true',
        'ipaddresses': json.dumps(domaintools_data['Hosting']['IPAddresses']),
        'ipcountrycode': domaintools_data['Hosting']['IPCountryCode'],
        'mailservers': json.dumps(domaintools_data['Hosting']['MailServers']),
        'spfrecord': domaintools_data['Hosting']['SPFRecord'],
        'nameservers': domaintools_data['Hosting']['NameServers'],
        'sslcertificate': json.dumps(domaintools_data['Hosting']['SSLCertificate']),
        'soaemail': domaintools_data['Identity']['SOAEmail'],
        'sslcertificateemail': domaintools_data['Identity']['SSLCertificateEmail'],
        'emaildomains': domaintools_data['Identity']['EmailDomains'],
        'additionalwhoisemails': domaintools_data['Identity']['AdditionalWhoisEmails'],
        'domainage': domain_age
    }
    resp = demisto.executeCommand('createNewIndicator', demisto_indicator)
    human_readable_str = "Data for {} enriched.".format(domaintools_data['Name'])

demisto.results({
    "Type": entryTypes["note"],
    "ContentsFormat": formats["json"],
    "Contents": {},
    "HumanReadable": human_readable_str,
    "EntryContext": {}
})
