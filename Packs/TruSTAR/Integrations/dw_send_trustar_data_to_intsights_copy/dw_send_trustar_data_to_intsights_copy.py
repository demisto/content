import base64
import json
import re
import time
from datetime import datetime, timedelta
# from json import dumps
# from time import sleep

import demistomock as demisto  # noqa: F401
import requests
import urllib3
from CommonServerPython import *  # noqa: F401
from trustar import *

# Declare unclean list of Indicators
uncleanListOfIndicators = []

# Declare clean list of Indicators
cleanListOfIndicators = []  # type: List[Dict]
getUncleanList = []  # type: List[Dict]
lengthOfUncleanList = 0  # type: int
getCleanList = []  # type: List[Dict]
lengthOfCleanList = 0  # type: int
getCountOfCleanList = 0  # type: int

# Set up Timestamp Set (for better accuracy use time() to return epoch float value)

timeStamp = time.time()

# Format Timestamp to Real-Time

realTime = datetime.fromtimestamp(timeStamp).strftime(' - %Y-%m-%d %H:%M:%S EST')

demisto.info("Stating the dw_send_trustar_data_to_insights - customer integration.")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

keys = {
    "scan_ip": "ipv4",
    "apt_ip": "ipv4",
    "spam_ip": "ipv4",
    "compromised_email": "email_address"
}

demisto.debug("Loading the IntSights configuration information.")
intsights_api = 'https://api.intsights.com/public/v1'
intsights_add_source = '/iocs/add-source'
intsights_del_source = '/iocs/delete-source'
intsights_get_sources = '/iocs/sources'
intsights_id = demisto.params()['intsights']['identifier']
intsights_key = demisto.params()['intsights']['password']
INTEGRATION_NAME = 'Data Relay to Intsights'
ConfidenceLevel = demisto.params()['ConfidenceLevel']
# Used to control the rate of flow of sending IOCs to IntSights
sleep_setting = demisto.params()['sleep_setting']

# demisto.results("Loading the TruSTAR configuration information.")
# Configuration Parameters
doc_source_name = "TruSTAR" + realTime

# TruSTAR API URLs
auth_endpoint = 'https://api.trustar.co/oauth/token'
api_endpoint = 'https://api.trustar.co/api/1.3'
enclave_ids = demisto.params()['enclave_ids']
client_metatag = demisto.params()['client_metatag']
user_api_key = demisto.params()['trustar']['identifier']
user_api_secret = demisto.params()['trustar']['password']

demisto.debug("Instantiating an instance the TruSTAR class.")

configDictionary = {
    'auth_endpoint': auth_endpoint,
    'api_endpoint': api_endpoint,
    'user_api_key': user_api_key,
    'user_api_secret': user_api_secret,
    'enclave_ids': enclave_ids,
    'client_metatag': client_metatag
}

ts = TruStar(config=configDictionary)

# demisto.results("Starting the TruSTAR ping.")
# demisto.results("Results of the TruSTAR ping -->"+str(ts.ping()))

# set 'from' to the start of a week ago and 'to' to the current time
to_time = datetime.now()
from_time = to_time - timedelta(days=7)

# convert to millis since epoch
to_time = datetime_to_millis(to_time)
from_time = datetime_to_millis(from_time)

demisto.debug("Starting the definition of the required REGEX components.")

IPAddressRegex = re.compile(
    r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]\""
    "[0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))"
    "\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f"
    "{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25"
    "[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:"
    "[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5"
    "|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:"
    "[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|"
    "1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(("
    "[0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4})"
    "{0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|"
    "[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5}|"
    "((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]"
    "|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:"
    "[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|"
    "1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:"
    "[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|"
    "1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?"
    "\s*$))\")"
)


def validateIP(ip):
    if (re.match(IPAddressRegex, str(ip))):
        return True
    else:
        demisto.debug("Invalid IP Address: " + str(ip))
        return False


urlregex = re.compile(
    r'^https?://'  # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
    r'localhost|'  # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
    r'(?::\d+)?'  # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)


def validateUrl(url):
    if(re.match(urlregex, str(url))):
        return True
    else:
        demisto.debug("Invalid Url: " + str(url))
        return False


emailregex = '^[a-zA-Z0-9._%+-]+@.*[.]\w{2,3}$'


def validateEmail(email):
    if(re.match(emailregex, str(email))):
        return True
    else:
        demisto.debug("Invalid Email: " + str(email))
        return False


def cleanData(uncleanListOfIndicators):

    cleanListOfIndicators = []

    # Iterate through the unclean list of indicators
    for i in uncleanListOfIndicators:
        indicator = i  # .to_dict(True)
        itype = indicator['indicatorType'].lower()
        demisto.info("Indicator: " + str(indicator) + " - indicator_type (lowercase): " + itype)

        # Chcks to see if indicator already exists
        if i not in cleanListOfIndicators:

            # Make calls to the check functions for URLs, emails, IPv4 addresses, IPv6 addresses
            if itype == 'ipv4' or itype == 'ipv6' or itype == 'ip':
                if validateIP(indicator['value']) is True:
                    cleanListOfIndicators.append(indicator)

            if itype == 'email_address':
                if validateEmail(indicator['value']) is True:
                    cleanListOfIndicators.append(indicator)

            if itype == 'url':
                if validateUrl(indicator['value']) is True:
                    cleanListOfIndicators.append(indicator)
                elif validateUrl(indicator['value']) is False:
                    indicator['value'] = "http://" + indicator['value']
                    if validateUrl(indicator['value']) is True:
                        cleanListOfIndicators.append(indicator)

            if itype == 'sha256' or itype == 'md5' or itype == 'sha1' or itype == 'sha512':
                cleanListOfIndicators.append(indicator)

            if itype == 'fqdn':
                cleanListOfIndicators.append(indicator)

            if itype == 'software':
                cleanListOfIndicators.append(indicator)

    return cleanListOfIndicators


def get_ioc_data():

    # Define the list to hold the unclean list of indicators
    uncleanListOfIndicators = []

    # demisto.info("Starting data collection - Download TruSTAR data.")
    demisto.info("Starting data collection - Download TruSTAR data.")

    try:
        # keep count of reports (for logging)
        report_count = 0

        # get all reports from the specified enclaves and in the given time interval
        reports = ts.get_reports(from_time=from_time,
                                 to_time=to_time,
                                 is_enclave=True,
                                 enclave_ids=ts.enclave_ids)

        # iterate over the reports, finding the tags and indicators for each

        for report in reports:
            demisto.info("Found report %s." % report.id)
            # demisto.results("Found report %s." % report.id)

            '''
            # get all tags for the report and convert list to string
            tags = [tag.name for tag in ts.get_enclave_tags(report.id)]

            # join tags into a semicolon-separated list
            tags = ';'.join(tags)

            demisto.info("Tags: %s" % tags)
            demisto.info("Writing indicators for report...")
            '''
            # keep count of indicators for this report (for logging)
            indicator_count = 0

            # get indicators for report and add an item to the list of unclean indicators for each
            try:
                for indicator in ts.get_indicators_for_report(report.id):
                    # Write the indicator to the list of unclean indicators
                    indicator_item = {"value": indicator.value, "indicatorType": indicator.type}
                    uncleanListOfIndicators.append(indicator_item)
                    demisto.debug("Indicator: " + str(indicator_item))
                    indicator_count += 1

                    demisto.info("Wrote %d indicators for report." % indicator_count)
                    # demisto.results("Wrote %d indicators for report." % indicator_count)
                    report_count += 1
            except Exception as e:
                demisto.debug("Error: %s" % e)
                demisto.results("Error: %s" % e)
                # raise

        demisto.info("Found %d reports." % report_count)
        # demisto.results("Found %d reports." % report_count)

    except Exception as e:
        demisto.debug("Error: %s" % e)
        # demisto.results("Error: %s" % e)
        # raise

    return uncleanListOfIndicators
    # Clean the list of indicators
    # demisto.results("Aggregated %d unclean indicators" % len(uncleanListOfIndicators))
    # cleanListOfIndicators = cleanData(uncleanListOfIndicators)
    # demisto.debug("Aggregated %d clean indicators" % len(cleanListOfIndicators))
    # demisto.results("Aggregated %d clean indicators" % len(cleanListOfIndicators))

    # Send the cleanListOfIndicators to IntSights
    # demisto.results("Send the cleanListOfIndicators to IntSights.")
    # sendData(cleanListOfIndicators, doc_source_name)


def sendData(data, title):
    demisto.info("Sending Data: " + title)
    demisto.results(len(data))
    iocs = []
    for item in data:
        itype = item['indicatorType'].lower()
        indicator = item['value']
        if itype == 'sha1' or itype == 'sha256' or itype == 'sha512' or itype == 'md5':
            indicator_dict = {'Type': 'Hashes', "Value": indicator}
            iocs.append(indicator_dict)
        elif itype == 'ipv4' or itype == 'ipv6' or itype == 'ip':
            indicator_dict = {'Type': 'IpAddresses', 'Value': indicator}
            iocs.append(indicator_dict)
        elif itype == 'fqdn':
            indicator_dict = {'Type': 'Domains', 'Value': indicator}
            iocs.append(indicator_dict)
        elif itype == 'url':
            indicator_dict = {'Type': 'Urls', 'Value': indicator.replace(' ', '')}
            iocs.append(indicator_dict)
        elif itype == 'email_address':
            indicator_dict = {'Type': 'Emails', 'Value': indicator}
            iocs.append(indicator_dict)
        elif itype == 'software':
            indicator_dict = {'Type': 'Software', 'Value': indicator}

    demisto.info("Length before IOCS are uploaded to Intsights...")
    demisto.results(len(iocs))

    # Connect to Intsights
    # Prepare POST request header
    code = base64.b64encode(bytes("{}:{}".format(intsights_id, intsights_key), 'utf-8'))
    code = code.decode("utf-8")
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic {}'.format(code),
        'Zone': 'us'
    }

    # Template of IOCs dictionary to upoad to Intsights
    custom_ioc_source = {
        'DocumentDetails': {
            'Name': doc_source_name,
            'Description': 'IOCs imported from Taxii server via Demisto',
            'ConfidenceLevel': ConfidenceLevel
        },
        'Iocs': [{}]
    }

    # Add downloaded IOCs to dictonary
    custom_ioc_source['Iocs'] = iocs

    # Delete existing source (IOCs) in Intsights
    demisto.info("Deleting IOC source document if it exists...")
    try:
        response = requests.get(intsights_api + intsights_get_sources, headers=headers)

        if response:
            response.raise_for_status()
            for source in response.json()['Files']:

                if source['Name'] == doc_source_name:
                    demisto.info('Deleting existing document in Intsights...')
                    response = requests.delete(
                        '{}{}/{}'.format(intsights_api, intsights_del_source, source['_id']),
                        data=json.dumps(custom_ioc_source),
                        headers=headers
                    )
    except Exception as e:
        sendError('Unable to delete a source - {}'.format(e))

    # Add IOCs to Intsights
    demisto.info('Adding IOC source document to Intsights...')
    try:
        response = requests.post(intsights_api + intsights_add_source, data=json.dumps(custom_ioc_source), headers=headers)
        if response:
            response.raise_for_status()
            demisto.info('IOCs document was successfully added')

            title = '{} - {} document created'.format(INTEGRATION_NAME, doc_source_name)

            ioc_count = len(iocs)

            context = {
                INTEGRATION_NAME + '.ioc_count': ioc_count,
            }

            tableHeaders = ['IOC count']  # type: List[str]
            human_readable = tableToMarkdown(title, str(ioc_count), tableHeaders)
            return human_readable, context, ioc_count

        else:
            sendError('Unable to add IOCs document - {}'.format(response.content))
    except Exception as e:
        sendError('Unable to add IOCs document - {}'.format(e))


# The command demisto.command() holds the command sent from the user.
if demisto.command() == 'trustar-get-IOC-data':
    uncleanListOfIndicators = get_ioc_data()
    lengthOfUncleanList = len(uncleanListOfIndicators)
    demisto.results(lengthOfUncleanList)
    demisto.results("The IOCs that were Obtained...")
    demisto.results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': uncleanListOfIndicators})
    demisto.setIntegrationContext(uncleanListOfIndicators)

if demisto.command() == 'trustar-clean-IOC-data':
    getUncleanList = demisto.getIntegrationContext()
    cleanListOfIndicators = cleanData(getUncleanList)
    demisto.results({'ContentsFormat': formats['table'], 'Type': entryTypes['note'], 'Contents': cleanListOfIndicators})
    lengthOfCleanList = len(cleanListOfIndicators)
    demisto.results(lengthOfCleanList)
    demisto.setIntegrationContext(cleanListOfIndicators)

if demisto.command() == 'trustar-send-IOC-data-to-intsights':
    getCleanList = demisto.getIntegrationContext()
    demisto.results("Running TruSTAR IOC Data to Intsights...")
    demisto.results(len(getCleanList))
    sendData(getCleanList, doc_source_name)

if demisto.command() == 'trustar-length-IOC-data':
    getCleanList = demisto.getIntegrationContext()
    demisto.results("Getting the count of IOC Data...")
    getCountOfCleanList = len(getCleanList)
    demisto.results(
        {
            "Type": entryTypes["note"],
            "ContentsFormat": formats["text"],
            "Contents": getCountOfCleanList,
            "EntryContext":
            {
                "IndicatorValues.Length": getCountOfCleanList
            }
        })


def sendError(reason):
    return_error(reason)
