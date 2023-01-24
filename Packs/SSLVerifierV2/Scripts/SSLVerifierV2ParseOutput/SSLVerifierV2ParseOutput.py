import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def include_keys(dictionary, keys):
    key_set = set(keys) & set(dictionary.keys())
    return {key: dictionary[key] for key in key_set}


def create_md_table(headers, certList):
    counter = 0
    md = ""

    # Build header
    for arg in headers:
        md += "|**" + arg + "**"
    md += "|\n"

    # Close out markdown header
    for arg in headers:
        md += "|--------------"
    md += "|\n"

    # Fill in tabular data
    for cert in certList:
        md += "|" + certList[counter]["Site"]
        md += "|" + certList[counter]["ExpirationDate"]
        md += "|" + certList[counter]["TimeToExpiration"]
        counter += 1
        md += "|\n"

    return md


def main():
    md = ""
    keyName = demisto.getArg('SSLVerifierKey')
    statusCode = demisto.getArg('StatusType')

    SSLVerifier_json = demisto.get(demisto.context(), keyName)

    good = {}
    warning = {}
    expiring = {}

    goodctr = 0
    warnctr = 0
    expctr = 0

    interestingKeys = ("Site", "ExpirationDate", "TimeToExpiration")

    for cert in SSLVerifier_json["Certificate"]:
        intTimeToExp = [int(i) for i in cert["TimeToExpiration"].split() if i.isdigit()][0]
        if intTimeToExp <= 90:
            expiring.update({expctr: include_keys(cert, interestingKeys)})
            expctr += 1
        elif intTimeToExp > 90 and intTimeToExp <= 180:
            warning.update({warnctr: include_keys(cert, interestingKeys)})
            warnctr += 1
        elif intTimeToExp > 180:
            good.update({goodctr: include_keys(cert, interestingKeys)})
            goodctr += 1

    # Update Context and create markdown table for good, warning, and expiring certificates

    if (statusCode == "expiring" or statusCode == "all"):
        tblExp = create_md_table(("Site", "Expiration Date", "Days to Expiration"), expiring)
        md += "### {{color:red}}(** SSL Certificates expiring in 90 days or less **) ###\n\n" + tblExp
        demisto.setContext("SSLReport.Expiring", expiring)
        demisto.setContext("SSLReport.ExpTable", tblExp)

    if (statusCode == "warning" or statusCode == "all"):
        tblWarn = create_md_table(("Site", "Expiration Date", "Days to Expiration"), warning)
        md += "### {{color:yellow}}(** SSL Certificates expiring between 91 and 180 days from now **) ###\n\n" + tblWarn
        demisto.setContext("SSLReport.Warning", warning)
        demisto.setContext("SSLReport.WarnTable", tblWarn)

    if (statusCode == "good" or statusCode == "all"):
        tblGood = create_md_table(("Site", "Expiration Date", "Days to Expiration"), good)
        md += "### {{color:green}}(** SSL Certificates expiring in greater than 180 days **) ###\n\n" + tblGood
        demisto.setContext("SSLReport.Good", good)
        demisto.setContext("SSLReport.GoodTable", tblGood)

    if demisto.getArg('OutputToWarRoom') == "True":
        demisto.results({'ContentsFormat': formats['markdown'], 'Type': entryTypes['note'], 'Contents': md})


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
