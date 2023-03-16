import demistomock as demisto
from CommonServerPython import *


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
        md += "|" + certList[counter]["Domain"]
        md += "|" + certList[counter]["ExpirationDate"]
        md += "|" + str(certList[counter]["TimeToExpiration"]) + " days"
        counter += 1
        md += "|\n"

    return md


def main():
    try:
        md = ""
        results = {}
        keyName = demisto.getArg('SSLVerifierKey')
        statusCode = demisto.getArg('StatusType')

        SSLVerifier_json = demisto.get(demisto.context(), keyName)

        good = []
        warning = []
        expiring = []
        expired = []

        interestingKeys = ("Domain", "ExpirationDate", "TimeToExpiration")

        for cert in SSLVerifier_json["Certificate"]:
            expTime = int(cert["TimeToExpiration"])
            if expTime <= 90 and expTime > 0:
                expiring.append(include_keys(cert, interestingKeys))
            elif expTime > 90 and expTime <= 180:
                warning.append(include_keys(cert, interestingKeys))
            elif expTime > 180:
                good.append(include_keys(cert, interestingKeys))
            elif expTime <= 0:
                expired.append(include_keys(cert, interestingKeys))

        # Update Context and create markdown table for good, warning, expiring, and expired certificates

        if ((statusCode == "expired" or statusCode == "all") and expired):
            tblExpired = create_md_table(("Site", "Expiration Date", "Days Expired"), expired)
            md += "# {{color:red}}(** EXPIRED SSL CERTIFICATES **) #\n\n" + tblExpired
            results['Expired'] = expired
            results['ExpiredTable'] = tblExpired

        if ((statusCode == "expiring" or statusCode == "all") and expiring):
            tblExpiring = create_md_table(("Site", "Expiration Date", "Days to Expiration"), expiring)
            md += "### {{color:red}}(** SSL Certificates expiring in 90 days or less **) ###\n\n" + tblExpiring
            results['Expiring'] = expiring
            results['ExpiringTable'] = tblExpiring

        if ((statusCode == "warning" or statusCode == "all") and warning):
            tblWarn = create_md_table(("Site", "Expiration Date", "Days to Expiration"), warning)
            md += "### {{color:yellow}}(** SSL Certificates expiring between 91 and 180 days from now **) ###\n\n" + tblWarn
            results['Warning'] = warning
            results['WarningTable'] = tblWarn

        if ((statusCode == "good" or statusCode == "all") and good):
            tblGood = create_md_table(("Site", "Expiration Date", "Days to Expiration"), good)
            md += "### {{color:green}}(** SSL Certificates expiring in greater than 180 days **) ###\n\n" + tblGood
            results['Good'] = good
            results['GoodTable'] = tblGood

        results['md'] = md  # type: ignore

        return_results(CommandResults(
            outputs_prefix="SSLReport",
            outputs=results,
            readable_output=md
        )
        )
    except Exception as ex:
        return_error(f'An Error occured: {ex}', error=ex)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
