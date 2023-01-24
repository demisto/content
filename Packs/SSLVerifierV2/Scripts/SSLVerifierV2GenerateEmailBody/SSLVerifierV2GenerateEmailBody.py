from datetime import datetime

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def create_html_table(headers, certList, listType):
    counter = 0
    tableBody = ""

    tableBody += "<p style=\"text-align: center;\"><span style=\"color: "

    # Table header setup
    if listType == "expiring":
        tableBody += "#ff0000;\"><strong>Certificates expiring in 90 days or less</strong></span></p>" + '\n\n'
    elif listType == "warning":
        tableBody += "#ff9900;\"><strong>Certificates expiring between 91 and 180 days from today</strong></span></p>" + '\n\n'
    elif listType == "good":
        tableBody += "#339966;\"><strong>Certificates expiring more than 180 days from today</strong></span></p>" + '\n\n'

    # Setup table
    tableBody += "<table style=\"border-collapse: collapse; width: 100%;\" border=\"1\"><tbody>"

    # Setup table row headers
    tableBody += "<tr><td style=\"width: 33.3333%; text-align: center;\"><strong>Site/Domain/IP</strong></td>"
    tableBody += "<td style=\"width: 33.3333%; text-align: center;\"><strong>Expiration Date</strong></td>"
    tableBody += "<td style=\"width: 33.3333%; text-align: center;\"><strong>Days to Expiration</strong></td></tr>"

    # Parse table rows from certList
    for cert in certList:
        tableBody += "<tr><td style=\"text-align: center;\">" + certList[str(counter)]["Site"]
        tableBody += "</td><td style=\"text-align: center;\">" + certList[str(counter)]["ExpirationDate"]
        tableBody += "</td><td style=\"text-align: center;\">" + certList[str(counter)]["TimeToExpiration"] + "</td></tr>"
        counter += 1

    tableBody += "</tbody></table>"

    return tableBody


def main():
    emailHTMLBody = ""
    headers = ("Site", "Expiration Date", "Days to Expiration")
    good = demisto.get(demisto.context(), "SSLReport.Good")
    warning = demisto.get(demisto.context(), "SSLReport.Warning")
    expiring = demisto.get(demisto.context(), "SSLReport.Expiring")

    # Setup email header
    emailHTMLBody += "<html><body><p style=\"text-align:center\"><strong>SSL Certificate Report for " \
        + datetime.today().strftime('%Y/%m/%d') + '</strong></p>\n\n'

    # Setup tables
    emailHTMLBody += create_html_table(headers, expiring, "expiring")
    emailHTMLBody += create_html_table(headers, warning, "warning")
    emailHTMLBody += create_html_table(headers, good, "good")

    emailHTMLBody += "</body></html>"

    demisto.setContext("SSLReport.HTML", emailHTMLBody)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
