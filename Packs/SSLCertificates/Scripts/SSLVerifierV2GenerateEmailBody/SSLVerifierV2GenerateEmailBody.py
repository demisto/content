import demistomock as demisto
from CommonServerPython import *

from datetime import datetime


def create_html_table(headers, certList, listType):
    tableBody = ""

    tableBody += "\t\t<p>\n\t\t\t<span"

    # Table header setup
    if listType == "expired":
        tableBody += ">\n\t\t\t\t<h1>EXPIRED CERTIFICATES</h1>\n\t\t\t</span>\n\t\t</p>\n"
    elif listType == "expiring":
        tableBody += ">\n\t\t\t\t<h2>Certificates expiring in 90 days or less</h2>\n\t\t\t</span>\n\t\t</p>\n"
    elif listType == "warning":
        tableBody += " style=\"color: #ff9900;\">\n\t\t\t\t<strong>Certificates expiring between 91 and 180 days" \
                     + " from today</strong>\n\t\t\t</span>\n\t\t</p>\n"
    elif listType == "good":
        tableBody += " style=\"color: #339966;\">\n\t\t\t\t<strong>Certificates expiring more than 180 days from today</strong>" \
                     + "\n\t\t\t</span>\n\t\t</p>\n"

    # Setup table
    tableBody += "\t\t<table style=\"border-collapse: collapse; width: 100%;\" border=\"1\">\n\t\t\t<tbody>"

    # Setup table row headers
    tableBody += "\n\t\t\t\t<tr><td style=\"width: 33.3333%; text-align: center;\"><strong>Site/Domain/IP</strong></td>"
    tableBody += "<td style=\"width: 33.3333%; text-align: center;\"><strong>Expiration Date</strong></td>"
    if listType != "expired":
        tableBody += "<td style=\"width: 33.3333%; text-align: center;\"><strong>Days to Expiration</strong></td></tr>\n"
    else:
        tableBody += "<td style=\"width: 33.3333%; text-align: center;\"><strong>Days Expired</strong></td></tr>\n"

    # Parse table rows from certList
    for cert in certList:
        tableBody += "\t\t\t\t<tr>\n\t\t\t\t\t<td style=\"text-align: center;\">" + cert['Domain']
        tableBody += "</td>\n\t\t\t\t\t<td style=\"text-align: center;\">" + cert['ExpirationDate']
        tableBody += "</td>\n\t\t\t\t\t<td style=\"text-align: center;\">" + str(
            cert['TimeToExpiration']) + " days</td>" + "\n\t\t\t\t</tr>\n"

    tableBody += "\t\t\t</tbody>\n\t\t</table>\n"

    return tableBody


def main():
    try:
        emailHTMLBody = ""
        headers = ("Site", "Expiration Date", "Days to Expiration")
        good = demisto.get(demisto.context(), "SSLReport.Good")
        warning = demisto.get(demisto.context(), "SSLReport.Warning")
        expiring = demisto.get(demisto.context(), "SSLReport.Expiring")
        expired = demisto.get(demisto.context(), "SSLReport.Expired")

        # Setup email header
        emailHTMLBody += "<html>\n\t<head>\n\t\t<style>\n\t\t\tp {\n\t\t\t\ttext-align: center;\n\t\t\t}" \
                         + "\n\t\t\th1 {\n\t\t\t\ttext-align: center;\n\t\t\t\tcolor: #ff0000;\n\t\t\t}" \
                         + "\n\t\t\th2 {\n\t\t\t\ttext-align: center;\n\t\t\t\tcolor: #ff0000;\n\t\t\t}" \
                         + "\n\t\t\th3 {\n\t\t\t\ttext-align: center;\n\t\t\t\tcolor: #000000;\n\t\t\t\tfont-weight:" \
                           " bold;\n\t\t\t\t" + "font-size: 1.5em;\n\t\t\t\ttext-decoration: underline;\n\t\t\t}" \
                           "</style></head>\n\t<body>\n\t\t<h3>\n" + "\t\t\tSSL Certificate Report for " \
                         + datetime.today().strftime('%Y/%m/%d') + '\n\t\t</h3>\n'

        # Setup tables
        if expired:
            emailHTMLBody += create_html_table(headers, expired, "expired")
        if expiring:
            emailHTMLBody += create_html_table(headers, expiring, "expiring")
        if warning:
            emailHTMLBody += create_html_table(headers, warning, "warning")
        if good:
            emailHTMLBody += create_html_table(headers, good, "good")

        emailHTMLBody += "\t</body>\n</html>"

        demisto.setContext("SSLReport.HTML", emailHTMLBody)

    except Exception as ex:
        return_error(f'An Error occured: {ex}', error=ex)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
