import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
args = demisto.args()
# !ConvertTableToHTML table=${PrismaCloudCompute.Images.ComplianceIssues} title=`Compliance Results`
res = demisto.executeCommand("ConvertTableToHTML", {"table": args.get("table"), "title": args.get("title")})
html = res[0]["EntryContext"]["HTMLTable"]

body = f"""
Hello,

Please see below the details for the compliance report from Prisma Cloud Compute

{html}

- DBot
"""


# !send-mail
res = demisto.executeCommand("send-mail", {"to": args.get("to"),
                             "subject": "IMPORTANT: Prisma Cloud Compute Compliance", "body": body})
demisto.results(res)
