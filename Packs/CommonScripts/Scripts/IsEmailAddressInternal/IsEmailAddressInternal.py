import re
from distutils.util import strtobool

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

email = demisto.args()['email']
domains = [x.lower() for x in argToList(demisto.get(demisto.args(), 'domain'))]
include_subdomains = strtobool(demisto.getArg('include_subdomains') or 'no')

parts = email.split('@', 1)

network_type = "Unknown"
in_domain = "no"

if len(parts) > 1:
    if parts[1].lower() in domains or include_subdomains and re.match("^(.*\\.)?({})".format('|'.join([re.escape(d) for d in domains])), parts[1].lower()):
        in_domain = "yes"
        network_type = "Internal"
    else:
        network_type = "External"

    email_dict = {
        "Address": email,
        "Domain": parts[1],
        "Username": parts[0],
        "NetworkType": network_type
    }

    email_obj = {
        "Account.Email(val.Address && val.Address == obj.Address)": email_dict
    }
    demisto.results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": in_domain,
        "HumanReadable": in_domain,
        "EntryContext": email_obj
    })

else:
    demisto.results({"Type": entryTypes["error"], "ContentsFormat": formats["text"],
                    "Contents": 'Email address "{0}" is not valid'})
    sys.exit(0)
