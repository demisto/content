import re

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Python template - reading arguments, calling a command, handling errors and returning results
res = []
# Constant and mandatory arguments
dArgs = {"TicketDescription": demisto.args()["TicketDescription"]}

"""
# Optional arguments
if "myoptionalscriptarg" in demisto.args():
    dArgs["myinternalarg"] = demisto.args()["myoptionalscriptarg"]
# Optional arguments with defaults - sometimes the arg is mandatory for our executeCommand
dArgs["myargwithdefault"] = demisto.args()["myotherscriptarg"] if "myotherscriptarg" in demisto.args() else "10"
"""

ticket_desc = dArgs["TicketDescription"]
print(ticket_desc)

start_date_match = re.search('(?<=StartDate:\s)(\S+)', ticket_desc)
if start_date_match:
    start_date = start_date_match.group(0)
else:
    start_date = ""

mirrored_username_match = re.search('(?<=MirroredUser:\s)(\S+)', ticket_desc)
if mirrored_username_match:
    mirrored_username = mirrored_username_match.group(0)
else:
    mirrored_username = ""

first_name_match = re.search('(?<=FirstName:\s)(\S+)', ticket_desc)
if first_name_match:
    first_name = first_name_match.group(0)
else:
    first_name = ""

last_name_match = re.search('(?<=LastName:\s)(\S+)', ticket_desc)
if last_name_match:
    last_name = last_name_match.group(0)
else:
    last_name = ""

alias_match = re.search('(?<=Alias:\s)(\S+)', ticket_desc)
if alias_match:
    alias = alias_match.group(0)
else:
    alias = ""

email_match = re.search('(?<=Email:\s)(\S+)', ticket_desc)
if email_match:
    email = email_match.group(0)
else:
    email = ""

username_match = re.search('(?<=Username:\s)(\S+)', ticket_desc)
if username_match:
    username = username_match.group(0)
else:
    username = ""

nickname_match = re.search('(?<=Nickname:\s)(\S+)', ticket_desc)
if nickname_match:
    nickname = nickname_match.group(0)
else:
    nickname = ""

phone_number_match = re.search('(?<=PhoneNumber:\s)(\S+)', ticket_desc)
if phone_number_match:
    phone_number = phone_number_match.group(0)
else:
    phone_number = ""


mobile_number_match = re.search('(?<=MobileNumber:\s)(\S+)', ticket_desc)
if mobile_number_match:
    mobile_number = mobile_number_match.group(0)
else:
    mobile_number = ""

address_match = re.search('(?<=Address:\s)(\S+)', ticket_desc)
if address_match:
    address = address_match.group(0)
else:
    address = ""

"""
demisto.executeCommand("SetContext", {"key":"SUO.StartDate","value":start_date})
demisto.executeCommand("SetContext", {"key":"SUO.MirroredUsername","value":mirrored_username})
demisto.executeCommand("SetContext", {"key":"SUO.FirstName","value":first_name})
demisto.executeCommand("SetContext", {"key":"SUO.LastName","value":last_name})
demisto.executeCommand("SetContext", {"key":"SUO.Alias","value":alias})
demisto.executeCommand("SetContext", {"key":"SUO.Email","value":email})
demisto.executeCommand("SetContext", {"key":"SUO.Username","value":username})
demisto.executeCommand("SetContext", {"key":"SUO.Nickname","value":nickname})
demisto.executeCommand("SetContext", {"key":"SUO.PhoneNumber","value":phone_number})
demisto.executeCommand("SetContext", {"key":"SUO.MobileNumber","value":mobile_number})
demisto.executeCommand("SetContext", {"key":"SUO.Adress","value":address})
"""

print("test SUO.MirroredUsernamePrint", mirrored_username)


results = CommandResults(
    outputs_prefix='SUO',
    outputs_key_field='Email',
    outputs={
        "StartDate": start_date,
        "MirroredUsername": mirrored_username,
        "FirstName": first_name,
        "LastName": last_name,
        "Alias": alias,
        "Email": email,
        "Username": username,
        "Nickname": nickname,
        "PhoneNumber": phone_number,
        "MobileNumber": mobile_number,
        "Adress": address
    }
)
return_results(results)

"""
demisto.results({
    "SUO.StartDate":start_date,
    "SUO.MirroredUsername":mirrored_username,
    "SUO.FirstName":first_name,
    "SUO.LastName":last_name,
    "SUO.Alias":alias,
    "SUO.Email":email,
    "SUO.Username":username,
    "SUO.Nickname":nickname,
    "SUO.PhoneNumber":phone_number,
    "SUO.MobileNumber":mobile_number,
    "SUO.Adress":address
})
"""
