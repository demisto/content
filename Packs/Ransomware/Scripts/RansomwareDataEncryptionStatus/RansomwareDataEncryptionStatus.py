import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()
query = incident[0].get('CustomFields', {}).get('ransomwaredataencryptionstatus', "Pending Confirmation")
Color = 'green'

if query == "Encrypted":
    color = 'red'
    html = "<div style='color:red;text-align:center;'><h2>Encrypted</h2></div>"

elif query == "Decrypted":
    color = 'green'
    html = "<div style='color:green;text-align:center;'><h2>Decrypted</h2></div>"

else:
    html = "<div style='color:black;text-align:center;'><h2>Pending Confirmation</h2></div>"


demisto.results({
    'ContentsFormat': formats['html'],
    'Type': entryTypes['note'],
    'Contents': html
})
