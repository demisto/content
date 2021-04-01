import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re
available_modules = []

res = demisto.executeCommand('getFilePath', {'id': demisto.args()['entryID']})
if res[0]['Type'] == entryTypes['error']:
    demisto.results('File not found')

else:
    try:
        with open(res[0]['Contents']['path'], 'r') as f:
            for line in f:
                if "Release Version:" in line:
                    words = line.split()
                    for i, word in enumerate(words):
                        if word == "Version:":
                            contentVersion = words[i + 1].rstrip('.')

                if "No content" in line:
                    contentVersion = "No Content"

                if '- Enabled,' in line:
                    reg = re.findall('.*\)', line)
                    fetchcheck = re.findall('.*? ', line)
                    reg = reg[0]
                    if 'Not ' in fetchcheck:
                        fetch = ' - No Fetch'
                    else:
                        fetch = ' - Fetch'
                    available_modules.append({"modules": reg.title() + fetch})

            try:
                contentVersion
            except NameError:
                contentVersion = "No Content"

            demisto.executeCommand("setIncident", {
                'contentversion': contentVersion,
                'enabledmodules': available_modules
            })

    except UnicodeDecodeError:
        demisto.results("Could not read file")
