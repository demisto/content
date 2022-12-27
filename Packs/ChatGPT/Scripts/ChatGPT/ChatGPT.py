import json

import demistomock as demisto  # noqa: F401
import requests
from CommonServerPython import *  # noqa: F401

# Disable warning
requests.packages.urllib3.disable_warnings()

# Setup atgumanets
args = demisto.args()
apiKey = args.get('api')
prompt = args.get('prompt')
maxToken = args.get('maxToken')
temp = args.get('temp')

url = 'https://api.openai.com/v1/completions'

headers = {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + apiKey
}

data = {
    'model': 'text-davinci-003',
    'prompt': prompt,
    'max_tokens': int(maxToken),
    'temperature': float(temp)
}

jsondata = json.dumps(data)
res = requests.post(url, headers=headers, data=jsondata)
readableResult = res.json()['choices'][0]['text'].replace('\n', '')

ec = {'ChatGPT': readableResult}
demisto.results({
    'ContentsFormat': formats["text"],
    'Contents': readableResult,
    'HumanReadable': readableResult,
    'EntryContext': ec
})
