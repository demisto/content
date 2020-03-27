import requests
import re
from bs4 import BeautifulSoup

requests.packages.urllib3.disable_warnings()

url = 'https://docs.microsoft.com/en-us/intune/fundamentals/intune-endpoints'
r = requests.get(url, verify=False, timeout=3).text
headers = requests.get(url, verify=False, timeout=3)
soup = BeautifulSoup(r, 'html.parser')

def subs(text):
    patterns = (('comp', 'com p'), ('comm', 'com m'), ('comf', 'com f'), ('\*\.', ''), ('\n', ''))
    for e in patterns:
        text = re.sub(e[0], e[1], text)
    return text

domains_list = sum([subs(cell.text).rstrip().split() for cell in soup.select("tbody tr td") if re.findall(r'microsoft\.(com|net)', cell.text)], [])

for url in domains_list[0:3]:
    print(requests.get(f'https://{url}', verify=False).status_code)
        # print(url)