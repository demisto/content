import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
""""
https://44.237.254.46:8083/#!/monitor/events/firewall/app/container?filters=%257B%2522time%2522%253A%255B%257B%2522from%2522%253A%25222022-07-05T11%253A14%253A36.722Z%2522%252C%2522to%2522%253A%25222022-07-09T03%253A58%253A59.994Z%2522%257D%255D%252C%2522imageName%2522%253A%255B%2522vulnerables%252Fweb-dvwa%253Alatest%2522%255D%252C%2522type%2522%253A%255B%2522sqli%2522%255D%257D
"""

import urllib.parse

args = demisto.args()
encoded_filters = urllib.parse.quote(f"imageName={args.get('imageName')}&type={args.get('type')}", safe='')

url = f"https://44.237.254.46:8083/#!/monitor/events/firewall/app/container?filters={encoded_filters}"


return_results(CommandResults(outputs={"link": url}))
