import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib.parse


def main():
    args = demisto.args()
    encoded_filters = urllib.parse.quote(f"imageName={args.get('imageName')}&type={args.get('type')}", safe='')
    baseUrl = demisto.args().get("baseUrl")

    url = f"{baseUrl}/#!/monitor/events/firewall/app/container?filters={encoded_filters}"

    return_results(CommandResults(outputs={"link": url}))


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
