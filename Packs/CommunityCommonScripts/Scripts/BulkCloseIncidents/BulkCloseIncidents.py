import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def send_post_request(endpoint, data=None):
    try:
        if data:
            data = json.dumps(data)
            res = demisto.executeCommand("core-api-post", {
                "uri": endpoint,
                "body": data
            })
    except requests.HTTPError as e:
        return_error(f"HTTP error: {e}")
    return res


def main():
    args = demisto.args()
    query = args.get('query')
    try:
        batch_size = int(args.get('batch_size'))
        sleep_seconds = int(args.get('sleep'))
    except ValueError:
        return_error("'batch_size' and 'sleep' must be integers.")
    try:
        # only get active incidents (status == 1)
        incidents = [inc['id'] for inc in demisto.executeCommand('getIncidents', {
            'query': query,
            'size': '10000'
        })[0]['Contents']['data'] if inc['status'] == 1]
    except:
        return_error('No incidents found matching query.')

    if not incidents:
        return_error('No active incidents found matching query.')

    first = True
    for b in batch(incidents, batch_size=batch_size):
        # sleep in between iterations, unless it's the first iteration
        if first:
            first = False
        else:
            time.sleep(sleep_seconds)
        data = {
            "ids": b,
            "all": False,
            "filter": {
                "page": 0,
                "size": 50,
                "sort": [{"field": "id", "asc": False}]
            }
        }
        try:
            response = send_post_request("/incident/batchClose", data=data)
            if is_error(response):
                return_error(f"API call to 'POST /incident/batchClose' returned an error: {response[0].get('Contents')}")
            return_results(f'Closed the following incidents: {b}')
        except Exception as e:
            return_error(f'Error occurred: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
