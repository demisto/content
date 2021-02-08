import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def main():
    try:
        res_type = demisto.getArg('reultType')
        query_type = demisto.getArg('queryType')
        to_date = demisto.getArg('to')
        from_date = demisto.getArg('from')
        list_name = f'xdrIncidents_{query_type}'

        # parse time arguments
        date_pattern = re.compile('\d{4}[-/]\d{2}[-/]\d{2}T\d{2}:\d{2}:\d{2}')

        if to_date and to_date != '0001-01-01T00:00:00Z':
            result = date_pattern.findall(to_date)[0]
            to_date = datetime.strptime(result, '%Y-%m-%dT%H:%M:%S')
        else:
            to_date = datetime.max

        if from_date and from_date != '0001-01-01T00:00:00Z':
            result = date_pattern.findall(from_date)[0]
            from_date = datetime.strptime(result, '%Y-%m-%dT%H:%M:%S')
        else:
            from_date = datetime.min

        incidents = []
        list_res = demisto.executeCommand("getList", {"listName": list_name})
        if isError(list_res):
            return_error(f'Error occurred while trying to get the list {list_name}: {get_error(list_res)}')

        try:
            incidents = json.loads(list_res[0]["Contents"])
        except ValueError as e:
            return_error(
                f'Unable to parse JSON string from {list_name} list. Please verify the JSON is valid. - ' + str(e))

        res_dict = {}  # type:dict
        for incident in incidents:
            creation_date = datetime.strptime(incident.get('created'), '%Y-%m-%dT%H:%M:%S')
            if from_date <= creation_date <= to_date:
                for key, val in incident.get('data').items():
                    if res_dict.get(key):
                        res_dict[key] = res_dict[key] + val
                    else:
                        res_dict[key] = val

        if res_type == 'Top10':
            res = sorted(res_dict.items(), key=lambda x: x[1], reverse=True)[:10]

            data = []
            for item in res:
                data.append({'name': item[0], 'data': [item[1]]})

            return_results(json.dumps(data))
        elif res_type == 'DistinctCount':
            return_results(len(res_dict))

    except Exception as e:
        return_error(str(e))


if __name__ in ['builtins', '__main__']:
    main()
