import demistomock as demisto
from CommonServerPython import *


def get_query(cre_name_null):
    if cre_name_null == "False":
        query = "SELECT *,\"CRE Name\",\"CRE Description\",CATEGORYNAME(highlevelcategory) " \
                "FROM events WHERE \"CRE NAME\" <> NULL AND INOFFENSE({0}) START '{1}'"
    else:
        query = "SELECT *,\"CRE Name\",\"CRE Description\",CATEGORYNAME(highlevelcategory) " \
                "FROM events WHERE \"CRE NAME\" IS NULL AND INOFFENSE({0}) START '{1}'"
    return query


def main():
    d_args = demisto.args()
    is_cre_name_null = demisto.args().get("is_cre_name_null", "True")
    QUERY = get_query(is_cre_name_null)

    offense_id = demisto.get(d_args, 'offenseID')
    start_time = demisto.get(d_args, 'startTime')
    # Try converting from date string to timestamp
    try:
        start_time = date_to_timestamp(str(start_time), '%Y-%m-%dT%H:%M:%S.%f000Z')
    except Exception:
        pass
    d_args["query_expression"] = QUERY.format(offense_id, start_time)

    resp = demisto.executeCommand('QRadarFullSearch', d_args)
    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], 'Contents.events')

        if not data:
            resp[0]['HumanReadable'] = "No Correlations were found for offense id {0}".format(offense_id)
        else:
            data = data if isinstance(data, list) else [data]

            QRadar = {
                'Correlation': []
            }  # type: Dict

            for corr in data:
                keys = corr.keys()
                correlation = {
                    "SourceIP": demisto.get(corr, "sourceip")
                }  # type: Dict
                # Standardized known keys
                keys.remove("sourceip") if "sourceip" in keys else None

                correlation["CREDescription"] = demisto.get(corr, "CRE Description")
                keys.remove("CRE Description") if "CRE Description" in keys else ""

                correlation["CREName"] = demisto.get(corr, "CRE Name")
                keys.remove("CRE Name") if "CRE Name" in keys else ""

                correlation["QID"] = demisto.get(corr, "qid")
                keys.remove("qid") if "qid" in keys else ""

                correlation["DestinationIP"] = demisto.get(corr, "destinationip")
                keys.remove("destinationip") if "destinationip" in keys else ""

                correlation["Category"] = demisto.get(corr, "categoryname_highlevelcategory")
                keys.remove("categoryname_highlevelcategory") if "categoryname_highlevelcategory" in keys else ""

                correlation["CategoryID"] = demisto.get(corr, "category")
                keys.remove("category") if "category" in keys else ""

                correlation["Username"] = demisto.get(corr, "username")
                keys.remove("username") if "username" in keys else ""

                correlation["StartTime"] = demisto.get(corr, "starttime")
                keys.remove("starttime") if "starttime" in keys else ""

                # Push to context rest of the keys (won't be shown in 'outputs')
                for key in keys:
                    correlation[''.join(x for x in key.title() if not x.isspace())] = demisto.get(corr, key)

                QRadar['Correlation'].append(correlation)

            context = {"QRadar": QRadar}
            resp[0]['EntryContext'] = context

    demisto.results(resp)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins'):
    main()
