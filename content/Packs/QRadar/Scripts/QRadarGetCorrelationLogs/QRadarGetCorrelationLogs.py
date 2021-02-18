import demistomock as demisto
from CommonServerPython import *


def get_query(cre_name_null):
    if cre_name_null == "True":
        query = "select RULENAME({0}), sourceip, destinationip, eventcount, sourceport, " \
                "username, starttime, destinationport, magnitude, identityip, CATEGORYNAME(category), " \
                "PROTOCOLNAME(protocolid), LOGSOURCENAME(logsourceid){1} from " \
                "events where \"CRE Name\" IS NULL AND INOFFENSE({2}) START '{3}'"
    else:
        query = "select RULENAME({0}), sourceip, destinationip, eventcount, " \
                "sourceport, username, starttime, destinationport, magnitude, " \
                "identityip, CATEGORYNAME(category), PROTOCOLNAME(protocolid), " \
                "LOGSOURCENAME(logsourceid){1} from events " \
                "where \"CRE Name\" <> NULL AND INOFFENSE({2}) START '{3}'"
    return query


def main():
    d_args = demisto.args()
    is_cre_name_null = demisto.args().get("is_cre_name_null", "True")
    QUERY = get_query(is_cre_name_null)

    offense_id = demisto.get(d_args, 'offenseID')
    start_time = demisto.get(d_args, 'startTime')
    correlation_id = demisto.get(d_args, 'qid')
    additional_query_fields = demisto.get(d_args, 'additionalQueryFields')
    # Try converting from date string to timestamp
    try:
        start_time = date_to_timestamp(str(start_time), '%Y-%m-%dT%H:%M:%S.%f000Z')
    except Exception:
        pass

    d_args["query_expression"] = QUERY.format(correlation_id, additional_query_fields, offense_id, start_time)

    resp = demisto.executeCommand('QRadarFullSearch', d_args)
    if isError(resp[0]):
        demisto.results(resp)
    else:
        data = demisto.get(resp[0], 'Contents.events')

        if not data:
            resp[0]['HumanReadable'] = "No logs were found for correlation id {0}".format(correlation_id)
        else:
            data = data if isinstance(data, list) else [data]

            QRadar = {
                'Log': []
            }  # type: Dict

            for corr in data:

                keys = corr.keys()
                log = {
                    "QID": correlation_id,
                    "SourceIP": demisto.get(corr, "sourceip")
                }  # type: Dict
                # Standardized known keys
                keys.remove("sourceip") if "sourceip" in keys else None

                log["DestinationPort"] = demisto.get(corr, "destinationport")
                keys.remove("destinationport") if "destinationport" in keys else ""

                log["SourcePort"] = demisto.get(corr, "sourceport")
                keys.remove("sourceport") if "sourceport" in keys else ""

                log["EventCount"] = demisto.get(corr, "eventcount")
                keys.remove("eventcount") if "eventcount" in keys else ""

                log["DestinationIP"] = demisto.get(corr, "destinationip")
                keys.remove("destinationip") if "destinationip" in keys else ""

                log["Category"] = demisto.get(corr, "categoryname_category")
                keys.remove("categoryname_category") if "categoryname_category" in keys else ""

                log["IdentityIP"] = demisto.get(corr, "identityip")
                keys.remove("identityip") if "identityip" in keys else ""

                log["Username"] = demisto.get(corr, "username")
                keys.remove("username") if "username" in keys else ""

                log["StartTime"] = demisto.get(corr, "starttime")
                keys.remove("starttime") if "starttime" in keys else ""

                log["Magnitude"] = demisto.get(corr, "magnitude")
                keys.remove("magnitude") if "magnitude" in keys else ""

                log["ProtocolName"] = demisto.get(corr, "protocolname_protocolid")
                keys.remove("protocolname_protocolid") if "protocolname_protocolid" in keys else ""

                # Push to context rest of the keys (won't be shown in 'outputs')
                for key in keys:
                    log[''.join(x for x in key.title() if not x.isspace())] = demisto.get(corr, key)

                QRadar['Log'].append(log)

            context = {"QRadar": QRadar}
            resp[0]['EntryContext'] = context

    demisto.results(resp)


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins'):
    main()
