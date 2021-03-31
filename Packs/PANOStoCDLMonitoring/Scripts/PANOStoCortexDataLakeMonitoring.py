from CommonServerPython import *


# Cortex Data Lake PAN-OS log monitoring monitoring
# PRE_REQUISITE: Enable Cortex Data Lake integration and/or PAN-OS integration (if the automated creation of a FW list is expected)

def check_instance(all_instances: list, integration_name: str, err_msg: str):
    instance_found_active: bool = False
    for instance in all_instances:
        if all_instances[instance]['brand'] == integration_name and all_instances[instance]['state'] == 'active':
            instance_found_active = True
            break
    if not instance_found_active:
        raise Exception(err_msg)


def main():
    try:
        args = demisto.args()
        NO_LOG_ANSWER = "### Logs traffic table\n**No entries.**\n"

        # Gather existing instances
        all_instances = demisto.getModules()

        # Look for active Cortex Data Lake instance
        check_instance(all_instances, "Cortex Data Lake",
                                        "No active Cortex Data Lake integration found, please configure one.")

        now = datetime.datetime.utcnow()
        start_time = now - datetime.timedelta(hours=12)  # Looking for the last 12 hours of logs
        start_time = start_time.strftime('%Y-%m-%d %H:%M:%S')

        # The Firewall list must be a comma-separated list of FW serials
        fw_monitor_list = argToList(args.get('fw_serials'))
        if not fw_monitor_list:  # List of FW to monitor is empty, get it from Panorama
            pan_os_integration = args.get('panorama')
            if not pan_os_integration:
                raise Exception("A Firewall serial list or a PAN-OS integration instance name is needed.")

            # Look for active PAN-OS instance
            check_instance(all_instances, pan_os_integration,
                                            f'Integration {pan_os_integration} is not active or is not a PAN-OS integration.')

            # Get FW serials
            fw_query = {'type': 'op', 'cmd': '<show><devices><all></all></devices></show>', 'raw-response': 'true',
                        'using': pan_os_integration}
            fw_query_result = demisto.executeCommand("panorama", fw_query)
            if fw_query_result and isinstance(fw_query_result, list):
                for fw in fw_query_result[0]['Contents']['response']['result']['devices']['entry']:
                    fw_monitor_list.append(fw['serial'])
            else:
                raise Exception("Failed to retrieve Firewalls list from PAn-OS, try to specify manually a list of serials.")

        # Log the list of firewalls to be monitored
        demisto.debug(f'List of FW serials: {fw_monitor_list}')

        FW_OK = []
        FW_KO = []

        query = {'fields': 'all', 'time_range': '1 day', 'limit': str(1), 'start_time': start_time}

        for current_fw in fw_monitor_list:
            if not (len(current_fw) == 12 or len(current_fw) == 15):
                # VM serial are 15 digits and FW serial are 12 digits
                return_error("%s - incorrect FW serial format." % current_fw)

            query['query'] = 'log_source_id = \'%s\'' % current_fw
            query_result = demisto.executeCommand("cdl-query-traffic-logs", query)

            if query_result:
                if query_result[0]['HumanReadable'] == NO_LOG_ANSWER:
                    FW_KO.append(current_fw)
                else:
                    FW_OK.append(current_fw)

        all_results = [{'FW OK': FW_OK, 'FW KO': FW_KO}]

        command_results = CommandResults(
            outputs_prefix='CDL.monitoring',
            outputs_key_field=['FW OK', 'FW KO'],
            ignore_auto_extract=True,
            outputs=all_results
        )

        return_results(command_results)
    except Exception as err:
        return_error(str(err), err)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
