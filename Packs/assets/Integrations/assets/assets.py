import demistomock as demisto  # noqa:  F401
from CommonServerPython import *  # noqa:  F401

VENDOR = 'test'
PRODUCT = 'assets'

FETCH_COMMAND = {
    'events':  0,
    'assets':  1
}


def get_host_list_detections_events(next_page):
    res = {
           "1": {
               "next_page": '2',
               "val": [
                  {
                     "ID": "46729999",
                     "IP": "105.162.48.222",
                     "TRACKING_METHOD": "MAC",
                     "NETWORK_ID": "4",
                     "OS": "Linux",
                     "NETBIOS": "TRNSISSRV7",
                     "LAST_SCAN_DATETIME": "2013-05-03T17:46:22Z",
                     "LAST_VM_SCANNED_DATE": "2013-03-14T20:58:48Z",
                     "LAST_VM_SCANNED_DURATION": "1921",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "6459270949",
                        "QID": "56118",
                        "TYPE": "Informational",
                        "SEVERITY": "2",
                        "PORT": "11484",
                        "PROTOCOL": "udp",
                        "SSL": "0",
                        "STATUS": "Active",
                        "FIRST_FOUND_DATETIME": "2021-04-16T15:52:16Z",
                        "LAST_FOUND_DATETIME": "2020-04-12T13:40:22Z",
                        "TIMES_FOUND": "193",
                        "LAST_TEST_DATETIME": "2022-10-27T08:20:41Z",
                        "LAST_UPDATE_DATETIME": "2019-10-24T10:31:58Z",
                        "LAST_FIXED_DATETIME": "2011-09-28T02:25:51Z",
                        "IS_IGNORED": "1",
                        "IS_DISABLED": "1",
                        "LAST_PROCESSED_DATETIME": "2012-03-16T21:23:31Z"
                     },
                     "_time": "2010-09-16T15:39:09Z",
                     "event_type": "host_list_detection"
                  },
                  {
                     "ID": "48453571",
                     "IP": "255.224.123.217",
                     "TRACKING_METHOD": "MAC",
                     "NETWORK_ID": "8",
                     "OS": "Windows 2012",
                     "NETBIOS": "TRNSISSRV8",
                     "LAST_SCAN_DATETIME": "2012-10-03T09:15:37Z",
                     "LAST_VM_SCANNED_DATE": "2014-07-12T16:04:07Z",
                     "LAST_VM_SCANNED_DURATION": "1042",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "9760294402",
                        "QID": "95597",
                        "TYPE": "Confirmed",
                        "SEVERITY": "3",
                        "PORT": "5081",
                        "PROTOCOL": "udp",
                        "SSL": "0",
                        "STATUS": "Active",
                        "FIRST_FOUND_DATETIME": "2021-01-04T03:39:16Z",
                        "LAST_FOUND_DATETIME": "2022-01-03T06:13:09Z",
                        "TIMES_FOUND": "912",
                        "LAST_TEST_DATETIME": "2021-08-22T12:32:07Z",
                        "LAST_UPDATE_DATETIME": "2013-01-13T17:26:50Z",
                        "LAST_FIXED_DATETIME": "2020-07-01T14:52:33Z",
                        "IS_IGNORED": "0",
                        "IS_DISABLED": "0",
                        "LAST_PROCESSED_DATETIME": "2024-02-15T13:53:24Z"
                     },
                     "_time": "2022-10-05T22:57:11Z",
                     "event_type": "host_list_detection"
                  },
                  {
                     "ID": "29428400",
                     "IP": "122.129.91.225",
                     "TRACKING_METHOD": "MAC",
                     "NETWORK_ID": "9",
                     "OS": "Linux",
                     "NETBIOS": "TRNSISSRV7",
                     "LAST_SCAN_DATETIME": "2022-04-01T23:58:06Z",
                     "LAST_VM_SCANNED_DATE": "2018-08-27T04:08:42Z",
                     "LAST_VM_SCANNED_DURATION": "896",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "8937818025",
                        "QID": "95845",
                        "TYPE": "Confirmed",
                        "SEVERITY": "4",
                        "PORT": "31156",
                        "PROTOCOL": "tcp",
                        "SSL": "0",
                        "STATUS": "Active",
                        "FIRST_FOUND_DATETIME": "2015-02-11T15:08:23Z",
                        "LAST_FOUND_DATETIME": "2020-02-16T18:09:36Z",
                        "TIMES_FOUND": "441",
                        "LAST_TEST_DATETIME": "2015-07-01T04:14:02Z",
                        "LAST_UPDATE_DATETIME": "2020-03-15T05:51:41Z",
                        "LAST_FIXED_DATETIME": "2020-10-29T06:44:58Z",
                        "IS_IGNORED": "1",
                        "IS_DISABLED": "0",
                        "LAST_PROCESSED_DATETIME": "2023-10-04T23:42:12Z"
                     },
                     "_time": "2016-03-01T07:14:48Z",
                     "event_type": "host_list_detection"
                  }
                ]},
           "2": {
               "next_page": '3',
               "val": [
                   {
                       "ID": "36690125",
                       "IP": "97.85.74.17",
                       "TRACKING_METHOD": "HOSTNAME",
                       "NETWORK_ID": "7",
                       "OS": "macOS",
                       "NETBIOS": "TRNSISSRV8",
                       "LAST_SCAN_DATETIME": "2013-03-15T11:26:17Z",
                       "LAST_VM_SCANNED_DATE": "2011-08-01T05:29:27Z",
                       "LAST_VM_SCANNED_DURATION": "857",
                       "DETECTION": {
                           "UNIQUE_VULN_ID": "4440754987",
                           "QID": "69577",
                           "TYPE": "Informational",
                           "SEVERITY": "3",
                           "PORT": "48209",
                           "PROTOCOL": "udp",
                           "SSL": "0",
                           "STATUS": "Active",
                           "FIRST_FOUND_DATETIME": "2016-11-09T03:37:07Z",
                           "LAST_FOUND_DATETIME": "2020-10-05T23:17:27Z",
                           "TIMES_FOUND": "959",
                           "LAST_TEST_DATETIME": "2011-05-09T09:23:47Z",
                           "LAST_UPDATE_DATETIME": "2014-09-12T11:30:28Z",
                           "LAST_FIXED_DATETIME": "2023-08-16T00:17:35Z",
                           "IS_IGNORED": "1",
                           "IS_DISABLED": "1",
                           "LAST_PROCESSED_DATETIME": "2014-05-16T11:49:04Z"
                       },
                       "_time": "2021-01-06T07:27:50Z",
                       "event_type": "host_list_detection"
                   }
               ]},
           "3": {
               "next_page": '4',
               "val": [
                   {
                       "ID": "36690124",
                       "IP": "97.85.74.16",
                       "TRACKING_METHOD": "HOSTNAME",
                       "NETWORK_ID": "6",
                       "OS": "macOS",
                       "NETBIOS": "TRNSISSRV8",
                       "LAST_SCAN_DATETIME": "2013-03-15T11:26:15Z",
                       "LAST_VM_SCANNED_DATE": "2011-08-01T05:29:20Z",
                       "LAST_VM_SCANNED_DURATION": "856",
                       "DETECTION": {
                           "UNIQUE_VULN_ID": "4440754985",
                           "QID": "69575",
                           "TYPE": "Informational",
                           "SEVERITY": "3",
                           "PORT": "48208",
                           "PROTOCOL": "udp",
                           "SSL": "0",
                           "STATUS": "Active",
                           "FIRST_FOUND_DATETIME": "2016-11-09T03:37:02Z",
                           "LAST_FOUND_DATETIME": "2020-10-05T23:17:26Z",
                           "TIMES_FOUND": "959",
                           "LAST_TEST_DATETIME": "2011-05-09T09:23:44Z",
                           "LAST_UPDATE_DATETIME": "2014-09-12T11:30:27Z",
                           "LAST_FIXED_DATETIME": "2023-08-16T00:17:34Z",
                           "IS_IGNORED": "1",
                           "IS_DISABLED": "1",
                           "LAST_PROCESSED_DATETIME": "2014-05-16T11:49:03Z"
                       },
                       "_time": "2021-01-06T07:27:49Z",
                       "event_type": "host_list_detection"
                   }
           ]},
           "4": {
               "next_page": '5',
               "val": [
              {
                 "ID": "80976624",
                 "IP": "66.209.112.34",
                 "TRACKING_METHOD": "MAC",
                 "NETWORK_ID": "10",
                 "OS": "Linux",
                 "NETBIOS": "TRNSISSRV3",
                 "LAST_SCAN_DATETIME": "2024-08-15T09:17:02Z",
                 "LAST_VM_SCANNED_DATE": "2014-10-19T23:45:41Z",
                 "LAST_VM_SCANNED_DURATION": "817",
                 "DETECTION": {
                    "UNIQUE_VULN_ID": "6322670242",
                    "QID": "60823",
                    "TYPE": "Confirmed",
                    "SEVERITY": "1",
                    "PORT": "44883",
                    "PROTOCOL": "tcp",
                    "SSL": "1",
                    "STATUS": "Active",
                    "FIRST_FOUND_DATETIME": "2023-11-03T07:50:37Z",
                    "LAST_FOUND_DATETIME": "2018-01-12T03:22:09Z",
                    "TIMES_FOUND": "554",
                    "LAST_TEST_DATETIME": "2012-01-07T14:13:22Z",
                    "LAST_UPDATE_DATETIME": "2013-03-26T11:54:16Z",
                    "LAST_FIXED_DATETIME": "2021-09-21T19:12:22Z",
                    "IS_IGNORED": "0",
                    "IS_DISABLED": "0",
                    "LAST_PROCESSED_DATETIME": "2015-03-18T05:13:29Z"
                 },
                 "_time": "2012-11-05T03:09:01Z",
                 "event_type": "host_list_detection"
              },
              {
                 "ID": "36690029",
                 "IP": "97.84.74.14",
                 "TRACKING_METHOD": "HOSTNAME",
                 "NETWORK_ID": "2",
                 "OS": "macOS",
                 "NETBIOS": "TRNSISSRV8",
                 "LAST_SCAN_DATETIME": "2013-03-15T11:26:13Z",
                 "LAST_VM_SCANNED_DATE": "2011-08-01T05:29:18Z",
                 "LAST_VM_SCANNED_DURATION": "855",
                 "DETECTION": {
                    "UNIQUE_VULN_ID": "4440754983",
                    "QID": "69573",
                    "TYPE": "Informational",
                    "SEVERITY": "3",
                    "PORT": "48206",
                    "PROTOCOL": "udp",
                    "SSL": "0",
                    "STATUS": "Active",
                    "FIRST_FOUND_DATETIME": "2016-11-09T03:36:01Z",
                    "LAST_FOUND_DATETIME": "2020-10-05T23:17:24Z",
                    "TIMES_FOUND": "958",
                    "LAST_TEST_DATETIME": "2011-05-09T09:23:42Z",
                    "LAST_UPDATE_DATETIME": "2014-09-12T11:30:25Z",
                    "LAST_FIXED_DATETIME": "2023-08-16T00:17:32Z",
                    "IS_IGNORED": "1",
                    "IS_DISABLED": "1",
                    "LAST_PROCESSED_DATETIME": "2014-05-16T11:49:01Z"
                 },
                 "_time": "2021-01-06T07:27:47Z",
                 "event_type": "host_list_detection"
              }
           ]},
           "5": {
               "next_page": None,
               "val": [
                   {
                       "ID": "36690123",
                       "IP": "97.85.74.15",
                       "TRACKING_METHOD": "HOSTNAME",
                       "NETWORK_ID": "5",
                       "OS": "macOS",
                       "NETBIOS": "TRNSISSRV8",
                       "LAST_SCAN_DATETIME": "2013-03-15T11:26:14Z",
                       "LAST_VM_SCANNED_DATE": "2011-08-01T05:29:19Z",
                       "LAST_VM_SCANNED_DURATION": "856",
                       "DETECTION": {
                           "UNIQUE_VULN_ID": "4440754984",
                           "QID": "69574",
                           "TYPE": "Informational",
                           "SEVERITY": "3",
                           "PORT": "48207",
                           "PROTOCOL": "udp",
                           "SSL": "0",
                           "STATUS": "Active",
                           "FIRST_FOUND_DATETIME": "2016-11-09T03:37:01Z",
                           "LAST_FOUND_DATETIME": "2020-10-05T23:17:25Z",
                           "TIMES_FOUND": "958",
                           "LAST_TEST_DATETIME": "2011-05-09T09:23:43Z",
                           "LAST_UPDATE_DATETIME": "2014-09-12T11:30:26Z",
                           "LAST_FIXED_DATETIME": "2023-08-16T00:17:33Z",
                           "IS_IGNORED": "1",
                           "IS_DISABLED": "1",
                           "LAST_PROCESSED_DATETIME": "2014-05-16T11:49:02Z"
                       },
                       "_time": "2021-01-06T07:27:48Z",
                       "event_type": "host_list_detection"
                   }
           ]}
        }

    return res[next_page]['val'], res[next_page]['next_page']


def main():   # pragma:  no cover
    command = demisto.command()

    demisto.debug(f"Command being called is {command}")
    try:
        if command == 'fetch-assets': 
            last_run = demisto.getAssetsLastRun()
            demisto.debug(f'saved lastrun assets:  {last_run}')

            total_assets = 8
            demisto.debug('Starting fetch for assets')
            next_page = last_run.get('next_page', '1')
            snapshot_id = last_run.get('snapshot_id', round(time.time() * 1000))

            assets, next_run_page = get_host_list_detections_events(next_page)

            if next_run_page:
                new_last_run = {'next_page': next_run_page, 'snapshot_id': snapshot_id,
                                'nextTrigger': '0', "type": FETCH_COMMAND.get('assets')}
            else:
                new_last_run = {'nextTrigger': None, "type": FETCH_COMMAND.get('assets')}

            demisto.debug('sending assets to XSIAM.')
            send_data_to_xsiam(data=assets, vendor=VENDOR, product='assets', data_type='assets', snapshot_id=str(snapshot_id),
                               items_count=total_assets, should_update_health_module=False)

            demisto.setAssetsLastRun(new_last_run)
            if not next_run_page:
                demisto.updateModuleHealth({'{data_type}Pulled'.format(data_type='assets'):  total_assets})
            demisto.debug('finished fetch assets run')

    except Exception as e: 
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError: \n{str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()

