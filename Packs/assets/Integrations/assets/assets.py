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
                     "LAST_SCAN_DATETIME": "2013-05-03T17: 46: 22Z",
                     "LAST_VM_SCANNED_DATE": "2013-03-14T20: 58: 48Z",
                     "LAST_VM_SCANNED_DURATION": "1921",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "6459270949",
                        "QID": "56118",
                        "TYPE": "Informational",
                        "SEVERITY": "2",
                        "PORT": "11484",
                        "PROTOCOL": "udp",
                        "SSL": "0",
                        "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                        "STATUS": "Inactive",
                        "FIRST_FOUND_DATETIME": "2021-04-16T15: 52: 16Z",
                        "LAST_FOUND_DATETIME": "2020-04-12T13: 40: 22Z",
                        "TIMES_FOUND": "193",
                        "LAST_TEST_DATETIME": "2022-10-27T08: 20: 41Z",
                        "LAST_UPDATE_DATETIME": "2019-10-24T10: 31: 58Z",
                        "LAST_FIXED_DATETIME": "2011-09-28T02: 25: 51Z",
                        "IS_IGNORED": "1",
                        "IS_DISABLED": "1",
                        "LAST_PROCESSED_DATETIME": "2012-03-16T21: 23: 31Z"
                     },
                     "_time": "2010-09-16T15: 39: 09Z",
                     "event_type": "host_list_detection"
                  },
                  {
                     "ID": "48453571",
                     "IP": "255.224.123.217",
                     "TRACKING_METHOD": "MAC",
                     "NETWORK_ID": "8",
                     "OS": "Windows 2012",
                     "NETBIOS": "TRNSISSRV8",
                     "LAST_SCAN_DATETIME": "2012-10-03T09: 15: 37Z",
                     "LAST_VM_SCANNED_DATE": "2014-07-12T16: 04: 07Z",
                     "LAST_VM_SCANNED_DURATION": "1042",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "9760294402",
                        "QID": "95597",
                        "TYPE": "Confirmed",
                        "SEVERITY": "3",
                        "PORT": "5081",
                        "PROTOCOL": "udp",
                        "SSL": "0",
                        "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                        "STATUS": "Inactive",
                        "FIRST_FOUND_DATETIME": "2021-01-04T03: 39: 16Z",
                        "LAST_FOUND_DATETIME": "2022-01-03T06: 13: 09Z",
                        "TIMES_FOUND": "912",
                        "LAST_TEST_DATETIME": "2021-08-22T12: 32: 07Z",
                        "LAST_UPDATE_DATETIME": "2013-01-13T17: 26: 50Z",
                        "LAST_FIXED_DATETIME": "2020-07-01T14: 52: 33Z",
                        "IS_IGNORED": "0",
                        "IS_DISABLED": "0",
                        "LAST_PROCESSED_DATETIME": "2024-02-15T13: 53: 24Z"
                     },
                     "_time": "2022-10-05T22: 57: 11Z",
                     "event_type": "host_list_detection"
                  },
                  {
                     "ID": "29428400",
                     "IP": "122.129.91.225",
                     "TRACKING_METHOD": "MAC",
                     "NETWORK_ID": "9",
                     "OS": "Linux",
                     "NETBIOS": "TRNSISSRV7",
                     "LAST_SCAN_DATETIME": "2022-04-01T23: 58: 06Z",
                     "LAST_VM_SCANNED_DATE": "2018-08-27T04: 08: 42Z",
                     "LAST_VM_SCANNED_DURATION": "896",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "8937818025",
                        "QID": "95845",
                        "TYPE": "Confirmed",
                        "SEVERITY": "4",
                        "PORT": "31156",
                        "PROTOCOL": "tcp",
                        "SSL": "0",
                        "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                        "STATUS": "Inactive",
                        "FIRST_FOUND_DATETIME": "2015-02-11T15: 08: 23Z",
                        "LAST_FOUND_DATETIME": "2020-02-16T18: 09: 36Z",
                        "TIMES_FOUND": "441",
                        "LAST_TEST_DATETIME": "2015-07-01T04: 14: 02Z",
                        "LAST_UPDATE_DATETIME": "2020-03-15T05: 51: 41Z",
                        "LAST_FIXED_DATETIME": "2020-10-29T06: 44: 58Z",
                        "IS_IGNORED": "1",
                        "IS_DISABLED": "0",
                        "LAST_PROCESSED_DATETIME": "2023-10-04T23: 42: 12Z"
                     },
                     "_time": "2016-03-01T07: 14: 48Z",
                     "event_type": "host_list_detection"
                  }
                ]},
           "2": {
               "next_page": '3',
               "val": [
                   {
                       "ID": "47055485",
                       "IP": "224.22.28.196",
                       "TRACKING_METHOD": "HOSTNAME",
                       "NETWORK_ID": "5",
                       "OS": "Windows 2016",
                       "NETBIOS": "TRNSISSRV8",
                       "LAST_SCAN_DATETIME": "2014-11-06T12: 39: 24Z",
                       "LAST_VM_SCANNED_DATE": "2020-11-14T21: 55: 13Z",
                       "LAST_VM_SCANNED_DURATION": "1870",
                       "DETECTION": {
                           "UNIQUE_VULN_ID": "6001433227",
                           "QID": "57069",
                           "TYPE": "Potential",
                           "SEVERITY": "5",
                           "PORT": "61155",
                           "PROTOCOL": "udp",
                           "SSL": "1",
                           "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                           "STATUS": "Inactive",
                           "FIRST_FOUND_DATETIME": "2023-07-15T17: 53: 01Z",
                           "LAST_FOUND_DATETIME": "2015-12-31T17: 50: 12Z",
                           "TIMES_FOUND": "609",
                           "LAST_TEST_DATETIME": "2014-11-26T21: 37: 26Z",
                           "LAST_UPDATE_DATETIME": "2012-08-21T15: 04: 38Z",
                           "LAST_FIXED_DATETIME": "2017-03-10T12: 04: 10Z",
                           "IS_IGNORED": "1",
                           "IS_DISABLED": "0",
                           "LAST_PROCESSED_DATETIME": "2018-07-25T08: 16: 05Z"
                       },
                       "_time": "2020-04-15T20: 08: 20Z",
                       "event_type": "host_list_detection"
                   },
                   {
                     "ID": "29764416",
                     "IP": "245.186.1.40",
                     "TRACKING_METHOD": "MAC",
                     "NETWORK_ID": "3",
                     "OS": "Linux",
                     "NETBIOS": "TRNSISSRV9",
                     "LAST_SCAN_DATETIME": "2011-01-17T09: 52: 29Z",
                     "LAST_VM_SCANNED_DATE": "2015-04-20T18: 19: 25Z",
                     "LAST_VM_SCANNED_DURATION": "519",
                     "DETECTION": {
                        "UNIQUE_VULN_ID": "4628808725",
                        "QID": "16432",
                        "TYPE": "Potential",
                        "SEVERITY": "3",
                        "PORT": "34956",
                        "PROTOCOL": "tcp",
                        "SSL": "1",
                        "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                        "STATUS": "Inactive",
                        "FIRST_FOUND_DATETIME": "2017-04-11T06: 43: 07Z",
                        "LAST_FOUND_DATETIME": "2020-05-01T21: 55: 28Z",
                        "TIMES_FOUND": "519",
                        "LAST_TEST_DATETIME": "2020-06-25T09: 43: 53Z",
                        "LAST_UPDATE_DATETIME": "2022-06-06T07: 39: 17Z",
                        "LAST_FIXED_DATETIME": "2013-06-02T13: 30: 35Z",
                        "IS_IGNORED": "0",
                        "IS_DISABLED": "0",
                        "LAST_PROCESSED_DATETIME": "2014-04-24T22: 24: 08Z"
                     },
                     "_time": "2021-12-28T21: 46: 36Z",
                     "event_type": "host_list_detection"
                  }
                   ]},
           "3": {
               "next_page": '4',
               "val": [
              {
                 "ID": "61775581",
                 "IP": "155.54.33.120",
                 "TRACKING_METHOD": "HOSTNAME",
                 "NETWORK_ID": "10",
                 "OS": "Windows 2016",
                 "NETBIOS": "TRNSISSRV9",
                 "LAST_SCAN_DATETIME": "2010-05-24T16: 25: 59Z",
                 "LAST_VM_SCANNED_DATE": "2011-03-25T21: 04: 33Z",
                 "LAST_VM_SCANNED_DURATION": "837",
                 "DETECTION": {
                    "UNIQUE_VULN_ID": "3770915971",
                    "QID": "38397",
                    "TYPE": "Confirmed",
                    "SEVERITY": "2",
                    "PORT": "30856",
                    "PROTOCOL": "udp",
                    "SSL": "0",
                    "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                    "STATUS": "Inactive",
                    "FIRST_FOUND_DATETIME": "2015-03-01T03: 30: 11Z",
                    "LAST_FOUND_DATETIME": "2023-05-14T02: 16: 54Z",
                    "TIMES_FOUND": "265",
                    "LAST_TEST_DATETIME": "2022-11-16T22: 52: 58Z",
                    "LAST_UPDATE_DATETIME": "2020-02-16T21: 40: 58Z",
                    "LAST_FIXED_DATETIME": "2016-10-19T18: 41: 17Z",
                    "IS_IGNORED": "1",
                    "IS_DISABLED": "0",
                    "LAST_PROCESSED_DATETIME": "2019-08-12T17: 27: 39Z"
                 },
                 "_time": "2013-09-22T14: 58: 18Z",
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
                 "LAST_SCAN_DATETIME": "2024-08-15T09: 17: 02Z",
                 "LAST_VM_SCANNED_DATE": "2014-10-19T23: 45: 41Z",
                 "LAST_VM_SCANNED_DURATION": "817",
                 "DETECTION": {
                    "UNIQUE_VULN_ID": "6322670242",
                    "QID": "60823",
                    "TYPE": "Confirmed",
                    "SEVERITY": "1",
                    "PORT": "44883",
                    "PROTOCOL": "tcp",
                    "SSL": "1",
                    "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                    "STATUS": "Inactive",
                    "FIRST_FOUND_DATETIME": "2023-11-03T07: 50: 37Z",
                    "LAST_FOUND_DATETIME": "2018-01-12T03: 22: 09Z",
                    "TIMES_FOUND": "554",
                    "LAST_TEST_DATETIME": "2012-01-07T14: 13: 22Z",
                    "LAST_UPDATE_DATETIME": "2013-03-26T11: 54: 16Z",
                    "LAST_FIXED_DATETIME": "2021-09-21T19: 12: 22Z",
                    "IS_IGNORED": "0",
                    "IS_DISABLED": "0",
                    "LAST_PROCESSED_DATETIME": "2015-03-18T05: 13: 29Z"
                 },
                 "_time": "2012-11-05T03: 09: 01Z",
                 "event_type": "host_list_detection"
              },
              {
                 "ID": "36690029",
                 "IP": "97.84.74.14",
                 "TRACKING_METHOD": "HOSTNAME",
                 "NETWORK_ID": "2",
                 "OS": "macOS",
                 "NETBIOS": "TRNSISSRV8",
                 "LAST_SCAN_DATETIME": "2013-03-15T11: 26: 13Z",
                 "LAST_VM_SCANNED_DATE": "2011-08-01T05: 29: 18Z",
                 "LAST_VM_SCANNED_DURATION": "855",
                 "DETECTION": {
                    "UNIQUE_VULN_ID": "4440754983",
                    "QID": "69573",
                    "TYPE": "Informational",
                    "SEVERITY": "3",
                    "PORT": "48206",
                    "PROTOCOL": "udp",
                    "SSL": "0",
                    "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                    "STATUS": "Inactive",
                    "FIRST_FOUND_DATETIME": "2016-11-09T03: 36: 01Z",
                    "LAST_FOUND_DATETIME": "2020-10-05T23: 17: 24Z",
                    "TIMES_FOUND": "958",
                    "LAST_TEST_DATETIME": "2011-05-09T09: 23: 42Z",
                    "LAST_UPDATE_DATETIME": "2014-09-12T11: 30: 25Z",
                    "LAST_FIXED_DATETIME": "2023-08-16T00: 17: 32Z",
                    "IS_IGNORED": "1",
                    "IS_DISABLED": "1",
                    "LAST_PROCESSED_DATETIME": "2014-05-16T11: 49: 01Z"
                 },
                 "_time": "2021-01-06T07: 27: 47Z",
                 "event_type": "host_list_detection"
              }
           ]},
           "5": {
               "next_page": None,
               "val": [
              {
                 "ID": "97669178",
                 "IP": "136.213.191.93",
                 "TRACKING_METHOD": "IP",
                 "NETWORK_ID": "10",
                 "OS": "Windows 2016",
                 "NETBIOS": "TRNSISSRV6",
                 "LAST_SCAN_DATETIME": "2015-01-17T02: 21: 37Z",
                 "LAST_VM_SCANNED_DATE": "2014-07-12T11: 32: 28Z",
                 "LAST_VM_SCANNED_DURATION": "264",
                 "DETECTION": {
                    "UNIQUE_VULN_ID": "8393580012",
                    "QID": "68991",
                    "TYPE": "Confirmed",
                    "SEVERITY": "2",
                    "PORT": "30987",
                    "PROTOCOL": "tcp",
                    "SSL": "0",
                    "RESULTS": "Certificate #0 CN=TRNSISSRV5.trnsis.svg.net doesn&apos;t resolve",
                    "STATUS": "Active",
                    "FIRST_FOUND_DATETIME": "2012-04-08T20: 05: 58Z",
                    "LAST_FOUND_DATETIME": "2018-07-10T00: 30: 34Z",
                    "TIMES_FOUND": "242",
                    "LAST_TEST_DATETIME": "2018-06-05T21: 53: 17Z",
                    "LAST_UPDATE_DATETIME": "2019-05-22T16: 11: 34Z",
                    "LAST_FIXED_DATETIME": "2010-12-01T01: 29: 42Z",
                    "IS_IGNORED": "0",
                    "IS_DISABLED": "1",
                    "LAST_PROCESSED_DATETIME": "2012-09-10T06: 06: 51Z"
                 },
                 "_time": "2016-05-15T18: 55: 01Z",
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

            total_assets = 9
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

