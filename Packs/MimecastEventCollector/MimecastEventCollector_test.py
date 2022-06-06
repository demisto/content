import io
import os
from zipfile import ZipFile
import tempfile
import json

import pytest
import re

from test_data.test_data import WITH_OUT_DUP_TEST, WITH_DUP_TEST, EMPTY_EVENTS_LIST

def test_unpacking_virtual_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        print(f'\ntemp dir path: {tmpdir}\n')
        print(f'files in tmpdir: {os.listdir(tmpdir)}\n')
        with ZipFile('test_data/Archive.zip', 'r') as zip_ref:
            zip_ref.extractall(tmpdir)
            extracted_logs_list = []
            for file in os.listdir(tmpdir):
                with open(os.path.join(tmpdir, file)) as json_res:
                    extracted_logs_list.append(json.load(json_res))
            print(f'files after extraction {os.listdir(tmpdir)}')


def test_tmpdir():
    temp_dir = tempfile.TemporaryDirectory()
    print('\n\n', temp_dir.name)
    # use temp_dir, and when done:
    temp_dir.cleanup()


def test_process_audit_data():
    with open('test_data/audit_logs.json') as f:
        data = json.load(f).get('data', [])
        event_list = []
        for event in data:
            event_list.append(event)
        print(event_list)


def test_set_last_run():
    from MimecastFromGitHub import set_last_run, EventTypeEnum, LastRun
    set_last_run(EventTypeEnum.SIEM_LOGS, 'siem')
    assert LastRun == {'siem_last_run': 'siem', 'audit_last_run': ''}
    set_last_run(EventTypeEnum.AUDIT_LOGS, 'audit')
    assert LastRun == {'siem_last_run': 'siem', 'audit_last_run': 'audit'}

# def write_file(file_name, data_to_write):
#     if '.zip' in file_name:
#         try:
#             byte_content = io.BytesIO(data_to_write)
#             zip_file = ZipFile(byte_content)
#             zip_file.extractall(LOG_FILE_PATH)
#         except Exception as e:
#             print('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))
#             quit()
#
#     else:
#         try:
#             with open(file_name, 'w') as f:
#                 f.write(data_to_write)
#         except Exception as e:
#             print('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))
#             quit()


@pytest.mark.parametrize('audit_response, res', [(
        {
            "meta": {
                "status": 200,
                "pagination": {
                    "pageSize": 230,
                    "next": "eNotj8sKgkAUQP_lbhUyUyqhhWVFSDbRG9r4uNqYOjbjTFL070W1PHAW5zyhDjMU9IE0Acc2DB0ExpJ_Eaz8lhZtq8WIm2WktHPHwnPnuCnnVebb3qBuJ9nicunPiK_Z01OeLnaHNJLKH64CNyCmme93XdEkMZrKGFd37TT0_PvW69ulOWVNOehZ9WPd9ogyiDsC_RsTyDJCDs4nhQrCUVEmBThpWAj8GVt2xQqcShaFDgq5oOyDXR04xownogl58995vQHKLUrC"
                }
            },
            "data": [
                {
                    "id": "eNoVzt0KgjAAQOF32a1B23SpQRemZrEoKy2EbkrnT6ULndOK3j17gI9zPqBhcVuzIgFToPEAEk_a6xotozs5j_eQMvEqvSqjxDGevZ2t8lxf-FQhbnRLV-EpvbaSmtuNtfExvh1D1IgkZljCedUpkenQLnB0UmKXi9JQted716u-hL41AyNwaZNCPHj2jyNdM5BhIm0E4rYRvGR1zBM2XNnhwUIQW1idDEayuil4NYDvD0ccOyU",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T12:50:33+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
                {
                    "id": "eNoVzkkOgjAAQNG7dIsLWkCKiQsmCWKwKkhYIpQpQAmUIRrvLh7g5f8PGGk6DbTKwAH0pE4aJViwYfEIXfD93CyO2Tpd4SkW7lezcMtSPRFPUOy4zt0wyl_T7GlXX_cJQvUzhCPPUopm0egWIdYsbwksVWmRzXiLJbl_31aJzCLRj2AHkimreMOKfxuqMoZYg9IOpNPIWUuHlGV0mzLDhw5FpCNpv5mZDmPFug18f0rLOy0",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T12:50:33+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
                {
                    "id": "eNoVzkkOgjAAQNG7dCsLWmYTFwUca7AEkbDEtiDGUsNoNN5dPMDL_x_QCTa0ouZgCQ6Gj6-ZWcRyYjtYUH7EEUnktqmIFbrPV1DtbzdnQ8nCWuf3cp9m5XUYiXeKcEQRul9S2PWcCTTqfjMtci8k0zl0LInWqpeuYT7f8cugo07xCmigGHjdP1T1b0PHdKFnQ0cDbOh6JUXLFBfzVJAmGOoII8OezSjarlbNDL4_Ets63Q",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T11:35:31+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 09:35:31 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
                {
                    "id": "eNoVzkkOgjAAQNG7dIsLWmYTF5WiQSJiFAlLKWVSKAIFovHu4gFe_v-AnlHRsTIFa5AcuYviB3Qw0cmBvqJJ8Mau903uacRsZzt3i8LYBZ6kOXGVuWGUJWL0rJOP_QCh6hbCfkgpQ6O8bSYptog3XYmh1cjhQ20qavs-z0owygHegBW4i7Qcnjz_t6GhmtCCqrECVPQDr1lHecqWKTu8YCgjjBR9MSPr-pI3C_j-AFEpO0E",
                    "auditType": "User Logged On",
                    "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                    "eventTime": "2022-05-31T9:05:31+0000",
                    "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 09:05:31 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                    "category": "authentication_logs"
                },
            ]
        },
        [
            {
                "id": "eNoVzt0KgjAAQOF32a1B23SpQRemZrEoKy2EbkrnT6ULndOK3j17gI9zPqBhcVuzIgFToPEAEk_a6xotozs5j_eQMvEqvSqjxDGevZ2t8lxf-FQhbnRLV-EpvbaSmtuNtfExvh1D1IgkZljCedUpkenQLnB0UmKXi9JQted716u-hL41AyNwaZNCPHj2jyNdM5BhIm0E4rYRvGR1zBM2XNnhwUIQW1idDEayuil4NYDvD0ccOyU",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T12:50:33+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            },
            {
                "id": "eNoVzkkOgjAAQNG7dIsLWkCKiQsmCWKwKkhYIpQpQAmUIRrvLh7g5f8PGGk6DbTKwAH0pE4aJViwYfEIXfD93CyO2Tpd4SkW7lezcMtSPRFPUOy4zt0wyl_T7GlXX_cJQvUzhCPPUopm0egWIdYsbwksVWmRzXiLJbl_31aJzCLRj2AHkimreMOKfxuqMoZYg9IOpNPIWUuHlGV0mzLDhw5FpCNpv5mZDmPFug18f0rLOy0",
                "auditType": "User Logged On",
                "user": "outbound-auth@journal.paloaltonetworks.mime.integration.com",
                "eventTime": "2022-05-31T12:50:33+0000",
                "eventInfo": "Successful authentication for outbound-auth@journal.paloaltonetworks.mime.integration.com <SMTP Outbound Auth>, Date: 2022-05-31, Time: 08:50:33 GMT-04:00, IP: 54.243.138.179, Application: SMTP-MTA2, Method: Cloud",
                "category": "authentication_logs"
            }
        ]
)])
def test_filter_same_time_events(audit_response, res):
    time = "2022-05-31T12:50:33+0000"
    data = audit_response.get('data', [])
    same_time_events = []
    for event in data:
        if event.get('eventTime', '') == time:
            same_time_events.append(event)
    assert same_time_events == res


@pytest.mark.parametrize('audit_events, last_run_potential_dup, res', [
    (WITH_OUT_DUP_TEST.get('audit_events'), WITH_OUT_DUP_TEST.get('last_run_potential_dup'),
     WITH_OUT_DUP_TEST.get('audit_events')),
    (WITH_DUP_TEST.get('audit_events'), WITH_DUP_TEST.get('last_run_potential_dup'), WITH_DUP_TEST.get('res')),
    (EMPTY_EVENTS_LIST.get('audit_events'), EMPTY_EVENTS_LIST.get('last_run_potential_dup'),
     EMPTY_EVENTS_LIST.get('res'))
])
def test_dedup_audit_events(audit_events, last_run_potential_dup, res):
    from MimecasrConnector import dedup_audit_events
    assert dedup_audit_events(audit_events, last_run_potential_dup) == res


@pytest.mark.parametrize('lst1, lst2 ,res', [
    ([1, 2, 3], [4, 5, 6], [1, 2, 3, 4, 5, 6]),
    ([1, 2, 3], ['a', 'b'], [1, 2, 3, 'a', 'b']),
    ([], [], []),
    ([{'g': 'g'}], [5], [{'g': 'g'}, 5]),
    (['t'] , [], ['t'])
])
def test_gather_events(lst1, lst2, res):
    from MimecasrConnector import gather_events
    assert gather_events(lst1, lst2) == res
