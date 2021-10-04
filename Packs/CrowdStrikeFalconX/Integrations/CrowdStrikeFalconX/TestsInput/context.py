from CommonServerPython import DemistoException

SEND_UPLOADED_FILE_TO_SENDBOX_ANALYSIS_CONTEXT = {
    'csfalconx.resource(val.submitted_id === obj.submitted_id)':
        [{'submitted_id': 'id',
          'state': 'created',
          'created_timestamp': '2020-05-12T15:34:11Z',
          'environment_id': 160,
          'sha256': 'sha256'
          }]
}

SEND_URL_TO_SANDBOX_ANALYSIS_CONTEXT = {
    'csfalconx.resource(val.submitted_id === obj.submitted_id)':
        [{
            'submitted_id': 'id',
            'state': 'created',
            'created_timestamp': '2020-05-12T16:40:52Z',
            'environment_id': 160
        }]
}

GET_REPORT_SUMMARY_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        [{
            'id': 'id',
            'verdict': 'no specific threat',
            'created_timestamp': '2020-03-16T17:04:48Z',
            'ioc_report_strict_csv_artifact_id': 'ioc_report_strict_csv_artifact_id',
            'ioc_report_broad_csv_artifact_id': 'ioc_report_broad_csv_artifact_id',
            'ioc_report_strict_json_artifact_id': 'ioc_report_strict_json_artifact_id',
            'ioc_report_broad_json_artifact_id': 'ioc_report_broad_json_artifact_id',
            'ioc_report_strict_stix_artifact_id': 'ioc_report_strict_stix_artifact_id',
            'ioc_report_broad_stix_artifact_id': 'ioc_report_broad_stix_artifact_id',
            'ioc_report_strict_maec_artifact_id': 'ioc_report_strict_maec_artifact_id',
            'ioc_report_broad_maec_artifact_id': 'ioc_report_broad_maec_artifact_id',
            'environment_id': 160,
            'environment_description': 'Windows 10 64 bit',
            'threat_score': 13,
            'submit_url': 'hxxps://www.google.com',
            'submission_type': 'page_url',
            'sha256': 'sha256'
        }]
}

GET_ANALYSIS_STATUS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        [{
            'id': 'id',
            'state': 'success',
            'created_timestamp': '2020-03-16T17:04:48Z',
            'environment_id': 160
        }]
}

CHECK_QUOTA_STATUS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        [{
            'total': 100,
            'used': 47,
            'in_progress': 2
        }]
}

FIND_SANDBOX_REPORTS_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        [{
            'resources': ['resources1', 'resources2', 'resources3', 'resources4']
        }]
}

FIND_SUBMISSION_ID_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        [{
            'resources': ['resources1', 'resources2', 'resources3', 'resources4']
        }]
}

GET_FULL_REPORT_CONTEXT = {
    'csfalconx.resource(val.id === obj.id)':
        [{
            'id': 'id',
            'verdict': 'no specific threat',
            'created_timestamp': '2020-03-16T17:04:48Z',
            'ioc_report_strict_csv_artifact_id': 'ioc_report_strict_csv_artifact_id',
            'ioc_report_broad_csv_artifact_id': 'ioc_report_broad_csv_artifact_id',
            'ioc_report_strict_json_artifact_id': 'ioc_report_strict_json_artifact_id',
            'ioc_report_broad_json_artifact_id': 'ioc_report_broad_json_artifact_id',
            'ioc_report_strict_stix_artifact_id': 'ioc_report_strict_stix_artifact_id',
            'ioc_report_broad_stix_artifact_id': 'ioc_report_broad_stix_artifact_id',
            'ioc_report_strict_maec_artifact_id': 'ioc_report_strict_maec_artifact_id',
            'ioc_report_broad_maec_artifact_id': 'ioc_report_broad_maec_artifact_id',
            'environment_id': 160,
            'environment_description': 'Windows 10 64 bit',
            'threat_score': 13,
            'submit_url': 'hxxps://www.google.com',
            'submission_type': 'page_url',
            'sha256': 'sha256'
        }]
}

MULTIPLE_ERRORS_RESULT = DemistoException('403: access denied, authorization failed\n401: test error #1\n402: test error #2')
