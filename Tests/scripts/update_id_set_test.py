import os
import json
import sys
import tempfile
WIDGET_DATA = {
    "id": "temp-widget-dup-check",
    "version": -1,
    "fromVersion": "3.5.0",
    "name": "check duplicate",
    "dataType": "incidents",
    "widgetType": "pie"
}

REPORT_DATA = {
    "id": "temp-report-dup-check",
    "name": "Critical and High incidents",
    "description": "All critical and high severity incidents that may need the analyst attention.",
    "fromVersion": "3.5.0"
}

CLASSIFIER_DATA = {
    "id": "dup_check-classifier",
    "version": -1,
    "modified": "2018-05-21T12:41:29.542577629Z",
    "defaultIncidentType": "",
    "brandName": "dup_check-classifier-name"
}

LAYOUT_DATA = {
    "TypeName": "layout-dup-check-type-name",
    "kind": "details",
    "fromVersion": "5.0.0",
    "layout": {
        "TypeName": "",
        "id": "layout-dup-check-id",
        "kind": "details",
        "modified": "2019-09-01T12:25:49.808989+03:00",
        "name": "",
        "system": False
    },
    "name": "my-layout",
    "typeId": "layout-dup-check-id",
    "version": -1
}

DASHBOARD_DATA = {
    "id": "dup-check-dashbaord",
    "version": -1,
    "fromVersion": "4.0.0",
    "description": "",
    "name": "My Dashboard",
}

DASHBOARD_DATA2 = {
    "id": "dup-check-dashbaord",
    "version": -1,
    "fromVersion": "4.0.0",
    "description": "",
    "name": "My Dashboard2",
}

INCIDENT_FIELD_DATA = {
    "cliName": "accountid",
    "description": "",
    "fieldCalcScript": "",
    "group": 0,
    "id": "incident_account_field_dup_check",
    "name": "Account ID",
    "fromVersion": "5.0.0"
}


def test_find_duplicates():
    print(os.getcwd())
    sys.path.insert(1, os.getcwd())
    from update_id_set import re_create_id_set
    from update_id_set import find_duplicates
    # Make the script run from content
    os.chdir(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

    # create duplicate report
    temp_report = tempfile.NamedTemporaryFile(mode="w+", prefix='report-',
                                              suffix='.json', dir='Reports')  # disable-secrets-detection
    json.dump(REPORT_DATA, temp_report)
    temp_report.flush()
    os.fsync(temp_report.fileno())
    temp_report2 = tempfile.NamedTemporaryFile(mode="w+", prefix='report-',
                                               suffix='.json', dir='Reports')  # disable-secrets-detection
    json.dump(REPORT_DATA, temp_report2)
    temp_report2.flush()
    os.fsync(temp_report2.fileno())

    # create duplicate Widgets
    temp_widget = tempfile.NamedTemporaryFile(mode="w+", prefix='widget-',
                                              suffix='.json', dir='Widgets')  # disable-secrets-detection
    json.dump(WIDGET_DATA, temp_widget)
    temp_widget.flush()
    os.fsync(temp_widget.fileno())
    temp_widget2 = tempfile.NamedTemporaryFile(mode="w+", prefix='widget-',
                                               suffix='.json', dir='Widgets')  # disable-secrets-detection
    json.dump(WIDGET_DATA, temp_widget2)
    temp_widget2.flush()
    os.fsync(temp_widget2.fileno())

    # create duplicate Classifier
    temp_classifier = tempfile.NamedTemporaryFile(mode="w+", prefix='classifier-',
                                                  suffix='.json', dir='Classifiers')  # disable-secrets-detection
    json.dump(WIDGET_DATA, temp_classifier)
    temp_classifier.flush()
    os.fsync(temp_classifier.fileno())
    temp_classifier2 = tempfile.NamedTemporaryFile(mode="w+", prefix='classifier-',
                                                   suffix='.json', dir='Classifiers')  # disable-secrets-detection
    json.dump(WIDGET_DATA, temp_classifier2)
    temp_classifier2.flush()
    os.fsync(temp_classifier2.fileno())

    # create duplicate Layout
    temp_layout = tempfile.NamedTemporaryFile(mode="w+", prefix='layout-',
                                              suffix='.json', dir='Layouts')  # disable-secrets-detection
    json.dump(LAYOUT_DATA, temp_layout)
    temp_layout.flush()
    os.fsync(temp_layout.fileno())
    temp_layout2 = tempfile.NamedTemporaryFile(mode="w+", prefix='layout-', suffix='.json',  # disable-secrets-detection
                                               dir='Packs/CortexXDR/Layouts')  # disable-secrets-detection
    json.dump(LAYOUT_DATA, temp_layout2)
    temp_layout2.flush()
    os.fsync(temp_layout2.fileno())

    # create duplicate Dashboard
    temp_dashboard = tempfile.NamedTemporaryFile(mode="w+", prefix='dashboard-',
                                                 suffix='.json', dir='Dashboards')  # disable-secrets-detection
    json.dump(DASHBOARD_DATA, temp_dashboard)
    temp_dashboard.flush()
    os.fsync(temp_dashboard.fileno())
    temp_dashboard2 = tempfile.NamedTemporaryFile(mode="w+", prefix='dashboard-',
                                                  suffix='.json', dir='Dashboards')  # disable-secrets-detection
    json.dump(DASHBOARD_DATA2, temp_dashboard2)
    temp_dashboard2.flush()
    os.fsync(temp_dashboard2.fileno())

    # create one incident type field and one indicator type field with same data
    temp_incident_field = tempfile.NamedTemporaryFile(mode='w+', prefix='incidentfield-', suffix='.json',
                                                      dir='IncidentFields')  # disable-secrets-detection
    json.dump(INCIDENT_FIELD_DATA, temp_incident_field)
    temp_incident_field.flush()
    os.fsync(temp_incident_field.fileno())
    temp_indicator_field = tempfile.NamedTemporaryFile(mode='w+', prefix='incidentfield-', suffix='.json',
                                                       dir='IndicatorFields')  # disable-secrets-detection
    json.dump(INCIDENT_FIELD_DATA, temp_indicator_field)
    temp_indicator_field.flush()
    os.fsync(temp_indicator_field.fileno())

    # create temporary file for id_set
    temp_id_set = tempfile.NamedTemporaryFile(mode="w+", prefix='temp_id_set-',
                                              suffix='.json', dir='Tests/scripts')  # disable-secrets-detection
    json_path = temp_id_set.name

    re_create_id_set(json_path, ['Reports', 'Layouts', 'Widgets', 'Classifiers', 'Dashboards',
                                 'IndicatorFields', 'IncidentFields'])
    with open(json_path) as json_file:
        data = json.load(json_file)
        dup_data = find_duplicates(data)
        assert any('temp-widget-dup-check' in i for i in dup_data)
        assert any('temp-report-dup-check' in i for i in dup_data)
        assert any('temp-widget-dup-check' in i for i in dup_data)
        assert any('dup-check-dashbaord' in i for i in dup_data)
        assert any('layout-dup-check-id' in i for i in dup_data)
        assert any('incident_account_field_dup_check' in i for i in dup_data)
