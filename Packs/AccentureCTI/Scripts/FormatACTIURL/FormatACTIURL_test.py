from FormatACTIURL import url_to_uuid


def test_url_to_uuid_func():
    expected_output = "a487dfdc-08b4-49a09-82ea-2d934c27d901"
    intelligence_alert_link = (
        "https://intelgraph.idefense.com/#/node/intelligence_alert/view/a487dfdc-08b4-49a09-82ea-2d934c27d901"
    )
    intelligence_report_link = (
        "https://intelgraph.idefense.com/#/node/intelligence_report/view/a487dfdc-08b4-49a09-82ea-2d934c27d901"
    )

    assert url_to_uuid(intelligence_alert_link) == expected_output
    assert url_to_uuid(intelligence_report_link) == expected_output
