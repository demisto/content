import pytest
import demistomock as demisto

from InstancesCheck_NumberofEnabledInstances import main, ORANGE_HTML_STYLE, GREEN_HTML_STYLE


@pytest.mark.parametrize('incident_ids, expected', [
    (5, f"<h1 style={ORANGE_HTML_STYLE}5</h1>"),
    (1, f"<h1 style={ORANGE_HTML_STYLE}1</h1>"),
    (0, f"<h1 style={GREEN_HTML_STYLE}0</h1>"),
    (None, f"<h1 style={GREEN_HTML_STYLE}0</h1>")
])
def test_script(mocker, incident_ids, expected):
    mocker.patch.object(demisto, 'incidents',
                        return_value=[{'CustomFields': {'totalinstances': incident_ids}}])
    mocker.patch.object(demisto, 'results')

    main()

    html = demisto.results.call_args[0][0].get('Contents')
    assert html == expected
