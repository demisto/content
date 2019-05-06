import demistomock as demisto
from rasterize import rasterize
from CommonServerPython import entryTypes


def test_rasterize_error(mocker):
    url = 'https://attivazione-sicurezzaweb-2019.com/dati/'  # disable-secrets-detection

    args = {
        'url': url
    }
    mocker.patch.object(demisto, 'args',
                        return_value=args)
    mocker.patch.object(demisto, 'results')
    rasterize()
    assert demisto.results.call_count == 1
    results = demisto.results.call_args[0]
    assert len(results) == 1
    assert results[0]['Type'] == entryTypes['error']
    assert results[0]['Contents'] == "PhantomJS returned - Can't access the URL. It might be malicious, " \
                                     "or unreachable for one of several reasons."
