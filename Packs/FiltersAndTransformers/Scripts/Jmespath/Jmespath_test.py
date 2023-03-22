from Jmespath import jmespath_search, main
import demistomock as demisto
import json


def test_search():
    expression = "AutoFocus.IP[?IndicatorType=='IPV4_ADDRESS'].{Value: IndicatorValue, Type: IndicatorType}"
    value = {
        "AutoFocus": {
            "IP": [{
                "IndicatorType": "IPV4_ADDRESS",
                "IndicatorValue": "1.1.1.1",
            }, {
                "IndicatorType": "IPV4_ADDRESS",
                "IndicatorValue": "2.2.2.2",
            }]
        }
    }
    result = jmespath_search(expression, value)
    assert result == [
        {
            "Value": "1.1.1.1",
            "Type": "IPV4_ADDRESS"
        },
        {
            "Value": "2.2.2.2",
            "Type": "IPV4_ADDRESS"
        }
    ]


def test_search_string(mocker):
    expression = "AutoFocus.IP[?IndicatorType=='IPV4_ADDRESS'].{Value: IndicatorValue, Type: IndicatorType}"
    value = json.dumps({
        "AutoFocus": {
            "IP": [{
                "IndicatorType": "IPV4_ADDRESS",
                "IndicatorValue": "1.1.1.1",
            }, {
                "IndicatorType": "IPV4_ADDRESS",
                "IndicatorValue": "2.2.2.2",
            }]
        }
    })
    mocker.patch.object(demisto, 'args', return_value={'value': value, 'expression': expression})
    mocker.patch.object(demisto, 'results')
    main()
    res = demisto.results.call_args[0][0]
    assert res == ([
        {
            "Value": "1.1.1.1",
            "Type": "IPV4_ADDRESS"
        },
        {
            "Value": "2.2.2.2",
            "Type": "IPV4_ADDRESS"
        }
    ])
