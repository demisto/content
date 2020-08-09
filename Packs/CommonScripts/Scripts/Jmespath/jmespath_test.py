from jmespath_transformer import jmespath_search


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
