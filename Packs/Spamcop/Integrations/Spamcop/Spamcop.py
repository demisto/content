import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' IMPORTS '''


from socket import gaierror


def results_return(command, thingtoreturn):
    for item in thingtoreturn:
        description = ''
        ip_reputation = {
            'indicator': item['Address'],
        }
        try:
            if item['Malicious']['Vendor']:
                score = Common.DBotScore.BAD
                description = ip_reputation['description'] = item['Malicious']['Description']
            else:
                score = Common.DBotScore.NONE
                demisto.debug(f"No Malicious Vendor -> {score=}")
        except LookupError:
            score = Common.DBotScore.NONE
        dbot_score = Common.DBotScore(
            indicator=item['Address'],
            indicator_type=DBotScoreType.IP,
            integration_name='Spamcop',
            malicious_description=description,
            score=score,
            reliability=demisto.params().get('integrationReliability')
        )
        ip = Common.IP(
            ip=item['Address'],
            dbot_score=dbot_score
        )
        results = CommandResults(
            outputs_prefix='Spamcop.' + str(command),
            outputs_key_field='indicator',
            outputs=ip_reputation,
            indicator=ip
        )
        return_results(results)


def get_ip_details(ip):
    finaldata = []
    listofips = str(ip).split(',')
    for item in listofips:
        reverselist = str(item).split('.')
        address = reverselist[3] + '.' + reverselist[2] + '.' + reverselist[1] + '.' + reverselist[0] + '.bl.spamcop.net'
        try:
            result = socket.gethostbyname(address)
            if result == '127.0.0.2':
                data = {'Address': item,
                        'Malicious': {'Vendor': 'Spamcop',
                                      'Description': 'IP was found to be on the Spamcop block list'}}
                finaldata.append(data)
        except gaierror:
            data = {'Address': item}
            finaldata.append(data)
        except Exception as e:
            return_error(f'Error from Spamcop - {str(e)}.')

    return finaldata


def test_module():
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    Returns:
        'ok' if test passed, anything else will fail the test.
    """
    result = socket.gethostbyname('www.spamcop.net')
    reverselist = str(result).split('.')
    address = reverselist[3] + '.' + reverselist[2] + '.' + reverselist[1] + '.' + reverselist[0] + '.bl.spamcop.net'
    try:
        testresult = socket.gethostbyname(address)
        return 'Test Failed. Spamcop is blocklisted ' + str(testresult)
    except gaierror:
        return 'ok'
    except Exception as e:
        return f'Error from Spamcop - {str(e)}.'


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """

    demisto.info(f'Command being called is {demisto.command()}')
    try:
        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module()
            demisto.results(result)

        elif demisto.command() == 'ip':
            results_return('IP', get_ip_details(demisto.args().get('ip')))

    # Log exceptions
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command. Error: {str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
