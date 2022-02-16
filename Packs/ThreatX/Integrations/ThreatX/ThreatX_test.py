from ThreatX import *


def test_blacklist_ip_command_with_singel_ip(mocker):
    mocker.patch('ThreatX.blacklist_ip', return_value='127.0.0.1')
    return_results_mocker = mocker.patch('ThreatX.return_results')
    blacklist_ip_command({'ip': '127.0.0.1'})
    assert return_results_mocker.call_args[0][0].outputs[0] == '127.0.0.1'


def test_blacklist_ip_command_with_multiple_ips(mocker):
    ips = '127.0.0.1,127.0.0.2'
    ips_list = ips.split(',')

    def iter_ips(a, _b):
        return a
    mocker.patch('ThreatX.blacklist_ip', side_effect=iter_ips)
    return_results_mocker = mocker.patch('ThreatX.return_results')
    blacklist_ip_command({'ip': ips})
    assert return_results_mocker.call_args[0][0].outputs == ips_list


def test_blacklist_ip_command_with_multiple_ips_and_error(mocker, capfd):
    ips = '127.0.0.1,test'

    def iter_ips(a, _b):
        if a == 'test':
            raise DemistoException('TEST')
        return a
    mocker.patch('ThreatX.blacklist_ip', side_effect=iter_ips)
    return_results_mocker = mocker.patch('ThreatX.return_results')
    return_error_mocker = mocker.patch('ThreatX.return_error')
    with capfd.disabled():
        blacklist_ip_command({'ip': ips})
    assert return_results_mocker.call_args[0][0].outputs == ['127.0.0.1']
    assert return_error_mocker.call_args[0][0] == "Failed to add ip: test to blacklist error: TEST"
