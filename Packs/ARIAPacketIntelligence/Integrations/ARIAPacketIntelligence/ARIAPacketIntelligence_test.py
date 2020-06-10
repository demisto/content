from ARIAPacketIntelligence import *
import pytest
import random
import requests_mock


class TestARIA:
    sdso = 'sdso_mock_server'
    sdso_url = f'http://{sdso}:7443/Aria/SS/1.0.0/PBaaS/server'
    aria = ARIA(sdso_url)

    label_sia_group = 'mock_sia_group'
    label_sia_name = 'mock_sia_name'
    label_sia_region = 'mock_sia_region'

    # write a ip generate function to skip the secret check
    @staticmethod
    def _ip(ip1=None, ip2=None, ip3=None, ip4=None):

        ip1 = random.randint(0, 255) if ip1 is None else ip1

        ip2 = random.randint(0, 255) if ip2 is None else ip2

        ip3 = random.randint(0, 255) if ip3 is None else ip3

        ip4 = random.randint(0, 255) if ip4 is None else ip4

        return f'{str(ip1)}.{str(ip2)}.{str(ip3)}.{str(ip4)}'

    def _mock_request(self, function_name, demisto_args):
        # mock data
        mock_fqn = '<sds_cluster_0>.<sds_node_sia_mock>.<sds_component_PacketIntelligence>.' \
                   '<sds_uuid_b84af73d-03df-48d1-9624-61849abde4d2>'
        mock_trid = '587a0dc8-c8a4-06a7-254a-91b34e179518'
        mock_endpoint_entry = {
            'FQN': mock_fqn,
            'IPAddress': 'Mock_IP',
            'Model': 'sia-lx2160',
            'OS': 'GNU/Linux',
            'Processor': 'sia-lx2160',
            'Processors': 1,
            'trid': mock_trid
        }
        mock_response_ruleforward = {
            'endpoints': [mock_endpoint_entry],
            'timestamp': 123456789
        }
        mock_tcl_entry = {
            'PC_TRID': mock_trid,
            'status': 'SUCCESS - The transaction completed successfully.'
        }
        mock_response_trid = {
            'tclCount': 1,
            'tclList': [mock_tcl_entry]
        }
        trid_url = self.sdso_url + f'/packetClassification/completion/transaction?PC_TRID={mock_trid}'
        ruleforward_url = self.sdso_url + '/ruleForward'

        functions_dict = {
            'aria-block-conversation': block_conversation_command,
            'aria-unblock-conversation': unblock_conversation_command,
            'aria-record-conversation': record_conversation_command,
            'aria-stop-recording-conversation': stop_recording_conversation_command,
            'aria-alert-conversation': alert_conversation_command,
            'aria-mute-alert-conversation': mute_alert_conversation_command,
            'aria-block-dest-port': block_dest_port_command,
            'aria-unblock-dest-port': unblock_dest_port_command,
            'aria-record-dest-port': record_dest_port_command,
            'aria-stop-recording-dest-port': stop_recording_dest_port_command,
            'aria-alert-dest-port': alert_dest_port_command,
            'aria-mute-alert-dest-port': mute_alert_dest_port_command,
            'aria-block-src-port': block_src_port_command,
            'aria-unblock-src-port': unblock_src_port_command,
            'aria-record-src-port': record_src_port_command,
            'aria-stop-recording-src-port': stop_recording_src_port_command,
            'aria-alert-src-port': alert_src_port_command,
            'aria-mute-alert-src-port': mute_alert_src_port_command,
            'aria-block-dest-subnet': block_dest_subnet_command,
            'aria-unblock-dest-subnet': unblock_dest_subnet_command,
            'aria-record-dest-subnet': record_dest_subnet_command,
            'aria-stop-recording-dest-subnet': stop_recording_dest_subnet_command,
            'aria-alert-dest-subnet': alert_dest_subnet_command,
            'aria-mute-alert-dest-subnet': mute_alert_dest_subnet_command,
            'aria-block-src-subnet': block_src_subnet_command,
            'aria-unblock-src-subnet': unblock_src_subnet_command,
            'aria-record-src-subnet': record_src_subnet_command,
            'aria-stop-recording-src-subnet': stop_recording_src_subnet_command,
            'aria-alert-src-subnet': alert_src_subnet_command,
            'aria-mute-alert-src-subnet': mute_alert_src_subnet_command
        }

        call_func = functions_dict.get(function_name)

        with requests_mock.Mocker() as m:
            m.register_uri(method='PUT', url=ruleforward_url, json=mock_response_ruleforward, status_code=201)
            m.register_uri(method='GET', url=trid_url, json=mock_response_trid)
            _, ec = call_func(self.aria, demisto_args)
        context_entry = list(ec.values())[0]
        assert context_entry.get('Status').get('code') == 201
        assert context_entry.get('Status').get('command_state') == 'Success'
        for ep in context_entry.get('Endpoints'):
            assert ep.get('completion') is True

    def test_process_ip_address(self):
        # invalid ip format raises ValueError Exception
        ip_addr_invalid = ['0', '11,22,33,44', TestARIA()._ip(111, 222, 333, 444), f'{TestARIA()._ip(1, 2, 3, 4)}|32',
                           f'{TestARIA()._ip(25, 89, 125, 255)}/33', TestARIA()._ip(10, 20, 30, 256)]

        for i in range(0, len(ip_addr_invalid)):
            with pytest.raises(ValueError):
                ARIA(self.sdso_url)._process_ip_address(ip=ip_addr_invalid[i])

        # valid ip format input
        ip_addr_valid = ['1.2. 3.4', f'{TestARIA()._ip(1, 2, 3, 4)}  /32',
                         f'{TestARIA()._ip(255, 255, 255, 255)}/ 24', '10.20.30. 40']

        for i in range(0, len(ip_addr_valid)):
            res = ARIA(self.sdso_url)._process_ip_address(ip=ip_addr_valid[i])
            # output IP addresses are in format like 1.2.3.4/32
            if '/' in ip_addr_valid[i]:
                assert res == ip_addr_valid[i].replace(' ', '')
            else:
                assert res == ip_addr_valid[i].replace(' ', '') + '/32'

    def test_process_port_range(self):
        # invalid port range format raises ValeError Exception
        port_range_invalid = ['0-65536', '80_8000', '8000-80', '0, 8000 - 80', '0,1,2,']

        for i in range(0, len(port_range_invalid)):
            with pytest.raises(ValueError):
                ARIA(self.sdso_url)._process_port_range(port_range=port_range_invalid[i])

        # valid port range input
        port_range_valid = ['0-65535', None, '80-8000', '80, 100 -8000', '100, 101-1024, 1025 - 65535']

        for i in range(0, len(port_range_valid)):
            res = ARIA(self.sdso_url)._process_port_range(port_range=port_range_valid[i])
            if port_range_valid[i] is None:
                assert res == '0 - 65535'
            else:
                # input port range will be changed in format like 80, 800 - 8000, ...
                assert res == port_range_valid[i].replace(' ', '').replace(',', ', ').replace('-', ' - ')

    def test_build_alert_instruction(self):
        # invalid alert parameter raises ValueError Exception

        transport_type = ['text', 'email', 'syslog', 'SMS', 'webhook']
        tti_index = ['0', '8', '1', '2', '3']
        aio_index = ['0', '1', '16', '15', '14']
        trigger_type = ['one-shot', 're-trigger-count', 're-trigger-timed-ms', 'two-shot', 're-trigger-timed-sec']
        trigger_value = ['1', '100', '1000', '8191', '8192']
        for i in range(0, len(transport_type)):
            with pytest.raises(ValueError):
                ARIA(self.sdso_url)._build_alert_instruction(transport_type={transport_type[i]},
                                                             tti_index={tti_index[i]}, aio_index={aio_index[i]},
                                                             trigger_type={trigger_type[i]},
                                                             trigger_value={trigger_value[i]})

    def test_block_conversation_command(self):
        demisto_args = {
            'src_ip': TestARIA()._ip(1, 2, 3, 4),
            'target_ip': TestARIA()._ip(5, 6, 7, 8),
            'rule_name': 'block_conversation',
            'src_port': '0-65535'
        }
        self._mock_request('aria-block-conversation', demisto_args)

    def test_unblock_conversation_command(self):
        demisto_args = {
            'rule_name': 'block_conversation'
        }
        self._mock_request('aria-unblock-conversation', demisto_args)

    def test_record_conversation_command(self):
        demisto_args = {
            'src_ip': f'{TestARIA()._ip(11, 22, 33, 44)}/24',
            'target_ip': f'{TestARIA()._ip(55, 66, 77, 88)}/32',
            'rule_name': 'record_conversation',
            'src_port': '0-1000',
            'target_port': '0-1000, 5000-6000',
            'protocol': 'TCP',
            'vlan_id': '123',
            'transport_type': 'email',
            'trigger_type': 'one-shot',
            'trigger_value': '1',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-record-conversation', demisto_args)

    def test_stop_recording_conversation_command(self):
        demisto_args = {
            'rule_name': 'record_conversation'
        }
        self._mock_request('aria-stop-recording-conversation', demisto_args)

    def test_alert_conversation_command(self):
        demisto_args = {
            'src_ip': TestARIA()._ip(192, 168, 0, 1),
            'target_ip': TestARIA()._ip(10, 20, 30, 40),
            'rule_name': 'alert_conversation',
            'protocol': 'UDP',
            'transport_type': 'syslog',
            'trigger_type': 'one-shot',
            'trigger_value': '100',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-alert-conversation', demisto_args)

    def test_mute_alert_conversation_command(self):
        demisto_args = {
            'rule_name': 'alert_conversation'
        }
        self._mock_request('aria-mute-alert-conversation', demisto_args)

    def test_block_dest_port_command(self):
        demisto_args = {
            'rule_name': 'block_dest_port',
            'port_range': '1111-2222'
        }
        self._mock_request('aria-block-dest-port', demisto_args)

    def test_unblock_dest_port_command(self):
        demisto_args = {
            'rule_name': 'block_dest_port',
        }
        self._mock_request('aria-unblock-dest-port', demisto_args)

    def test_record_dest_port_command(self):
        demisto_args = {
            'rule_name': 'record_dest_port',
            'port_range': '10, 20 - 50, 90, 65535',
            'vlan_id': '123',
            'transport_type': 'email',
            'trigger_type': 're-trigger-count',
            'trigger_value': '8191',
            'tti_index': '0',
            'aio_index': '0',
            'label_sia_region': self.label_sia_region,
            'label_sia_group': self.label_sia_group
        }
        self._mock_request('aria-record-dest-port', demisto_args)

    def test_stop_recording_dest_port_command(self):
        demisto_args = {
            'rule_name': 'record_dest_port',
            'label_sia_region': self.label_sia_region,
            'label_sia_group': self.label_sia_group
        }
        self._mock_request('aria-stop-recording-dest-port', demisto_args)

    def test_alert_dest_port_command(self):
        demisto_args = {
            'rule_name': 'alert_dest_port',
            'port_range': '0-65535',
            'transport_type': 'email',
            'trigger_type': 're-trigger-timed-sec',
            'trigger_value': '100',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-alert-dest-port', demisto_args)

    def test_mute_alert_dest_port_command(self):
        demisto_args = {
            'rule_name': 'alert_dest_port'
        }
        self._mock_request('aria-mute-alert-dest-port', demisto_args)

    def test_block_src_port_command(self):
        demisto_args = {
            'rule_name': 'block_src_port',
            'port_range': '1, 10-100',
            'label_sia_name': self.label_sia_name,
            'label_sia_group': self.label_sia_group
        }
        self._mock_request('aria-block-src-port', demisto_args)

    def test_unblock_src_port_command(self):
        demisto_args = {
            'rule_name': 'block_src_port'
        }
        self._mock_request('aria-unblock-src-port', demisto_args)

    def test_record_src_port_command(self):
        demisto_args = {
            'rule_name': 'record_src_port',
            'port_range': '10, 20 - 50, 90, 65535',
            'vlan_id': '345'
        }
        self._mock_request('aria-record-src-port', demisto_args)

    def test_stop_recording_src_port_command(self):
        demisto_args = {
            'rule_name': 'record_src_port'
        }
        self._mock_request('aria-stop-recording-src-port', demisto_args)

    def test_alert_src_port_command(self):
        demisto_args = {
            'rule_name': 'alert_src_port',
            'port_range': '0-30000',
            'transport_type': 'syslog',
            'trigger_type': 're-trigger-timed-ms',
            'trigger_value': '1000',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-alert-src-port', demisto_args)

    def test_mute_alert_src_port_command(self):
        demisto_args = {
            'rule_name': 'alert_src_port'
        }
        self._mock_request('aria-mute-alert-src-port', demisto_args)

    def test_block_dest_subnet_command(self):
        demisto_args = {
            'rule_name': 'block_dest_subnet',
            'target_ip': f'{TestARIA()._ip(1, 2, 3, 4)}/32',
            'label_sia_name': self.label_sia_name,
            'label_sia_region': self.label_sia_region
        }
        self._mock_request('aria-block-dest-subnet', demisto_args)

    def test_unblock_dest_subnet_command(self):
        demisto_args = {
            'rule_name': 'block_dest_subnet',
            'label_sia_name': self.label_sia_name,
            'label_sia_region': self.label_sia_region
        }
        self._mock_request('aria-unblock-dest-subnet', demisto_args)

    def test_record_dest_subnet_command(self):
        demisto_args = {
            'rule_name': 'record_dest_subnet',
            'target_ip': TestARIA()._ip(192, 100, 0, 68),
            'transport_type': 'syslog',
            'vlan_id': '999',
            'sia_interface': 'B',
            'trigger_type': 're-trigger-count',
            'trigger_value': '1',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-record-dest-subnet', demisto_args)

    def test_stop_recording_dest_subnet_command(self):
        demisto_args = {
            'rule_name': 'record_dest_subnet'
        }
        self._mock_request('aria-stop-recording-dest-subnet', demisto_args)

    def test_alert_dest_subnet_command(self):
        demisto_args = {
            'rule_name': 'alert_dest_subnet',
            'target_ip': f'{TestARIA()._ip(11, 22, 33, 44)}/24',
            'transport_type': 'syslog',
            'trigger_type': 're-trigger-timed-ms',
            'trigger_value': '100',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-alert-dest-subnet', demisto_args)

    def test_mute_alert_dest_subnet_command(self):
        demisto_args = {
            'rule_name': 'alert_dest_subnet'
        }
        self._mock_request('aria-mute-alert-dest-subnet', demisto_args)

    def test_block_src_subnet_command(self):
        demisto_args = {
            'rule_name': 'block_src_subnet',
            'src_ip': f'{TestARIA()._ip(2, 3, 4, 5)}/32',
            'label_sia_name': self.label_sia_name,
            'label_sia_region': self.label_sia_region
        }
        self._mock_request('aria-block-src-subnet', demisto_args)

    def test_unblock_src_subnet_command(self):
        demisto_args = {
            'rule_name': 'block_src_subnet',
            'label_sia_name': self.label_sia_name,
            'label_sia_region': self.label_sia_region
        }
        self._mock_request('aria-unblock-src-subnet', demisto_args)

    def test_record_src_subnet_command(self):
        demisto_args = {
            'rule_name': 'record_src_subnet',
            'src_ip': f'{TestARIA()._ip(11, 22, 33, 44)}/32',
            'transport_type': 'email',
            'vlan_id': '345',
            'sia_interface': 'A',
            'trigger_type': 'one-shot',
            'trigger_value': '3333',
            'tti_index': '0',
            'aio_index': '0'
        }
        self._mock_request('aria-record-src-subnet', demisto_args)

    def test_stop_recording_src_subnet_command(self):
        demisto_args = {
            'rule_name': 'record_src_subnet'
        }
        self._mock_request('aria-stop-recording-src-subnet', demisto_args)

    def test_alert_src_subnet_command(self):
        demisto_args = {
            'rule_name': 'alert_src_subnet',
            'src_ip': f'{TestARIA()._ip(1, 1, 1, 1)}/8',
            'transport_type': 'syslog',
            'trigger_type': 're-trigger-timed-ms',
            'trigger_value': '1234',
            'tti_index': '0',
            'aio_index': '0',
            'label_sia_name': self.label_sia_name,
            'label_sia_region': self.label_sia_region
        }
        self._mock_request('aria-alert-src-subnet', demisto_args)

    def test_mute_alert_src_subnet_command(self):
        demisto_args = {
            'rule_name': 'alert_src_subnet',
            'label_sia_name': self.label_sia_name,
            'label_sia_region': self.label_sia_region
        }
        self._mock_request('aria-mute-alert-src-subnet', demisto_args)
