from aria_packet_intelligence import *
import pytest
import time
import random
# do not run it in multi-threading
# To run script: $pytest -s file_name.py
# use pytest -s to enter sdso and sia labels
# use pytest -s show the printout information for each case


class TestARIA:
    sdso = input('\nPlease enter your SDSo Node\'s IP address: ')
    sdso_url = f'http://{sdso}:7443/Aria/SS/1.0.0/PBaaS/server'
    aria = ARIA(sdso_url)

    # some function may test with specific label_sia_name, label_sia_region and label_sia_group
    print('\nTest cases will use specific labels of SIA, please enter valid labels for your SIA: ')
    label_sia_group = None
    label_sia_name = None
    label_sia_region = None

    wait_time = 1

    # write a ip generate function to skip the secret check
    def _ip(self, ip1=None, ip2=None, ip3=None, ip4=None):

        ip1 = random.randint(0, 255) if ip1 is None else ip1

        ip2 = random.randint(0, 255) if ip2 is None else ip2

        ip3 = random.randint(0, 255) if ip3 is None else ip3

        ip4 = random.randint(0, 255) if ip4 is None else ip4

        return f'{str(ip1)}.{str(ip2)}.{str(ip3)}.{str(ip4)}'

    def test_process_ip_address(self):

        print('\nCase 1: Test invalid IP input: ')

        # invalid ip format raises ValueError Exception
        ip_addr_invalid = ['0', '11,22,33,44', self._ip(111, 222, 333, 444), f'{self._ip(1, 2, 3, 4)}|32',
                           f'{self._ip(25, 89, 125, 255)}/33', self._ip(10, 20, 30, 256)]

        for i in range(0, len(ip_addr_invalid)):

            with pytest.raises(ValueError):

                self.aria._process_ip_address(ip=ip_addr_invalid[i])

        print('\nCase 2: Test valid IP input: ')

        # valid ip format input
        ip_addr_valid = ['1.2. 3.4', f'{self._ip(1, 2, 3, 4)}  /32',
                         f'{self._ip(255, 255, 255, 255)}/ 24', '10.20.30. 40']

        for i in range(0, len(ip_addr_valid)):

            res = self.aria._process_ip_address(ip=ip_addr_valid[i])

            # output IP addresses are in format like 1.2.3.4/32
            if '/' in ip_addr_valid[i]:
                assert res == ip_addr_valid[i].replace(' ', '')
            else:
                assert res == ip_addr_valid[i].replace(' ', '') + '/32'

    def test_process_port_range(self):

        print('\nCase 3: Test invalid port input: ')

        # invalid port range format raises ValeError Exception
        port_range_invalid = ['0-65536', '80_8000', '8000-80', '0, 8000 - 80', '0,1,2,']

        for i in range(0, len(port_range_invalid)):
            with pytest.raises(ValueError):
                print(f'_process_port_range(port_range={port_range_invalid[i]})')
                self.aria._process_port_range(port_range=port_range_invalid[i])

        print('\nCase 4: Test valid port input: ')

        # valid port range input
        port_range_valid = ['0-65535', None, '80-8000', '80, 100 -8000', '100, 101-1024, 1025 - 65535']

        for i in range(0, len(port_range_valid)):

            print(f'_process_port_range(port_range={port_range_valid[i]})')

            res = self.aria._process_port_range(port_range=port_range_valid[i])

            if port_range_valid[i] is None:
                assert res == '0 - 65535'
            else:
                # input port range will be changed in format like 80, 800 - 8000, ...
                assert res == port_range_valid[i].replace(' ', '').replace(',', ', ').replace('-', ' - ')

    def test_build_alert_instruction(self):

        print('\nCase 5: Test invalid alert instruction: ')

        # invalid alert parameter raises ValueError Exception

        transport_type = ['text', 'email', 'syslog', 'SMS', 'webhook']
        tti_index = ['0', '8', '1', '2', '3']
        aio_index = ['0', '1', '16', '15', '14']
        trigger_type = ['one-shot', 're-trigger-count', 're-trigger-timed-ms', 'two-shot', 're-trigger-timed-sec']
        trigger_value = ['1', '100', '1000', '8191', '8192']
        for i in range(0, len(transport_type)):

            with pytest.raises(ValueError):

                print(f'_build_alert_instruction(transport_type={transport_type[i]}, tti_index={tti_index[i]}, '
                      f'aio_index={aio_index[i]}, trigger_type={trigger_type[i]}, trigger_value={trigger_value[i]})')

                self.aria._build_alert_instruction(transport_type={transport_type[i]}, tti_index={tti_index[i]},
                                                aio_index={aio_index[i]}, trigger_type={trigger_type[i]},
                                                trigger_value={trigger_value[i]})

    def test_block_conversation(self):

        print('\nCase 6: Test block_conversation: ')

        src_ip = self._ip(1, 2, 3, 4)
        target_ip = self._ip(5, 6, 7, 8)
        rule_name = 'block_conversation'
        src_port = '0-65535'
        target_port = None
        print(f'block_conversation(src_ip={src_ip}, target_ip={target_ip}, src_port={src_port}, '
              f'target_port={target_port}, rule_name={rule_name})')
        res = self.aria.block_conversation(src_ip=src_ip, target_ip=target_ip, src_port=src_port,
                                           target_port=target_port, rule_name=rule_name)
        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_unblock_conversation(self):

        print('\nCase 7: Test unblock_conversation: ')

        rule_name = 'block_conversation'

        print(f'unblock_conversation(rule_name={rule_name})')
        res = self.aria.unblock_conversation(rule_name=rule_name)
        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_record_conversation(self):

        print('\nCase 8: Test record_conversation: ')

        src_ip = f'{self._ip(11, 22, 33, 44)}/24'
        target_ip = f'{self._ip(55, 66, 77, 88)}/32'
        rule_name = 'record_conversation'
        src_port = '0-1000'
        target_port = '0-1000, 5000-6000'
        protocol = 'TCP'
        vlan_id = '123'
        transport_type = 'email'
        trigger_type = 'one-shot'
        trigger_value = '1'
        tti_index = '0'
        aio_index = '0'

        print(f'record_conversation(src_ip={src_ip}, target_ip={target_ip}, vlan_id={vlan_id}, rule_name={rule_name}, '
              f'src_port={src_port}, target_port={target_port}, protocol={protocol}, transport_type={transport_type}, '
              f'tti_index={tti_index}, aio_index={aio_index}, '
              f'trigger_type={trigger_type}, trigger_value={trigger_value})')

        res = self.aria.record_conversation(src_ip=src_ip, target_ip=target_ip, vlan_id=vlan_id, rule_name=rule_name,
                                            src_port=src_port, target_port=target_port, protocol=protocol,
                                            transport_type=transport_type, tti_index=tti_index, aio_index=aio_index,
                                            trigger_type=trigger_type, trigger_value=trigger_value)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_stop_recording_conversation(self):

        print('\nCase 9: Test stop_recording_conversation: ')

        rule_name = 'record_conversation'

        print(f'stop_recording_conversation(rule_name={rule_name})')

        res = self.aria.stop_recording_conversation(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_alert_conversation(self):

        print('\nCase 10: Test alert_conversation: ')

        src_ip = self._ip(192, 168, 0, 1)
        target_ip = self._ip(10, 20, 30, 40)
        rule_name = 'alert_conversation'
        protocol = 'UDP'
        transport_type = 'syslog'
        trigger_type = 'one-shot'
        trigger_value = '100'
        tti_index = '0'
        aio_index = '0'
        label_sia_name = self.label_sia_name

        print(f'alert_conversation(src_ip={src_ip}, target_ip={target_ip}, rule_name={rule_name}, '
              f'transport_type={transport_type}, tti_index={tti_index}, aio_index={aio_index}, '
              f'trigger_type={trigger_type}, trigger_value={trigger_value}, protocol={protocol}, '
              f'label_sia_name={label_sia_name})')

        res = self.aria.alert_conversation(src_ip=src_ip, target_ip=target_ip, rule_name=rule_name,
                                           transport_type=transport_type, tti_index=tti_index, aio_index=aio_index,
                                           trigger_type=trigger_type, trigger_value=trigger_value, protocol=protocol,
                                           label_sia_name=label_sia_name)
        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_mute_alert_conversation(self):

        print('\nCase 11: Test mute_alert_conversation: ')

        rule_name = 'alert_conversation'
        label_sia_name = self.label_sia_name

        print(f'mute_alert_conversation(rule_name={rule_name}, label_sia_name={label_sia_name})')

        res = self.aria.mute_alert_conversation(rule_name=rule_name, label_sia_name=label_sia_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_block_dest_port(self):

        print('\nCase 12: Test block_dest_port: ')
        rule_name = 'block_dest_port'
        port_range = '1111-2222'

        print(f'block_dest_port(rule_name={rule_name}, port_range={port_range})')

        res = self.aria.block_dest_port(rule_name=rule_name, port_range=port_range)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_unblock_dest_port(self):

        print('\nCase 13: Test unblock_dest_port: ')
        rule_name = 'block_dest_port'

        print(f'block_dest_port(rule_name={rule_name})')
        res = self.aria.unblock_dest_port(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_record_dest_port(self):

        print('\nCase 14: Test record_dest_port: ')

        rule_name = 'record_dest_port'
        port_range = '10, 20 - 50, 90, 65535'
        vlan_id = '123'
        transport_type = 'email'
        trigger_type = 're-trigger-count'
        trigger_value = '8191'
        tti_index = '0'
        aio_index = '0'
        label_sia_region = self.label_sia_region
        label_sia_group = self.label_sia_group
        print(f'record_dest_port(port_range={port_range}, vlan_id={vlan_id}, rule_name={rule_name}, '
              f'transport_type={transport_type}, tti_index={tti_index}, aio_index={aio_index}, '
              f'trigger_type={trigger_type}, trigger_value={trigger_value}, label_sia_region={label_sia_region}, '
              f'label_sia_group={label_sia_group})')

        res = self.aria.record_dest_port(port_range=port_range, vlan_id=vlan_id, rule_name=rule_name,
                                         transport_type=transport_type, tti_index=tti_index, aio_index=aio_index,
                                         trigger_type=trigger_type, trigger_value=trigger_value,
                                         label_sia_group=label_sia_group, label_sia_region=label_sia_region)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_stop_recording_dest_port(self):

        print('\nCase 15: Test stop_recording_dest_port: ')

        rule_name = 'record_dest_port'
        label_sia_region = self.label_sia_region
        label_sia_group = self.label_sia_group

        print(f'stop_recording_dest_port(rule_name={rule_name}, label_sia_region={label_sia_region}, '
              f'label_sia_group={label_sia_group})')

        res = self.aria.stop_recording_dest_port(rule_name=rule_name, label_sia_region=label_sia_region,
                                                 label_sia_group=label_sia_group)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_alert_dest_port(self):

        print('\nCase 16: Test alert_dest_port: ')

        rule_name = 'alert_dest_port'
        port_range = '0-65535'
        transport_type = 'email'
        trigger_type = 're-trigger-timed-sec'
        trigger_value = '100'
        tti_index = '0'
        aio_index = '0'
        print(f'alert_dest_port(port_range={port_range}, rule_name={rule_name}, transport_type={transport_type}, '
              f'tti_index={tti_index}, aio_index={aio_index}, trigger_type={trigger_type}, '
              f'trigger_value={trigger_value})')

        res = self.aria.alert_dest_port(port_range=port_range, rule_name=rule_name, transport_type=transport_type,
                                        tti_index=tti_index, aio_index=aio_index, trigger_type=trigger_type,
                                        trigger_value=trigger_value)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_mute_alert_dest_port(self):

        print('\nCase 17: Test mute_alert_dest_port: ')

        rule_name = 'alert_dest_port'

        print(f'mute_alert_dest_port(rule_name={rule_name})')

        res = self.aria.mute_alert_dest_port(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_block_src_port(self):

        print('\nCase 18: Test block_src_port: ')

        rule_name = 'block_src_port'
        port_range = '1, 10-100'
        label_sia_name = self.label_sia_name
        label_sia_group = self.label_sia_group

        print(f'block_src_port(rule_name={rule_name}, port_range={port_range}, label_sia_name={label_sia_name}, '
              f'label_sia_group={label_sia_group})')

        res = self.aria.block_src_port(rule_name=rule_name, port_range=port_range, label_sia_name=label_sia_name,
                                       label_sia_group=label_sia_group)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_unblock_src_port(self):

        print('\nCase 19: Test unblock_src_port: ')
        rule_name = 'block_src_port'

        print(f'unblock_src_port(rule_name={rule_name})')
        res = self.aria.unblock_src_port(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_record_src_port(self):

        print('\nCase 20: Test record_src_port: ')

        rule_name = 'record_src_port'
        port_range = '10, 20 - 50, 90, 65535'
        vlan_id = '345'
        print(f'record_src_port(port_range={port_range}, vlan_id={vlan_id}, rule_name={rule_name})')

        res = self.aria.record_src_port(port_range=port_range, vlan_id=vlan_id, rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_stop_recording_src_port(self):

        print('\nCase 21: Test stop_recording_src_port: ')

        rule_name = 'record_src_port'

        print(f'stop_recording_src_port(rule_name={rule_name})')

        res = self.aria.stop_recording_src_port(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_alert_src_port(self):

        print('\nCase 22: Test alert_src_port: ')

        rule_name = 'alert_src_port'
        port_range = '0-30000'
        transport_type = 'syslog'
        trigger_type = 're-trigger-timed-ms'
        trigger_value = '1000'
        tti_index = '0'
        aio_index = '0'
        print(f'alert_src_port(port_range={port_range}, rule_name={rule_name}, transport_type={transport_type}, '
              f'tti_index={tti_index}, aio_index={aio_index}, trigger_type={trigger_type}, '
              f'trigger_value={trigger_value})')

        res = self.aria.alert_src_port(port_range=port_range, rule_name=rule_name, transport_type=transport_type,
                                       tti_index=tti_index, aio_index=aio_index, trigger_type=trigger_type,
                                       trigger_value=trigger_value)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_mute_alert_src_port(self):

        print('\nCase 23: Test mute_alert_src_port: ')

        rule_name = 'alert_src_port'

        print(f'mute_alert_src_port(rule_name={rule_name})')

        res = self.aria.mute_alert_src_port(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_block_dest_subnet(self):

        print('\nCase 24: Test block_dest_subnet: ')

        rule_name = 'block_dest_subnet'
        target_ip = f'{self._ip(1, 2, 3, 4)}/32'
        label_sia_name = self.label_sia_name
        label_sia_region = self.label_sia_region

        print(f'block_dest_subnet(rule_name={rule_name}, target_ip={target_ip}, label_sia_name={label_sia_name}, '
              f'label_sia_region={label_sia_region})')

        res = self.aria.block_dest_subnet(rule_name=rule_name, target_ip=target_ip, label_sia_name=label_sia_name,
                                          label_sia_region=label_sia_region)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_unblock_dest_subnet(self):

        print('\nCase 25: Test unblock_dest_subnet: ')
        rule_name = 'block_dest_subnet'
        label_sia_name = self.label_sia_name
        label_sia_region = self.label_sia_region

        print(f'unblock_dest_subnet(rule_name={rule_name}, label_sia_name={label_sia_name}, '
              f'label_sia_region={label_sia_region})')

        res = self.aria.unblock_dest_subnet(rule_name=rule_name, label_sia_name=label_sia_name,
                                            label_sia_region=label_sia_region)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_record_dest_subnet(self):

        print('\nCase 26: Test record_dest_subnet: ')

        rule_name = 'record_dest_subnet'
        target_ip = self._ip(192, 100, 0, 68)
        vlan_id = '999'
        sia_interface = 'B'
        transport_type = 'email'
        trigger_type = 're-trigger-count'
        trigger_value = '1'
        tti_index = '0'
        aio_index = '0'

        print(f'record_dest_subnet(target_ip={target_ip}, vlan_id={vlan_id}, rule_name={rule_name}, '
              f'transport_type={transport_type}, tti_index={tti_index}, aio_index={aio_index}, '
              f'trigger_type={trigger_type}, trigger_value={trigger_value}, sia_interface={sia_interface})')

        res = self.aria.record_dest_subnet(target_ip=target_ip, vlan_id=vlan_id, rule_name=rule_name,
                                           transport_type=transport_type, tti_index=tti_index, aio_index=aio_index,
                                           trigger_type=trigger_type, trigger_value=trigger_value,
                                           sia_interface=sia_interface)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_stop_recording_dest_subnet(self):

        print('\nCase 27: Test stop_recording_dest_subnet: ')

        rule_name = 'record_dest_subnet'

        print(f'stop_recording_dest_subnet(rule_name={rule_name})')

        res = self.aria.stop_recording_dest_subnet(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_alert_dest_subnet(self):

        print('\nCase 28: Test alert_dest_subnet: ')

        rule_name = 'alert_dest_subnet'
        target_ip = f'{self._ip(11, 22, 33, 44)}/24'
        transport_type = 'syslog'
        trigger_type = 're-trigger-timed-ms'
        trigger_value = '1000'
        tti_index = '0'
        aio_index = '0'
        print(f'alert_dest_subnet(target_ip={target_ip}, rule_name={rule_name}, transport_type={transport_type}, '
              f'tti_index={tti_index}, aio_index={aio_index}, trigger_type={trigger_type}, '
              f'trigger_value={trigger_value})')

        res = self.aria.alert_dest_subnet(target_ip=target_ip, rule_name=rule_name, transport_type=transport_type,
                                          tti_index=tti_index, aio_index=aio_index, trigger_type=trigger_type,
                                          trigger_value=trigger_value)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_mute_alert_dest_subnet(self):

        print('\nCase 29: Test mute_alert_dest_subnet: ')

        rule_name = 'alert_dest_subnet'

        print(f'mute_alert_dest_subnet(rule_name={rule_name})')

        res = self.aria.mute_alert_dest_subnet(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_block_src_subnet(self):

        print('\nCase 30: Test block_src_subnet: ')

        rule_name = 'block_src_subnet'
        src_ip = f'{self._ip(2, 3, 4, 5)}/32'
        label_sia_name = self.label_sia_name
        label_sia_region = self.label_sia_region

        print(f'block_src_subnet(rule_name={rule_name}, src_ip={src_ip}, label_sia_name={label_sia_name}, '
              f'label_sia_region={label_sia_region})')

        res = self.aria.block_src_subnet(rule_name=rule_name, src_ip=src_ip, label_sia_name=label_sia_name,
                                         label_sia_region=label_sia_region)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_unblock_src_subnet(self):

        print('\nCase 31: Test unblock_src_subnet: ')
        rule_name = 'block_src_subnet'
        label_sia_name = self.label_sia_name
        label_sia_region = self.label_sia_region

        print(f'unblock_src_subnet(rule_name={rule_name}, label_sia_name={label_sia_name}, '
              f'label_sia_region={label_sia_region})')

        res = self.aria.unblock_src_subnet(rule_name=rule_name, label_sia_name=label_sia_name,
                                           label_sia_region=label_sia_region)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_record_src_subnet(self):

        print('\nCase 32: Test record_src_subnet: ')

        rule_name = 'record_src_subnet'
        src_ip = f'{self._ip(11, 22, 33, 44)}/32'
        vlan_id = '345'
        sia_interface = 'A'
        transport_type = 'email'
        trigger_type = 'one-shot'
        trigger_value = '3333'
        tti_index = '0'
        aio_index = '0'

        print(f'record_src_subnet(src_ip={src_ip}, vlan_id={vlan_id}, rule_name={rule_name}, '
              f'transport_type={transport_type}, tti_index={tti_index}, aio_index={aio_index}, '
              f'trigger_type={trigger_type}, trigger_value={trigger_value}, sia_interface={sia_interface})')

        res = self.aria.record_src_subnet(src_ip=src_ip, vlan_id=vlan_id, rule_name=rule_name,
                                          transport_type=transport_type, tti_index=tti_index, aio_index=aio_index,
                                          trigger_type=trigger_type, trigger_value=trigger_value,
                                          sia_interface=sia_interface)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_stop_recording_src_subnet(self):

        print('\nCase 33: Test stop_recording_src_subnet: ')

        rule_name = 'record_src_subnet'

        print(f'stop_recording_src_subnet(rule_name={rule_name})')

        res = self.aria.stop_recording_src_subnet(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_alert_src_subnet(self):

        print('\nCase 34: Test alert_src_subnet: ')

        rule_name = 'alert_src_subnet'
        src_ip = f'{self._ip(1, 1, 1, 1)}/8'
        transport_type = 'syslog'
        trigger_type = 're-trigger-timed-ms'
        trigger_value = '1234'
        tti_index = '0'
        aio_index = '0'
        label_sia_name = self.label_sia_name
        label_sia_region = self.label_sia_region

        print(f'alert_src_subnet(src_ip={src_ip}, rule_name={rule_name}, transport_type={transport_type}, '
              f'tti_index={tti_index}, aio_index={aio_index}, trigger_type={trigger_type}, '
              f'trigger_value={trigger_value}, label_sia_name={label_sia_name}, label_sia_region={label_sia_region})')

        res = self.aria.alert_src_subnet(src_ip=src_ip, rule_name=rule_name, transport_type=transport_type,
                                         tti_index=tti_index, aio_index=aio_index, trigger_type=trigger_type,
                                         trigger_value=trigger_value, label_sia_name=label_sia_name,
                                         label_sia_region=label_sia_region)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True

    def test_mute_alert_src_subnet(self):

        print('\nCase 35: Test mute_alert_src_subnet: ')

        rule_name = 'alert_src_subnet'

        print(f'mute_alert_src_subnet(rule_name={rule_name})')

        res = self.aria.mute_alert_src_subnet(rule_name=rule_name)

        time.sleep(self.wait_time)
        assert res['Status']['code'] == 201
        assert res['Status']['command_state'] == 'Success'
        for ep in res['Endpoints']:
            assert ep['completion'] is True
