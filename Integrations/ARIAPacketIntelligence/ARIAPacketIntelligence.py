import demistomock as demisto
from CommonServerPython import *
import json
import requests
import time
from typing import List


class ParameterError(Exception):
    """ Raised when the function parameters do not meet requirements """
    pass


class ARIA(object):

    def __init__(self, sdso_url: str, verify_cert: bool = True):
        self.sdso_url = sdso_url
        self.time_out = 20
        self.verify_cert = verify_cert

    """HELPER FUNCTION"""

    @staticmethod
    def _build_alert_instruction(transport_type: str, tti_index: int, aio_index: int,
                                 trigger_type: str, trigger_value: int) -> str:
        """ Create an alert instruction

        Args:
            transport_type: The type of notification to generate.
                Valid values are 'email', 'SMS', 'syslog' or 'webhook'.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.

        Returns: Alert instruction string.

        Raises:
            ValueError: If parameters are out of range or not in the type list.

        """
        transport_type_list = ['email', 'SMS', 'syslog', 'webhook']

        if transport_type not in transport_type_list:
            raise ValueError(f'Wrong transport_type {transport_type}! Valid values are email, SMS, syslog or webhook')

        if tti_index > 7 or tti_index < 0:
            # This is an ARIA PI Reaper production requirement
            raise ValueError('Transport type info index(tti_index) out of range! '
                             'Valid value must be in the range [0, 7].')

        if aio_index > 15 or aio_index < 0:
            # This is an ARIA PI Reaper production requirement
            raise ValueError('Alert info object index(aio_index) out of range! '
                             'Valid value must be in range [0, 15]')

        trigger_type_list = ['one-shot', 're-trigger-count', 're-trigger-timed-ms', 're-trigger-timed-sec']

        if trigger_type not in trigger_type_list:
            # This is an ARIA PI Reaper production requirement
            raise ValueError(f'Wrong trigger_type {trigger_type}! Valid values are one-shot, re-trigger-count, '
                             're-trigger-timed-ms, re-trigger-timed-sec')

        if trigger_value < 1 or trigger_value > 8191:
            # This is an ARIA PI Reaper production requirement
            raise ValueError('Trigger value(trigger_value) out of range! It must be in range [1, 8191]')

        instruction = f'ALERT {transport_type} {tti_index} {aio_index} {trigger_type} {trigger_value}'

        return instruction

    @staticmethod
    def _process_port_range(port_range: str = None) -> str:
        """ Validation function for range of ports

        Args:
            port_range: The source or destination port(s). This accepts a
                comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).

        Returns: The string of port_range.

        Raises:
            ValueError: If port_range is out of range 0-65535 or in wrong format.

        """
        if not port_range:
            port_range = '0-65535'  # default port_range value

        split_port_range = port_range.replace(' ', '').split(',')

        res = ''

        for port in split_port_range:
            if res:
                res = res + ', '

            if '-' in port:

                beg, end = port.replace(' ', '').split('-')

                for j in beg, end:
                    if int(j) < 0 or int(j) > 65535:
                        raise ValueError('Port must be in 0-65535!')

                if int(beg) > int(end):
                    raise ValueError('Wrong port range format!')

                res += beg + ' - ' + end
            else:
                if int(port) < 0 or int(port) > 65535:
                    raise ValueError('Port must be in 0-65535!')
                res += port

        return res

    @staticmethod
    def _process_ip_address(ip: str) -> str:
        """ Validation function for IP address

        Args:
            ip: The IP address and mask of the IP address, in the format <IP_address>/<mask>. If the mask is omitted,
                a value of 32 is used.

        Returns: String of IP address.

        Raises:
            ValueError: If the netmask is out of range or IP address is not expressed in CIDR notation

        """
        netmask = '32'

        ip_str = ip.replace(' ', '')

        if '/' in ip_str:
            ip_addr, netmask = ip_str.split('/')
        else:
            ip_addr = ip_str

        if int(netmask) > 32 or int(netmask) < 1:
            raise ValueError('Subnet mask must be in range [1, 32].')

        ip_addr_split = ip_addr.split('.')
        for syllable in ip_addr_split:
            if int(syllable) < 0 or int(syllable) > 255:
                raise ValueError('Wrong IP format!')
        if len(ip_addr_split) != 4:
            raise ValueError('Wrong IP format!')
        res = ip_addr + '/' + netmask
        return res

    @staticmethod
    def _generate_named_rule_data(rule_name: str, logic_block: str, rule: str, action: str, instance_id: str = None,
                                  label_sia_group: str = None, label_sia_name: str = None,
                                  label_sia_region: str = None) -> dict:
        """ Generate a named rule data

        Args:
            rule_name: The name of the rule to create.
            logic_block: Parameter used to form named rule data. Examples: '5-tuple', 'src-port', etc.
            rule: Parameter used to form named rule data.
            action: Must be 'add' or 'remove'
            instance_id: The instance number of the ARIA PI instance.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which SIA belongs.

        Returns: Dictionary data of named rule.

        Raises:
            ParameterError: Raised when parameters label_sia_group, label_sia_name and label_sia_region are used at
                the same time.

        """
        selector = dict()

        count = 0

        type_dict = ['group', 'name', 'region']

        for index, label in enumerate([label_sia_group, label_sia_name, label_sia_region]):
            if label:
                count += 1

                # three labels used at the same time are not allowed
                if count == 3:
                    raise ParameterError('Command only supports two SIA labels!')

                cur_label = f'label{str(count)}'
                selector[cur_label] = {
                    'kind': 'string',
                    'SIA_label_type': type_dict[index],
                    'SIA_label': label
                }

        # default label if no labels provided
        if count == 0:
            selector = {
                'label1': {
                    'kind': 'string',
                    'SIA_label_type': 'region',
                    'SIA_label': 'all'
                },
                'label2': {
                    'kind': 'string',
                    'SIA_label_type': 'region',
                    'SIA_label': 'all'
                }
            }

        instance_id_type = 'instance-number'

        if instance_id is None:
            instance_id_type = 'all'
            instance_id = ''

        if action == 'remove':
            rule = ''

        named_rule = f'\"name\": \"{rule_name}\", \"logic_block\": \"{logic_block}\", \"rule\": \"{rule}\"'

        data = {
            'selector': {
                'kind': 'string',
                'named_rule': named_rule,
                'named_rule_action': action,
                'label_query': selector,
                'instance_ID_type': instance_id_type,
                'instance_ID': instance_id
            }
        }

        return data

    def _wait_for_trid(self, trid: str) -> bool:
        """ Valid whether the request completed by trid

        Args:
            trid: The request id when you want to adding a rule to ARIA PI Reaper.

        Returns: True if complete, False if not.

        """

        # url to valid the request
        trid_url = self.sdso_url + f'/packetClassification/completion/transaction?PC_TRID={trid}'

        # Use trid of transaction to get if a transaction success

        t0 = time.perf_counter()

        delta = time.perf_counter() - t0

        while delta < 20:
            res = requests.get(trid_url, timeout=self.time_out, verify=self.verify_cert)

            delta = time.perf_counter() - t0

            if res.ok:
                try:
                    tcl_list = res.json().get('tclList')
                except json.JSONDecodeError:
                    raise

                for tcl_entry in tcl_list:
                    if 'SUCCESS' in tcl_entry['status']:
                        return True
                    elif 'FAILURE' in tcl_entry['status']:
                        return False
            time.sleep(0.1)

        return False

    def _remove_rule(self, rule_name: str, logic_block: str, instance_id: str = None, label_sia_group: str = None,
                     label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Remove rule in the ARIA PI Reaper

        Args:
            rule_name: The name of the rule to create.
            logic_block: Parameter used to form named rule data. Examples: '5-tuple', 'src-port', etc.
            instance_id: The instance number of the ARIA PI instance.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """

        url = self.sdso_url + '/ruleForward'

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        data = self._generate_named_rule_data(rule_name, logic_block, 'no_rule', 'remove', instance_id,
                                              label_sia_group, label_sia_name, label_sia_region)

        response = requests.put(url, data=json.dumps(data), headers=headers, timeout=self.time_out,
                                verify=self.verify_cert)

        response_timestamp = ''

        endpoints: List[dict] = []

        command_state = False

        if response.ok:

            command_state = True

            try:
                response_json = response.json()
            except json.JSONDecodeError:
                raise

            endpoints = response_json.get('endpoints')

            for ep in endpoints:
                trid = ep.get('trid')
                success = self._wait_for_trid(str(trid))
                ep['completion'] = success
                if not success:
                    command_state = False
            response_timestamp = response_json.get('timestamp')

        if command_state:
            command_state_str = 'Success'
        else:
            command_state_str = 'Failure'

        data = {
            'Rule': {
                'Name': rule_name,
                'Definition': ''
            },
            'Status': {
                'code': response.status_code,
                'timestamp': response_timestamp,
                'command_state': command_state_str
            },
            'Endpoints': endpoints  # list of endpoints
        }

        return data

    def _do_request(self, data: dict, rule_name: str, rule: str) -> dict:
        """ Send a request to ARIA PI Reaper to create a rule

        Args:
            data: Named rule data.
            rule_name: Name of the rule.
            rule: String representation of rule.

        Returns: Dictionary context data contains useful response information.

        """
        url = self.sdso_url + '/ruleForward'

        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        data['selector']['instance_ID_type'] = 'instance-number'

        instance_number = 10  # 10 total instances in ARIA PI Reaper

        # randomly looking for an available instances
        instance_list = list(range(0, instance_number))

        response_timestamp = ''

        code = None

        endpoints: List[dict] = []

        command_state = False
        # If response code is not 201, the error message may be caused by no connection to the SDSo or no ISA
        # can be found based on the labels provided.
        # A response code of 201 may also be returned, even if the rule is not successfully added to
        # the SIAs. completion will be false to a specific SIA if the range within the rule overlaps the range of an
        # existing rule or the rule name is not unique for all the 10 instances.

        # the loop will break if the request successfully find an available instance and complete adding the rule

        for i in instance_list:
            data['selector']['instance_ID'] = str(i)

            response = requests.put(url, data=json.dumps(data), headers=headers, timeout=self.time_out,
                                    verify=self.verify_cert)

            code = response.status_code

            if response.ok:

                try:
                    response_json = response.json()
                except json.JSONDecodeError:
                    raise

                endpoints = response_json.get('endpoints')

                command_state = True

                at_least_one_completion = False

                for ep in endpoints:
                    trid = ep.get('trid')
                    success = self._wait_for_trid(str(trid))  # check if the request completes successfully
                    ep['completion'] = success
                    if success:
                        at_least_one_completion = True  # Set to True if at least one endpoints complete
                    else:
                        command_state = False  # Set to False if at least one endpoints not complete

                response_timestamp = response_json.get('timestamp')

                if command_state:  # break the loop if all rules successfully complete
                    break
                # if not at least one endpoints return success, finding a free spots to add rules individually for
                # failed endpoints
                if at_least_one_completion:
                    for ep_index, ep in enumerate(endpoints):
                        for instance_index in range(i + 1, instance_number):
                            if ep['completion']:
                                continue
                            data['selector']['instance_ID'] = str(instance_index)
                            data['selector']['label_query']['label1']['SIA_label_type'] = 'group'
                            data['selector']['label_query']['label1']['SIA_label'] = ep.get('Group')
                            data['selector']['label_query']['label2']['SIA_label_type'] = 'name'
                            data['selector']['label_query']['label2']['SIA_label'] = ep.get('Name')

                            response = requests.put(url, data=json.dumps(data), headers=headers, timeout=self.time_out,
                                                    verify=self.verify_cert)
                            try:
                                response_json = response.json()
                            except json.JSONDecodeError:
                                raise

                            endpoints[ep_index] = response_json.get('endpoints')[0]

                            trid = ep.get('trid')
                            success = self._wait_for_trid(str(trid))
                            endpoints[ep_index]['completion'] = success
                            if endpoints[ep_index]['completion']:
                                break
                    for ep in endpoints:
                        if not ep['completion']:
                            command_state = False
                    break
            else:
                command_state = False

        if command_state:
            command_state_str = 'Success'
        else:
            command_state_str = 'Failure'

        data = {
            'Rule': {
                'Name': rule_name,
                'Definition': rule
            },
            'Status': {
                'code': code,
                'command_state': command_state_str,
                'timestamp': response_timestamp
            },
            'Endpoints': endpoints  # list of endpoints
        }

        return data

    """SOAR API"""
    def block_conversation(self, src_ip: str, target_ip: str, rule_name: str, src_port: str = None,
                           target_port: str = None, protocol: str = None, label_sia_group: str = None,
                           label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that drops all packets matching the specified 5-tuple values.

        Args:
            src_ip: The source IP address.
            target_ip: The destination IP address.
            rule_name: The name of the rule to create.
            src_port: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            target_port: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            protocol: The protocol (e.g., TCP) used for the packets.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        src_ip = self._process_ip_address(src_ip)

        src_port = self._process_port_range(src_port)

        target_ip = self._process_ip_address(target_ip)

        target_port = self._process_port_range(target_port)

        if not protocol:
            protocol = 'HOPOPT-255'  # default protocol is no value provided

        protocol = protocol.upper()

        rule = f'{target_ip} @ {target_port} & {src_ip} @ {src_port} <> {protocol} : DROP, END'

        data = self._generate_named_rule_data(rule_name, '5-tuple', rule, 'add', None, label_sia_group,
                                              label_sia_name, label_sia_region)

        return self._do_request(data, rule_name, rule)

    def unblock_conversation(self, rule_name: str, label_sia_group: str = None, label_sia_name: str = None,
                             label_sia_region: str = None) -> dict:
        """ Deletes a named rule from the 5-tuple logic block.

            This allows the previously blocked conversation to resume.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name, '5-tuple', None, label_sia_group, label_sia_name, label_sia_region)

    def record_conversation(self, src_ip: str, target_ip: str, vlan_id: str, rule_name: str, src_port: str = None,
                            target_port: str = None, protocol: str = None, sia_interface: str = None,
                            transport_type: str = None, tti_index: str = None, aio_index: str = None,
                            trigger_type: str = None, trigger_value: str = None, label_sia_group: str = None,
                            label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that redirects a conversation matching 5-tuple values
            to the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            src_ip: The source IP address.
            target_ip: The destination IP address.
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            src_port: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            target_port: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            protocol: The protocol (e.g., TCP) used for the packets.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.
        """
        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        src_ip = self._process_ip_address(src_ip)

        src_port = self._process_port_range(src_port)

        target_ip = self._process_ip_address(target_ip)

        target_port = self._process_port_range(target_port)

        if not protocol:
            protocol = 'HOPOPT-255'

        protocol = protocol.upper()

        rule = f'{target_ip} @ {target_port} & {src_ip} @ {src_port} <> {protocol} : ' \
            f'REDIRECT-VLAN {sia_interface} {vlan_id}'
        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value to '
                                     f'use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))

        rule += ', END'

        data = self._generate_named_rule_data(rule_name, '5-tuple', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def stop_recording_conversation(self, rule_name: str, label_sia_group: str = None,
                                    label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes the named rule from the 5-tuple block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, '5-tuple', None, label_sia_group, label_sia_name, label_sia_region)

    def alert_conversation(self, src_ip: str, target_ip: str, rule_name: str, transport_type: str, tti_index: str,
                           aio_index: str, trigger_type: str, trigger_value: str, src_port: str = None,
                           target_port: str = None, protocol: str = None, label_sia_group: str = None,
                           label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that generates an alert when a conversation matching the specified 5-tuple values is detected.

        Args:
            src_ip: The source IP address.
            target_ip: The destination IP address.
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            src_port: The source port(s). This accepts a comma-separated list (e.g., “1, 3”), a range (e.g., “1-3”),
                or a combination (e.g., “1, 3-5”).
            target_port: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            protocol: The protocol (e.g., TCP) used for the packets.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        src_ip = self._process_ip_address(src_ip)

        src_port = self._process_port_range(src_port)

        target_ip = self._process_ip_address(target_ip)

        target_port = self._process_port_range(target_port)

        if not protocol:
            protocol = 'HOPOPT-255'  # default protocol

        protocol = protocol.upper()

        rule = f'{target_ip} @ {target_port} & {src_ip} @ {src_port} <> {protocol} : '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                              trigger_type, int(trigger_value)) + ', END'

        data = self._generate_named_rule_data(rule_name, '5-tuple', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def mute_alert_conversation(self, rule_name: str, label_sia_group: str = None, label_sia_name: str = None,
                                label_sia_region: str = None) -> dict:
        """ Removes a named rule from the 5-tuple logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, '5-tuple', None, label_sia_group, label_sia_name, label_sia_region)

    def block_dest_port(self, port_range: str, rule_name: str, label_sia_group: str = None,
                        label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that blocks packets destined for one or more specific ports.

        Args:
            port_range: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: DROP, END'

        data = self._generate_named_rule_data(rule_name, 'dst-port', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def unblock_dest_port(self, rule_name: str, label_sia_group: str = None, label_sia_name: str = None,
                          label_sia_region: str = None) -> dict:
        """ Removes a named rule from the destination port logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'dst-port', None, label_sia_group, label_sia_name, label_sia_region)

    def record_dest_port(self, port_range: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                         transport_type: str = None, tti_index: str = None, aio_index: str = None,
                         trigger_type: str = None, trigger_value: str = None, label_sia_group: str = None,
                         label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that redirects traffic destined for one or more ports to the Packet Recorder
            and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            port_range: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.
        """
        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_port_range(port_range)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))
        rule += ', END'

        data = self._generate_named_rule_data(rule_name, 'dst-port', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def stop_recording_dest_port(self, rule_name: str, label_sia_group: str = None,
                                 label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the destination port logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name, 'dst-port', None, label_sia_group, label_sia_name, label_sia_region)

    def alert_dest_port(self, port_range: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                        trigger_type: str, trigger_value: str, label_sia_group: str = None,
                        label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that generates an alert when traffic destined for one or more ports is detected.

        Args:
            port_range: The destination port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index), trigger_type,
                                              int(trigger_value)) + ', END'

        data = self._generate_named_rule_data(rule_name, 'dst-port', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def mute_alert_dest_port(self, rule_name: str, label_sia_group: str = None, label_sia_name: str = None,
                             label_sia_region: str = None) -> dict:
        """ Removes a named rule from the destination port logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'dst-port', None, label_sia_group, label_sia_name, label_sia_region)

    def block_src_port(self, port_range: str, rule_name: str, label_sia_group: str = None,
                       label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that blocks packets originating from one or more specific ports.

        Args:
            port_range: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: DROP, END'

        data = self._generate_named_rule_data(rule_name, 'src-port', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def unblock_src_port(self, rule_name: str, label_sia_group: str = None, label_sia_name: str = None,
                         label_sia_region: str = None) -> dict:
        """ Removes a named rule from the source port logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'src-port', None, label_sia_group, label_sia_name, label_sia_region)

    def record_src_port(self, port_range: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                        transport_type: str = None, tti_index: str = None, aio_index: str = None,
                        trigger_type: str = None, trigger_value: str = None, label_sia_group: str = None,
                        label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that redirects traffic originating from one or more ports to
            the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            port_range: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.

        """
        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_port_range(port_range)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index), trigger_type,
                                                  int(trigger_value))

        rule += ', END'

        data = self._generate_named_rule_data(rule_name, 'src-port', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def stop_recording_src_port(self, rule_name: str, label_sia_group: str = None,
                                label_sia_name: str = None, label_sia_region: str = None):
        """ Removes a named rule from the source port logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name, 'src-port', None, label_sia_group, label_sia_name, label_sia_region)

    def alert_src_port(self, port_range: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                       trigger_type: str, trigger_value: str, label_sia_group: str = None,
                       label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that generates an alert when traffic originating from one or more ports is detected.

        Args:
            port_range: The source port(s). This accepts a comma-separated list (e.g., “1, 3”),
                a range (e.g., “1-3”), or a combination (e.g., “1, 3-5”).
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_port_range(port_range)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                              trigger_type, int(trigger_value)) + ', END'

        data = self._generate_named_rule_data(rule_name, 'src-port', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def mute_alert_src_port(self, rule_name: str, label_sia_group: str = None, label_sia_name: str = None,
                            label_sia_region: str = None) -> dict:
        """ Removes a named rule from the source port logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'src-port', None, label_sia_group, label_sia_name, label_sia_region)

    def block_dest_subnet(self, target_ip: str, rule_name: str, label_sia_group: str = None,
                          label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that blocks packets destined for a specific IP address or range of IP addresses.

        Args:
            target_ip: The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(target_ip)}: DROP, END'

        data = self._generate_named_rule_data(rule_name, 'dst-subnet', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def unblock_dest_subnet(self, rule_name: str, label_sia_group: str = None,
                            label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the destination subnet logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'dst-subnet', None,
                                 label_sia_group, label_sia_name, label_sia_region)

    def record_dest_subnet(self, target_ip: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                           transport_type: str = None, tti_index: str = None, aio_index: str = None,
                           trigger_type: str = None, trigger_value: str = None, label_sia_group: str = None,
                           label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that redirects traffic destined for a specific IP address or
            range of IP addresses to the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            target_ip: The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.

        """

        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_ip_address(target_ip)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')

            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))
        rule += ', END'

        data = self._generate_named_rule_data(rule_name, 'dst-subnet', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def stop_recording_dest_subnet(self, rule_name: str, label_sia_group: str = None,
                                   label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the destination subnet logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name, 'dst-subnet', None, label_sia_group,
                                 label_sia_name, label_sia_region)

    def alert_dest_subnet(self, target_ip: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                          trigger_type: str, trigger_value: str, label_sia_group: str = None,
                          label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that generates an alert when traffic destined for
            a specific IP address or range of IP addresses is detected.

        Args:
            target_ip: The IP address and mask of the destination IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(target_ip)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index), trigger_type,
                                              int(trigger_value)) + ', END'

        data = self._generate_named_rule_data(rule_name, 'dst-subnet', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def mute_alert_dest_subnet(self, rule_name: str, label_sia_group: str = None,
                               label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the destination subnet logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'dst-subnet', None, label_sia_group,
                                 label_sia_name, label_sia_region)

    def block_src_subnet(self, src_ip: str, rule_name: str, label_sia_group: str = None,
                         label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that blocks packets originating from a specific IP address or range of IP addresses.

        Args:
            src_ip: The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(src_ip)}: DROP, END'

        data = self._generate_named_rule_data(rule_name, 'src-subnet', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def unblock_src_subnet(self, rule_name: str, label_sia_group: str = None,
                           label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the source subnet logic block.

            This allows the previously blocked traffic to resume.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'src-subnet', None, label_sia_group,
                                 label_sia_name, label_sia_region)

    def record_src_subnet(self, src_ip: str, vlan_id: str, rule_name: str, sia_interface: str = None,
                          transport_type: str = None, tti_index: str = None, aio_index: str = None,
                          trigger_type: str = None, trigger_value: str = None, label_sia_group: str = None,
                          label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Creates a rule that redirects traffic originating from one or more specific IP addresses
            to the Packet Recorder and generates an alert.

            Packets are tagged with the VID specified in the command.

        Args:
            src_ip: The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            vlan_id: The VLAN ID your network switch uses to forward packets to the Packet Recorder.
            rule_name: The name of the rule to create.
            sia_interface: The letter of the interface on the SIA used for forwarding packets.
                If omitted, interface A is used.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        Raises:
            ParameterError: Raised when transport_type is used but one or more parameters in tti_index,
                aio_index, trigger_type and trigger_value are missing.

        """

        if sia_interface is None or sia_interface != 'B':
            sia_interface = 'A'  # SIA use labels A and B to select its interface (data port), default to A.

        rule = f'{self._process_ip_address(src_ip)}: REDIRECT-VLAN {sia_interface} {vlan_id}'

        if transport_type is not None:

            if tti_index is None or aio_index is None or trigger_type is None or trigger_value is None:
                raise ParameterError(f'Please provide tti_index, aio_index, trigger_type and trigger_value '
                                     f'to use {transport_type} to send an alert.')
            rule += ', '

            rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                                  trigger_type, int(trigger_value))

        rule += ', END'

        data = self._generate_named_rule_data(rule_name, 'src-subnet', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)

        return self._do_request(data, rule_name, rule)

    def stop_recording_src_subnet(self, rule_name: str, label_sia_group: str = None,
                                  label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the source subnet logic block.

            This stops redirecting traffic to the Packet Recorder.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """

        return self._remove_rule(rule_name, 'src-subnet', None, label_sia_group, label_sia_name, label_sia_region)

    def alert_src_subnet(self, src_ip: str, rule_name: str, transport_type: str, tti_index: str, aio_index: str,
                         trigger_type: str, trigger_value: str, label_sia_group: str = None,
                         label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Adds a rule that generates an alert when traffic originating from a specific IP address
            or range of IP addresses is detected.

        Args:
            src_ip: The IP address and mask of the source IP address(es), in the format <IP_address>/<mask>.
                If the mask is omitted, a value of 32 is used.
            rule_name: The name of the rule to create.
            transport_type: The type of notification to generate. Valid values are: email, syslog.
            tti_index: The index of the entry in the transport type table.
            aio_index: The index of the entry in the alert information object table.
            trigger_type: The frequency of the alert. Valid values are 'one-shot', 're-trigger-count',
                're-trigger-timed-ms' or 're-trigger-timed-sec'.
            trigger_value: The threshold that must be met before the alert is triggered.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        rule = f'{self._process_ip_address(src_ip)}: '

        rule += self._build_alert_instruction(transport_type, int(tti_index), int(aio_index),
                                              trigger_type, int(trigger_value)) + ', END'

        data = self._generate_named_rule_data(rule_name, 'src-subnet', rule, 'add', None,
                                              label_sia_group, label_sia_name, label_sia_region)
        return self._do_request(data, rule_name, rule)

    def mute_alert_src_subnet(self, rule_name: str, label_sia_group: str = None,
                              label_sia_name: str = None, label_sia_region: str = None) -> dict:
        """ Removes a named rule from the source subnet logic block, disabling the alerts.

        Args:
            rule_name: The name of the rule to delete.
            label_sia_group: The name of the group to which the SIA belongs.
            label_sia_name: The name of the SIA.
            label_sia_region: The name of the region to which the SIA belongs.

        Returns: Dictionary context data contains useful response information.

        """
        return self._remove_rule(rule_name, 'src-subnet', None, label_sia_group, label_sia_name, label_sia_region)


''' HELPER FUNCTIONS '''


def func_call(instance: ARIA, func_name: str, command_name: str, demisto_arguments: list, args: dict):
    """ Helper function used to call different demisto command

    Args:
        instance: An ARIA instance.
        func_name: Name of the functions in the ARIA class.
        command_name: Related demisto command name.
        demisto_arguments: List of arguments name in the right order.
        args: Input of demisto arguments dict.

    """
    arguments_value = []
    for arg in demisto_arguments:
        value = args.get(arg)  # get values from demisto command
        arguments_value.append(value)

    context_entry = getattr(instance, func_name)(*tuple(arguments_value))  # get returned tuple

    table_header = ['Rule', 'Status', 'Endpoints']

    context_name = func_name.title().replace('_', '')

    ec = {
        f'Aria.{context_name}(val.name && val.name == obj.name)': context_entry
    }

    readable_output = tableToMarkdown(command_name, context_entry, table_header)

    return readable_output, ec


''' COMMAND FUNCTION '''


def block_conversation_command(instance, args):
    demisto_arguments = ['src_ip', 'target_ip', 'rule_name', 'src_port', 'target_port', 'protocol', 'label_sia_group',
                         'label_sia_name', 'label_sia_region']
    return func_call(instance, 'block_conversation', 'aria-block-conversation', demisto_arguments, args)


def unblock_conversation_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'unblock_conversation', 'aria-unblock-conversation', demisto_arguments, args)


def record_conversation_command(instance, args):
    demisto_arguments = ['src_ip', 'target_ip', 'vlan_id', 'rule_name', 'src_port', 'target_port', 'protocol',
                         'sia_interface', 'transport_type', 'tti_index', 'aio_index', 'trigger_type', 'trigger_value',
                         'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'record_conversation', 'aria-record-conversation', demisto_arguments, args)


def stop_recording_conversation_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'stop_recording_conversation', 'aria-stop-recording-conversation',
                     demisto_arguments, args)


def alert_conversation_command(instance, args):
    demisto_arguments = ['src_ip', 'target_ip', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'src_port', 'target_port', 'protocol', 'label_sia_group',
                         'label_sia_name', 'label_sia_region']
    return func_call(instance, 'alert_conversation', 'aria-alert-conversation', demisto_arguments, args)


def mute_alert_conversation_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'mute_alert_conversation', 'aria-mute-alert-conversation', demisto_arguments, args)


def block_dest_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'block_dest_port', 'aria-block-dest-port', demisto_arguments, args)


def unblock_dest_port_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'unblock_dest_port', 'aria-unblock-dest-port', demisto_arguments, args)


def record_dest_port_command(instance, args):
    demisto_arguments = ['port_range', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index',
                         'aio_index', 'trigger_type', 'trigger_value', 'label_sia_group', 'label_sia_name',
                         'label_sia_region']
    return func_call(instance, 'record_dest_port', 'aria-record-dest-port', demisto_arguments, args)


def stop_recording_dest_port_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'stop_recording_dest_port', 'aria-stop-recording-dest-port', demisto_arguments, args)


def alert_dest_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'alert_dest_port', 'aria-alert-dest-port', demisto_arguments, args)


def mute_alert_dest_port_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'mute_alert_dest_port', 'aria-mute-alert-dest-port', demisto_arguments, args)


def block_src_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'block_src_port', 'aria-block-src-port', demisto_arguments, args)


def unblock_src_port_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'unblock_src_port', 'aria-unblock-src-port', demisto_arguments, args)


def record_src_port_command(instance, args):
    demisto_arguments = ['port_range', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index',
                         'aio_index', 'trigger_type', 'trigger_value', 'label_sia_group', 'label_sia_name',
                         'label_sia_region']
    return func_call(instance, 'record_src_port', 'aria-record-src-port', demisto_arguments, args)


def stop_recording_src_port_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'stop_recording_src_port', 'aria-stop-recording-src-port', demisto_arguments, args)


def alert_src_port_command(instance, args):
    demisto_arguments = ['port_range', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'alert_src_port', 'aria-alert-src-port', demisto_arguments, args)


def mute_alert_src_port_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'mute_alert_src_port', 'aria-mute-alert-src-port', demisto_arguments, args)


def block_dest_subnet_command(instance, args):
    demisto_arguments = ['target_ip', 'rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'block_dest_subnet', 'aria-block-dest-subnet', demisto_arguments, args)


def unblock_dest_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'unblock_dest_subnet', 'aria-unblock-dest-subnet', demisto_arguments, args)


def record_dest_subnet_command(instance, args):
    demisto_arguments = ['target_ip', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index',
                         'aio_index', 'trigger_type', 'trigger_value', 'label_sia_group', 'label_sia_name',
                         'label_sia_region']
    return func_call(instance, 'record_dest_subnet', 'aria-record-dest-subnet', demisto_arguments, args)


def stop_recording_dest_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'stop_recording_dest_subnet', 'aria-stop-recording-dest-subnet',
                     demisto_arguments, args)


def alert_dest_subnet_command(instance, args):
    demisto_arguments = ['target_ip', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'alert_dest_subnet', 'aria-alert-dest-subnet', demisto_arguments, args)


def mute_alert_dest_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'mute_alert_dest_subnet', 'aria-mute-alert-dest-subnet', demisto_arguments, args)


def block_src_subnet_command(instance, args):
    demisto_arguments = ['src_ip', 'rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'block_src_subnet', 'aria-block-src-subnet', demisto_arguments, args)


def unblock_src_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'unblock_src_subnet', 'aria-unblock-src-subnet', demisto_arguments, args)


def record_src_subnet_command(instance, args):
    demisto_arguments = ['src_ip', 'vlan_id', 'rule_name', 'sia_interface', 'transport_type', 'tti_index', 'aio_index',
                         'trigger_type', 'trigger_value', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'record_src_subnet', 'aria-record-src-subnet', demisto_arguments, args)


def stop_recording_src_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'stop_recording_src_subnet', 'aria-stop-recording-src-subnet', demisto_arguments, args)


def alert_src_subnet_command(instance, args):
    demisto_arguments = ['src_ip', 'rule_name', 'transport_type', 'tti_index', 'aio_index', 'trigger_type',
                         'trigger_value', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'alert_src_subnet', 'aria-alert-src-subnet', demisto_arguments, args)


def mute_alert_src_subnet_command(instance, args):
    demisto_arguments = ['rule_name', 'label_sia_group', 'label_sia_name', 'label_sia_region']
    return func_call(instance, 'mute_alert_src_subnet', 'aria-mute-alert-src-subnet', demisto_arguments, args)


def main():
    # disable insecure warnings
    requests.packages.urllib3.disable_warnings()

    # IP address or FQDN of your SDSo node
    SDSO = demisto.params().get('sdso')

    handle_proxy()

    INSECURE = demisto.params().get('insecure', False)

    verify_cert = not INSECURE

    sdso_url = f'{SDSO}/Aria/SS/1.0.0/PBaaS/server'

    aria = ARIA(sdso_url, verify_cert)

    commnds_dict = {
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

    command = demisto.command()
    LOG('ARIA: command is %s' % (command,))

    if demisto.command() == 'test-module':
        # Test if the ARIA PI Reaper is ready
        url = sdso_url + '/endPoint'
        try:
            res = requests.get(url, timeout=20, verify=verify_cert)
            size = len(json.loads(res.text))
            if res.ok and size != 0:
                demisto.results('ok')
            else:
                return_error('Fail to Connect to SDSo or no PacketIntelligence Service!')
        except (json.JSONDecodeError, requests.exceptions.RequestException):
            return_error('Fail to Connect to SDSo or no PacketIntelligence Service!')

    else:
        cmd_func = commnds_dict.get(command)

        if cmd_func is None:
            raise NotImplementedError(f'Command "{command}" is not implemented.')
        else:
            readable_output, ec = cmd_func(aria, demisto.args())
            context_entry = list(ec.values())[0]

            LOG(json.dumps(ec))

            if context_entry['Status']['command_state'] != 'Success':
                LOG.print_log()
                if context_entry['Status']['code'] != 201:
                    return_error('Failed to send a request to SDSo Node!')
                else:
                    endpoints_str = json.dumps(context_entry['Endpoints'])
                    return_error(f'One or more endpoints fail to create/remove rules. Please see {endpoints_str}')
            else:
                return_outputs(readable_output, ec)


# python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
