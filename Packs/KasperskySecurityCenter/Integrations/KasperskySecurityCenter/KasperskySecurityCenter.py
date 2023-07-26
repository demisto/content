import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

import urllib3
urllib3.disable_warnings()

HOST_FIELDS = [
    'KLHST_WKS_FQDN',
    'KLHST_WKS_DNSNAME',
    'KLHST_WKS_HOSTNAME',
    'KLHST_WKS_OS_NAME',
    'KLHST_WKS_GROUPID',
    'KLHST_WKS_DNSDOMAIN',
    'KLHST_WKS_DN',
]

HOST_DETAILED_FIELDS = [
    'KLHST_WKS_DN',
    'KLHST_WKS_GROUPID',
    'KLHST_WKS_CREATED',
    'KLHST_WKS_LAST_VISIBLE',
    'KLHST_WKS_STATUS',
    'KLHST_WKS_HOSTNAME',
    'KLHST_INSTANCEID',
    'KLHST_WKS_DNSDOMAIN',
    'KLHST_WKS_DNSNAME',
    'KLHST_WKS_FQDN',
    'KLHST_WKS_CTYPE',
    'KLHST_WKS_PTYPE',
    'KLHST_WKS_OS_NAME',
    'KLHST_WKS_COMMENT',
    'KLHST_WKS_NAG_VERSION',
    'KLHST_WKS_RTP_AV_VERSION',
    'KLHST_WKS_RTP_AV_BASES_TIME',
    'KLHST_WKS_RBT_REQUIRED',
    'KLHST_WKS_RBT_REQUEST_REASON',
    'KLHST_WKS_OSSP_VER_MAJOR',
    'KLHST_WKS_OSSP_VER_MINOR',
    'KLHST_WKS_CPU_ARCH',
    'KLHST_WKS_OS_BUILD_NUMBER',
    'KLHST_WKS_OS_RELEASE_ID',
    'KLHST_WKS_NAG_VER_ID',
    'KLHST_WKS_OWNER_ID',
    'KLHST_WKS_OWNER_IS_CUSTOM',
    'KLHST_WKS_CUSTOM_OWNER_ID',
    'KLHST_WKS_ANTI_SPAM_STATUS',
    'KLHST_WKS_DLP_STATUS',
    'KLHST_WKS_COLLAB_SRVS_STATUS',
    'KLHST_WKS_EMAIL_AV_STATUS',
    'KLHST_WKS_EDR_STATUS',
]

GROUP_FIELDS = [
    'id',
    'name',
]

GROUP_DETAILED_FIELDS = [
    'id',
    'name',
    'parentId',
    'autoRemovePeriod',
    'notifyPeriod',
    'creationDate',
    'KLGRP_HlfInherited',
    'KLGRP_HlfForceChildren',
    'KLGRP_HlfForced',
    'lastUpdate',
    'hostsNum',
    'childGroupsNum',
    'grp_full_name',
    'level',
    'KLSRV_HSTSTAT_CRITICAL',
    'KLSRV_HSTSTAT_WARNING',
    'KLGRP_GRP_GROUPID_GP',
    'c_grp_autoInstallPackageId',
    'grp_from_unassigned',
    'grp_enable_fscan',
    'KLSRVH_SRV_DN',
    'KLVSRV_ID',
    'KLVSRV_DN',
    'KLGRP_CHLDGRP_CNT',
    'KLGRP_CHLDHST_CNT',
    'KLGRP_CHLDHST_CNT_OK',
    'KLGRP_CHLDHST_CNT_CRT',
    'KLGRP_CHLDHST_CNT_WRN',
]


class Client(BaseClient):
    def login(self, username: str, password: str) -> None:
        encoded_username = base64.b64encode(username.encode('utf-8')).decode('utf-8')
        encoded_password = base64.b64encode(password.encode('utf-8')).decode('utf-8')
        self._http_request(
            method='POST',
            url_suffix='/login',
            headers={
                'Authorization': f'KSCBasic user="{encoded_username}", pass="{encoded_password}"',
                'Content-Type': 'application/json',
            },
            resp_type='response'
        )

    def _raise_for_error(self, res: Dict):
        if error := res.get('PxgError'):
            raise RuntimeError(f'{error.get("code")} - {error.get("message")}')

    def get_results(self, str_accessor: str, limit: Optional[int] = 50) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/ChunkAccessor.GetItemsChunk',
            json_data={
                'strAccessor': str_accessor,
                'nStart': 0,
                'nCount': limit,
            }
        )
        self._raise_for_error(response)
        return response

    def list_hosts_request(self,
                           wstr_filter: Optional[str] = None,
                           fields_to_return: Optional[List[str]] = None
                           ) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/HostGroup.FindHosts',
            json_data={
                'wstrFilter': wstr_filter,
                'lMaxLifeTime': 600,
                'vecFieldsToReturn': fields_to_return,
            }
        )
        self._raise_for_error(response)
        return response

    def list_groups_request(self,
                            wstr_filter: Optional[str] = None,
                            fields_to_return: Optional[List[str]] = None
                            ) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/HostGroup.FindGroups',
            json_data={
                'wstrFilter': wstr_filter,
                'lMaxLifeTime': 600,
                'vecFieldsToReturn': fields_to_return
            }
        )
        self._raise_for_error(response)
        return response

    def add_group_request(self,
                          name: str,
                          parent_id: Optional[int] = None,
                          ) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/HostGroup.AddGroup',
            json_data={
                'pInfo': {
                    'name': name,
                    'parentId': parent_id,
                }
            }
        )
        self._raise_for_error(response)
        return response

    def delete_group_request(self,
                             group_id: int,
                             flags: int = 1,
                             ) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/HostGroup.RemoveGroup',
            json_data={
                'nGroup': group_id,
                'nFlags': flags,
            }
        )
        self._raise_for_error(response)
        return response

    def list_software_applications_request(self) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/InventoryApi.GetInvProductsList',
        )
        self._raise_for_error(response)
        return response

    def list_software_patches_request(self) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/InventoryApi.GetInvPatchesList',
        )
        self._raise_for_error(response)
        return response

    def list_host_software_applications_request(self, hostname: str) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/InventoryApi.GetHostInvProducts',
            json_data={
                'szwHostId': hostname,
            }
        )
        self._raise_for_error(response)
        return response

    def list_host_software_patches_request(self, hostname: str) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/InventoryApi.GetHostInvPatches',
            json_data={
                'szwHostId': hostname
            }
        )
        self._raise_for_error(response)
        return response

    def list_policies_request(self, group_id: int) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/Policy.GetPoliciesForGroup',
            json_data={
                'nGroupId': group_id,
            }
        )
        self._raise_for_error(response)
        return response

    def get_policy_request(self, policy_id: int) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/Policy.GetPolicyData',
            json_data={
                'nPolicy': policy_id,
            }
        )
        self._raise_for_error(response)
        return response

    def get_action_status_request(self, action_id: str) -> Dict:
        response = self._http_request(
            method='POST',
            url_suffix='/AsyncActionStateChecker.CheckActionState',
            json_data={
                'wstrActionGuid': action_id,
            }
        )
        self._raise_for_error(response)
        return response


def test_module(client: Client) -> str:
    client.list_hosts_request(fields_to_return=HOST_FIELDS)
    return 'ok'


def list_hosts(client: Client, args: Dict) -> CommandResults:
    wstr_filter = args.get('filter')
    limit = arg_to_number(args.get('limit', 50))
    response = client.list_hosts_request(wstr_filter=wstr_filter, fields_to_return=HOST_FIELDS)
    str_accessor = response.get('strAccessor', '')
    results = client.get_results(str_accessor, limit)
    outputs = [host.get('value') for host in results.get('pChunk', {}).get('KLCSP_ITERATOR_ARRAY', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No hosts found.'}
    else:
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Host',
            'outputs_key_field': 'KLHST_WKS_HOSTNAME',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown(
                'Hosts List',
                outputs,
                ['KLHST_WKS_HOSTNAME', 'KLHST_WKS_DN', 'KLHST_WKS_OS_NAME', 'KLHST_WKS_FQDN']
            ),
            'raw_response': results,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def get_host(client: Client, args: Dict) -> CommandResults:
    hostname = args.get('hostname')
    wstr_filter = f'KLHST_WKS_HOSTNAME = "{hostname}"'
    response = client.list_hosts_request(wstr_filter=wstr_filter, fields_to_return=HOST_DETAILED_FIELDS)
    str_accessor = response.get('strAccessor', '')
    results = client.get_results(str_accessor)
    iter_array = results.get('pChunk', {}).get('KLCSP_ITERATOR_ARRAY')
    if iter_array and isinstance(iter_array, list) and iter_array[0].get('value'):
        outputs = iter_array[0]['value']
        endpoint = Common.Endpoint(
            id=outputs.get('KLHST_WKS_HOSTNAME'),
            hostname=outputs.get('KLHST_WKS_DN'),
            domain=outputs.get('KLHST_WKS_DNSDOMAIN'),
            os=outputs.get('KLHST_WKS_OS_NAME'),
        )
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Host',
            'outputs_key_field': 'KLHST_WKS_HOSTNAME',
            'outputs': outputs,
            'readable_output': tableToMarkdown(
                f'Host {hostname}',
                outputs,
                ['KLHST_WKS_HOSTNAME', 'KLHST_WKS_OS_NAME', 'KLHST_WKS_FQDN', 'KLHST_WKS_DN', 'KLHST_WKS_NAG_VERSION']
            ),
            'raw_response': results,
            'indicator': endpoint,
        }
    else:
        command_results_args = {'readable_output': 'No host found.'}
    return CommandResults(**command_results_args)


def list_groups(client: Client, args: Dict) -> CommandResults:
    wstr_filter = args.get('filter', '')
    limit = arg_to_number(args.get('limit', 50))
    response = client.list_groups_request(wstr_filter=wstr_filter, fields_to_return=GROUP_FIELDS)
    str_accessor = response.get('strAccessor', '')
    results = client.get_results(str_accessor, limit)
    outputs = [group.get('value') for group in results.get('pChunk', {}).get('KLCSP_ITERATOR_ARRAY', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No groups found.'}
    else:
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Group',
            'outputs_key_field': 'id',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown('Groups List', outputs),
            'raw_response': results,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def add_group(client: Client, args: Dict) -> CommandResults:
    name = args.get('name', '')
    parent_id = arg_to_number(args.get('parent_id'))
    response = client.add_group_request(name, parent_id)
    outputs = {'id': response.get('PxgRetVal'), 'name': name}
    return CommandResults(
        outputs_prefix='KasperskySecurityCenter.Group',
        outputs_key_field='id',
        outputs=outputs,
        readable_output=tableToMarkdown('Group was added successfully', outputs),
        raw_response=response,
    )


def delete_group(client: Client, args: Dict) -> CommandResults:
    group_id = arg_to_number(args.get('group_id'))
    flags = arg_to_number(args.get('flags', 1))
    response = client.delete_group_request(group_id, flags)  # type: ignore[arg-type]
    return CommandResults(
        readable_output='Delete group action was submitted',
        raw_response=response,
    )


def list_software_applications(client: Client) -> CommandResults:
    response = client.list_software_applications_request()
    outputs = [app.get('value') for app in response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No software applications found.'}
    else:
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Inventory.Software',
            'outputs_key_field': 'ProductID',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown(
                'Inventory Software Applications',
                outputs,
                headers=['DisplayName', 'Publisher', 'DisplayVersion'],
            ),
            'raw_response': response,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def list_software_patches(client: Client) -> CommandResults:
    response = client.list_software_patches_request()
    outputs = [app.get('value') for app in response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No software patches found.'}
    else:
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Inventory.Patch',
            'outputs_key_field': 'PatchID',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown(
                'Inventory Software Patches',
                outputs,
                headers=['DisplayName', 'Publisher', 'DisplayVersion'],
            ),
            'raw_response': response,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def list_host_software_applications(client: Client, args: Dict) -> CommandResults:
    hostname = args.get('hostname', '')
    response = client.list_host_software_applications_request(hostname)
    outputs = [app.get('value') for app in response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No software applications found.'}
    else:
        command_results_args = {
            'outputs_prefix': f'KasperskySecurityCenter.Host(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == '
                              f'{hostname}).Software',
            'outputs_key_field': 'ProductID',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown(
                f'Host {hostname} Software Applications',
                outputs,
                headers=['DisplayName', 'Publisher', 'DisplayVersion'],
            ),
            'raw_response': response,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def list_host_software_patches(client: Client, args: Dict) -> CommandResults:
    hostname = args.get('hostname', '')
    response = client.list_host_software_patches_request(hostname)
    outputs = [app.get('value') for app in response.get('PxgRetVal', {}).get('GNRL_EA_PARAM_1', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No software patches found.'}
    else:
        command_results_args = {
            'outputs_prefix': f'KasperskySecurityCenter.Host(val.KLHST_WKS_HOSTNAME && val.KLHST_WKS_HOSTNAME == '
                              f'{hostname}).Patch',
            'outputs_key_field': 'PatchID',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown(
                f'Host {hostname} Software Patches',
                outputs,
                headers=['DisplayName', 'Publisher', 'DisplayVersion'],
            ),
            'raw_response': response,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def list_policies(client: Client, args: Dict) -> CommandResults:
    group_id = arg_to_number(args.get('group_id', -1))
    response = client.list_policies_request(group_id)  # type: ignore[arg-type]
    outputs = [policy.get('value') for policy in response.get('PxgRetVal', [])]
    if not outputs:
        command_results_args = {'readable_output': 'No policies found.'}
    else:
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Policy',
            'outputs_key_field': 'KLPOL_ID',
            'outputs': outputs,  # type: ignore[dict-item]
            'readable_output': tableToMarkdown(
                'Policies List',
                outputs,
                headers=['KLPOL_ID', 'KLPOL_DN', 'KLPOL_PRODUCT', 'KLPOL_VERSION'],
            ),
            'raw_response': response,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def get_policy(client: Client, args: Dict) -> CommandResults:
    policy_id = arg_to_number(args.get('policy_id'))
    response = client.get_policy_request(policy_id)  # type: ignore[arg-type]
    outputs = response.get('PxgRetVal', {})
    if not outputs:
        command_results_args = {'readable_output': 'No policies found.'}
    else:
        command_results_args = {
            'outputs_prefix': 'KasperskySecurityCenter.Policy',
            'outputs_key_field': 'KLPOL_ID',
            'outputs': outputs,
            'readable_output': tableToMarkdown(
                f'Policy {policy_id}',
                outputs,
                headers=['KLPOL_ID', 'KLPOL_DN', 'KLPOL_PRODUCT', 'KLPOL_VERSION'],
            ),
            'raw_response': response,  # type: ignore[dict-item]
        }
    return CommandResults(**command_results_args)  # type: ignore[arg-type]


def main():
    command = demisto.command()
    params = demisto.params()

    try:
        handle_proxy()
        client = Client(
            base_url=urljoin(params.get('server'), '/api/v1.0'),
            verify=not params.get('insecure'),
            proxy=params.get('proxy'),
        )
        credentials = params.get('credentials')
        client.login(credentials.get('identifier'), credentials.get('password'))

        LOG(f'Command being called is {command}')

        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'ksc-hosts-list':
            return_results(list_hosts(client, demisto.args()))
        elif command == 'ksc-host-get':
            return_results(get_host(client, demisto.args()))
        elif command == 'ksc-groups-list':
            return_results(list_groups(client, demisto.args()))
        elif command == 'ksc-group-add':
            return_results(add_group(client, demisto.args()))
        elif command == 'ksc-group-delete':
            return_results(delete_group(client, demisto.args()))
        elif command == 'ksc-software-applications-list':
            return_results(list_software_applications(client))
        elif command == 'ksc-software-patches-list':
            return_results(list_software_patches(client))
        elif command == 'ksc-host-software-applications-list':
            return_results(list_host_software_applications(client, demisto.args()))
        elif command == 'ksc-host-software-patches-list':
            return_results(list_host_software_patches(client, demisto.args()))
        elif command == 'ksc-policies-list':
            return_results(list_policies(client, demisto.args()))
        elif command == 'ksc-policy-get':
            return_results(get_policy(client, demisto.args()))
    except Exception as e:
        return_error(str(e), error=e)


if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
