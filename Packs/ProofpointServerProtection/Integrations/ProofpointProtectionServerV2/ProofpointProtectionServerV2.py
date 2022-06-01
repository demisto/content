from typing import Any, Dict, Union

import urllib3
from dateparser import parse
from requests import Response

import demistomock as demisto
from CommonServerPython import *

urllib3.disable_warnings()


class Client(BaseClient):
    def health_check(self) -> Dict[str, str]:
        return self._http_request(method='GET', url_suffix='/pss/health')

    @logger
    def smart_search_request(self,
                             action: Optional[str] = None,
                             from_: Optional[str] = None,
                             to: Optional[str] = None,
                             virus: Optional[str] = None,
                             env_from: Optional[str] = None,
                             env_rcpt: Optional[str] = None,
                             attach: Optional[str] = None,
                             qid: Optional[str] = None,
                             host: Optional[str] = None,
                             sid: Optional[str] = None,
                             subject: Optional[str] = None,
                             guid: Optional[str] = None,
                             hdr_mid: Optional[str] = None,
                             count: Optional[int] = 100,
                             ) -> Dict[str, Union[str, List]]:
        return self._http_request(
            method='GET',
            url_suffix='/pss/filter',
            params={
                'action': action,
                'from': from_,
                'to': to,
                'virus': virus,
                'env_from': env_from,
                'env_rcpt': env_rcpt,
                'attach': attach,
                'qid': qid,
                'host': host,
                'sid': sid,
                'subject': subject,
                'guid': guid,
                'hdr_mid': hdr_mid,
                'count': count,
            }
        )

    @logger
    def list_quarantined_messages_request(self,
                                          from_: Optional[str] = None,
                                          rcpt: Optional[str] = None,
                                          startdate: Optional[str] = None,
                                          enddate: Optional[str] = None,
                                          subject: Optional[str] = None,
                                          folder: Optional[str] = None,
                                          ) -> Dict[str, Union[str, List]]:
        return self._http_request(
            method='GET',
            url_suffix='/quarantine',
            params={
                'from': from_,
                'rcpt': rcpt,
                'startdate': startdate,
                'enddate': enddate,
                'subject': subject,
                'folder': folder,
                'dlpviolation': 'details',
                'messagestatus': 't',
            }
        )

    @logger
    def quarantine_action_request(self,
                                  action: str,
                                  folder: str,
                                  localguid: str,
                                  scan: Optional[str] = None,
                                  brandtemplate: Optional[str] = None,
                                  securitypolicy: Optional[str] = None,
                                  deletedfolder: Optional[str] = None,
                                  targetfolder: Optional[str] = None,
                                  subject: Optional[str] = None,
                                  appendoldsubject: Optional[str] = None,
                                  from_: Optional[str] = None,
                                  headerfrom: Optional[str] = None,
                                  to: Optional[str] = None,
                                  comment: Optional[str] = None,
                                  resp_type: str = 'json',
                                  ) -> Dict[str, str]:
        return self._http_request(
            method='POST',
            url_suffix='/quarantine',
            json_data={
                'action': action,
                'folder': folder,
                'localguid': localguid,
                'scan': scan,
                'brandtemplate': brandtemplate,
                'securitypolicy': securitypolicy,
                'deletedfolder': deletedfolder,
                'targetfolder': targetfolder,
                'subject': subject,
                'appendoldsubject': appendoldsubject,
                'from': from_,
                'headerfrom': headerfrom,
                'to': to,
                'comment': comment,
            },
            resp_type=resp_type,
        )

    @logger
    def download_message_request(self,
                                 guid: str,
                                 ) -> Response:
        return self._http_request(
            method='GET',
            url_suffix='/quarantine',
            params={
                'guid': guid,
            },
            resp_type='response',
            ok_codes=(200, 404),
        )


def test_module(client: Client) -> str:
    client.health_check()  # test pss managed module
    client.list_quarantined_messages_request(subject='Test')  # test Quarantine managed module
    return 'ok'


def smart_search(client: Client, args: Dict[str, Any]) -> CommandResults:
    assert (start_time := parse(args.get('start_time', '24 hours'), settings={'RETURN_AS_TIMEZONE_AWARE': True})), \
        f"Failed parsing start time: {args.get('start_time')}"
    if end_time := args.get('end_time'):
        assert (end_time := parse(end_time, settings={'RETURN_AS_TIMEZONE_AWARE': True})), \
            f"Failed parsing start time: {end_time}"
        end_time = end_time.strftime("%Y-%m-%dT%H:%M:%S%z")
    result = client.smart_search_request(
        action=args.get('action'),
        from_=start_time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        to=end_time,
        virus=args.get('virus'),
        env_from=args.get('sender'),
        env_rcpt=args.get('recipient'),
        attach=args.get('attachment'),
        qid=args.get('queue_id'),
        host=args.get('host'),
        sid=args.get('sid'),
        subject=args.get('subject'),
        guid=args.get('guid'),
        hdr_mid=args.get('message_id'),
        count=int(args.get('limit', 100)),
    )
    if isinstance(result, dict) and result.get('result'):
        search_result = result.get('result')
        command_results_args = {
            'readable_output': tableToMarkdown(
                'Proofpoint Protection Server Smart Search Results',
                search_result,
                ['GUID', 'Date', 'Sender', 'Recipients', 'Subject', 'Final_Action'],
            ),
            'outputs_prefix': 'Proofpoint.SmartSearch',
            'outputs_key_field': 'GUID',
            'outputs': search_result,
            'raw_response': result,
        }
    else:
        command_results_args = {'readable_output': 'No results found.'}
    return CommandResults(**command_results_args)


def list_quarantined_messages(client: Client, args: Dict[str, Any]) -> CommandResults:
    sender = args.get('sender')
    recipient = args.get('recipient')
    subject = args.get('subject')
    if not any([sender, recipient, subject]):
        raise ValueError('At least one of the following arguments must be specified: sender, recipient, subject.')
    assert (start_time := parse(args.get('start_time', '24 hours'))), \
        f"Failed parsing start time: {args.get('start_time')}"
    assert (end_time := parse(args.get('end_time', 'now'))), f"Failed parsing end time: {args.get('end_time')}"
    result = client.list_quarantined_messages_request(
        from_=sender,
        rcpt=recipient,
        startdate=start_time.strftime('%Y-%m-%d %H:%M:%S'),
        enddate=end_time.strftime('%Y-%m-%d %H:%M:%S'),
        subject=subject,
        folder=args.get('folder_name'),
    )
    if isinstance(result, dict) and result.get('records'):
        records = result.get('records')
        command_results_args = {
            'readable_output': tableToMarkdown(
                'Proofpoint Protection Server Quarantined Messages',
                records,
                ['localguid', 'folder', 'spamscore', 'from', 'rcpts', 'date', 'subject', 'size', 'host_ip'],
            ),
            'outputs_prefix': 'Proofpoint.QuarantinedMessage',
            'outputs_key_field': 'guid',
            'outputs': records,
            'raw_response': result,
        }
    else:
        command_results_args = {'readable_output': 'No results found.'}
    return CommandResults(**command_results_args)


def release_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = str(client.quarantine_action_request(
        action='release',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        deletedfolder=args.get('deleted_folder'),
        scan='t' if args.get('scan') == 'true' else 'f',
        brandtemplate=args.get('brand_template'),
        securitypolicy=args.get('security_policy'),
        resp_type='text',
    ))
    return CommandResults(readable_output=result)


def resubmit_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = str(client.quarantine_action_request(
        action='resubmit',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        resp_type='text',
    ))
    return CommandResults(readable_output=result)


def forward_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = str(client.quarantine_action_request(
        action='forward',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        to=args.get('recipient'),
        deletedfolder=args.get('deleted_folder'),
        subject=args.get('subject'),
        appendoldsubject='t' if args.get('append_old_subject') == 'true' else 'f',
        from_=args.get('sender'),
        headerfrom=args.get('header_from'),
        comment=args.get('comment'),
        resp_type='text',
    ))
    return CommandResults(readable_output=result)


def move_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    local_guid = args.get('local_guid')
    result = client.quarantine_action_request(
        action='move',
        folder=args.get('folder_name'),
        localguid=local_guid,
        targetfolder=args.get('target_folder'),
    )
    if isinstance(result, dict):
        return CommandResults(readable_output=result.get('status', f'Successfully moved message {local_guid}'))
    raise RuntimeError(f'Message move action failed.\n{result}')


def delete_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    local_guid = args.get('local_guid')
    result = client.quarantine_action_request(
        action='delete',
        folder=args.get('folder_name'),
        localguid=local_guid,
        deletedfolder=args.get('deleted_folder'),
    )
    if isinstance(result, dict):
        return CommandResults(readable_output=result.get('status', f'Successfully deleted message {local_guid}'))
    raise RuntimeError(f'Message delete action failed.\n{result}')


def download_message(client: Client, args: Dict[str, Any]) -> Union[CommandResults, Dict]:
    guid = args.get('guid', '')
    result = client.download_message_request(guid)
    if result.status_code == 404:
        return CommandResults(readable_output='No message found.')
    return fileResult(guid + '.eml', result.content)


def main() -> None:
    try:
        command = demisto.command()
        params = demisto.params()
        handle_proxy()
        client = Client(
            base_url=urljoin(params['url'], '/rest/v1'),
            auth=(params['credentials']['identifier'], params['credentials']['password']),
            verify=not params.get('unsecure', False),
            proxy=params.get('proxy', False),
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'proofpoint-pps-smart-search':
            return_results(smart_search(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-messages-list':
            return_results(list_quarantined_messages(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-message-release':
            return_results(release_message(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-message-resubmit':
            return_results(resubmit_message(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-message-forward':
            return_results(forward_message(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-message-move':
            return_results(move_message(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-message-delete':
            return_results(delete_message(client, demisto.args()))
        elif command == 'proofpoint-pps-quarantine-message-download':
            return_results(download_message(client, demisto.args()))

    except Exception as e:
        return_error(str(e), error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
