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
            }
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
    client.health_check()
    return 'ok'


def smart_search(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.smart_search_request(
        action=args.get('action'),
        from_=parse(args.get('start_time', '24 hours ago')).isoformat(),  # type: ignore[union-attr]
        to=parse(args.get('end_time', 'now')).isoformat(),  # type: ignore[union-attr]
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
            'readable_output': tableToMarkdown(  # TODO: add headers
                'Proofpoint Protection Server Smart Search Results',
                search_result
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
    result = client.list_quarantined_messages_request(
        from_=sender,
        rcpt=recipient,
        startdate=parse(args.get('start_time', '24 hours')).strftime('%Y-%m-%d %H:%M:%S'),  # type: ignore[union-attr]
        enddate=parse(args.get('end_time', 'now')).strftime('%Y-%m-%d %H:%M:%S'),  # type: ignore[union-attr]
        subject=subject,
        folder=args.get('folder_name'),
    )
    if isinstance(result, dict) and result.get('records'):
        records = result.get('records')
        command_results_args = {
            'readable_output': tableToMarkdown(  # TODO: add headers
                'Proofpoint Protection Server Quarantined Messages',
                records
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
    result = client.quarantine_action_request(
        action='release',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        deletedfolder=args.get('deleted_folder'),
        scan='t' if args.get('scan') == 'true' else 'f',
        brandtemplate=args.get('brand_template'),
        securitypolicy=args.get('security_policy'),
    )
    if isinstance(result, dict) and result.get('status'):
        return CommandResults(readable_output='The message was released successfully.')
    raise RuntimeError(f'Message release action failed.\n{result}')


def resubmit_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.quarantine_action_request(
        action='resubmit',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
    )
    if isinstance(result, dict) and result.get('status'):
        return CommandResults(readable_output='The message was resubmitted successfully.')
    raise RuntimeError(f'Message resubmit action failed.\n{result}')


def forward_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.quarantine_action_request(
        action='forward',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        deletedfolder=args.get('deleted_folder'),
        subject=args.get('subject'),
        appendoldsubject='t' if args.get('append_old_subject') == 'true' else 'f',
        from_=args.get('from'),
        headerfrom=args.get('header_from'),
        to=args.get('to'),
        comment=args.get('comment'),
    )
    if isinstance(result, dict) and result.get('status'):
        return CommandResults(readable_output='The message was forwarded successfully.')
    raise RuntimeError(f'Message forward action failed.\n{result}')


def move_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.quarantine_action_request(
        action='move',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        targetfolder=args.get('target_folder'),
    )
    if isinstance(result, dict) and result.get('status'):
        return CommandResults(readable_output='The message was moved successfully.')
    raise RuntimeError(f'Message move action failed.\n{result}')


def delete_message(client: Client, args: Dict[str, Any]) -> CommandResults:
    result = client.quarantine_action_request(
        action='delete',
        folder=args.get('folder_name'),
        localguid=args.get('local_guid'),
        deletedfolder=args.get('deleted_folder'),
    )
    if isinstance(result, dict) and result.get('status'):
        return CommandResults(readable_output='The message was deleted successfully.')
    raise RuntimeError(f'Message delete action failed.\n{result}')


def download_message(client: Client, args: Dict[str, Any]) -> Union[CommandResults, Dict]:
    guid = args.get('guid', '')
    result = client.download_message_request(guid)
    if result.status_code == 404:
        return CommandResults(readable_output='No message found.')
    return fileResult(guid + '.eml', result.content)


# TODO: version
def main() -> None:
    try:
        command = demisto.command()
        params = demisto.params()
        client = Client(
            base_url=urljoin(params['url'], '/rest/v1'),
            auth=(params['credentials']['identifier'], params['credentials']['password']),
            verify=not params.get('insecure', False),
            proxy=params.get('proxy', False),
        )
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'proofpoint-pps-smart-search':
            return_results(smart_search(client, demisto.args()))
        elif command == 'proofpoint-pps-list-quarantined-messages':
            return_results(list_quarantined_messages(client, demisto.args()))
        elif command == 'proofpoint-pps-release-message':
            return_results(release_message(client, demisto.args()))
        elif command == 'proofpoint-pps-resubmit-message':
            return_results(resubmit_message(client, demisto.args()))
        elif command == 'proofpoint-pps-forward-message':
            return_results(forward_message(client, demisto.args()))
        elif command == 'proofpoint-pps-move-message':
            return_results(move_message(client, demisto.args()))
        elif command == 'proofpoint-pps-delete-message':
            return_results(delete_message(client, demisto.args()))
        elif command == 'proofpoint-pps-download-message':
            return_results(download_message(client, demisto.args()))

    except Exception as e:
        return_error(str(e), error=e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
