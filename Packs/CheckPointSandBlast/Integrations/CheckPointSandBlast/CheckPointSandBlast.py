import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""
Check Point Threat Emulation (SandBlast) API Integration for Cortex XSOAR (aka Demisto).
"""
from typing import Dict, Any, List
from CommonServerUserPython import *


''' GLOBAL/PARAMS '''


DEFAULT_INTERVAL = 60
DEFAULT_TIMEOUT = 600
MD5_SIZE = 32
SHA1_SIZE = 40
SHA256_SIZE = 64
DIGEST_BY_LENGTH = {
    MD5_SIZE: 'md5',
    SHA1_SIZE: 'sha1',
    SHA256_SIZE: 'sha256',
}
EXTRACTED_PARTS_CODE_BY_DESCRIPTION = {
    'Linked Objects': 1025,
    'Macros and Code': 1026,
    'Sensitive Hyperlinks': 1034,
    'PDF GoToR Actions': 1137,
    'PDF Launch Actions': 1139,
    'PDF URI Actions': 1141,
    'PDF Sound Actions': 1142,
    'PDF Movie Actions': 1143,
    'PDF JavaScript Actions': 1150,
    'PDF Submit Form Actions': 1151,
    'Database Queries': 1018,
    'Embedded Objects': 1019,
    'Fast Save Data': 1021,
    'Custom Properties': 1017,
    'Statistic Properties': 1036,
    'Summary Properties': 1037,
}
FEATURE_BY_NAME = {
    'Threat Emulation': 'te',
    'Anti-Virus': 'av',
    'Threat Extraction': 'extraction',
    'All': 'all'
}
QUOTA_HEADERS = [
    'RemainQuotaHour',
    'RemainQuotaMonth',
    'AssignedQuotaHour',
    'AssignedQuotaMonth',
    'HourlyQuotaNextReset',
    'MonthlyQuotaNextReset',
    'QuotaId',
    'CloudMonthlyQuotaPeriodStart',
    'CloudMonthlyQuotaUsageForThisGw',
    'CloudHourlyQuotaUsageForThisGw',
    'CloudMonthlyQuotaUsageForQuotaId',
    'CloudHourlyQuotaUsageForQuotaId',
    'MonthlyExceededQuota',
    'HourlyExceededQuota',
    'CloudQuotaMaxAllowToExceedPercentage',
    'PodTimeGmt',
    'QuotaExpiration',
    'Action',
]


''' CLIENT CLASS '''


class Client(BaseClient):
    """
    API Client to communicate with Check Point Threat Prevention API.
    """
    VERSION = 'v1'

    def __init__(self, host: str, api_key: str, reliability: str, verify: bool = False, proxy: bool = False):
        """
        Client constructor, set headers and call super class BaseClient.

        Args:
            host (str): Check Point Threat Emulation (SandBlast) API URL.
            api_key (str): API key to connect to the server.
            verify (bool): SSL verification handled by BaseClient. Defaults to False.
            proxy (bool): System proxy is handled by BaseClient. Defaults to False.
        """
        super().__init__(
            base_url=f'{host}/tecloud/api/{Client.VERSION}/file',
            verify=verify,
            proxy=proxy,
            headers={
                'Authorization': api_key
            }
        )
        self.reliability = reliability

    def query_request(
        self,
        features: List[str],
        reports: List[str],
        method: str,
        file_name: str = None,
        extracted_parts_codes: List[int] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Return an analysis report or status of a file that was uploaded according to a file hash.

        Args:
            features (List[str]): Features to include in the query, options: te, av, extraction.
            reports (List[str]): Report format for the query, options: pdf, xml, tar, summary.
            method (str): Threat extraction method, options: clean, pdf.
            file_name (str): Name of the file to query. Defaults to None.
            extracted_parts_codes (List[int]): Cleans file according to inserted codes.
                Defaults to None.
            **kwargs: can hold -
                md5 (str): md5 digest of the file to query. Defaults to None.
                sha1 (str): sha1 digest of the file to query. Defaults to None.
                sha256 (str): sha256 digest of the file to query. Defaults to None.

        Returns:
            Dict[str, Any]: Analysis report or status of the queried file.
        """
        json_data = remove_empty_elements({
            'request': {
                'features': features,
                'md5': kwargs.get('md5'),
                'sha1': kwargs.get('sha1'),
                'sha256': kwargs.get('sha256'),
                'file_name': file_name,
                'te': {
                    'reports': reports,
                },
                'extraction': {
                    'extracted_parts_codes': extracted_parts_codes,
                    'method': method
                }
            }
        })

        return self._http_request(
            method='POST',
            url_suffix='/query',
            json_data=json_data
        )

    def upload_request(
        self,
        file_path: str,
        file_name: str,
        file_type: str,
        features: List[str],
        image_ids: List[str],
        image_revisions: List[Optional[int]],
        reports: List[str],
        method: str,
        extracted_parts_codes: List[int] = None,
    ) -> Dict[str, Any]:
        """
        Once the file has been uploaded return an analysis report or status of a file
        that was uploaded.

        Args:
            file_path (str): Path to the file to upload.
            file_name (str): Name of the file to upload.
            file_type (str): Type (extension) of the file to upload.
            features (List[str]): Features to include when uploading, options: te, av, extraction.
            image_ids (List[str]): ID of available OS images.
                An image is an operating system configuration.
            image_revisions (List[int]): Revision of available OS images.
                An image is an operating system configuration.
            reports (List[str]): Report format to upload, options: pdf, xml, tar, summary.
            method (str): Threat extraction method, options: clean, pdf.
            extracted_parts_codes (List[int]): Cleans file according to inserted codes.
                Defaults to None.

        Returns:
            Dict[str, Any]: Analysis report or status of the uploaded file.
        """
        request = json.dumps(remove_empty_elements({
            'request': {
                'file_name': file_name,
                'file_type': file_type,
                'features': features,
                'te': {
                    'reports': reports,
                    'images': [
                       {'id': image_id, 'image_revision': revision}
                        for image_id, revision in zip(image_ids, image_revisions)
                    ]
                },
                'extraction': {
                    'extracted_parts_codes': extracted_parts_codes,
                    'method': method
                }
            }
        }))

        with open(file_path, 'rb') as file_handler:
            file = (file_name, file_handler.read())

        return self._http_request(
            method='POST',
            url_suffix='/upload',
            files={
                'request': request,
                'file': file
            }
        )

    def download_request(self, file_id: str) -> requests.Response:
        """
        Return the file saved in the server.

        Args:
            file_id (str): ID of the file in the database.

        Returns:
            bytes: File in database.
        """
        return self._http_request(
            method='GET',
            url_suffix='/download',
            params={
                'id': file_id
            },
            resp_type='response'
        )

    def quota_request(self) -> Dict[str, Any]:
        """
        Return the quota information about current API key.

        Returns:
            Dict[str, Any]: Quota information.
        """
        return self._http_request(
            method='POST',
            url_suffix='/quota',
        )


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests API connectivity and authentication
    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.

    Returns:
        str: 'ok' if test passed, anything else will fail the test.
    """
    try:
        client.query_request(
            file_name='test.pdf',
            features=['te', 'av', 'extraction'],
            reports=['xml', 'summary'],
            method='pdf',
            **{'md5': '80f284ccdf2afae0f5347f4532584a61'}  # type:ignore
        )
    except DemistoException as e:
        e_string = str(e)

        if '403' in e_string:
            return 'Authorization Error: make sure API Key is correctly set'

        if '404' in e_string:
            return 'URL Error: make sure URL is correctly set'

        return e_string

    return 'ok'


def file_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Get file_hash list from user input and check if they are in the correct format.
    Client will make a Query request with every file_hash,
    if the file_hash exists in the server a dbot_score will be calculated.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: In case the file_hash isn't

    Returns:
        List[CommandResults]: Indicator for every file_hash
    """
    files = argToList(args['file'])
    command_results: List[CommandResults] = []

    for file_hash in files:
        try:
            hash_type = get_hash_type(file_hash)

            if hash_type not in ('md5', 'sha1', 'sha256'):
                raise ValueError(f'Hash "{file_hash}" is not of type SHA-256, SHA-1 or MD5')

            raw_response = client.query_request(
                features=['te', 'av', 'extraction'],
                reports=['xml', 'summary'],
                method='pdf',
                **{hash_type: file_hash}
            )

            label = dict_safe_get(raw_response, ['response', 'status', 'label'])

            if label not in ('FOUND', 'PARTIALLY_FOUND'):
                message = dict_safe_get(raw_response, ['response', 'status', 'message'])
                command_results.append(CommandResults(readable_output=f'File not found: "{file_hash}"\n{message}'))
                continue

            file_indicator = get_file_indicator(file_hash, hash_type, raw_response, client.reliability)
            verdict_str = file_indicator.dbot_score.to_readable()

            score_description = {
                'confidence': dict_safe_get(raw_response, ['response', 'te', 'confidence']),
                'severity': dict_safe_get(raw_response, ['response', 'te', 'severity']),
                'signature_name': dict_safe_get(raw_response, ['response', 'av', 'malware_info', 'signature_name'])
            }
            outputs = remove_empty_elements({
                'MD5': dict_safe_get(raw_response, ['response', 'md5']),
                'SHA1': dict_safe_get(raw_response, ['response', 'sha1']),
                'SHA256': dict_safe_get(raw_response, ['response', 'sha256']),
                verdict_str: {
                    'Vendor': 'CheckPointSandBlast',
                    'Description': score_description
                }
            })
            readable_output = tableToMarkdown(
                f'Results of file hash: "{file_hash}"',
                outputs,
                headers=[
                    'MD5',
                    'SHA1',
                    'SHA256',
                    verdict_str,
                ]
            )

            command_results.append(CommandResults(
                readable_output=readable_output,
                outputs_prefix=outputPaths.get('file'),
                indicator=file_indicator,
                outputs=outputs,
                raw_response=raw_response,
            ))

        except Exception as e:
            command_results.append(CommandResults(readable_output=f'Could not process file: "{file_hash}"\n{str(e)}'))

    return command_results


def query_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Query information of a file.
    The command will be a bridge between the client request and the presented value to the user.
    Get arguments inputted by the user and send them to the client.
    Once a response has been received, process and return it so it can be sent to the user.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: reports input was invalid.
        ValueError: file_hash input was invalid.

    Returns:
        CommandResults: Information about the queried file.
    """
    file_name = args.get('file_name', '')
    file_hash = args['file_hash']
    features = argToList(args.get('features', ''))
    reports = argToList(args.get('reports'))
    method = args.get('method', '')
    extracted_parts = argToList(args.get('extracted_parts'))

    features = [FEATURE_BY_NAME[feature] for feature in features]

    if 'all' in features:
        features = ['te', 'av', 'extraction']

    if 'te' in features and {'pdf', 'summary'}.issubset(reports):
        raise ValueError(
            'Requesting for PDF and summary reports simultaneously is not supported!'
        )

    if method != 'clean':
        extracted_parts_codes = None
    else:
        extracted_parts_codes = [
            EXTRACTED_PARTS_CODE_BY_DESCRIPTION[extracted_part]
            for extracted_part in extracted_parts
        ]

    file_hash_size = len(file_hash)
    digest = DIGEST_BY_LENGTH.get(file_hash_size)

    if digest is None:
        raise ValueError('file_hash is not recognized!')

    raw_output = client.query_request(
        file_name=file_name,
        features=features,
        reports=reports,
        method=method,
        extracted_parts_codes=extracted_parts_codes,
        **{digest: file_hash}
    )

    output = raw_output.get('response', {'': ''})
    readable_output = get_analysis_readable_output(features, output, 'Query')
    output = get_analysis_context_output(output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SandBlast.Query',
        outputs_key_field=['MD5', 'SHA1', 'SHA256'],
        outputs=output,
        raw_response=raw_output,
    )


def upload_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Upload a file to the server.
    The command will be a bridge between the client request and the presented value to the user.
    Get arguments inputted by the user and send them to the client.
    Once a response has been received, process and return it so it can be sent to the user.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Raises:
        ValueError: The new file's name extension is different from the original.
        ValueError: The length of image_id and image_revision isn't equal.
        ValueError: Reports input was invalid.

    Returns:
        CommandResults: Information about the uploaded file.
    """
    file_id = args['file_id']
    file_name = args.get('file_name')
    features = argToList(args.get('features'))
    image_ids = argToList(args.get('image_ids'))
    image_revisions = [arg_to_number(image_revision)
                       for image_revision in argToList(args.get('image_revisions'))]
    reports = argToList(args.get('reports'))
    method = args.get('method', '')
    extracted_parts = argToList(args.get('extracted_parts'))

    file_entry = demisto.getFilePath(file_id)

    if not file_name:
        file_name = file_entry['name']

    file_type = os.path.splitext(file_name)[1]

    if file_type != os.path.splitext(file_entry['name'])[1]:
        raise ValueError('New file name must have the same extension as the original file!')

    features = [FEATURE_BY_NAME[feature] for feature in features]

    if 'all' in features:
        features = ['te', 'av', 'extraction']

    if len(image_ids) != len(image_revisions):
        raise ValueError('Image IDs and image revisions must be of same length!')

    if 'te' in features and {'pdf', 'summary'}.issubset(reports):
        raise ValueError(
            'Requesting for PDF and summary reports simultaneously is not supported!'
        )

    if method != 'clean':
        extracted_parts_codes = None
    else:
        extracted_parts_codes = [
            EXTRACTED_PARTS_CODE_BY_DESCRIPTION[extracted_part]
            for extracted_part in extracted_parts
        ]

    raw_output = client.upload_request(
        file_path=file_entry['path'],
        file_name=file_name,
        file_type=file_type,
        features=features,
        image_ids=image_ids,
        image_revisions=image_revisions,
        reports=reports,
        method=method,
        extracted_parts_codes=extracted_parts_codes,
    )

    output = raw_output.get('response', {'': ''})
    readable_output = get_analysis_readable_output(features, output, 'Upload')
    output = get_analysis_context_output(output)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SandBlast.Upload',
        outputs_key_field=['MD5', 'SHA1', 'SHA256'],
        outputs=output,
        raw_response=raw_output,
    )


def download_command(client: Client, args: Dict[str, Any]) -> Any:
    """
    Download a file from the server.
    The command will be a bridge between the client request and the presented value to the user.
    Get arguments inputted by the user and send them to the client.
    Once a response has been received, process and return it so it can be sent to the user.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        Any: File from the server.
    """
    file_id = args['file_id']

    output = client.download_request(file_id)

    content_disposition = output.headers.get("Content-Disposition")
    split_content_disposition = content_disposition.split('"') if content_disposition is not None else []

    if len(split_content_disposition) < 2:
        file_name = 'file.pdf'
    else:
        file_name = split_content_disposition[1]

    return fileResult(filename=file_name, data=output.content)


def quota_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Get quota information about an API key.
    The command will be a bridge between the client request and the presented value to the user.
    Once a response has been received, process and return it so it can be sent to the user.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: Quota information about the API key.
    """
    raw_outputs = client.quota_request()
    outputs = raw_outputs.get('response')[0]  # type:ignore

    output = get_quota_context_output(outputs)

    readable_output = tableToMarkdown(
        'Quota Information',
        output,
        headers=QUOTA_HEADERS,
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='SandBlast.Quota',
        outputs_key_field='QuotaId',
        outputs=output,
        raw_response=raw_outputs,
    )


''' POLLING COMMANDS '''


def setup_upload_polling_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """
    Initiate polling command for upload command.

    Args:
        client (Client): Connection to the client class from which we can run the desired request.
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request.

    Returns:
        CommandResults: A result to return to the user which will be presented in a markdown value.
            The result itself will depend on the stage of polling.
    """
    return upload_polling_command(args, client=client)


@polling_function(
    name='sandblast-upload',
    interval=arg_to_number(demisto.args().get('interval_in_seconds', DEFAULT_INTERVAL)),
    timeout=arg_to_number(demisto.args().get('timeout_in_seconds', DEFAULT_TIMEOUT)),
    requires_polling_arg=False,
)
def upload_polling_command(args: Dict[str, Any], **kwargs) -> PollResult:
    """
    Polling command to display the progress of the upload command.
    After the first run, progress will be shown through the query command.
    Once a new file is uploaded to the server, upload command will provide the status
    'UPLOAD_SUCCESS' and pass arguments to the with query command.
    Query command will run till its status is 'FOUND' or 'PARTIALLY_FOUND',
    which is the ending term for the polling command.

    Args:
        args (Dict[str, Any]): Arguments passed down by the CLI to provide in the HTTP request and a Client.

    Returns:
        PollResult: A result to return to the user which will be set as a CommandResults.
            The result itself will depend on the stage of polling.
    """
    if 'file_hash' not in args:
        command_results = upload_command(kwargs['client'], args)

    else:
        command_results = query_command(kwargs['client'], args)

    raw_response = command_results.raw_response

    file_name = dict_safe_get(raw_response, ['response', 'file_name'])
    file_hash = dict_safe_get(raw_response, ['response', 'md5'])
    label = dict_safe_get(raw_response, ['response', 'status', 'label'])

    if label in ('FOUND', 'PARTIALLY_FOUND'):
        return PollResult(
            response=command_results,
            continue_to_poll=False,
        )

    polling_args = {
        'file_name': file_name,
        'file_hash': file_hash,
        **args
    }

    return PollResult(
        response=command_results,
        continue_to_poll=True,
        args_for_next_run=polling_args,
        partial_result=command_results
    )


''' HELPER FUNCTIONS '''


def get_analysis_context_output(output: Dict[str, Any]) -> Dict[str, Any]:
    av = dict_safe_get(output, ['av'])
    malware_info = dict_safe_get(av, ['malware_info'])
    extraction = dict_safe_get(output, ['extraction'])
    extraction_data = dict_safe_get(extraction, ['extraction_data'])
    te = dict_safe_get(output, ['te'])

    return remove_empty_elements({
        'Status': dict_safe_get(output, ['status']),
        'MD5': dict_safe_get(output, ['md5']),
        'SHA1': dict_safe_get(output, ['sha1']),
        'SHA256': dict_safe_get(output, ['sha256']),
        'FileType': dict_safe_get(output, ['file_type']),
        'FileName': dict_safe_get(output, ['file_name']),
        'Features': dict_safe_get(output, ['features']),
        'AntiVirus': {
            'SignatureName': dict_safe_get(malware_info, ['signature_name']),
            'MalwareFamily': dict_safe_get(malware_info, ['malware_family']),
            'MalwareType': dict_safe_get(malware_info, ['malware_type']),
            'Severity': dict_safe_get(malware_info, ['severity']),
            'Confidence': dict_safe_get(malware_info, ['confidence']),
            'Status': dict_safe_get(av, ['status']),
        },
        'ThreatExtraction': {
            'Method': dict_safe_get(extraction, ['method']),
            'ExtractResult': dict_safe_get(extraction, ['extract_result']),
            'ExtractedFileDownloadId': dict_safe_get(extraction, ['extracted_file_download_id']),
            'OutputFileName': dict_safe_get(extraction, ['output_file_name']),
            'Time': dict_safe_get(extraction, ['time']),
            'ExtractContent': dict_safe_get(extraction, ['extract_content']),
            'TexProduct': dict_safe_get(extraction, ['tex_product']),
            'Status': dict_safe_get(extraction, ['status']),
            'ExtractionData': {
                'InputExtension': dict_safe_get(extraction_data, ['input_extension']),
                'InputRealExtension': dict_safe_get(extraction_data, ['input_real_extension']),
                'Message': dict_safe_get(extraction_data, ['message']),
                'ProtectionName': dict_safe_get(extraction_data, ['protection_name']),
                'ProtectionType': dict_safe_get(extraction_data, ['protection_type']),
                'ProtocolVersion': dict_safe_get(extraction_data, ['protocol_version']),
                'RealExtension': dict_safe_get(extraction_data, ['real_extension']),
                'Risk': dict_safe_get(extraction_data, ['risk']),
                'ScrubActivity': dict_safe_get(extraction_data, ['scrub_activity']),
                'ScrubMethod': dict_safe_get(extraction_data, ['scrub_method']),
                'ScrubResult': dict_safe_get(extraction_data, ['scrub_result']),
                'ScrubTime': dict_safe_get(extraction_data, ['scrub_time']),
                'ScrubbedContent': dict_safe_get(extraction_data, ['scrubbed_content']),
            },
        },
        'ThreatEmulation': {
            'Trust': dict_safe_get(te, ['trust']),
            'Score': dict_safe_get(te, ['score']),
            'CombinedVerdict': dict_safe_get(te, ['combined_verdict']),
            'Images': dict_safe_get(te, ['images']),
            'Status': dict_safe_get(te, ['status']),
        }
    })


def get_analysis_readable_output(
    features: List[str],
    output: Dict[str, Any],
    command: str
) -> Any:
    """
    Get a response outputs and set them to be readable outputs with tableToMarkdown.

    Args:
        features (Dict[str, Any]): Features in the HTTP response.
        output (Dict[str, Any]): HTTP response outputs which will be processed.
        command (str): Name of the calling command.

    Returns:
        Any: Readable outputs which have been set to Markdown
    """
    readable_output = f'{command} Results\n'
    status_label = dict_safe_get(output, ['status', 'label'])

    output_file_info = {
        'FileName': dict_safe_get(output, ['file_name']),
        'FileType': dict_safe_get(output, ['file_type']),
        'Label': status_label,
        'Message': dict_safe_get(output, ['status', 'message']),
        'MD5': dict_safe_get(output, ['md5']),
        'SHA1': dict_safe_get(output, ['sha1']),
        'SHA256': dict_safe_get(output, ['sha256']),
    }
    headers_file_info = [
        'FileName',
        'FileType',
        'Label',
        'Message',
        'MD5',
        'SHA1',
        'SHA256',
    ]
    readable_output += tableToMarkdown(
        'File Info',
        output_file_info,
        headers=headers_file_info,
        headerTransform=string_to_table_header,
        removeNull=True,
    )

    if status_label not in ('FOUND', 'PARTIALLY_FOUND'):
        return readable_output

    if 'te' in features:
        output_te = {
            'CombinedVerdict': dict_safe_get(output, ['te', 'combined_verdict']),
            'Severity': dict_safe_get(output, ['te', 'severity']),
            'Confidence': dict_safe_get(output, ['te', 'confidence']),
            'Verdict': dict_safe_get(output, ['te', 'verdict']),
        }
        headers_te = [
            'CombinedVerdict',
            'Severity',
            'Confidence',
            'Verdict',
        ]
        readable_output += tableToMarkdown(
            'Threat Emulation',
            output_te,
            headers=headers_te,
            headerTransform=string_to_table_header,
            removeNull=True,
        )

    if 'av' in features:
        output_av = {
            'SignatureName': dict_safe_get(output, ['av', 'malware_info', 'signature_name']),
            'MalwareFamily': dict_safe_get(output, ['av', 'malware_info', 'malware_family']),
            'MalwareType': dict_safe_get(output, ['av', 'malware_info', 'malware_type']),
            'Confidence': dict_safe_get(output, ['av', 'malware_info', 'confidence']),
            'Severity': dict_safe_get(output, ['av', 'malware_info', 'severity']),
        }
        headers_av = [
            'SignatureName',
            'MalwareFamily',
            'MalwareType',
            'Confidence',
            'Severity',
        ]
        readable_output += tableToMarkdown(
            'Anti-Virus',
            output_av,
            headers=headers_av,
            headerTransform=string_to_table_header,
            removeNull=True,
        )

    if 'extraction' in features:
        output_extraction = {
            'ExtractResult': dict_safe_get(output, ['extraction', 'extract_result']),
            'ExtractedFileDownloadId':
                dict_safe_get(output, ['extraction', 'extracted_file_download_id']),
            'Risk': dict_safe_get(output, ['extraction', 'extraction_data', 'risk']),
        }
        headers_extraction = [
            'ExtractResult',
            'ExtractedFileDownloadId',
            'Risk',
        ]
        readable_output += tableToMarkdown(
            'Threat Extraction',
            output_extraction,
            headers=headers_extraction,
            headerTransform=string_to_table_header,
            removeNull=True,
        )

    return readable_output


def get_dbotscore(response: Dict[str, Any]) -> int:
    """
    Response received from the API request which holds fields that will help indicate the DBotScore.

    Args:
        response (Dict[str, Any]): Response received from the API request.

    Returns:
        int: A score to represent the reputation of an indicator.
    """
    av_confidence = dict_safe_get(response, ['response', 'av', 'malware_info', 'confidence'])
    av_severity = dict_safe_get(response, ['response', 'av', 'malware_info', 'severity'])

    te_confidence = dict_safe_get(response, ['response', 'te', 'confidence'])
    te_severity = dict_safe_get(response, ['response', 'te', 'severity'])
    te_combined_verdict = dict_safe_get(response, ['response', 'te', 'combined_verdict'])
    if av_confidence == 0 and av_severity == 0 and \
            te_combined_verdict.lower() == 'benign' and (te_severity == 0 or te_severity is None) and \
            (te_confidence <= 1 or te_confidence is None):
        score = Common.DBotScore.GOOD

    elif te_severity == 1:
        score = Common.DBotScore.SUSPICIOUS

    else:
        score = Common.DBotScore.BAD

    return score


def get_file_indicator(file_hash: str, hash_type: str, response: Dict[str, Any], reliability: str) -> Common.File:
    """
    Returns a file indicator that could potentially be malicious and will be checked for reputation.

    Args:
        file_hash (str): File hash value
        hash_type (str): File hash type.
        response (Dict[str, Any]): Response received from the API request.
        reliability (str): integration source reliability.

    Returns:
        Common.File: File indicator.
    """
    dbot_score = Common.DBotScore(
        indicator=file_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name='CheckPointSandBlast',
        reliability=reliability,
        score=get_dbotscore(response),
    )

    file_name = dict_safe_get(response, ['response', 'file_name'])

    if not file_name:
        file_type = None

    else:
        file_type = os.path.splitext(file_name)[1]

    file_indicator = Common.File(
        dbot_score=dbot_score,
        name=file_name,
        file_type=file_type,
        **{hash_type: file_hash}
    )

    return file_indicator


def get_date_string(timestamp_string: str = '0') -> str:
    """
    Cast timestamp to int and convert it to a datetime string.

    Args:
        timestamp_string (str, optional): Holds a timestamp to be converted.
            Defaults to '0'.

    Returns:
        str: A string with the timestamp in datetime format.
    """
    timestamp = int(timestamp_string) * 1000
    return timestamp_to_datestring(timestamp)


def get_quota_context_output(outputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert outputs keys to PascalCase and convert any timestamp to date format.

    Args:
        outputs (Dict[str, Any]): API key quota information.

    Returns:
        Dict[str, Any]: outputs in a more readable form.
    """
    response_by_context = {
        'RemainQuotaHour': 'remain_quota_hour',
        'RemainQuotaMonth': 'remain_quota_month',
        'AssignedQuotaHour': 'assigned_quota_hour',
        'AssignedQuotaMonth': 'assigned_quota_month',
        'HourlyQuotaNextReset': 'hourly_quota_next_reset',
        'MonthlyQuotaNextReset': 'monthly_quota_next_reset',
        'QuotaId': 'quota_id',
        'CloudMonthlyQuotaPeriodStart': 'cloud_monthly_quota_period_start',
        'CloudMonthlyQuotaUsageForThisGw': 'cloud_monthly_quota_usage_for_this_gw',
        'CloudHourlyQuotaUsageForThisGw': 'cloud_hourly_quota_usage_for_this_gw',
        'CloudMonthlyQuotaUsageForQuotaId': 'cloud_monthly_quota_usage_for_quota_id',
        'CloudHourlyQuotaUsageForQuotaId': 'cloud_hourly_quota_usage_for_quota_id',
        'MonthlyExceededQuota': 'monthly_exceeded_quota',
        'HourlyExceededQuota': 'hourly_exceeded_quota',
        'CloudQuotaMaxAllowToExceedPercentage': 'cloud_quota_max_allow_to_exceed_percentage',
        'PodTimeGmt': 'pod_time_gmt',
        'QuotaExpiration': 'quota_expiration',
        'Action': 'action',
    }

    context_outputs_with_date = [
        'HourlyQuotaNextReset',
        'MonthlyQuotaNextReset',
        'CloudMonthlyQuotaPeriodStart',
        'PodTimeGmt',
        'QuotaExpiration',
    ]

    output: Dict[str, Any] = {}

    for context_output, response in response_by_context.items():
        output[context_output] = outputs.get(response)

    for key in context_outputs_with_date:
        output[key] = get_date_string(output[key])

    return output


''' MAIN FUNCTION '''


def main() -> None:
    """
    Getting data from instance setting and setting up the class Client with an API key.
    Checking user input command with if statements and a dictionary.
    """
    params: Dict[str, Any] = demisto.params()
    args: Dict[str, Any] = demisto.args()
    command = demisto.command()

    api_key = params['credentials']['password']
    host = params['url']
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    reliability = params.get('integrationReliability', 'C - Fairly reliable')

    commands = {
        'sandblast-query': query_command,
        'sandblast-upload': setup_upload_polling_command,
        'sandblast-download': download_command,
        'sandblast-quota': quota_command,
        'file': file_command
    }

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            host=host,
            api_key=api_key,
            reliability=reliability,
            verify=verify_certificate,
            proxy=proxy,
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command in commands:
            return_results(commands[command](client, args))

        else:
            raise NotImplementedError(f'Command doesn\'t exist - {command}')

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
