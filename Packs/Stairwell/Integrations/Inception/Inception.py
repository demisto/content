import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import
import json
import urllib3

urllib3.disable_warnings()  # pylint: disable=no-member


class Client(BaseClient):
    def get_file_reputation(self, file_hash: str) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=file_hash
        )

    def get_file_variants(self, file_hash: str,) -> Dict[str, Any]:
        return self._http_request(
            method='GET',
            url_suffix=file_hash
        )


def test_module(client):  # pragma: no cover
    try:
        # We'll use a default file hash, accessible by all, to test the connection
        response = client.get_file_reputation("e7762f90024c5366807c7c145d3456f0ac3be086c0ec3557427d3c2c10a2052d")
        response = json.dumps(response)
        if("attributes" in response):
            return 'ok'
    except Exception:
        return 'Authorization Error: make sure API Key is correctly set'


def file_enrichment_command(client, file_hash):
    try:
        response = client.get_file_reputation(file_hash)
        response = json.dumps(response)
        if("attributes" in response):
            responseJson = json.loads(response)
            md = '# Stairwell Inception\n'
            file_md5 = responseJson['data']['attributes']['md5']
            file_sha256 = responseJson['data']['attributes']['sha256']
            md += f'MD5: {file_md5}\n'
            md += f'SHA256: {file_sha256}\n'

            # List the filename(s) if present
            if responseJson['data']['attributes']['names']:
                filenames = []
                for ind in responseJson['data']['attributes']['names']:
                    if "\\" in ind:
                        full_path = ind.split('\\')
                        filename = full_path[-1].lower()
                        filenames.append(filename) if filename not in filenames else filenames
                    elif "/" in ind:
                        full_path = ind.split('/')
                        filename = full_path[-1].lower()
                        filenames.append(filename) if filename not in filenames else filenames
                filenames_string = (', '.join([str(x) for x in filenames]))
                md += f'Filename(s): {filenames_string}\n'

            # Count the number of assets if there are seen assets
            if responseJson['data']['attributes']['inception']['assets']:
                seen_assets = len(responseJson['data']['attributes']['inception']['assets'])
                md += f'Seen Assets: {seen_assets}\n'

            # Show matching YARA intelligence if present
            if responseJson['data']['attributes']['crowdsourced_yara_results']:
                yara_rules = []
                for yara in responseJson['data']['attributes']['crowdsourced_yara_results']:
                    yara_rules.append(yara['rule_name'])
                yara_string = (', '.join([str(x) for x in yara_rules]))
                md += f'Matching YARA Intel: {yara_string}\n'

            # Create readable output if AV results exist
            if responseJson['data']['attributes']['last_analysis_results']:
                avResults = responseJson['data']['attributes']['last_analysis_results']
                md += '### AV Scanning Results\n'
                md += 'Engine Name|Result\n'
                md += '---|---\n'
                for indAv in avResults:
                    engine_name = avResults[indAv]['engine_name']
                    result = avResults[indAv]['result']
                    md += f'{engine_name}|{result}\n'
            results = CommandResults(
                readable_output=md,
                outputs_prefix='Inception.File_Details',
                outputs=responseJson,
            )
            return(results)
    except DemistoException as err:
        # API will return 404 if the file is not found
        if "404" in str(err):
            results = CommandResults(
                readable_output="File not found: " + file_hash
            )
            return(results)
        else:
            raise err


def variant_discovery_command(client, file_hash):
    try:
        response = client.get_file_reputation(file_hash)
        response = json.dumps(response)
        if("similarity" in response):
            response_json = json.loads(response)
            md_string = tableToMarkdown("File Variants Discovered", response_json['variants'])
            results = CommandResults(
                outputs_prefix='Inception.Variants',
                readable_output=md_string,
                outputs=response_json,
            )
            return(results)
        elif("variants" in response):
            results = CommandResults(
                readable_output="No variants discovered for: " + file_hash
            )
            return(results)
    except DemistoException as err:
        # API will return 500 if the file is not found
        if "500" in str(err):
            results = CommandResults(
                readable_output="File not found: " + file_hash
            )
            return(results)
        else:
            raise err


def main() -> None:  # pragma: no cover
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')

    # Params enabled by XSOAR functionality
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        # Built-in command
        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            client = Client(
                base_url="https://reputation.app.stairwell.com/api/v3/files/",
                verify=verify_certificate,
                headers={"X-Apikey": api_key},
                proxy=proxy)
            result = test_module(client)
            return_results(result)

        elif command == 'inception-file-enrichment':
            client = Client(
                base_url="https://reputation.app.stairwell.com/api/v3/files/",
                verify=verify_certificate,
                headers={"X-Apikey": api_key},
                proxy=proxy)
            result = file_enrichment_command(client, args.get('fileHash'))
            return_results(result)

        elif command == 'inception-variant-discovery':
            client = Client(
                base_url="https://app.stairwell.com/v202112/variants/",
                verify=verify_certificate,
                headers={"Authorization": api_key},
                proxy=proxy,
                timeout=120)
            result = variant_discovery_command(client, args.get('sha256'))
            return_results(result)

        else:
            raise NotImplementedError(f"command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join(("Failed to execute {command} command.",
                                "Error:",
                                str(e))))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
