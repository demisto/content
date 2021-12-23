from CommonServerPython import *
from CommonServerUserPython import *

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

''' CLIENT CLASS '''


class Client(BaseClient):

    def _httpp_request(self, method, url_suffix='', full_url=None, headers=None, auth=None, json_data=None,
                       params={}, data=None, files=None, timeout=100, resp_type='json', ok_codes=None,
                       return_empty_response=False, retries=0, status_list_to_retry=None, backoff_factor=5,
                       raise_on_redirect=False, raise_on_status=False, error_handler=None, empty_valid_codes=None,
                       **kwargs):
        try:
            # Replace params if supplied
            address = full_url if full_url else urljoin(self._base_url, url_suffix)
            headers = headers if headers else self._headers
            auth = auth if auth else self._auth
            if retries:
                self._implement_retry(retries, status_list_to_retry, backoff_factor, raise_on_redirect,
                                      raise_on_status)
            # Execute
            res = self._session.request(
                method,
                address,
                verify=self._verify,
                params=params,
                data=data,
                json=json_data,
                files=files,
                headers=headers,
                auth=auth,
                timeout=timeout,
                **kwargs)
            # Handle error responses gracefully
            if not self._is_status_code_valid(res, ok_codes):
                if error_handler:
                    error_handler(res)
                else:
                    err_msg = 'Error in API call [{}] - {}' \
                        .format(res.status_code, res.reason)
                    try:
                        # Try to parse json error response
                        error_entry = res.json()
                        err_msg += '\n{}'.format(json.dumps(error_entry))
                        raise DemistoException(err_msg, res=res)
                    except ValueError:
                        err_msg += '\n{}'.format(res.text)
                        raise DemistoException(err_msg, res=res)

            if not empty_valid_codes:
                empty_valid_codes = [204]
            is_response_empty_and_successful = (res.status_code in empty_valid_codes)
            if is_response_empty_and_successful and return_empty_response:
                return res

            resp_type = resp_type.lower()
            try:
                if resp_type == 'json':
                    return res.json()
                if resp_type == 'text':
                    return res.text
                if resp_type == 'content':
                    return res.content
                if resp_type == 'xml':
                    ET.parse(res.text)
                return res

            except ValueError:
                pass

        except requests.exceptions.RetryError:
            pass

    def get_access_policies(self) -> CommandResults:

        data = self._httpp_request(
            method='GET',
            url_suffix='/wsa/api/v3.0/web_security/access_policies')

        return data

    def get_domain_map(self) -> CommandResults:

        data = self._httpp_request(

            method='GET',
            url_suffix='/wsa/api/v2.0/configure/web_security/domain_map')

        return data

    def get_url_categories(self) -> CommandResults:

        data = self._httpp_request(

            method='GET',
            url_suffix='/wsa/api/v3.0/generic_resources/url_categories')

        return data

    def get_identification_profiles(self) -> CommandResults:

        data = self._httpp_request(

            method='GET',
            url_suffix='/wsa/api/v3.0/web_security/identification_profiles')

        return data

    def modify_access_policies(self, args) -> CommandResults:

        policy_name = args.get('policyname')
        profile_name = args.get('profile_name')
        policy_order = args.get('policy_order')
        policy_status = args.get('policy_status')
        auth = args.get('auth')
        accesspoliciesdata = {"access_policies": [{"policy_name": "{}".format(policy_name),
                                                   "policy_status": "{}".format(policy_status),
                                                   "policy_order": int(policy_order),
                                                   "membership":
                                                       {"identification_profiles": [{
                                                           "profile_name": "{}".format(profile_name),
                                                           "auth": "{}".format(auth)}]}}]}
        response = self._httpp_request(method='PUT',
                                       url_suffix='/wsa/api/v3.0/web_security/access_policies?format=json',
                                       data=json.dumps(accesspoliciesdata))

        try:
            if not response:
                outputs = {'wsa': {
                    'response': "The modifying request has been processed successfully and all "
                                "the given access policies are updated with the given payload"}}
                return CommandResults(
                    outputs=outputs)

            else:
                outputs = {'wsa': {
                    'response': response}}
                return CommandResults(
                    outputs=outputs)

        except DemistoException:
            pass

        return CommandResults(outputs=outputs)

    def delete_access_policies(self, a_data) -> CommandResults:
        policy_namess = a_data.get('policy_name')

        access_data = {"policy_names": policy_namess}

        data = self._httpp_request(method='DELETE', url_suffix='/wsa/api/v3.0/web_security/access_policies',
                                   params=access_data)

        try:
            if not data:
                outputs = {'wsa': {
                    'response': "The deleting request has been processed successfully and all "
                                "the given access policies are updated with the given payload"}}
                return CommandResults(
                    outputs=outputs)

            else:
                outputs = {'wsa': {
                    'response': data}}
                return CommandResults(
                    outputs=outputs)

        except DemistoException:
            pass
        return CommandResults(outputs=outputs)


''' HELPER FUNCTIONS '''


def initiateheaderrequest(api_key):

    headerrequest = {'Content-Type': 'application/json',
                     "cache-control": "no-cache", "User-Agent":
                         "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36",
                     "Accept": "*/*", 'Authorization': 'Basic {}'.format(api_key), "accept-encoding": "gzip, deflate"}

    return headerrequest


''' COMMAND FUNCTIONS '''


def test_module(client: Client):
    try:
        client.get_access_policies()
    except DemistoException as exception:
        if 'Authorization Required' in str(exception) or 'Authentication failed' in str(exception):
            return_error(f'Authorization Error: please check your credentials.\n\nError:\n{exception}')

        if 'HTTPSConnectionPool' in str(exception):
            return_error(f'Connection Error: please check your server ip address.\n\nError: {exception}')
        raise
    return 'ok'


def wsa_get_access_policies_command(client) -> CommandResults:
    results = client.get_access_policies()

    return CommandResults(
        outputs_key_field='',
        outputs=results)


def wsa_get_domain_map_command(client) -> CommandResults:
    results = client.get_domain_map()

    return CommandResults(
        outputs_key_field='',
        outputs=results)


def wsa_get_url_categories_command(client) -> CommandResults:
    results = client.get_url_categories()

    return CommandResults(
        outputs_key_field='',
        outputs=results)


def wsa_get_identification_profiles_command(client) -> CommandResults:
    results = client.get_identification_profiles()

    return CommandResults(
        outputs_key_field='',
        outputs=results)


def wsa_delete_access_policies_command(client, args):
    results = client.delete_access_policies(args)

    return results


def wsa_modify_access_policies_command(client, args):
    results = client.modify_access_policies(args)

    return results


''' MAIN FUNCTION '''


def main() -> None:

    args = demisto.args()
    api_key = demisto.params()['apikey']
    port = demisto.params()['port']
    port = ":" + port
    base_url = demisto.params()['url'] + port
    verify_certificate = demisto.params()['insecure']
    proxyy = demisto.params().get('proxy', False)

    handle_proxy()

    demisto.debug(f'Command being called is {demisto.command()}')

    try:
        header = initiateheaderrequest(api_key)

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=header,
            proxy=proxyy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif demisto.command() == 'wsa-get-access-policies':
            return_results(wsa_get_access_policies_command(client))

        elif demisto.command() == 'wsa-get-domain-map':
            return_results(wsa_get_domain_map_command(client))

        elif demisto.command() == 'wsa-get-identification-profiles':
            return_results(wsa_get_identification_profiles_command(client))

        elif demisto.command() == 'wsa-get-url-categories':
            return_results(wsa_get_url_categories_command(client))

        elif demisto.command() == 'wsa-delete-access-policies':
            return_results(wsa_delete_access_policies_command(client, args))

        elif demisto.command() == 'wsa-modify-access-policies':
            return_results(wsa_modify_access_policies_command(client, args))

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
