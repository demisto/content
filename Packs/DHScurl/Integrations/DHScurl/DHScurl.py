import demistomock as demisto
from CommonServerPython import *

import subprocess
import tempfile


def call_curl(curl: str = None):
    demisto.log('curl{}'.format(curl))
    # curl = 'apt-get update && apt-get install curl -y'
    # process = subprocess.Popen(curl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # stdout, stderr = process.communicate()
    time_before = time.time()
    completed_process = subprocess.run(curl, shell=True, capture_output=True, timeout=180, encoding='utf-8')
    demisto.log('running the curl took {}sec'.format(round(time.time() - time_before)))
    demisto.log('completed_process.stdout{}'.format(completed_process.stdout))
    demisto.log('completed_process.stderr{}'.format(completed_process.stderr))
    return completed_process.stdout, completed_process.stderr


def call_curls(curls: List[str]):
    curl = ' && '.join(curls)
    response_stdout, response_stderr = call_curl(curl)
    # return list(zip(curls, response.split('\n')))
    return response_stdout, response_stderr


def dhscurl_run_command(curl_to_run, key_tempfile_name, certificate_tempfile_name):
    cert_key_to_curl = ' --cert {} --key {}'.format(certificate_tempfile_name, key_tempfile_name)

    curl_get_production_collection_endpoints = 'curl -X GET ' \
                                               'https://ais2.cisa.dhs.gov/taxii2/ ' \
                                               '-H "Accept: application/taxii+json;version=2.1" ' \
                                               '-H "Content-Type: application/taxii+json" ' \
                                               '--noproxy "*" -k' + cert_key_to_curl
    curl_get_public_collections_info = 'curl -X GET ' \
                                       'https://ais2.cisa.dhs.gov/public/collections/ ' \
                                       '-H "Accept: application/taxii+json;version=2.1" ' \
                                       '-H "Content-Type: application/taxii+json" ' \
                                       '--noproxy "*" -k' + cert_key_to_curl
    collection_id = ''
    curl_get_public_objects_info = 'curl -X GET ' \
                                   '"https://ais2.cisa.dhs.gov/public/collections/{}/objects/' \
                                   '?limit=10' \
                                   '&added_after=2022-10-18T13%3A10%3A50.84906Z"' \
                                   ' -H "Accept: application/taxii+json;version=2.1" ' \
                                   '-H "Content-Type: application/taxii+json" ' \
                                   '--noproxy "*" -k'.format(collection_id) + cert_key_to_curl

    response_stdout, response_stderr = '', ''
    if curl_to_run == 'all':
        response_stdout, response_stderr = call_curls([curl_get_production_collection_endpoints,
                                                       curl_get_public_collections_info,
                                                       curl_get_public_objects_info])
    elif curl_to_run == 'taxii2':
        response_stdout, response_stderr = call_curl(curl_get_production_collection_endpoints)
    elif curl_to_run == 'collections':
        response_stdout, response_stderr = call_curl(curl_get_public_collections_info)
    elif curl_to_run == 'objects':
        response_stdout, response_stderr = call_curl(curl_get_public_objects_info)

    return response_stdout


def build_certificate(cert_var):
    var_list = cert_var.split('-----')
    # replace spaces with newline characters
    certificate_fixed = '-----'.join(
        var_list[:2] + [var_list[2].replace(' ', '\n')] + var_list[3:])
    cf = tempfile.NamedTemporaryFile(delete=False)
    cf.write(certificate_fixed.encode())
    cf.flush()
    return cf.name


def main():
    params = demisto.params()
    key = params.get('key', {}).get('password')
    certificate = params.get('certificate')

    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))

    try:
        key_tempfile_name = build_certificate(key)
        certificate_tempfile_name = build_certificate(certificate)

        if command == 'test-module':
            return_results('ok')
        elif command == 'dhscurl-run':
            args = demisto.args()
            return_results(dhscurl_run_command(args['curl'], key_tempfile_name, certificate_tempfile_name))
    except Exception as e:
        return_error('Failed to execute {} command.\nError:\n{}'.format(command, str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
