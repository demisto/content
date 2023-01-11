import demistomock as demisto
from CommonServerPython import *

import subprocess
import tempfile


def call_curl(curl: str = None):
    demisto.log('curl={}'.format(curl))
    # curl = 'apt-get update && apt-get install curl -y'
    # process = subprocess.Popen(curl, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # stdout, stderr = process.communicate()
    time_before = time.time()
    completed_process = subprocess.run(curl, shell=True, capture_output=True, timeout=1800, encoding='utf-8')
    demisto.log('running the curl took {}sec'.format(round(time.time() - time_before)))
    demisto.log('completed_process.stdout={}'.format(completed_process.stdout))
    demisto.log('completed_process.stderr={}'.format(completed_process.stderr))
    return completed_process.stdout, completed_process.stderr


def call_curls(curls: List[str]):
    curl = ' && '.join(curls)
    response_stdout, response_stderr = call_curl(curl)
    # return list(zip(curls, response.split('\n')))
    return response_stdout, response_stderr


def curl_run_command(curl_to_run):
    # full_curl = 'curl -v -X GET {}' \
    #             ' -H "Accept: application/taxii+json;version=2.1"' \
    #             ' -H "Content-Type: application/taxii+json"' \
    #             ' --noproxy "*" -k'.format(curl_to_run) + cert_key_to_curl
    response_stdout, response_stderr = call_curl(curl_to_run)

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


def curl_cert_key(key, certificate):
    if key and certificate:
        key_tempfile_name = build_certificate(key)
        certificate_tempfile_name = build_certificate(certificate)
        # curl makes sure the cert and key match, and raises an error if not
        return ' --cert {} --key {}'.format(certificate_tempfile_name, key_tempfile_name)
    return ''


def main():
    params = demisto.params()
    key = params.get('key', {}).get('password')
    certificate = params.get('certificate')
    # cert_key_to_curl = curl_cert_key(key, certificate)

    command = demisto.command()
    demisto.info('Command being called is {}'.format(command))

    try:
        if command == 'test-module':
            return_results('ok')
        elif command == 'taxii2-curl-run':
            args = demisto.args()
            # return_results(curl_run_command(args['curl'], cert_key_to_curl))
            return_results(curl_run_command(args['curl']))
    except Exception as e:
        return_error('Failed to execute {} command.\nError:\n{}'.format(command, str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
