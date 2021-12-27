import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Set parameters to access the NIOS WAPI.
params = demisto.params()
base_url = params.get("domain")
api_version = params.get("version")
url = f"https://{base_url}/wapi/{api_version}/"

valid_cert = not params.get('insecure', False)
proxy = params.get('proxy', False)
user_id = demisto.get(params, 'credentials.identifier')
pw = demisto.get(params, 'credentials.password')

# Helper functions.


def sanitize_filename(pathname):
    """Return sanitized filename without path information."""

    # Get the base filename without the directory path, convert dashes
    # to underscores, and get rid of other special characters.
    filename = ''
    for c in os.path.basename(pathname):
        if c == '-':
            c = '_'
        if c.isalnum() or c == '_' or c == '.':
            filename += c
    return filename


if demisto.command() == 'test-module':
    # This is the call made when pressing the integration Test button.
    """
    curl -k -u admin:infoblox -X GET "https://gridmaster/wapi/v2.11/zone_rp?_return_fields%2B=rpz_policy&_return_as_object=1"
    """
    params = {
        "_return_fields": "rpz_policy",
        "_return_as_object": "1"
    }
    result = requests.get(f"{url}zone_rp", params=params, auth=(user_id, pw))
    if result.status_code == 200:
        demisto.results("ok")
    else:
        return_error(result.text)

elif demisto.command() == 'infoblox-upload-csv':
    fileID = demisto.args().get("fileID")
    raw_path = demisto.getFilePath(fileID)
    csv_data = raw_path['path']
    # Initiate a file upload operation, providing a filename (with
    # alphanumeric, underscore, or periods only) for the CSV job manager.
    req_params = {'filename': sanitize_filename(csv_data)}
    r = requests.post(url + 'fileop?_function=uploadinit',
                      params=req_params,
                      auth=(user_id, pw),
                      verify=valid_cert)
    if r.status_code != requests.codes.ok:
        demisto.results(r.text)
        exit_msg = 'Error {} initiating upload: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))
    results = r.json()

    # Save the authentication cookie for use in subsequent requests.
    ibapauth_cookie = r.cookies['ibapauth']

    # Save the returned URL and token for subsequent requests.
    # Hack since API returns url with local IP address
    # swap ip for domain integration parameter
    raw_url = results['url'].split("/")
    url_parts = raw_url[3:]
    upload_url = f"https://{base_url}/{'/'.join(url_parts)}"
    upload_token = results['token']

    # Upload the data in the CSV file.

    # Specify a file handle for the file data to be uploaded.
    f = open(csv_data, 'r')
    req_files = {'filedata': f}

    # Specify the name of the file (not used?).
    req_params = {'name': sanitize_filename(csv_data)}

    # Use the ibapauth cookie to authenticate instead of userid/password.
    req_cookies = {'ibapauth': ibapauth_cookie}

    # Perform the actual upload. (NOTE: It does NOT return JSON results.)
    # ,
    r = requests.post(upload_url,
                      params=req_params,
                      files=req_files,
                      cookies=req_cookies,
                      verify=valid_cert)
    f.close()
    if r.status_code != requests.codes.ok:
        # demisto.results(r.text)
        exit_msg = 'Error {} uploading file: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    # Initiate the actual import task.
    req_params = {
        'token': upload_token,
        'doimport': True,
        'on_error': 'STOP',
        'operation': 'INSERT',
        'update_method': 'OVERRIDE'
    }

    r = requests.post(url + 'fileop?_function=csv_import',
                      params=req_params,
                      cookies=req_cookies,
                      verify=valid_cert)
    if r.status_code != requests.codes.ok:
        #demisto.results (r.text)
        exit_msg = 'Error {} starting CSV import: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))
    results = r.json()
    # Record cvsimporttask object reference for possible future use.
    csvimporttask = results['csv_import_task']['_ref']
    results = CommandResults(
        outputs_prefix='Infoblox.CSV',
        outputs_key_field='csvimporttask',
        outputs={
            'csvimporttask': csvimporttask,
            'fileID': fileID
        }
    )
    return_results(results)
    # demisto.results(csvimporttask)

elif demisto.command() == 'infoblox-check-upload-status':
    ref = demisto.args().get("ref")
    res = requests.get(f"{url}{ref}", auth=(user_id, pw), verify=valid_cert)
    # demisto.results(status)
    results = CommandResults(
        outputs_prefix='Infoblox.CSV',
        outputs_key_field='csvimporttask',
        outputs={
            'csvimporttask': ref,
            'status': res.json()
        }
    )
    return_results(results)
