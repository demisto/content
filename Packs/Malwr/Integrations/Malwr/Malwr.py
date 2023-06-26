import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ast
import hashlib
import re
from typing import Any

import requests
from bs4 import BeautifulSoup

MAIN_URL = 'https://malwr.com'
STATUS_URL = '/submission/status/{}/'
RESULT_URL = '/analysis/{}/'
MD5_PREFIX_STR = 'with MD5 '
SUPPORTED_COMMANDS = ['Submit', 'Status', 'Result', 'Detonate']
DETONATE_DEFAULT_TIMEOUT = 600
DETONATE_POLLING_INTERVAL = 10


def md5(fname):  # pragma: no cover
    hash_md5 = hashlib.md5()  # guardrails-disable-line  # nosec B324
    with open(fname, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_md5.update(chunk)

    return hash_md5.hexdigest()


def get_file_path(file_id):  # pragma: no cover
    filepath_result = demisto.getFilePath(file_id)
    if 'path' not in filepath_result:
        demisto.results(f'Error: entry {file_id} is not a file.')
        return

    return filepath_result['path']

# The Malwar API from https://github.com/PaulSec/API-malwr.com


class MalwrAPI:
    """
        MalwrAPI Main Handler
    """
    HEADERS = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0'}

    def __init__(self, url, username=None, password=None):  # pragma: no cover
        self.url = url
        self.session = requests.session()
        self.username = username
        self.password = password
        self.logged = False

    def login(self):  # pragma: no cover
        """Login on malwr.com website"""

        if self.username and self.password:
            soup = self.request_to_soup(self.url + '/account/login')
            csrf_input = soup.find(attrs=dict(name='csrfmiddlewaretoken'))
            csrf_token = csrf_input['value']
            payload = {
                'csrfmiddlewaretoken': csrf_token,
                'username': f'{self.username}',
                'password': f'{self.password}'
            }
            login_request = self.session.post(self.url + "/account/login/",
                                              data=payload, headers=self.HEADERS)

            if login_request.status_code == 200:
                self.logged = True
                return True
            else:
                self.logged = False
                return False

    def request_to_soup(self, url=None):  # pragma: no cover
        """Request url and return the Beautifoul Soup object of html returned"""
        if not url:
            url = self.url

        req = self.session.get(url, headers=self.HEADERS)
        soup = BeautifulSoup(req.text, "html.parser")
        return soup

    @staticmethod
    def evaluate_simple_math_expr(expr: str) -> Optional[int]:
        # from https://stackoverflow.com/a/38860845
        try:
            tree = ast.parse(expr, mode='eval')
        except SyntaxError:
            return None  # not a Python expression
        if not all(isinstance(node, (ast.Expression,
                                     ast.UnaryOp, ast.unaryop,
                                     ast.BinOp, ast.operator,
                                     ast.Num)) for node in ast.walk(tree)):
            return None  # not a mathematical expression (numbers and operators)
        result = eval(compile(tree, filename='', mode='eval'))  # nosec B307
        return result

    @staticmethod
    def find_submission_links(req):
        # regex to check if the file was already submitted before
        pattern = r'(\/analysis\/[a-zA-Z0-9]{12,}\/)'
        submission_links = re.findall(pattern, req.text)

        return submission_links

    def submit_sample(self, filepath, analyze=True, share=True, private=True):
        if self.logged is False:
            self.login()

        s = self.session
        req = s.get(self.url + '/submission/', headers=self.HEADERS)
        soup = BeautifulSoup(req.text, "html.parser")

        pattern = r'(\d [-+*] \d) ='
        math_captcha_fields = re.findall(pattern, req.text)
        math_captcha_field = None
        if math_captcha_fields:
            math_captcha_field = MalwrAPI.evaluate_simple_math_expr(math_captcha_fields[0])
        data = {
            'math_captcha_field': math_captcha_field,
            'math_captcha_question': soup.find('input', {'name': 'math_captcha_question'})['value'],
            'csrfmiddlewaretoken': soup.find('input', {'name': 'csrfmiddlewaretoken'})['value'],
            'share': 'on' if share else 'off',  # share by default
            'analyze': 'on' if analyze else 'off',  # analyze by default
            'private': 'on' if private else 'off'  # private by default
        }

        req = s.post(self.url + '/submission/', data=data, headers=self.HEADERS, files={'sample': open(filepath, 'rb')})
        submission_links = MalwrAPI.find_submission_links(req)

        res: dict[str, Any] = {
            'md5': hashlib.md5(open(filepath, 'rb').read()).hexdigest(),  # guardrails-disable-line  # nosec
            'file': filepath
        }

        if len(submission_links) > 0:
            res['analysis_link'] = submission_links[0]
            return res, soup
        else:
            pattern = r'(\/submission\/status\/[a-zA-Z0-9]{12,}\/)'
            submission_status = re.findall(pattern, req.text)

            if len(submission_status) > 0:
                res['analysis_link'] = submission_status[0]
                return res, soup
            elif 'file like this waiting for processing, submission aborted.' in req.text:
                return 'File already submitted, check its status.', soup
            else:
                return 'Error with the file.', soup

    def get_status(self, analysis_id):  # pragma: no cover
        s = self.session
        req = s.get(self.url + STATUS_URL.format(analysis_id), headers=self.HEADERS)
        soup = BeautifulSoup(req.text, 'html.parser')
        submission_links = MalwrAPI.find_submission_links(req)
        if len(submission_links) > 0:
            status = 'complete'
            return status, submission_links[0], soup
        elif 'The analysis is still pending' in str(soup):
            status = 'pending'
        else:
            status = 'error'

        return status, None, soup

    def get_result(self, analysis_id):  # pragma: no cover
        analysis_status, _, _ = self.get_status(analysis_id)
        if analysis_status != 'complete':
            status = 'pending'
            soup = None
            is_malicious = None
            md5 = None
        else:
            status = 'complete'
            s = self.session
            req = s.get(self.url + RESULT_URL.format(analysis_id), headers=self.HEADERS)
            soup = BeautifulSoup(req.text, 'html.parser')
            is_malicious = 'malicious' in str(soup)
            soup_str = str(soup)
            start_index = soup_str.find(MD5_PREFIX_STR)
            if start_index == -1:
                md5 = None
            else:
                start_index += len(MD5_PREFIX_STR)
                md5 = soup_str[start_index: start_index + 32]

        return status, is_malicious, soup, md5

    def __setattr__(self, name, value):
        if name == 'HEADERS':
            raise AttributeError(f"can't reassign constant '{name}'")
        else:
            self.__dict__[name] = value


def main():  # pragma: no cover
    if 'identifier' in demisto.params()['credentials'] and 'password' in demisto.params()['credentials']:
        username = demisto.params()['credentials']['identifier']
        password = demisto.params()['credentials']['password']
    else:
        username = None
        password = None

    malwr = MalwrAPI(
        url=demisto.params()['server'],
        username=username,
        password=password
    )

    entry: dict[str, Any] = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'ReadableContentsFormat': formats['text']
    }

    if demisto.command() == 'test-module':
        demisto.results('ok')
        return

    elif demisto.command() == 'malwr-submit':
        file_id = demisto.args()['fileId']
        filepath = get_file_path(file_id)
        res, soup = malwr.submit_sample(filepath)
        if isinstance(res, dict) and 'analysis_link' in res:
            analysis_id = res['analysis_link'].split('/')[-2]

            message = 'File submitted: {}{}\n'.format(MAIN_URL, res['analysis_link'])
            message += 'MD5: {}\n'.format(res['md5'])
            message += f'Analysis ID: {analysis_id}'

            entry['Contents'] = str(soup)
            entry['HumanReadable'] = message
            entry['EntryContext'] = {
                'Malwr.Submissions(val.Id==obj.Id)': {'Id': analysis_id, 'Md5': res['md5'], 'Status': 'pending'}
            }

        else:
            entry['HumanReadable'] = res

    elif demisto.command() == 'malwr-status':
        analysis_id = demisto.args()['analysisId']
        status, data, soup = malwr.get_status(analysis_id)
        if status == 'complete':
            message = f'The analysis is complete, you can view it at: {MAIN_URL}{data}.'
        elif status == 'pending':
            message = 'The analysis is still in progress.'
        else:
            message = 'Error: the specified analysis does not exist.'

        entry['Contents'] = str(soup)
        entry['HumanReadable'] = message
        entry['EntryContext'] = {'Malwr.Submissions(val.Id==obj.Id)': {'Id': analysis_id, 'Status': status}}

    elif demisto.command() == 'malwr-result':
        analysis_id = demisto.args()['analysisId']
        status, is_malicious, soup, md5 = malwr.get_result(analysis_id)

        if status == 'pending':
            message = 'The analysis is still in progress.'
            demisto.results(message)
            return

        if is_malicious:
            entry['EntryContext'] = {
                'Malwr.Submissions(val.Id==obj.Id)': {
                    'Id': analysis_id, 'Status': status, 'Malicious': {'Vendor': 'Malwr'}
                }
            }
            entry['EntryContext']['DBotScore'] = {'Indicator': md5, 'Vendor': 'Malwr', 'Score': 3}
            message = 'The file is malicious.'
        else:
            entry['EntryContext'] = {'Malwr.Submissions(val.Id==obj.Id)': {'Id': analysis_id, 'Status': status}}
            entry['EntryContext']['DBotScore'] = {'Indicator': md5, 'Vendor': 'Malwr', 'Score': 0}
            message = 'The file is not malicious.'

        entry['Contents'] = str(soup)
        entry['HumanReadable'] = message

    elif demisto.command() == 'malwr-detonate':
        status = ''
        file_id = demisto.args()['fileId']
        filepath = get_file_path(file_id)
        timeout = int(demisto.args()['timeout']) if 'timeout' in demisto.args() else DETONATE_DEFAULT_TIMEOUT

        # Submit the sample
        res, soup = malwr.submit_sample(filepath)
        if isinstance(res, dict) and 'analysis_link' not in res:
            demisto.results(f'ERROR: {res}')
            return

        # Poll the status of the analysis
        analysis_id = res.get('analysis_link', '').split('/')[-2]

        start_time = time.time()
        while (time.time() - start_time) < timeout:
            status, _, _ = malwr.get_status(analysis_id)

            if status == 'error':
                demisto.results('Error analyzing file.')
                return

            demisto.info(f'status = {status}')
            if status == 'complete':
                break

            time.sleep(DETONATE_POLLING_INTERVAL)  # pylint: disable=sleep-exists

        if status == 'pending':
            demisto.results('File analysis timed out.')
            return

        # Get the result
        status, is_malicious, soup, md5 = malwr.get_result(analysis_id)
        if status != 'complete':
            demisto.results('Error analyzing file.')
            return

        if is_malicious:
            entry['EntryContext'] = {
                'Malwr.Submissions(val.Id==obj.Id)': {
                    'Id': analysis_id, 'Md5': md5, 'Status': status, 'Malicious': {'Vendor': 'Malwr'}
                }
            }
            entry['EntryContext']['DBotScore'] = {
                'Indicator': md5, 'Vendor': 'Malwr', 'Score': 3 if is_malicious else 0
            }
            message = 'The file is malicious.'
        else:
            entry['EntryContext'] = {
                'Malwr.Submissions(val.Id==obj.Id)': {'Id': analysis_id, 'Md5': res['md5'], 'Status': status}
            }
            message = 'The file is not malicious.'

        entry['Contents'] = str(soup)
        entry['HumanReadable'] = message

    demisto.results(entry)


if __name__ in ('__main__', '__builtin__', 'builtins'):  # pragma: no cover
    main()
