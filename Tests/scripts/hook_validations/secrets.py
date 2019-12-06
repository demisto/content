import io
import os
import sys
import math
import json
import string
import argparse
import PyPDF2

from bs4 import BeautifulSoup
from Tests.scripts.constants import *
from Tests.test_utils import run_command, print_error, str2bool, print_color, LOG_COLORS, checked_type,\
    is_file_path_in_pack, get_pack_name

# secrets settings
# Entropy score is determined by shanon's entropy algorithm, most English words will score between 1.5 and 3.5
ENTROPY_THRESHOLD = 4.0
ACCEPTED_FILE_STATUSES = ['m', 'a']
SKIPPED_FILES = {'secrets_white_list', 'id_set.json', 'conf.json', 'Pipfile', 'secrets-ignore', 'ami_builds.json',
                 'secrets_test.py', 'secrets.py'}
TEXT_FILE_TYPES = {'.yml', '.py', '.json', '.md', '.txt', '.sh', '.ini', '.eml', '', '.csv', '.js', '.pdf', '.html',
                   '.ps1'}
SKIP_FILE_TYPE_ENTROPY_CHECKS = {'.eml'}
SKIP_DEMISTO_TYPE_ENTROPY_CHECKS = {'playbook-'}
WHITELIST_PATH = './Tests/secrets_white_list.json'
YML_FILE_EXTENSION = '.yml'

# disable-secrets-detection-start
# secrets
URLS_REGEX = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
IPV6_REGEX = r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1' \
             r'[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::' \
             r'(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]' \
             r'{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
             r'(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
             r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}' \
             r'|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}' \
             r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])' \
             r'\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}' \
             r'[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|' \
             r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}' \
             r'|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:' \
             r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]' \
             r'[0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]' \
             r'{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]' \
             r'|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|' \
             r'(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|' \
             r'(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)'
IPV4_REGEX = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
DATES_REGEX = r'((\d{4}[/.-]\d{2}[/.-]\d{2})[T\s](\d{2}:?\d{2}:?\d{2}:?(\.\d{5,10})?([+-]\d{2}:?\d{2})?Z?)?)'
# false positives
UUID_REGEX = r'([\w]{8}-[\w]{4}-[\w]{4}-[\w]{4}-[\w]{8,12})'
# disable-secrets-detection-end


def get_secrets(branch_name, is_circle):
    secrets_found = {}
    # make sure not in middle of merge
    if not run_command('git rev-parse -q --verify MERGE_HEAD'):
        secrets_file_paths = get_all_diff_text_files(branch_name, is_circle)
        secrets_found = search_potential_secrets(secrets_file_paths)
        if secrets_found:
            secrets_found_string = 'Secrets were found in the following files:\n'
            for file_name in secrets_found:
                secrets_found_string += ('\nFile Name: ' + file_name)
                secrets_found_string += json.dumps(secrets_found[file_name], indent=4)
            if not is_circle:
                secrets_found_string += '\nRemove or whitelist secrets in order to proceed, then re-commit\n'
            else:
                secrets_found_string += 'The secrets were exposed in public repository,' \
                                        ' remove the files asap and report it.\n'
            secrets_found_string += 'For more information about whitelisting visit: ' \
                                    'https://github.com/demisto/internal-content/tree/master/documentation/secrets'
            print_error(secrets_found_string)
    return secrets_found


def get_all_diff_text_files(branch_name, is_circle):
    """
    Get all new/modified text files that need to be searched for secrets
    :param branch_name: current branch being worked on
    :param is_circle: boolean to check if being ran from circle
    :return: list: list of text files
    """
    changed_files_string = run_command("git diff --name-status origin/master...{}".format(branch_name)) if is_circle \
        else run_command("git diff --name-status --no-merges HEAD")
    return get_diff_text_files(changed_files_string)


def get_diff_text_files(files_string):
    """Filter out only added/modified text files from git diff
    :param files_string: string representing the git diff files
    :return: text_files_list: string of full path to text files
    """
    # file statuses to filter from the diff, no need to test deleted files.
    all_files = files_string.split('\n')
    text_files_list = set()
    for file_name in all_files:
        file_data = file_name.split()
        if not file_data:
            continue
        file_status = file_data[0]
        if 'r' in file_status.lower():
            file_path = file_data[2]
        else:
            file_path = file_data[1]
        # only modified/added file, text readable, exclude white_list file
        if (file_status.lower() in ACCEPTED_FILE_STATUSES or 'r' in file_status.lower()) and is_text_file(file_path):
            if not any(skipped_file in file_path for skipped_file in SKIPPED_FILES):
                text_files_list.add(file_path)
    return text_files_list


def is_text_file(file_path):
    file_extension = os.path.splitext(file_path)[1]
    if file_extension in TEXT_FILE_TYPES:
        return True
    return False


def search_potential_secrets(secrets_file_paths):
    """Returns potential secrets(sensitive data) found in committed and added files
    :param secrets_file_paths: paths of files that are being commited to git repo
    :return: dictionary(filename: (list)secrets) of strings sorted by file name for secrets found in files
    """
    secrets_found = {}
    for file_path in secrets_file_paths:
        # Get if file path in pack and pack name
        is_pack = is_file_path_in_pack(file_path)
        pack_name = get_pack_name(file_path)
        # Get generic/ioc/files white list sets based on if pack or not
        secrets_white_list, ioc_white_list, files_white_list = get_white_listed_items(is_pack, pack_name)
        # Skip white listed files
        if file_path in files_white_list:
            print("Skipping secrets detection for file: {} as it is white listed".format(file_path))
            continue
        # Init vars for current loop
        file_name = os.path.basename(file_path)
        high_entropy_strings = []
        secrets_found_with_regex = []
        _, file_extension = os.path.splitext(file_path)
        skip_secrets = {'skip_once': False, 'skip_multi': False}
        # get file contents
        file_contents = get_file_contents(file_path, file_extension)
        # in packs regard all items as regex as well, reset pack's whitelist in order to avoid repetition later
        if is_pack:
            file_contents = remove_white_list_regex(file_contents, secrets_white_list)
            secrets_white_list = set()
        yml_file_contents = get_related_yml_contents(file_path)
        # Add all context output paths keywords to whitelist temporary
        if file_extension == YML_FILE_EXTENSION or yml_file_contents:
            temp_white_list = create_temp_white_list(yml_file_contents if yml_file_contents else file_contents)
            secrets_white_list = secrets_white_list.union(temp_white_list)
        # Search by lines after strings with high entropy / IoCs regex as possibly suspicious
        for line in file_contents.split('\n'):
            # if detected disable-secrets comments, skip the line/s
            skip_secrets = is_secrets_disabled(line, skip_secrets)
            if skip_secrets['skip_once'] or skip_secrets['skip_multi']:
                skip_secrets['skip_once'] = False
                continue
            # REGEX scanning for IOCs and false positive groups
            regex_secrets, false_positives = regex_for_secrets(line)
            for regex_secret in regex_secrets:
                if not any(ioc.lower() in regex_secret.lower() for ioc in ioc_white_list):
                    secrets_found_with_regex.append(regex_secret)
            # added false positives into white list array before testing the strings in line
            secrets_white_list = secrets_white_list.union(false_positives)
            # due to nature of eml files, skip string by string secret detection - only regex
            if file_extension in SKIP_FILE_TYPE_ENTROPY_CHECKS or \
                    any(demisto_type in file_name for demisto_type in SKIP_DEMISTO_TYPE_ENTROPY_CHECKS):
                continue
            line = remove_false_positives(line)
            # calculate entropy for each string in the file
            for string_ in line.split():
                # compare the lower case of the string against both generic whitelist & temp white list
                if not any(white_list_string.lower() in string_.lower() for white_list_string in secrets_white_list):
                    entropy = calculate_shannon_entropy(string_)
                    if entropy >= ENTROPY_THRESHOLD:
                        high_entropy_strings.append(string_)

        if high_entropy_strings or secrets_found_with_regex:
            # uniquify identical matches between lists
            file_secrets = list(set(high_entropy_strings + secrets_found_with_regex))
            secrets_found[file_name] = file_secrets

    return secrets_found


def remove_white_list_regex(file_contents, secrets_white_list):
    for regex in secrets_white_list:
        file_contents = re.sub(regex, '', file_contents)
    return file_contents


def create_temp_white_list(file_contents):
    temp_white_list = set()
    context_paths = re.findall(r'contextPath: (\S+\.+\S+)', file_contents)
    for context_path in context_paths:
        context_path = context_path.split('.')
        context_path = [white_item.lower() for white_item in context_path if len(white_item) > 4]
        temp_white_list = temp_white_list.union(context_path)

    return temp_white_list


def get_related_yml_contents(file_path):
    # if script or readme file, search for yml in order to retrieve temp white list
    yml_file_contents = ''
    # Validate if it is integration documentation file or supported file extension
    if checked_type(file_path, REQUIRED_YML_FILE_TYPES):
        yml_file_contents = retrieve_related_yml(os.path.dirname(file_path))
    return yml_file_contents


def retrieve_related_yml(integration_path):
    matching_yml_file_contents = None
    yml_file = os.path.join(integration_path, os.path.basename(integration_path) + '.yml')
    if os.path.exists(yml_file):
        with io.open('./' + yml_file, mode="r", encoding="utf-8") as matching_yml_file:
            matching_yml_file_contents = matching_yml_file.read()
    return matching_yml_file_contents


def regex_for_secrets(line):
    """Scans for IOCs with potentially low entropy score
    :param line: line to test as string representation (string)
    :return  potential_secrets (list) IOCs found via regex, false_positives (list) Non secrets with high entropy
    """
    potential_secrets = []
    false_positives = []

    # Dates REGEX for false positive preventing since they have high entropy
    dates = re.findall(DATES_REGEX, line)
    if dates:
        false_positives += [date[0].lower() for date in dates]
    # UUID REGEX
    uuids = re.findall(UUID_REGEX, line)
    if uuids:
        false_positives += uuids
    # docker images version are detected as ips. so we ignore and whitelist them
    # example: dockerimage: demisto/duoadmin:1.0.0.147
    re_res = re.search(r'dockerimage:\s*\w*demisto/\w+:(\d+.\d+.\d+.\d+)', line)
    if re_res:
        docker_version = re_res.group(1)
        false_positives.append(docker_version)
        line = line.replace(docker_version, '')
    # URL REGEX
    urls = re.findall(URLS_REGEX, line)
    if urls:
        potential_secrets += urls
    # EMAIL REGEX
    emails = re.findall(EMAIL_REGEX, line)
    if emails:
        potential_secrets += emails
    # IPV6 REGEX
    ipv6_list = re.findall(IPV6_REGEX, line)
    if ipv6_list:
        for ipv6 in ipv6_list:
            if ipv6 != '::' and len(ipv6) > 4:
                potential_secrets.append(ipv6)
    # IPV4 REGEX
    ipv4_list = re.findall(IPV4_REGEX, line)
    if ipv4_list:
        potential_secrets += ipv4_list

    return potential_secrets, false_positives


def calculate_shannon_entropy(data):
    """Algorithm to determine the randomness of a given data.
    Higher is more random/complex, most English words will yield in average result of 3
    :param data: could be either a list/dict or a string.
    :return: entropy: entropy score.
    """
    if not data:
        return 0
    entropy = 0
    # each unicode code representation of all characters which are considered printable
    for char in (ord(c) for c in string.printable):
        # probability of event X
        p_x = float(data.count(chr(char))) / len(data)
        if p_x > 0:
            # the information in every possible news, in bits
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_white_listed_items(is_pack, pack_name):
    whitelist_path = os.path.join(PACKS_DIR, pack_name, PACKS_WHITELIST_FILE_NAME) if is_pack else WHITELIST_PATH
    final_white_list, ioc_white_list, files_while_list = get_packs_white_list(whitelist_path) if is_pack else\
        get_generic_white_list(whitelist_path)
    return set(final_white_list), set(ioc_white_list), set(files_while_list)


def get_generic_white_list(whitelist_path):
    final_white_list = []
    ioc_white_list = []
    files_while_list = []
    with io.open(whitelist_path, mode="r", encoding="utf-8") as secrets_white_list_file:
        secrets_white_list_file = json.load(secrets_white_list_file)
        for name, white_list in secrets_white_list_file.items():
            if name == 'iocs':
                for sublist in white_list:
                    ioc_white_list += [white_item for white_item in white_list[sublist] if len(white_item) > 4]
                final_white_list += ioc_white_list
            elif name == 'files':
                files_while_list = white_list
            else:
                final_white_list += [white_item for white_item in white_list if len(white_item) > 4]

        return final_white_list, ioc_white_list, files_while_list


def get_packs_white_list(whitelist_path):
    final_white_list = []
    if os.path.isfile(whitelist_path):
        with io.open(whitelist_path, mode="r", encoding="utf-8") as secrets_white_list_file:
            final_white_list = secrets_white_list_file.read().split('\n')
    return final_white_list, [], []


def get_file_contents(file_path, file_extension):
    try:
        # if pdf or README.md file, parse text
        integration_readme = re.match(pattern=INTEGRATION_README_REGEX,
                                      string=file_path,
                                      flags=re.IGNORECASE)
        if file_extension == '.pdf':
            file_contents = extract_text_from_pdf(file_path)
        elif file_extension == '.md' and integration_readme:
            file_contents = extract_text_from_md_html(file_path)
        else:
            # Open each file, read its contents in UTF-8 encoding to avoid unicode characters
            with io.open('./' + file_path, mode="r", encoding="utf-8", errors='ignore') as commited_file:
                file_contents = commited_file.read()
        file_contents = ignore_base64(file_contents)
        return file_contents
    except Exception as ex:
        print("Failed opening file: {}. Exception: {}".format(file_path, ex))
        raise


def extract_text_from_pdf(file_path):
    page_num = 0
    file_contents = ''
    try:
        pdf_file_obj = open('./' + file_path, 'rb')
        pdf_reader = PyPDF2.PdfFileReader(pdf_file_obj)
        num_pages = pdf_reader.numPages
    except PyPDF2.utils.PdfReadError:
        print('ERROR: Could not parse PDF file in path: {} - ***Review Manually***'.format(file_path))
        return file_contents
    while page_num < num_pages:
        pdf_page = pdf_reader.getPage(page_num)
        page_num += 1
        file_contents += pdf_page.extractText()

    return file_contents


def extract_text_from_md_html(file_path):
    try:
        with open(file_path, mode='r') as html_page:
            soup = BeautifulSoup(html_page, features="html.parser")
            file_contents = soup.text
            return file_contents
    except Exception as ex:
        print_error('Unable to parse the following file {} due to error {}'.format(file_path, ex))
        raise


def remove_false_positives(line):
    false_positive = re.search(r'([^\s]*[(\[{].*[)\]}][^\s]*)', line)
    if false_positive:
        false_positive = false_positive.group(1)
        line = line.replace(false_positive, '')
    return line


def is_secrets_disabled(line, skip_secrets):
    if bool(re.findall(r'(disable-secrets-detection-start)', line)):
        skip_secrets['skip_multi'] = True
    elif bool(re.findall(r'(disable-secrets-detection-end)', line)):
        skip_secrets['skip_multi'] = False
    elif bool(re.findall(r'(disable-secrets-detection)', line)):
        skip_secrets['skip_once'] = True
    return skip_secrets


def ignore_base64(file_contents):
    base64_strings = re.findall(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|'
                                r'[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})', file_contents)
    for base64_string in base64_strings:
        if len(base64_string) > 500:
            file_contents = file_contents.replace(base64_string, '')
    return file_contents


def get_branch_name():
    branches = run_command('git branch')
    branch_name_reg = re.search(r'\* (.*)', branches)
    branch_name = branch_name_reg.group(1)
    return branch_name


def parse_script_arguments():
    parser = argparse.ArgumentParser(description='Utility CircleCI usage')
    parser.add_argument('-c', '--circle', type=str2bool, default=False, help='Is CircleCi or not')
    options = parser.parse_args()
    return options


def main():
    options = parse_script_arguments()
    is_circle = options.circle
    branch_name = get_branch_name()
    is_forked = re.match(EXTERNAL_PR_REGEX, branch_name) is not None
    if not is_forked:
        secrets_found = get_secrets(branch_name, is_circle)
        if secrets_found:
            sys.exit(1)
        else:
            print_color('Finished validating secrets, no secrets were found.', LOG_COLORS.GREEN)
    sys.exit(0)


if __name__ == '__main__':
    main()
