import io
import os
import re
import math
import json
import string

try:
    import PyPDF2
except ImportError:
    import pip._internal as pip
    pip.main(['install', 'PyPDF2'])
    import PyPDF2

from Tests.test_utils import run_command, print_error

# secrets settings
# Entropy score is determined by shanon's entropy algorithm, most English words will score between 1.5 and 3.5
ENTROPY_THRESHOLD = 4.2

SKIPPED_FILES = {'secrets_white_list', 'id_set.json', 'conf.json'}
ACCEPTED_FILE_STATUSES = ['M', 'A', "R099"]
TEXT_FILE_TYPES = {'.yml', '.py', '.json', '.md', '.txt', '.sh', '.ini', '.eml', '', '.csv', '.js', '.pdf', '.html'}
SKIP_FILE_TYPE_ENTROPY_CHECKS = {'.eml'}
SKIP_DEMISTO_TYPE_ENTROPY_CHECKS = {'playbook-'}

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
    secrets_found_string = ''
    if not run_command('git rev-parse -q --verify MERGE_HEAD'):
        secrets_file_paths = get_all_diff_text_files(branch_name, is_circle)
        secrets_found = search_potential_secrets(secrets_file_paths)
        if secrets_found:
            secrets_found_string += 'Secrets were found in the following files:\n'
            for file_name in secrets_found:
                secrets_found_string += ('\nFile Name: ' + file_name)
                secrets_found_string += json.dumps(secrets_found[file_name], indent=4)
            if not is_circle:
                secrets_found_string += 'Remove or whitelist secrets in order to proceed, then re-commit\n'
            else:
                secrets_found_string += 'The secrets were exposed in public repository,' \
                                        ' remove the files asap and report it.\n'
            secrets_found_string += 'For more information about whitelisting please visit: ' \
                                    'https://github.com/demisto/internal-content/tree/master/documentation/secrets'

    if secrets_found:
        print_error(secrets_found_string)

    return secrets_found


def get_all_diff_text_files(branch_name, is_circle):
    """
    Get all new/modified text files that need to be searched for secrets
    :param branch_name: current branch being worked on
    :param is_circle: boolean to check if being ran from circle
    :return: list: list of text files
    """
    if is_circle:
        branch_changed_files_string = \
            run_command("git diff --name-status origin/master...{}".format(branch_name))
        text_files_list = get_diff_text_files(branch_changed_files_string)

    else:
        local_changed_files_string = run_command("git diff --name-status --no-merges HEAD")
        text_files_list = get_diff_text_files(local_changed_files_string)

    return text_files_list


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
        if file_status.upper() == "R099":
            # if filename renamed
            # sometimes the R comes with numbers R099,
            # the R status file usually will look like:
            # R099 TestsPlaybooks/foo.yml TestPlaybooks/playbook-foo.yml
            # that is why we set index 2 to file_path - the second index is the updated file name
            file_path = file_data[2]
        else:
            file_path = file_data[1]

        # only modified/added file, text readable, exclude white_list file
        if file_status.upper() in ACCEPTED_FILE_STATUSES and is_text_file(file_path):
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
        file_name = os.path.basename(file_path)
        high_entropy_strings = []
        secrets_found_with_regex = []
        yml_file_contents = None
        file_path_temp, file_extension = os.path.splitext(file_path)
        skip_secrets = False

        # Get generic white list set
        secrets_white_list, ioc_white_list = get_white_list()
        # get file contents
        file_contents = get_file_contents(file_path, file_extension)
        # if py/js file, search for yml in order to retrieve temp white list
        if file_extension in {'.py', '.js'}:
            yml_file_contents = retrieve_related_yml(file_path_temp)
        # Add all context output paths keywords to whitelist temporary
        if file_extension == '.yml' or yml_file_contents:
            temp_white_list = create_temp_white_list(yml_file_contents if yml_file_contents else file_contents)
            secrets_white_list = secrets_white_list.union(temp_white_list)
        # Search by lines after strings with high entropy as possibly suspicious
        for line in file_contents.split('\n'):
            # if detected disable-secrets comment, skip the line
            skip_secrets = is_secrets_disabled(line, skip_secrets)
            if skip_secrets:
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


def create_temp_white_list(file_contents):
    temp_white_list = set()
    context_paths = re.findall(r'contextPath: (\S+\.+\S+)', file_contents)
    for context_path in context_paths:
        context_path = context_path.split('.')
        context_path = [white_item.lower() for white_item in context_path if len(white_item) > 4]
        temp_white_list = temp_white_list.union(context_path)

    return temp_white_list


def retrieve_related_yml(file_path_temp):
    matching_yml_file_contents = None
    yml_file = file_path_temp + '.yml'
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
    for x in (ord(c) for c in string.printable):
        # probability of event X
        px = float(data.count(chr(x))) / len(data)
        if px > 0:
            # the information in every possible news, in bits
            entropy += - px * math.log(px, 2)
    return entropy


def get_white_list():
    with io.open('./Tests/secrets_white_list.json', mode="r", encoding="utf-8") as secrets_white_list_file:
        final_white_list = []
        ioc_white_list = []
        secrets_white_list_file = json.load(secrets_white_list_file)
        for name, white_list in secrets_white_list_file.iteritems():
            if name == 'iocs':
                for sublist in white_list:
                    ioc_white_list += [white_item for white_item in white_list[sublist] if len(white_item) > 4]
                final_white_list += ioc_white_list
            else:
                final_white_list += [white_item for white_item in white_list if len(white_item) > 4]

        return set(final_white_list), set(ioc_white_list)


def get_file_contents(file_path, file_extension):
    # if pdf file, parse text
    if file_extension == '.pdf':
        file_contents = extract_text_from_pdf(file_path)
    else:
        # Open each file, read its contents in UTF-8 encoding to avoid unicode characters
        with io.open('./' + file_path, mode="r", encoding="utf-8", errors='ignore') as commited_file:
            file_contents = commited_file.read()

    file_contents = ignore_base64(file_contents)

    return file_contents


def extract_text_from_pdf(file_path):
    page_num = 0
    file_contents = ''
    try:
        pdf_file_obj = open('./' + file_path, 'rb')
        pdf_reader = PyPDF2.PdfFileReader(pdf_file_obj)
    except PyPDF2.utils.PdfReadError:
        print('ERROR: Could not parse PDF file in path: {} - ***Review Manually***'.format(file_path))
        return file_contents
    num_pages = pdf_reader.numPages

    while page_num < num_pages:
        pdf_page = pdf_reader.getPage(page_num)
        page_num += 1
        file_contents += pdf_page.extractText()

    return file_contents


def remove_false_positives(line):
    false_positive = re.search('([^\s]*[(\[{].*[)\]}][^\s]*)', line)
    if false_positive:
        false_positive = false_positive.group(1)
        line = line.replace(false_positive, '')
    return line


def is_secrets_disabled(line, skip_secrets):
    if bool(re.findall(r'(disable-secrets-detection)', line)):
        skip_secrets = True
    elif bool(re.findall(r'(disable-secrets-detection-start)', line)):
        skip_secrets = True
    elif bool(re.findall(r'(disable-secrets-detection-end)', line)):
        skip_secrets = False
    elif not skip_secrets:
        skip_secrets = False

    return skip_secrets


def ignore_base64(file_contents):
    base64_strings = re.findall(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|'
                                r'[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})', file_contents)
    for base64_string in base64_strings:
        if len(base64_string) > 500:
            file_contents = file_contents.replace(base64_string, '')
    return file_contents
