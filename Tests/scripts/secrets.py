import io
import os
import math
import string
import re
import json
import PyPDF2
import validate_files_structure

# secrets settings
# Entropy score is determined by shanon's entropy algorithm, most English words will score between 1.5 and 3.5
ENTROPY_THRESHOLD = 3.8
SECRETS_WHITE_LIST_FILE = 'secrets_white_list'
ACCEPTED_FILE_STATUSES = ['M', 'A']
TEXT_FILE_TYPES = {'.yml', '.py', '.json', '.md', '.txt', '.sh', '.ini', '.eml', '', '.csv', '.js', '.pdf'}
# disable-secrets-detection-start
URLS_REGEX = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\), ]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
EMAIL_REGEX = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
IPV6_REGEX = r'(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1' \
             r'[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::'\
             r'(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]'\
             r'{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'\
             r'(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|'\
             r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}'\
             r'|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}'\
             r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'\
             r'\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}'\
             r'[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|'\
             r'(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}'\
             r'|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:'\
             r'(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4]'\
             r'[0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]'\
             r'{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]'\
             r'|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|'\
             r'(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|'\
             r'(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)'
IPV4_REGEX = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)'
DATES_REGEX = r'((\d{4}[/.-]\d{2}[/.-]\d{2})[T\s](\d{2}:?\d{2}:?\d{2}:?(\.\d{5,6})?([+-]\d{2}:?\d{2})?Z?)?)'
# disable-secrets-detection-end


def is_text_file(file_path):
    file_extension = os.path.splitext(file_path)[1]
    if file_extension in TEXT_FILE_TYPES:
        return True
    return False


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
        file_path = file_data[1]
        # only modified/added file, text readable, exclude white_list file
        if file_status.upper() in ACCEPTED_FILE_STATUSES and is_text_file(file_path) \
                and SECRETS_WHITE_LIST_FILE not in file_path:
            text_files_list.add(file_path)

    return text_files_list


def get_all_diff_text_files(branch_name, is_circle):
    """
    Get all new/modified text files that need to be searched for secrets
    :param branch_name: current branch being worked on
    :param is_circle: boolean to check if being ran from circle
    :return: list: list of text files
    """
    if is_circle:
        branch_changed_files_string = \
            validate_files_structure.run_git_command("git diff --name-status origin/master...{}".format(branch_name))
        text_files_list = get_diff_text_files(branch_changed_files_string)

    else:
        local_changed_files_string = validate_files_structure.run_git_command("git diff --name-status --no-merges HEAD")
        text_files_list = get_diff_text_files(local_changed_files_string)

    return text_files_list


def search_potential_secrets(secrets_file_paths):
    """Returns potential secrets(sensitive data) found in committed and added files
    :param secrets_file_paths: paths of files that are being commited to git repo
    :return: dictionary(filename: (list)secrets) of strings sorted by file name for secrets found in files
    """
    # Get generic white list set
    secrets_white_list = get_white_list()
    secrets_found = {}

    for file_path in secrets_file_paths:
        file_name = file_path.split('/')[-1]
        high_entropy_strings = []
        secrets_found_with_regex = []
        yml_file_contents = None
        skip_secrets = False
        file_path_temp, file_extension = os.path.splitext(file_path)

        # if py/js file, search for yml in order to retrieve temp white list
        if file_extension in {'.py', '.js'}:
            yml_file_contents = retrieve_related_yml(file_path_temp)

        # if pdf file, parse text

        # Open each file, read its contents in UTF-8 encoding to avoid unicode characters
        with io.open('./' + file_path, mode="r", encoding="utf-8") as commited_file:
            file_contents = commited_file.read()

            # Add all context output paths keywords to whitelist temporary
            temp_white_list = create_temp_white_list(yml_file_contents if yml_file_contents else file_contents)
            secrets_white_list = secrets_white_list.union(temp_white_list)

            # Search by lines after strings with high entropy as possibly suspicious
            for line in file_contents.split('\n'):

                # if detected disable-secrets comment, skip the line
                if bool(re.findall(r'(disable-secrets-detection-start)', line)):
                    skip_secrets = True
                if bool(re.findall(r'(disable-secrets-detection-end)', line)):
                    skip_secrets = False
                if skip_secrets or bool(re.findall(r'(disable-secrets-detection)', line)):
                    continue

                # REGEX scanning for IOCs and false positive groups
                potential_secrets, false_positives = regex_for_secrets(line)
                for potential_secret in potential_secrets:
                    if not any(white_list_string in potential_secret for white_list_string in secrets_white_list):
                        secrets_found_with_regex.append(potential_secret)
                # added false positives into white list array before testing the strings in line
                secrets_white_list = secrets_white_list.union(false_positives)

                # calculate entropy for each string in the file
                for string_ in line.split():
                    string_ = string_.strip("\"()[],'><:;\\")
                    string_lower = string_.lower()
                    # compare the lower case of the string against both generic whitelist & temp white list
                    if not any(white_list_string in string_lower for white_list_string in secrets_white_list):
                        entropy = calculate_shannon_entropy(string_)
                        if entropy >= ENTROPY_THRESHOLD:
                            high_entropy_strings.append(string_)

        if high_entropy_strings or secrets_found_with_regex:
            # uniquify identical matches between lists
            file_secrets = list(set(high_entropy_strings + secrets_found_with_regex))
            secrets_found[file_name] = file_secrets

    return secrets_found


def create_temp_white_list(file_contents):
    temp_white_list = set([])
    context_paths = re.findall(r'contextPath: (\S+\.+\S+)', file_contents)
    for context_path in context_paths:
        context_path = context_path.split('.')
        context_path = [white_item.lower() for white_item in context_path]
        temp_white_list = temp_white_list.union(context_path)

    return temp_white_list


def retrieve_related_yml(file_path_temp):
    matching_yml_file_contents = None
    yml_file = file_path_temp + '.yml'
    if os.path.exists(yml_file):
        with io.open('./' + yml_file, mode="r", encoding="utf-8") as matching_yml_file:
            matching_yml_file_contents = matching_yml_file.read()
    return matching_yml_file_contents


def regex_for_secrets(file_contents):
    """Scans for IOCs with potentially low entropy score
    :param file_contents: file to test as string representation (string)
    :return  potential_secrets (list) IOCs found via regex, false_positives (list) Non secrets with high entropy
    """
    potential_secrets = []
    false_positives = []

    # URL REGEX
    urls = re.findall(URLS_REGEX, file_contents)
    if urls:
        potential_secrets += urls
    # EMAIL REGEX
    emails = re.findall(EMAIL_REGEX, file_contents)
    if emails:
        potential_secrets += emails
    # IPV6 REGEX
    ipv6_list = re.findall(IPV6_REGEX, file_contents)
    if ipv6_list:
        for ipv6 in ipv6_list:
            if ipv6 != '::':
                potential_secrets.append(ipv6)
    # IPV4 REGEX
    ipv4_list = re.findall(IPV4_REGEX, file_contents)
    if ipv4_list:
        potential_secrets += ipv4_list
    # Dates REGEX for false positive preventing since they have high entropy
    dates = re.findall(DATES_REGEX, file_contents)
    if dates:
        false_positives += [date[0] for date in dates]

    return potential_secrets, false_positives


def calculate_shannon_entropy(data):
    """Algorithm to determine the randomness of a given data.
    Higher is more random/complex, most English words will yield result of around 3+-
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


def get_secrets(branch_name, is_circle):
    secrets_file_paths = get_all_diff_text_files(branch_name, is_circle)
    secrets_found = search_potential_secrets(secrets_file_paths)
    secrets_found_string = ''
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

    return secrets_found, secrets_found_string


def get_white_list():
    with io.open('./Tests/secrets_white_list.json', mode="r", encoding="utf-8") as secrets_white_list_file:
        return set(json.load(secrets_white_list_file))
