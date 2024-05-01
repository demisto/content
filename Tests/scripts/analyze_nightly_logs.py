import csv
import re
from typing import Any

Nightly_Text = """"""


def main():
    failing_tests = []
    failing_test_sections: dict[Any, Any] = {}
    is_failing_section = False
    for row in Nightly_Text.split('\n'):
        if is_failing_section:
            failing_tests.append(
                row.strip()[2:].replace(' (Mock Disabled)', '').replace(' (Second Playback)', '').replace('[0m', ''))
        if "Failed Tests:" in row:
            is_failing_section = True
        if "Number of succeeded tests" in row:
            is_failing_section = False
    # extract sections
    for failing_test in failing_tests[:-1]:
        iter_row = iter(list(filter(lambda x: x != "", Nightly_Text.split('\n'))))
        failing_test_sections[failing_test] = []
        try:
            while row := next(iter_row):
                if failing_test in row and "------ Test playbook" in row and "start ------" in row:
                    while True:
                        row = next(iter_row)
                        if "end ------" in row:
                            break
                        failing_test_sections[failing_test].append(row)
        except StopIteration:
            pass

    error_msg_regex = r"Error:\s*(.*)"
    error_body_regex = r"(?<=\bBody:\n)[\s\S]+?(?=\n)"
    did_it_pass_regex = r"Test-Playbook was executed 3 times, and passed only (.*?)(?=\n|$)"
    fail_on_test_module = "test-module failed|Failed to execute test-module command."
    test_msg: dict[Any, Any] = {}

    for key, val in failing_test_sections.items():
        test_msg[key] = {'error_msgs': [], 'did_it_pass': False, 'fail_on_test_module': False}
        text = '\n'.join(val)
        match1 = re.search(error_msg_regex, text)
        match2 = re.search(error_body_regex, text)
        match3 = re.search(did_it_pass_regex, text)
        match4 = re.findall(fail_on_test_module, text)
        if match1:
            test_msg[key]['error_msgs'].append(match1.group(1).strip())
        if match2:
            test_msg[key]['error_msgs'].append(match2.group().strip())
        if match3 and match3.group(1).strip()[0] == '1':
            test_msg[key]['did_it_pass'] = True
        if match4:
            test_msg[key]['fail_on_test_module'] = True
    # Remove keys with empty lists
    test_msg = {key: value for key, value in test_msg.items() if value}
    for key in test_msg:
        test_msg[key]['error_msgs'] = list(set(test_msg[key]['error_msgs']))
    with open("/Users/sfainberg/Downloads/failing_tests.csv", 'w', newline='') as file:
        writer = csv.writer(file)
        for key, val in test_msg.items():
            error_str = '\n'.join(val["error_msgs"])
            writer.writerow([key, val['did_it_pass'], val['fail_on_test_module'], error_str])


if __name__ == '__main__':
    main()
