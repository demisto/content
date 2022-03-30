from __future__ import print_function
import sys


def add_descriptions(file_path, error_type):
    
    with open(file_path, 'r') as f:
        lines = f.readlines()
    
    extract_errors_list(lines, error_type)

    new_lines = lines[:]
    for i, line in enumerate(lines):
        # if line has `type: start` or `type: title` or `type: end`
        # we want to create empty description (description: "") inside its task field with correct indentation
        if (line.find('type: start') > -1 or line.find('type: title') > -1 or line.find('type: end'))\
                and lines[i + 1 if i + 1 < len(lines) else i].find('task:') > -1:
            inside_task_line = lines[i + 2]
            indentation = len(inside_task_line) - len(inside_task_line.lstrip(' '))

            empty_description = (' ' * indentation) + 'description: ""\n'
            new_lines.insert(i + 2, empty_description)

    with open(output_path, 'w') as f:
        f.write(''.join(new_lines))


def extract_errors_list(errors_log, error_type):


def main(argv):
    if len(argv) < 2:
        print("Please provide <source errors list>, <requested error>")
        sys.exit(1)

    source_path = argv[0]
    error_type = argv[1]

    print("Starting...")

    add_descriptions(source_path, error_type)

    print("Finished")


if __name__ == "__main__":
    main(sys.argv[1:])
