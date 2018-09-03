import sys
import yaml

class LOG_COLORS:
    NATIVE = '\033[m'
    RED = '\033[01;31m'


def print_error(error_str):
    print(LOG_COLORS.RED + error_str + LOG_COLORS.NATIVE)


def add_descriptions(file_path, output_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    new_lines = lines[:]
    for i, line in enumerate(lines):
        # if line has `type: start` or `type: title` or `type: end`
        # we want to create empty description (description: "") inside its task field with correct indentation
        if (line.find('type: start') > -1 or line.find('type: title') > -1 or line.find('type: end') > -1)\
                and lines[i + 1].find('task:') > -1:
            inside_task_line = lines[i + 2]
            indentation = len(inside_task_line) - len(inside_task_line.lstrip(' '))

            empty_description = (' ' * indentation) + 'description: ""\n'
            new_lines.insert(i + 2, empty_description)

    with open(output_path, 'w') as f:
        f.write(''.join(new_lines))


def main(argv):
    if len(argv) < 2:
        print "Please provide <source playbook path>, <destination playbook path>"
        sys.exit(1)

    source_path = argv[0]
    destination_path = argv[1]

    print "Starting..."

    errors = []
    with open(source_path, 'r') as f:
        playbook = yaml.safe_load(f)
        if playbook.get('version') is not -1:
            errors.append('Playbook version should be -1. got %s' % (playbook.get('version'), ))
        if not playbook.get('fromversion'):
            errors.append('Playbook should contain "fromversion" attribute')
        if playbook.get('id') != playbook.get('name'):
            errors.append('Playbook id should be the same as playbook name. id  - %s, name - %s' % (playbook.get('id'), playbook.get('name'), ))

    if len(errors) > 0:
        print_error('\n'.join(errors))
        sys.exit(1)

    add_descriptions(source_path, destination_path)

    print "Finished"


if __name__ == "__main__":
   main(sys.argv[1:])

