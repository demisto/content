import argparse
import json
import os
from pathlib import Path

ARTIFACTS_FOLDER_SERVER_TYPE = os.getenv('ARTIFACTS_FOLDER_SERVER_TYPE')
OUTPUT_FILE = Path(ARTIFACTS_FOLDER_SERVER_TYPE) / 'packs_to_install_by_machine.json'

class PackInfo:
    def __init__(self, name):
        self.name = name
        self.test_playbooks_to_run = set()
        self.dependencies = set()
        self.total_expected_execution_time = 0


def build_pack_information(playbooks, playbook_times):
    packs_to_install = {}
    for name, info in playbooks.items():
        pack_name = info['pack']
        if pack_name not in packs_to_install:
            pack_obj = PackInfo(pack_name)
            packs_to_install[pack_name] = pack_obj
        else:
            pack_obj: PackInfo = packs_to_install[pack_name]

        pack_obj.test_playbooks_to_run.add(name)
        pack_obj.total_expected_execution_time += playbook_times[name]
        pack_obj.dependencies |= set(info['dependencies'])

    return packs_to_install


def machine_assignment(pack_to_install: dict, machines):
    machine_assignments = {machine: {'packs_to_install': set(), 'playbooks_to_run': set()} for machine in machines}
    machine_loads = {machine: 0 for machine in machines}

    sorted_packs_by_execution_time = sorted(pack_to_install.values(), key=lambda pack: pack.total_expected_execution_time,
                                            reverse=True)

    for pack in sorted_packs_by_execution_time:
        min_load_machine = min(machine_loads, key=machine_loads.get)
        machine_assignments[min_load_machine]['packs_to_install'] |= {pack.name, *pack.dependencies}
        machine_assignments[min_load_machine]['playbooks_to_run'] |= {*pack.test_playbooks_to_run}
        machine_loads[min_load_machine] += pack.total_expected_execution_time

    return machine_assignments


def create_pack_graph(playbooks_file, machine_list, playbooks_time_file):
    """
  This function reads input files, creates a pack dependency graph, and assigns packs to machines.

  Args:
      playbooks_file (str): Path to the JSON file containing playbook information.
      machine_list (str): List of available machines.
      playbooks_time_file (str): Path to the file containing playbook execution times.

  Returns:
      dict: A dictionary representing the pack graph.
      dict: A dictionary mapping packs to their assigned machines.
  """

    # Read playbook information
    with open(playbooks_file, 'r') as f:
        playbooks = json.load(f)

    # Read available machines
    machines = set(machine_list)

    # Read playbook execution times
    playbook_times = {}
    with open(playbooks_time_file, 'r') as f:
        for line in f:
            name, time = line.strip().split(',')
            playbook_times[name] = int(time)

    pack_to_install = build_pack_information(playbooks, playbook_times)
    return machine_assignment(pack_to_install, machines)


def options_handler() -> argparse.Namespace:
    """
    Returns: options parsed from input arguments.

    """
    parser = argparse.ArgumentParser(description='Utility for splitting packs installation into chosen cloud machines')
    parser.add_argument('--cloud_machines', help='List of chosen cloud machines', required=True)
    parser.add_argument('--playbooks_to_packs', help='Path to file that contains connection between tpb to'
                                                     ' related packs to install', required=True)
    parser.add_argument('--playbooks_execution_times', help='Path to file that contains avg execution '
                                                            'time of tpb', required=True)

    options = parser.parse_args()
    return options

def main():
    options = options_handler()
    playbooks_file = "/Usrs/epintzov/Desktop/tests/playbooks.json"  # Replace with your file path
    # playbooks_file = options.playbooks_to_packs
    machine_list = options.cloud_machines
    # machine_list = "/Users/epintzov/Desktop/tests/machines.txt"
    playbooks_time_file = "/Users/epintzov/Desktop/tests/playbooks_times.txt"  # Replace with your file path
    # playbooks_time_file = options.playbooks_execution_times
    machine_assignments = create_pack_graph(playbooks_file, machine_list, playbooks_time_file)

    # output files
    OUTPUT_FILE.write_text(json.dumps(machine_assignments))



if __name__ == "__main__":
    main()
