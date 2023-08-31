import yaml

"""
Before running tests locally, please make sure there is not a conflicting conftest.py file.
"""

"""Classes"""


class PlaybookDataLoader:
    def __init__(self, playbook_path):
        self.playbook_path = playbook_path

    @property
    def playbook_tasks_data(self):
        playbook_data = load_yaml_file(self.playbook_path)
        tasks = playbook_data["tasks"]
        return tasks

    @property
    def full_playbook_data(self):
        playbook_data = load_yaml_file(self.playbook_path)
        return playbook_data


"""Helper Functions"""


def was_grid_field_value_found(playbook_tasks_data, grid_field_location: str, value: str) -> bool:
    """_summary_

    Args:
        playbook_tasks_data: a subset of yml playbook file that only includes the tasks data.
        grid_field_location (str): which "val" in a grid field in a playbook yml file (i.e val1, val2...)
        value (str): string value to be searched for

    Returns:
        bool: True or false for if value is found in any task and in the given grid_field_location.
    """
    for task_id, task_data in playbook_tasks_data.items():
        if "scriptName" in task_data["task"]:
            if task_data["task"]["scriptName"] == "GridFieldSetup":
                val = find_key(task_data, grid_field_location)
                if (
                    val
                    and isinstance(val, dict)
                    and "simple" in val
                    and val["simple"] == value
                ):
                    print(f"Task {task_id}: '{value}' found")
                    return True
    print(f"'{value}' not found in any task.")
    return False


def check_multiple_grid_field_values(playbook_tasks_data, grid_field_data: dict) -> list:
    """_summary_

    Args:
        playbook_tasks_data: a subset of yml playbook file that only includes the tasks data.
        grid_field_data (dict): a set of values to be found in a playbook task for setting grid fields.

    Returns:
        list: a list of the dictionary key-values found
    """
    for task_id, task_data in playbook_tasks_data.items():
        if "scriptName" in task_data["task"]:
            if task_data["task"]["scriptName"] == "GridFieldSetup":
                results = find_dicts_by_key_values(
                    playbook_tasks_data, grid_field_data, "simple"
                )
                return results


def load_yaml_file(file_path: str):
    """_summary_

    Args:
        file_path (str): a file path to a yml file to be loaded.

    Returns:
        Any: returns a dictionary representation of the yaml file given.
    """
    with open(file_path, "r") as file:
        data = yaml.safe_load(file)
    return data


""""utility functions"""


def find_key(task, key):
    """_summary_

    Args:
        task: the dictionary representation of a yaml playbook task
        key: key to look for in the task data.

    Returns:
        Any: returns a dictionary if key is in task
    """
    if isinstance(task, dict):
        if key in task:
            return task[key]
        for sub_key in task.values():
            result = find_key(sub_key, key)
            if result is not None:
                return result
    elif isinstance(task, list):
        for sub_key in task:
            result = find_key(sub_key, key)
            if result is not None:
                return result


def find_dicts_by_key_values(data, target_key_values: dict, accessor: str) -> list:
    """_summary_

    Args:
        data: A dictionary or list dictionaries to search through for target_key_values.
        target_key_values(dict): a set of values that should be inside of data.
        accessor (str): the key under the "val" keys in a yaml grid field (i.e. "simple" or "complex")

    Returns:
        list: the list of target_key_values if they are found.
    """
    results = []

    if isinstance(data, dict):
        found = True
        for key, value in target_key_values.items():
            if key not in data or data[key].get(accessor) != value:
                found = False
                break
        if found:
            results.append(data)

        for value in data.values():
            if isinstance(value, dict):
                results.extend(
                    find_dicts_by_key_values(value, target_key_values, accessor)
                )

    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                results.extend(
                    find_dicts_by_key_values(item, target_key_values, accessor)
                )

    return results
