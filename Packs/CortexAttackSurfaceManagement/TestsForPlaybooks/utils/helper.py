import yaml


def was_grid_field_value_found(playbook_tasks_data, grid_field_location: str, value: str):
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


def check_multiple_grid_field_values(playbook_tasks_data, grid_field_data: dict):
    for task_id, task_data in playbook_tasks_data.items():
        if "scriptName" in task_data["task"]:
            if task_data["task"]["scriptName"] == "GridFieldSetup":
                results = find_dicts_by_key_values(
                    playbook_tasks_data, grid_field_data, "simple"
                )
                print(results)
                return results


def load_yaml_file(file_path):
    with open(file_path, "r") as file:
        data = yaml.safe_load(file)
    return data


""""utility functions"""


def find_key(task, key):
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


def find_dicts_by_key_values(data, target_key_values, accessor: str):
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
