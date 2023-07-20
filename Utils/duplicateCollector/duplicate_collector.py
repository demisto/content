import os
import glob
import shutil
import re
import json
from pathlib import Path
from enum import Enum
import yaml

DATASET_REGEX = r"\[MODEL[^=]*=(?P<dataset_value>[^,^\]]*)"


class CollectorReltaedContent(str, Enum):
    INTEGRATIONS = "Integrations"
    PARSING_RULES = "ParsingRules"
    MODELING_RULES = "ModelingRules"
    PACK_METADATA = "pack_metadata.json"
    PACK_README = "README.md"


def find_matching_folders(root_folder: Path, folder_names):
    """
    Returns all the collector related folders and files paths
    """
    matching_folders = []
    for folder_name in folder_names:
        search_pattern = os.path.join(root_folder, "**", folder_name)
        matching_folders.extend(glob.glob(search_pattern, recursive=True))
    return matching_folders


def copy_matching_folder(
    matching_folder_list, pack_path: Path, custom_suffix: str = "Custom"
) -> Path:
    packs_folder_path, pack_name = pack_path.parent, pack_path.name
    new_pack_path: Path = packs_folder_path / f"{pack_name}{custom_suffix.capitalize()}"

    for folder_path in matching_folder_list:
        folder_path = Path(folder_path)
        folder_name = folder_path.name
        copy_to_path = new_pack_path / Path(folder_path).name

        if folder_name == CollectorReltaedContent.INTEGRATIONS:
            Integration_list = [
                name
                for name in os.listdir(folder_path)
                if os.path.isdir(os.path.join(folder_path, name))
            ]
            for integration in Integration_list:
                if "EventCollector" in integration:
                    copy_to_new_event_collector_integration = copy_to_path / integration
                    original_folder_path_integration = folder_path / integration
                    shutil.copytree(
                        original_folder_path_integration,
                        copy_to_new_event_collector_integration,
                        dirs_exist_ok=True,
                    )

        if folder_name in [CollectorReltaedContent.PACK_METADATA, CollectorReltaedContent.PACK_README]:
            shutil.copy(folder_path, copy_to_path)
        elif folder_name in [CollectorReltaedContent.MODELING_RULES, CollectorReltaedContent.PARSING_RULES]:
            shutil.copytree(folder_path, copy_to_path, dirs_exist_ok=True)

    return new_pack_path


def prepare_integration_yml(integration_yml_data: dict, custom_suffix: str):
    to_append = f" - {custom_suffix}"
    if integration_yml_data.get("name"):
        integration_yml_data["name"] += to_append
    if integration_yml_data.get("commonfields", {}).get("id"):
        integration_yml_data["commonfields"]["id"] += to_append
    if integration_yml_data.get("display"):
        integration_yml_data["display"] += to_append

    return integration_yml_data


def prepare_modeling_parsing_rules_yml(
    modeling_parsing_rule_yml_data: dict, custom_suffix: str
):
    if modeling_parsing_rule_yml_data.get("name"):
        modeling_parsing_rule_yml_data["name"] += f" {custom_suffix.capitalize()}"
    if modeling_parsing_rule_yml_data.get("id"):
        modeling_parsing_rule_yml_data["id"] += f"_{custom_suffix.lower()}"

    return modeling_parsing_rule_yml_data


def prepare_yml_files(
    new_pack_path: Path, custom_suffix: str, content_item_type: CollectorReltaedContent
):
    content_item_folder_path = new_pack_path / content_item_type.value
    if not content_item_folder_path.exists():
        return

    yml_file_pattern = os.path.join(content_item_folder_path, "**", "*.yml")
    content_items_path_list = glob.glob(yml_file_pattern)

    for content_item_path in content_items_path_list:
        with open(content_item_path, "r") as f:
            content_item_yml_data = yaml.safe_load(f)

        if content_item_type == CollectorReltaedContent.INTEGRATIONS:
            updated_yml_data = prepare_integration_yml(
                content_item_yml_data, custom_suffix
            )
        else:
            updated_yml_data = prepare_modeling_parsing_rules_yml(
                content_item_yml_data, custom_suffix
            )

        with open(content_item_path, "w") as file:
            yaml.dump(updated_yml_data, file)


def replace_metadata_id(new_pack_path: Path, custom_suffix: str):
    metadata_new_file_path = new_pack_path / CollectorReltaedContent.PACK_METADATA.value
    if not metadata_new_file_path.exists():
        return

    with open(metadata_new_file_path, "r") as f:
        metadata_data = json.load(f)

        if metadata_data.get("name"):
            metadata_data["name"] += f" {custom_suffix.capitalize()}"

    with open(metadata_new_file_path, "w") as f:
        json.dump(metadata_data, f, indent=4)


def monkey_patch_function(custom) -> str:
    return f"""def monkey_patch_send_events_to_xsiam(func):
    def wrapper(events, vendor, product, **kwargs):
        # Call the original function with the new vendor and product parameters
        func(events, '{custom}', '{custom}', **kwargs)
    return wrapper

send_events_to_xsiam= monkey_patch_send_events_to_xsiam(send_events_to_xsiam)
"""


def monkey_patch_send_events_to_xsiam(func):
    def wrapper(events, vendor, product, **kwargs):
        # Call the original function with the new vendor and product parameters
        func(events, '{custom}', '{custom}', **kwargs)
    return wrapper


def monkey_patch_collector_send_events_to_xsiam(new_pack_path, custom):
    content_integration_folder_path = new_pack_path / CollectorReltaedContent.INTEGRATIONS.value
    if not content_integration_folder_path.exists():
        return

    py_file_pattern = os.path.join(content_integration_folder_path, "**", "*.py")
    integration_python_files = glob.glob(py_file_pattern)

    integration_python_files_paths = [Path(integration_python_file) for integration_python_file in integration_python_files]

    for integration_python_file_path in integration_python_files_paths:
        if 'test' in integration_python_file_path.name or 'EventCollector' not in integration_python_file_path.name:
            continue

        with open(integration_python_file_path, 'r+') as integration_python_file:
            original_code = integration_python_file.read()

            integration_python_file.seek(0)
            code_to_patch = monkey_patch_function(custom)
            integration_python_file.write(code_to_patch + '\n' + original_code)


def prepare_xif_file(new_pack_path: Path, custom: str):
    content_integration_folder_path = new_pack_path / CollectorReltaedContent.MODELING_RULES.value
    if not content_integration_folder_path.exists():
        return

    xif_file_pattern = os.path.join(content_integration_folder_path, "**", "*.xif")
    xif_files_paths = glob.glob(xif_file_pattern)

    for xif_file_path in xif_files_paths:
        with open(xif_file_path, 'r') as xif_f:
            xif_data = xif_f.read()

        matches = re.findall(DATASET_REGEX, xif_data, re.MULTILINE)

        for match in matches:
            xif_data = xif_data.replace(match, f'{custom.lower()}_{custom.lower()}_raw')

        with open(xif_file_path, 'w') as xif_f:
            xif_f.write(xif_data)


def main():
    custom_suffix = "Custom"
    pack_path = Path("/Users/okarkkatz/dev/demisto/content/Packs/AzureSecurityCenter")
    matching_folder = find_matching_folders(
        pack_path, [item.value for item in list(CollectorReltaedContent)]
    )
    new_pack_path: Path = copy_matching_folder(matching_folder, pack_path)
    for collector_content_item in [
        CollectorReltaedContent.INTEGRATIONS,
        CollectorReltaedContent.MODELING_RULES,
        CollectorReltaedContent.PARSING_RULES,
    ]:
        prepare_yml_files(new_pack_path, custom_suffix, collector_content_item)

    replace_metadata_id(new_pack_path, custom_suffix)
    monkey_patch_collector_send_events_to_xsiam(new_pack_path, custom_suffix)
    prepare_xif_file(new_pack_path, custom_suffix)


if __name__ == "__main__":
    main()
