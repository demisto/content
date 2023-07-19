import os
import glob
import shutil
from pathlib import Path
from enum import Enum
import yaml


class CollectorReltaedContent(str, Enum):
    INTEGRATIONS = "Integrations"
    PARSING_RULES = "ParsingRules"
    MODELING_RULES = "ModelingRules"


def find_matching_folders(root_folder: Path, folder_names):
    matching_folders = []
    for folder_name in folder_names:
        search_pattern = os.path.join(root_folder, '**', folder_name)
        matching_folders.extend(glob.glob(search_pattern, recursive=True))
    return matching_folders


def copy_matching_folder(matching_folder_list, pack_path: Path, custom_suffix: str = 'Custom') -> Path:
    packs_folder_path, pack_name = pack_path.parent, pack_path.name
    new_pack_path: Path = packs_folder_path / f'{pack_name}{custom_suffix.capitalize()}'

    for folder_path in matching_folder_list:
        folder_path = Path(folder_path)
        folder_name = folder_path.name
        copy_to_path = new_pack_path / Path(folder_path).name

        if folder_name == CollectorReltaedContent.INTEGRATIONS:
            Integration_list = [name for name in os.listdir(folder_path) if os.path.isdir(os.path.join(folder_path, name))]
            for integration in Integration_list:
                if 'EventCollector' in integration:
                    event_collector_integration = copy_to_path / integration
                    folder_path_integration = folder_path / integration
                    shutil.copytree(folder_path_integration, event_collector_integration, dirs_exist_ok=True)

        else:
            shutil.copytree(folder_path, copy_to_path, dirs_exist_ok=True)

    return new_pack_path


def prepare_integration_yml(integration_yml_data: dict, custom_suffix: str):
    to_append = f' - {custom_suffix}'
    if integration_yml_data.get("name"):
        integration_yml_data["name"] += to_append
    if integration_yml_data.get("commonfields", {}).get("id"):
        integration_yml_data["commonfields"]["id"] += to_append
    if integration_yml_data.get("display"):
        integration_yml_data["display"] += to_append

    return integration_yml_data


def prepare_modeling_parsing_rules_yml(modeling_parsing_rule_yml_data: dict, custom_suffix: str):
    if modeling_parsing_rule_yml_data.get("name"):
        modeling_parsing_rule_yml_data["name"] += f' {custom_suffix.capitalize()}'
    if modeling_parsing_rule_yml_data.get("id"):
        modeling_parsing_rule_yml_data["id"] += f'_{custom_suffix.lower()}'

    return modeling_parsing_rule_yml_data


def prepare_yml_files(new_pack_path: Path, custom_suffix: str, content_item_type: CollectorReltaedContent):
    content_item_folder_path = new_pack_path / content_item_type.value
    if not content_item_folder_path.exists():
        return

    yml_file_pattern = os.path.join(content_item_folder_path, '**', '*.yml')
    content_items_path_list = glob.glob(yml_file_pattern)

    for content_item_path in content_items_path_list:
        with open(content_item_path, 'r') as f:
            content_item_yml_data = yaml.safe_load(f)

        if content_item_type == CollectorReltaedContent.INTEGRATIONS:
            updated_yml_data = prepare_integration_yml(content_item_yml_data, custom_suffix)
        else:
            updated_yml_data = prepare_modeling_parsing_rules_yml(content_item_yml_data, custom_suffix)

        with open(content_item_path, 'w') as file:
            yaml.dump(updated_yml_data, file)


def main():
    custom_suffix = 'Custom'
    pack_path = Path('/Users/okarkkatz/dev/demisto/content/Packs/AzureSecurityCenter')
    matching_folder = find_matching_folders(pack_path, [item.value for item in list(CollectorReltaedContent)])
    new_pack_path: Path = copy_matching_folder(matching_folder, pack_path)
    for collector_content_item in list(CollectorReltaedContent):
        prepare_yml_files(new_pack_path, custom_suffix, collector_content_item)


if __name__ == '__main__':
    main()
