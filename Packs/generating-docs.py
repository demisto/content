import os
import glob
import yaml
import re

# Define the base directory
base_dir = '/Users/iapt/dev/demisto/content/Packs'

def get_marketplace_name(yaml_data):
    if "marketplaces" not in yaml_data or not yaml_data["marketplaces"]:
        return ""

    xsoar_keys = {"xsoar", "xsoar_saas", "xsoar_on_prem"}
    if any(key in yaml_data.get("marketplaces", []) for key in xsoar_keys):
        return "" if "marketplacev2" in yaml_data.get("marketplaces", []) else "XSOAR"

    return "XSIAM" if "marketplacev2" in yaml_data.get("marketplaces", []) else "XSOAR"

def update_readme(integration_name, id, readme_content, mp):
    conf_xsoar = r"Configure (.+?) on Cortex XSOAR"
    match = re.search(conf_xsoar, readme_content)
    if match:
        wildcard_value = match.group(1)
        conf_xsoar = f"Configure {wildcard_value} on Cortex XSOAR"
    navigation = "Navigate to **Settings** > **Integrations** > **Servers & Services**."
    cortex_cli = "You can execute these commands from the Cortex XSOAR CLI"
    replacements = {}
    if mp == "XSOAR":
        replacements[navigation] = (
            "* For XSOAR 6.x users: Navigate to **Settings** > **Integrations** > **Instances**.\n"
            "   * For XSOAR 8.x users: Navigate to **Settings & Info** > **Settings** > **Integrations** > "
            "**Instances**."
        ).strip()
    elif mp == "":
        if conf_xsoar in readme_content:
            replacements[conf_xsoar] = f"Configure {wildcard_value if wildcard_value else integration_name} on Cortex"
        if navigation in readme_content:
            replacements[navigation] = (
                "  * For XSOAR 6.x users: Navigate to **Settings** > **Integrations** > **Instances**.\n"
                "   * For XSOAR 8.x users: Navigate to **Settings & Info** > **Settings** > **Integrations** > "
                "**Instances**.\n"
                "   * For XSIAM users: Navigate to **Settings** > **Configurations** > **Data Collection** > "
                "**Automation & Feed Integrations**."
            ).strip()
        if cortex_cli in readme_content:
            replacements[cortex_cli] = "You can execute these commands from the Cortex CLI"
    elif mp == "XSIAM":
        if conf_xsoar in readme_content:
            replacements[conf_xsoar] = f"Configure {wildcard_value if wildcard_value else integration_name} on Cortex XSIAM"
        if "Collector" in id:
            navigation_xsiam = "Navigate to **Settings** > **Configurations** > **Data Collection** > **Automation and Feed Integrations**."
            if navigation in readme_content :
                replacements[navigation] = "Navigate to **Settings** > **Data Sources** > **Add Data Source** > **Search**."
            if navigation_xsiam in readme_content:
                replacements[navigation_xsiam] = "Navigate to **Settings** > **Data Sources** > **Add Data Source** > **Search**."
        elif navigation in readme_content:
            replacements[navigation] = (
                "Navigate to **Settings** > **Configurations** > **Data Collection** > "
                "**Automation & Feed Integrations**."
            ).strip()
        if cortex_cli in readme_content:
            replacements[cortex_cli] = "You can execute these commands from the Cortex XSIAM CLI"
    return replacements
        

def process_files(readme_path, yml_content):
    try:
        yaml_data = yaml.safe_load(yml_content)
        marketplace_name = get_marketplace_name(yaml_data)
        with open(readme_path, 'r+') as readme_file:
            readme_content = readme_file.read()
            
            replacements = update_readme(yaml_data.get('display'), yaml_data.get('name'), readme_content, marketplace_name)
            
            # Perform replacements
            updated_content = readme_content
            for old_sentence, new_sentence in replacements.items():
                updated_content = updated_content.replace(old_sentence, new_sentence)
            
            # Write the updated content back to README.md
            readme_file.seek(0)
            readme_file.write(updated_content)
            readme_file.truncate()
    except yaml.YAMLError as exc:
        print(f"Error parsing YAML: {exc}")


# Iterate through each pack in the packs directory
for pack_path in glob.glob(os.path.join(base_dir, 'A*')):
    if os.path.isdir(pack_path):  # Ensure it's a directory
        integrations_path = os.path.join(pack_path, 'integrations')
        
        if os.path.isdir(integrations_path):
            # Iterate through each integration in the integrations directory
            for integration_path in glob.glob(os.path.join(integrations_path, '*')):
                if os.path.isdir(integration_path):  # Ensure it's a directory
                    integration_name = os.path.basename(integration_path)
                    readme_path = os.path.join(integration_path, 'README.md')
                    yml_file = os.path.join(integration_path, f'{integration_name}.yml')
                    if os.path.isfile(readme_path) and os.path.isfile(yml_file):
                        with open(yml_file, 'r') as yml_file_content:
                            yml_content = yml_file_content.read()
                        
                        process_files(readme_path, yml_content)
        