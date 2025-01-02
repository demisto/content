import os
import json
import random

# Specify the folder containing the JSON files
folder_path = "/Users/aday/dev/demisto/content/Packs/Core/Triggers"

def modify_md5(hash_str):
    """Modify one character in the given MD5 hash to ensure it's different."""
    index = random.randint(0, len(hash_str) - 1)
    char = hash_str[index]
    new_char = chr((ord(char) + 1) % 256) if char.isalnum() else 'a'
    return hash_str[:index] + new_char + hash_str[index + 1:]

# Loop through all files in the folder
for filename in os.listdir(folder_path):
    if filename.endswith(".json"):
        original_file = os.path.join(folder_path, filename)
        
        # Create the new filename with "silent-" prefix
        silent_filename = f"silent-{filename}"
        silent_file = os.path.join(folder_path, silent_filename)
        
        # Load the content of the original JSON file
        with open(original_file, 'r') as file:
            content = json.load(file)
        
        # Modify the `playbook_id` and `trigger_name`
        if "playbook_id" in content:
            content["playbook_id"] = f"silent-{content['playbook_id']}"
        if "trigger_name" in content:
            content["trigger_name"] = f"silent-{content['trigger_name']}"
        
        # Modify the `trigger_id`
        if "trigger_id" in content:
            content["trigger_id"] = modify_md5(content["trigger_id"])
        
        # Add the `issilent` field
        content["issilent"] = True
        
        # Save the modified content to the new file
        with open(silent_file, 'w') as file:
            json.dump(content, file, indent=4)
