
import glob
import json
import os
from os.path import join

CONTENT_ROOT = './Packs/'

def get_all_mapper_files(folder, file_matcher):
    ret_value = []
    seen_files = []
    for filename in glob.iglob(folder + '**/**', recursive=True):
        if filename in seen_files:
            continue
        seen_files.append(filename)
        if file_matcher(folder, filename):
            ret_value.append(filename)
    return ret_value

def get_all_incident_fields(folder):
    ret_value = {}
    seen_files = []
    for filename in glob.iglob(folder + '**/**', recursive=True):
        if filename in seen_files:
            continue
        seen_files.append(filename)
        incident_field = file_matcher_incident_field(folder, filename)
        if incident_field:
            ret_value[incident_field["name"]] = incident_field["cliName"]
            if "Aliases" in incident_field:
                for current_alias in incident_field["Aliases"]:
                    ret_value[current_alias["name"]] = current_alias["cliName"]
    return ret_value

def file_matcher_incident_field(folder, file):
    # Sample filename:
    #   incidentfield-MD5.json
    # Also should check that it's in marketplacev2

    if '/IncidentFields/incidentfield-' in file and file.endswith('.json'):
        with open(file, 'r') as if_file:
            incident_field = json.load(if_file)
            # "marketplaces": ["xsoar", "marketplacev2"]
            if not "marketplaces" in incident_field:
                return incident_field
            if "marketplacev2" in incident_field["marketplaces"]:
                return incident_field
    return None

def file_matcher_mapper(folder, file):
    # Sample filenames:
    #   classifier-GLPI_-_Incoming_Mapper.json
    #   classifier-GLPI_-_Outgoing_Mapper.json
    if 'classifier-' in file and file.endswith('-_Incoming_Mapper.json'):
        return True
    if 'classifier-' in file and file.endswith('-__Outgoing_Mapper.json'):
        return True
    return False

# def get_incident_field_details(incident_field):
#     return {
#         # "file": if_file,
#         # "json": incident_field,

#         # "id": incident_field["id"],
#         "name": incident_field["name"],
#         "cliName": incident_field["cliName"],
#     }

def fix_mapper_file(mapper_file, incident_fields_by_name):
    print(f'fix_mapper_file, {mapper_file=}')
    mapper = None
    with open(mapper_file, 'r') as mapper_file:
        mapper = json.load(mapper_file)

    if not mapper:
        print(f'Cannot fix mapper in {mapper_file=}')

    mapper_changed = False
    for current_mapping_name in mapper["mapping"].keys():
        current_mapping = mapper["mapping"][current_mapping_name]
        for current_field_name in current_mapping["internalMapping"].keys():
            current_field = current_mapping["internalMapping"][current_field_name]
            if current_field_name not in incident_fields_by_name:
                print(f'Cannot find incidentfield {current_field_name}')
                continue
            cliName = incident_fields_by_name[current_field_name] or None
            if cliName:
                mapper_changed = True
                current_field["cliName"] = cliName
    if mapper_changed:
        print(f'Updating Mapper file {mapper_file}')
        json_object = json.dumps(mapper, indent=4)
        with open(mapper_file.name, "w") as outfile:
            outfile.write(json_object)
    else:
        print(f'No changes in Mapper file {mapper_file}')

def print_first_list_items(list_of_items, count):
    counter = 0
    for current_item in list_of_items:
        counter += 1
        if counter > count:
            break

def main():
    all_incident_fields_by_name = get_all_incident_fields(CONTENT_ROOT)
    print('Got all_incident_fields, len(all_incident_fields): ' + str(len(all_incident_fields_by_name)))
    print('First all_incident_fields_by_name.keys:')
    print_first_list_items(all_incident_fields_by_name.keys(), 3)
    print('First all_incident_fields_by_name.values:')
    print_first_list_items(all_incident_fields_by_name.values(), 3)

    counter = 0
    for current_mapper_file in get_all_mapper_files(CONTENT_ROOT, file_matcher_mapper):
        fix_mapper_file(current_mapper_file, all_incident_fields_by_name)
        counter += 1
        if counter > 3:
            exit()

if __name__ == "__main__":
    main()
