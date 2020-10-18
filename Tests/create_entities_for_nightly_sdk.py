import argparse
import json
import re
import subprocess
from pathlib import Path


def run_command(cmd):
    return subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, encoding='utf-8').communicate()


def create_incident_field(path, layout):
    incident_field_path = path / 'IncidentFields'
    hello_field_path = incident_field_path / 'incidentfield-Hello_World_Type.json'
    with open(hello_field_path) as stream:
        field = json.load(stream)
    name = 'Hello World Incident Test'
    cliname = name.lower().replace(' ', '')
    field.update({
        'name': name,
        'cliName': cliname,
        'id': f'incident_{cliname}',
        'layout': layout
    })
    field_path = path / 'IncidentFields' / f'incidentfield-{name.replace(" ", "_")}.json'
    with open(field_path, 'w+') as stream:
        json.dump(field, stream, indent=4)
    return str(field_path)


def create_layout(path, name):
    layout_path = path / 'Layouts'
    layout_path_sample = layout_path / 'layout-details-Hello_World_Alert-V2.json'
    with open(layout_path_sample) as stream:
        layout = json.load(stream)
    layout.update({
        'TypeName': name,
        'typeId': name
    })
    layout['layout'].update({
        'id': name,
        'typeId': name
    })
    layout_path = path / 'Layouts' / f'layout-{name.replace(" ", "_")}.json'
    with open(layout_path, 'w+') as stream:
        json.dump(layout, stream, indent=4)
    return str(layout_path)


def create_incident_type(path, layout_name):
    incident_type_path = path / 'IncidentTypes'
    incident_type_path_sample = incident_type_path / 'incidenttype-Hello_World_Alert.json'
    with open(incident_type_path_sample) as stream:
        incident_type = json.load(stream)
    name = 'Hello World Alert Test'
    incident_type.update({
        'name': name,
        'id': name,
        'layout': layout_name
    })
    incident_path = incident_type_path / f'incidenttype-{name.replace(" ", "_")}.json'
    with open(incident_path, 'w+') as stream:
        json.dump(incident_type, stream, indent=4)
    return str(incident_path)


def upload_to_sdk(path, *args):
    """
    For some reasons, if uploading entities one by one we will get an exception,
        so we process the output to see that all files created are succeeded.
    """
    print('Uploading to SDK')
    stdout, _, = run_command(f'demisto-sdk upload -i {str(path)}')
    try:
        trimmed = re.search("SUCCESSFUL UPLOADS.*FAILED UPLOADS", stdout, flags=re.DOTALL).group()
    except AttributeError:
        raise AttributeError(f'Could not find output of the command. {stdout}')
    for arg in args:
        assert arg.split('/')[-1] in trimmed, f'Could not upload {arg}.\nstdout={stdout}'
        print(f'{arg} was uploaded to Cortex XSOAR')


def main():
    parser = argparse.ArgumentParser(description="Creates incident field, incident type and a layout in a given pack.")
    parser.add_argument('pack_name')
    args = parser.parse_args()
    pack_path = Path('Packs') / args.pack_name
    layout_name = 'Hello World Test Layout'
    uploaded_entities = [
        create_layout(pack_path, layout_name),
        create_incident_field(pack_path, layout_name),
        create_incident_type(pack_path, layout_name)
    ]
    print("Created entities:")
    print('\n'.join(uploaded_entities))
    upload_to_sdk(pack_path, *uploaded_entities)


if __name__ in '__main__':
    main()
