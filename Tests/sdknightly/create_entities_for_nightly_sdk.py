import argparse
import json
import re
import os
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Union


def run_command(cmd: str) -> Tuple[str, str]:
    return subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding='utf-8').communicate()


def create_incident_field(path: Path, layout_name: str) -> str:
    """
    Creates an incident field

    Args:
        path: A path of the pack
        layout_name: a layout to associate the incident field

    Returns:
        The path to the incident field
    """
    hello_field_path = 'Packs/HelloWorld/IncidentFields/incidentfield-Hello_World_Type.json'
    with open(hello_field_path) as stream:
        field = json.load(stream)
    name = 'Hello World Incident Test'
    cliname = name.lower().replace(' ', '')
    field.update({
        'name': name,
        'cliName': cliname,
        'id': f'incident_{cliname}',
        'layout': layout_name
    })
    dest_incident = path / 'IncidentFields'

    if not os.path.isdir(dest_incident):
        os.mkdir(dest_incident)

    field_path = dest_incident / f'incidentfield-{name.replace(" ", "_")}.json'
    with open(field_path, 'w+') as stream:
        json.dump(field, stream, indent=4)
    return str(field_path)


def create_layout(path: Path, layout_name: str) -> str:
    """
    Creates a layout field

    Args:
        path: A path of the pack
        layout_name: a layout name to create

    Returns:
        The path to the layout
    """
    layout_path_sample = Path('Packs/HelloWorld/Layouts/layout-details-Hello_World_Alert-V2.json')
    with open(layout_path_sample) as stream:
        layout = json.load(stream)
    dest_layout = path / 'Layouts'
    if not os.path.isdir(dest_layout):
        os.mkdir(dest_layout)

    layout_path = dest_layout / f'layout-{layout_name.replace(" ", "_")}.json'
    with open(layout_path, 'w+') as stream:
        json.dump(layout, stream, indent=4)
    return str(layout_path)


def create_incident_type(path: Path, layout_name: str) -> str:
    """
    Creates an incident type

    Args:
        path: A path of the pack
        layout_name: a layout to associate the incident field

    Returns:
        The path to the incident type
    """
    incident_type_path_sample = Path('Packs/HelloWorld/IncidentTypes/incidenttype-Hello_World_Alert.json')
    with open(incident_type_path_sample) as stream:
        incident_type = json.load(stream)
    name = 'Hello World Alert Test'
    incident_type.update({
        'name': name,
        'id': name,
        'layout': layout_name
    })
    dest_incident_path = path / 'IncidentTypes'

    if not os.path.isdir(dest_incident_path):
        os.mkdir(dest_incident_path)

    incident_path = dest_incident_path / f'incidenttype-{name.replace(" ", "_")}.json'
    with open(incident_path, 'w+') as stream:
        json.dump(incident_type, stream, indent=4)
    return str(incident_path)


def upload_to_sdk(path: Union[Path, str], *args: str, debug: bool = False):
    """
    For some reasons, if uploading entities one by one we will get an exception,
        so we process the output to see that all files created are succeeded.

    Args:
        path: Path of the pack to upload
        args: Entities to validate upload
    """
    print('Uploading to Cortex XSOAR')
    stdout, stderr, = run_command(f'demisto-sdk upload -i {str(path)} --insecure')
    try:
        if "FAILED UPLOADS" in stdout:
            searched_re = re.search("SUCCESSFUL UPLOADS.*FAILED UPLOADS", stdout, flags=re.DOTALL)
            if searched_re is None:
                raise AttributeError('Could not find output of the command.')
            trimmed = searched_re.group()
            for arg in args:
                assert arg.split('/')[-1] in trimmed, f'Could not upload {arg}.'
                print(f'{arg} was uploaded to Cortex XSOAR')
        else:
            print("All content entities were sucessfully uploaded to Cortex XSOAR.")
            print("Entities:")
            print("\t" + "\n\t".join(args))
    except AssertionError:
        debug = True
    finally:
        if debug:
            print("Uploading STDOUT")
            print(stdout)
            print("Uploading STDERR")
            print(stderr)


def main():
    parser = argparse.ArgumentParser(description="Creates incident field, incident type and a layout in a given pack.")
    parser.add_argument('pack_name')
    parser.add_argument('--artifacts-folder', required=False)
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    pack_path = Path('Packs') / args.pack_name
    layout_name = 'Hello World Test Layout'
    uploaded_entities = [
        create_layout(pack_path, layout_name),
        create_incident_field(pack_path, layout_name),
        create_incident_type(pack_path, layout_name)
    ]
    print("Created entities:")
    print("\t" + "\n\t".join(uploaded_entities))
    if args.artifacts_folder:
        entities_folder = Path(args.artifacts_folder) / 'UploadedEntities'
        if not os.path.isdir(entities_folder):
            os.mkdir(entities_folder)
        print(f"Storing files to {entities_folder}")
        for file in uploaded_entities:
            file_name = file.split('/')[-1]
            shutil.copyfile(file, entities_folder / file_name)
            print(f"file: {file_name} stored.")
    upload_to_sdk(pack_path, *uploaded_entities, debug=args.debug)


if __name__ in '__main__':
    main()
