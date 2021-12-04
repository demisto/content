import argparse
import io
import json
import os

PACKS_DIR = 'Packs'
PACKS_METADATA = 'pack_metadata.json'


def util_load_json(path):
    """ Gets the pack metadata.

        :rtype: ``dict``
        :return
        The pack metadata dictionary
    """
    try:
        with io.open(path, mode='r', encoding='utf-8') as f:
            return json.loads(f.read())
    except FileNotFoundError as e:
        raise FileNotFoundError(f'Pack metadata {path} was not found.') from e


def util_update_metadata(path, new_meta: dict):
    """ Writes the new metadata to the pack metadata file.

        :param
            new_meta: The new metadata to write

    """
    with open(path, 'w') as f:
        json.dump(new_meta, f, indent=4)


def option_handler():
    """Validates and parses script arguments.

    Returns:
        Namespace: Parsed arguments object.

    """
    parser = argparse.ArgumentParser(description="Add field to a pack metadata.")
    parser.add_argument('-a', '--all', help="Add the given field to all packs. This is the default value",
                        required=False)
    parser.add_argument('-p', '--packs', help="Comma separated list of packs to add the given field to.",
                        required=False)
    parser.add_argument('-k', '--key-name', help="The name of the key to add.", required=True)
    parser.add_argument('-v', '--value', help='The value of the key to set. Will be handled as a comma separated list.',
                        required=True)
    return parser.parse_args()


def add_field_to_metadata(pack, key, value):
    """
    Set a key, value pair to a pack metadata.
    """

    pack_metadata_path = os.path.join(pack, PACKS_METADATA)
    pack_metadata = util_load_json(pack_metadata_path)
    pack_metadata[key] = value.split(',')
    util_update_metadata(pack_metadata_path, pack_metadata)


def main():
    option = option_handler()
    key_to_add = option.key_name
    value = option.value

    if provided_packs := option.packs:
        packs = [os.path.join(PACKS_DIR, p) if PACKS_DIR not in p else p for p in provided_packs.split(',')]
    else:
        packs = list(filter(os.path.isdir, [os.path.join(PACKS_DIR, p) for p in os.listdir(PACKS_DIR)]))

    errors = ''
    for pack in packs:
        try:
            add_field_to_metadata(pack, key_to_add, value)
        except Exception as e:
            errors += f'An exception was raised when attempted to add field to pack: {pack}. error: {e}\n'
            continue

    user_output = f'Key: "{key_to_add}" with Value: "{value}" were added.'
    user_output += f'\nThe following errors occurred:\n{errors}' if errors else None
    print(user_output)


if __name__ == '__main__':
    main()
