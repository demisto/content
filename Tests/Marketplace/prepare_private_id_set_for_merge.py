import json
import argparse


def remove_old_pack_from_private_id_set(private_id_set, new_pack_name):
    """Removes the old data of the new pack from the private id set.

    Args:
        private_id_set (dict): The private ID set
        new_pack_name (str): The name of the new pack

    Returns:
        Private id set without the old data of the new package
    """
    for entity, entity_list in private_id_set.items():
        for item in entity_list[:]:
            item_value = item.get(list(item.keys())[0], {})
            if item_value.get('pack') == new_pack_name:
                entity_list.remove(item)
    return private_id_set


def prepare_private_id_set_for_merge(private_id_set_path, new_pack_name):
    with open(private_id_set_path, 'r') as id_set_file:
        private_id_set = json.load(id_set_file)

    private_id_set = remove_old_pack_from_private_id_set(private_id_set, new_pack_name)

    with open(private_id_set_path, 'w') as id_set_file:
        json.dump(private_id_set, id_set_file)


def options_handler():
    parser = argparse.ArgumentParser(description='Removes the old information that exists on the changed pack,'
                                                 ' from private ID set')
    parser.add_argument('-np', '--new_pack_name', help='New pack name', required=True)
    parser.add_argument('-pis', '--private_id_set_path', help='Private ID set path', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    private_id_set_path = options.private_id_set_path
    new_pack_name = options.new_pack_name
    prepare_private_id_set_for_merge(private_id_set_path, new_pack_name)


if __name__ == '__main__':
    main()
