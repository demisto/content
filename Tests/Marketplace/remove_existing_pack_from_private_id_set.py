import json
import argparse


def get_pack_id(pack_name, pack_value):
    return pack_value.get('id') if pack_value.get('id') else pack_name


def remove_old_pack_from_private_id_set(private_id_set, new_pack_name):
    """Removes the old data of the new pack from the private id set.

    Args:
        private_id_set (dict): The private ID set
        new_pack_name (str): The name of the new pack

    Returns:
        Private id set without the old data of the new package
    """
    for content_entity, content_entity_value_list in private_id_set.items():
        if content_entity != "Packs":
            entity_value_list = []
            for content_entity_value in content_entity_value_list:
                content_item_value = content_entity_value.get(list(content_entity_value.keys())[0], {})
                if content_item_value.get('pack') != new_pack_name:
                    entity_value_list.append(content_entity_value)

            private_id_set[content_entity] = entity_value_list

        else:
            packs_list = {}
            for pack_name, pack_value in content_entity_value_list.items():
                pack_id = get_pack_id(pack_name, pack_value)
                if pack_id != new_pack_name:
                    packs_list[pack_name] = pack_value

            private_id_set[content_entity] = packs_list

    return private_id_set


def get_and_set_private_id_set_by_path(private_id_set_path, new_pack_name):
    with open(private_id_set_path, 'r') as id_set_file:
        private_id_set = json.load(id_set_file)

    private_id_set = remove_old_pack_from_private_id_set(private_id_set, new_pack_name)

    with open(private_id_set_path, 'w') as id_set_file:
        json.dump(private_id_set, id_set_file, indent=4)


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
    get_and_set_private_id_set_by_path(private_id_set_path, new_pack_name)


if __name__ == '__main__':
    main()
