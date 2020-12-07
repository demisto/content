import json
import argparse
from Tests.Marketplace.download_private_id_set import download_private_id_set_from_gcp


def remove_old_pack_from_private_id_set(private_id_set_path, new_pack_name):
    with open(private_id_set_path, 'r') as id_set_file:
        private_id_set = json.load(id_set_file)

    for entity, entity_list in private_id_set.items():
        for item in entity_list[:]:
            if item.get(list(item.keys())[0], {}).get('pack') == new_pack_name:
                entity_list.remove(item)

    return private_id_set


def options_handler():
    parser = argparse.ArgumentParser(description='Returns the new pack name')
    parser.add_argument('-np', '--new_pack_name', help='New pack name', required=True)

    options = parser.parse_args()
    return options


def main():
    options = options_handler()
    private_id_set = download_private_id_set_from_gcp()

    new_pack_name = options.new_pack_name
    merged_private_id_set = remove_old_pack_from_private_id_set(private_id_set, new_pack_name)

    return merged_private_id_set


if __name__ == '__main__':
    main()
