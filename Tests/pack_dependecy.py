import json
import networkx as nx


def search_for_pack_items(pack_name, items_list):
    return list(filter(lambda s: next(iter(s.values())).get('pack') == pack_name, items_list))


def search_packs_by_items_names(items_names, items_list):
    if not isinstance(items_names, list):
        items_names = [items_names]

    content_items = list(
        filter(lambda s: list(s.values())[0].get('name', '') in items_names and 'pack' in list(s.values())[0],
               items_list))

    if content_items:
        return list(map(lambda s: next(iter(s.values()))['pack'], content_items))

    return None


def search_packs_by_integration_command(command, id_set):
    integrations = list(
        filter(lambda i: command in list(i.values())[0].get('commands', []) and 'pack' in list(i.values())[0],
               id_set['integrations']))

    if integrations:
        pack_names = [next(iter(i.values()))['pack'] for i in integrations]

        return pack_names

    return None


def collect_scripts_dependencies(pack_scripts, id_set):
    dependencies_packs = set()

    for script in pack_scripts:
        dependencies_commands = script.get('depends_on', [])

        for command in dependencies_commands:
            pack_names = search_packs_by_items_names(command, id_set['scripts'])

            if pack_names:
                dependencies_packs.update(pack_names)
                continue

            pack_names = search_packs_by_integration_command(command, id_set)

            if pack_names:
                dependencies_packs.update(pack_names)

            print(f"Pack not found for {command} command or task.")

    return dependencies_packs


def collect_playbooks_dependencies(pack_playbooks, id_set):
    dependencies_packs = set()

    for playbook in pack_playbooks:
        playbook_data = next(iter(playbook.values()))

        implementing_script_names = playbook_data.get('implementing_scripts', [])
        packs_found_from_scripts = search_packs_by_items_names(implementing_script_names, id_set['scripts'])

        if packs_found_from_scripts:
            dependencies_packs.update(packs_found_from_scripts)

        implementing_commands_and_integrations = playbook_data.get('command_to_integration', {})

        for command, integration_name in implementing_commands_and_integrations.items():
            packs_found_from_integration = search_packs_by_items_names(integration_name, id_set['integrations']) \
                if integration_name else search_packs_by_integration_command(command, id_set)

            if packs_found_from_integration:
                dependencies_packs.update(packs_found_from_integration)

        implementing_playbook_names = playbook_data.get('implementing_playbooks', [])
        packs_found_from_playbooks = search_packs_by_items_names(implementing_playbook_names, id_set['playbooks'])

        if packs_found_from_playbooks:
            dependencies_packs.update(packs_found_from_playbooks)

    return dependencies_packs


def collect_pack_items(pack_name, id_set):
    pack_scripts = search_for_pack_items(pack_name, id_set['scripts'])
    pack_playbooks = search_for_pack_items(pack_name, id_set['playbooks'])
    pack_integrations = search_for_pack_items(pack_name, id_set['integrations'])

    return pack_scripts, pack_playbooks, pack_integrations


def find_pack_dependencies(pack_name, id_set):
    pack_scripts, pack_playbooks, pack_integrations = collect_pack_items(pack_name, id_set)
    scripts_dependencies = collect_scripts_dependencies(pack_scripts, id_set)
    playbooks_dependencies = collect_playbooks_dependencies(pack_playbooks, id_set)
    pack_dependencies = scripts_dependencies | playbooks_dependencies
    # todo add additional data to the return result

    return pack_dependencies


def build_dependency_graph(pack_name, id_set):
    return []


def main():
    id_set_path = "/Users/igabashvili/Downloads/id_set.json"
    pack_name = "CortexXDR"

    with open(id_set_path, 'r') as id_set_file:
        id_set = json.load(id_set_file)

    dependency_graph = build_dependency_graph(pack_name, id_set)


if __name__ == "__main__":
    main()
