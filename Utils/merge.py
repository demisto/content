import re
from distutils.version import LooseVersion

ENTITY_TYPE_SECTION_REGEX = re.compile(r'^#### ([\w ]+)$\n([\w\W]*?)(?=^#### )|^#### ([\w ]+)$\n([\w\W]*)', re.M)
ENTITY_SECTION_REGEX = re.compile(r'^##### (.+)$\n([\w\W]*?)(?=^##### )|^##### (.+)$\n([\w\W]*)|^- \*\*(.+)\*\*$\n([\w\W]*)', re.M)


def merge_version_blocks(pack_versions_dict: dict, add_whitespaces: bool = True, rn_wrapper: str = '') -> str:
    """
    merge several pack release note versions into a single block.

    Args:
        pack_versions_dict: a mapping from a pack version to a release notes file content.
        add_whitespaces: a parameter to pass to construct_entities_block function which indicates
        whether to add whitespaces to the entity name or not
        rn_wrapper: a wrapper to wrap the release notes (usually /n)

    Returns:
        a single pack release note block

    """
    latest_version = '1.0.0'
    entities_data = {}
    for pack_version, version_release_notes in sorted(pack_versions_dict.items(),
                                                      key=lambda pack_item: LooseVersion(pack_item[0])):
        latest_version = pack_version
        version_release_notes = version_release_notes.strip()
        # extract release notes sections by content types (all playbooks, all scripts, etc...)
        # assuming all entity titles start with level 4 header ("####") and then a list of all comments
        sections = ENTITY_TYPE_SECTION_REGEX.findall(version_release_notes)
        for section in sections:
            # one of scripts, playbooks, integrations, layouts, incident fields, etc...
            entity_type = section[0] or section[2]
            # blocks of entity name and related release notes comments
            entity_section = section[1] or section[3]
            entities_data.setdefault(entity_type, {})

            # extract release notes comments by entity
            # assuming all entity titles start with level 5 header ("#####") and then a list of all comments
            entity_comments = ENTITY_SECTION_REGEX.findall(entity_section)
            for entity in entity_comments:
                # name of the script, integration, playbook, etc...
                entity_name = entity[0] or entity[2] or entity[4]
                entity_name = entity_name.replace('__', '')
                # release notes of the entity
                entity_comment = entity[1] or entity[3] or entity[5]
                if entity_name in entities_data[entity_type]:
                    entities_data[entity_type][entity_name] += f'{entity_comment.strip()}\n'
                else:
                    entities_data[entity_type][entity_name] = f'{entity_comment.strip()}\n'

    pack_release_notes = construct_entities_block(entities_data, add_whitespaces).strip()

    if rn_wrapper:
        pack_release_notes = f'{pack_release_notes}{rn_wrapper}' if not pack_release_notes.endswith(rn_wrapper) else \
            pack_release_notes
        pack_release_notes = f'{rn_wrapper}{pack_release_notes}' if not pack_release_notes.startswith(rn_wrapper) else \
            pack_release_notes

    return pack_release_notes


def construct_entities_block(entities_data: dict, add_whitespaces: bool = True) -> str:
    """
    convert entities information to a pack release note block

    Args:
        entities_data (dict): dictionary of the form:
            {
                Integrations: {
                    Integration1: <description>,
                    Integration2:<description>,
                },
                Scripts: {
                    Script1:<description>,
                    Script2:<description>,
                },
                ...
            }
        add_whitespaces (bool): whether to add whitespaces to the entity name or not

    Returns:
        release note block string

    """
    release_notes = ''
    for entity_type, entities_description in sorted(entities_data.items()):
        pretty_entity_type = re.sub(r'(\w)([A-Z])', r'\1 \2', entity_type)
        release_notes += f'#### {pretty_entity_type}\n'
        for name, description in entities_description.items():
            if entity_type in ('Connections', 'IncidentTypes', 'IndicatorTypes', 'Layouts', 'IncidentFields'):
                release_notes += f'- **{name}**\n'
            else:
                if add_whitespaces:
                    release_notes += f'##### {name}  \n{description}\n'
                else:
                    release_notes += f'##### {name}\n{description}\n'

    return release_notes


def main():
    with open('Packs/CortexXDR/ReleaseNotes/2_4_5.md') as f:
        first_lines = f.read()
    with open('Packs/CortexXDR/ReleaseNotes/2_4_6.md') as f:
        second_lines = f.read()
    # with open('Packs/CrowdStrikeIntel/ReleaseNotes/2_0_2.md') as f:
    #     first_lines = f.read()
    # with open('Packs/CrowdStrikeIntel/ReleaseNotes/2_0_3.md') as f:
    #     second_lines = f.read()
    first_lines = re.sub(r'<\!--.*?-->', '', first_lines, flags=re.DOTALL).strip()
    second_lines = re.sub(r'<\!--.*?-->', '', second_lines, flags=re.DOTALL).strip()
    pack_versions_dict = {'2.4.5': first_lines, '2.4.6': second_lines}
    output = merge_version_blocks(pack_versions_dict, False, '\n')
    print(f'output: {output}')


if __name__ == '__main__':
    main()
