import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


def extract_section(section):
    if section:
        return {
            'name': section.get('name')
        }


def extract_sections(tab):
    sections = tab.get('sections', [])
    return list(map(extract_section, sections))


def extract_tab(tab):
    return {
        'id': tab.get('id'),
        'name': tab.get('name'),
        'section': extract_sections(tab)
    }


def extract_tabs(layout):
    group = layout.get('group')
    tabs = []

    if group == 'incident':
        tabs = demisto.get(layout, 'detailsV2.tabs', [])
    elif group == 'indicator':
        tabs = demisto.get(layout, 'indicatorsDetails.tabs', [])

    tabs = list(map(extract_tab, tabs))
    return tabs


def extract_layout(layout):
    return {
        'id': layout.get('id'),
        'name': layout.get('name'),
        'tabs': extract_tabs(layout),
        'type': layout.get('group')
    }


def extract_layouts(_layouts):
    return list(map(extract_layout, _layouts))


def get_layouts():
    return execute_command('demisto-api-get', {'uri': '/layouts'})


def get_custom_layouts(_layouts):
    return filter(lambda layout: not layout.get('system'), _layouts)


layouts = get_layouts()
layouts = layouts.get('response', {})
layouts = get_custom_layouts(layouts)
layouts = extract_layouts(layouts)


results = CommandResults(
    outputs_prefix='XSOAR.Layouts',
    outputs_key_field='id',
    outputs=layouts
)

return_results(results)
