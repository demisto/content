import json
import random
import string
import tarfile
from tarfile import TarInfo
from typing import List, Union
from uuid import uuid4

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incident = demisto.incidents()[0]


class Layout:
    def __init__(self, data):
        try:
            self.data = data
            self.name = data['name']
            self.layout_type = data['group']
            self.tab_key = self.set_tab_key()
            self.tabs = data[self.tab_key].get('tabs', [])
            self.tab_names = []
            self.extract_tab_names()
        except KeyError:
            return None

    def set_tab_key(self):
        tab_key_map = {
            'incident': 'detailsV2',
            'indicator': 'indicatorsDetails'
        }
        return tab_key_map.get(self.layout_type)

    def extract_tab_names(self):
        self.set_tab_key()
        tabs = self.data[self.tab_key]['tabs']
        self.tab_names = [tab.get('name') for tab in tabs]

    def get_tab(self, tab_name):
        def tab_filter(tab):
            return tab['name'] == tab_name
        return next(filter(tab_filter, self.tabs))

    def commit_tab_data(self):
        self.data[self.tab_key]['tabs'] = self.tabs

    @staticmethod
    def generate_new_tab_id(tab):
        '''
        Caveat: If you don't replace the tab_id with a new one,
        the tabs will appear to copy correctly, but will then be
        purged by XSOAR within a few hours.
        '''

        tab['id'] = ''.join(random.choices(string.ascii_lowercase, k=10))

        def mod_uid(uid):
            return uid.replace(uid[random.randrange(len(uid))], random.choice(string.ascii_lowercase))

        def gen_i_id(uid):
            return f"{tab.get('id')}-{mod_uid(uid[0])}-{'-'.join(uid[1:])}"

        def gen_item_id(uid):
            return f"{uid[1]}-{mod_uid(uid[2])}-{'-'.join(uid[3:])}"

        for section in tab.get('sections'):
            uid = str(uuid4()).split('-')
            section.update({'i': gen_i_id(uid)})
            i_id = section.get('i').split('-')
            for item in section.get('items'):
                item.update({'id': gen_item_id(i_id)})
        return tab

    def merge_in_tab(self,
                     source_layout,
                     source_tab_name: str,
                     destination_tab_name: str = None):

        if not destination_tab_name:
            destination_tab_name = source_tab_name

        source_tab = source_layout.get_tab(source_tab_name)
        source_tab = self.generate_new_tab_id(source_tab)

        try:
            destination_tab = self.get_tab(destination_tab_name)
            destination_tab.update(source_tab)

        except StopIteration:
            self.tabs.append(source_tab)

        self.commit_tab_data()
        self.extract_tab_names()

    def upload_layout(self):
        return execute_command(
            'demisto-api-post',
            {
                'uri': '/layouts/save',
                'body':
                json.dumps(
                    self.data
                )
            }
        )


class LayoutCollection:
    def __init__(self):
        self.layouts = []
        self.tarball = None
        self.file_id = None

    def download_content(self):
        data = demisto.executeCommand('demisto-api-download', {'uri': '/content/bundle'})[0]
        self.file_id = data['FileID']

    @staticmethod
    def get_filter(filter_name, query: Union[str, list] = ''):
        filters = {
            'layout-file-filter': lambda tar_file: tar_file.name.startswith('/layoutscontainer-'),
            'get-layout': lambda layout: layout.name in query
        }
        return filters.get(filter_name)

    def extract_layout(self, file: TarInfo):
        layout = self.tarball.extractfile(file)
        layout = json.loads(layout.read())
        return Layout(layout)

    def get_content_file_path(self):
        incident_id = incident.get('id')
        return f'{incident_id}_{self.file_id}'

    def extract_content_file(self):
        file_path = self.get_content_file_path()
        self.tarball = tarfile.open(file_path)
        layout_files = filter(self.get_filter('layout-file-filter'), self.tarball.getmembers())
        self.layouts = list(map(self.extract_layout, layout_files))

    def import_layouts(self):
        self.download_content()
        self.extract_content_file()

    def get_layout(self, layout_names: Union[str, list]) -> List[Layout]:
        if type(layout_names) is str:
            layout_names = layout_names.split(',')
        layout_filter = self.get_filter('get-layout', layout_names)
        return list(filter(layout_filter, self.layouts))

    @staticmethod
    def _validate_result(result):
        name = demisto.get(result, 'response.name')
        if demisto.get(result, 'response.detailsV2'):
            return f'- ✅ {name} - Import Successful'
        return f'- ⛔️ {name} - Import Failed'

    def _format_tab_copy_results(self, results):
        pretty_results = list(map(self._validate_result, results))
        output = {
            'layoutcopy': {
                'pretty': pretty_results,
                'raw': results
            }
        }

        return CommandResults(
            outputs_prefix='XSOAR.results',
            outputs=output,
            readable_output='\n'.join(pretty_results),
            raw_response=results
        )

    def copy_tab(self,
                 source_layout,
                 source_tab,
                 destination_layouts: list,
                 destination_tab_name: str = None):

        source_layout = self.get_layout(source_layout)[0]
        destination_layouts = self.get_layout(destination_layouts)

        results = []
        for layout in destination_layouts:
            layout.merge_in_tab(source_layout, source_tab, destination_tab_name)
            results.append(layout.upload_layout())

        return self._format_tab_copy_results(results)

    
def main():
    def getArg(arg):
        return demisto.getArg(arg)

    source_layout_name = getArg('source_layout_name')
    source_tab_name = getArg('source_tab_name')
    destination_layout_name = argToList(getArg('destination_layout_name'))
    destination_tab_name = getArg('destination_tab_name')

    layouts = LayoutCollection()
    layouts.import_layouts()
    return_results(layouts.copy_tab(source_layout=source_layout_name,
                                    source_tab=source_tab_name,
                                    destination_layouts=destination_layout_name,
                                    destination_tab_name=destination_tab_name))


main()
