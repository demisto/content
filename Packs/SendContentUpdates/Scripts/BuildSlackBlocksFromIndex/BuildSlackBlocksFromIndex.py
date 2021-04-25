import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json
import os
import re
import pytz
from dateparser import parse
from tempfile import mkdtemp
from zipfile import ZipFile
from datetime import datetime
from typing import List

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
MP_LINK = "https://xsoar.pan.dev/marketplace"
MP_PACK_LINK = f"{MP_LINK}/details"
NUM_FULL_PREVIEW = 10
SUPPORT = ['xsoar', 'partner', 'community']
DESCRIPTION_MAX_LENGTH = 156
PACK_ID_REGEX = r'\s|-|\.'


class IndexPack:
    def __init__(self, path: str, pack_id: str):
        self.index_path: str = path
        self.id: str = pack_id
        self.metadata_path: str = self.get_metadata_path()
        self.metadata: dict = load_json(self.metadata_path)
        self.name: str = self.metadata.get('name')
        self.created: str = self.metadata.get('created')
        self.created_datetime: datetime = datetime.strptime(self.created, DATE_FORMAT).replace(tzinfo=pytz.UTC)
        self.price: int = self.metadata.get('price', 0)
        self._is_private_pack: bool = True if self.metadata.get('partnerId') else False
        self.support: str = self.metadata.get('support', 'xsoar')
        self.author: str = self.metadata.get('author', 'Cortex XSOAR')
        self.description: str = self.get_description()
        self.pan_dev_mp_id: str = re.sub(PACK_ID_REGEX, '', self.id)

    def get_metadata_path(self) -> str:
        metadata_path = os.path.join(self.index_path, 'metadata.json')
        if os.path.exists(metadata_path):
            return metadata_path
        else:
            demisto.error(f'metadata.json file was not found for pack: {self.id}')
            return ''

    def get_description(self) -> str:
        description = self.metadata.get('description', '')
        description_words = []
        aggregated_length = 0

        for word in description.split(' '):
            aggregated_length += len(word)
            if aggregated_length <= DESCRIPTION_MAX_LENGTH:
                description_words.append(word)
            else:
                break

        parsed_description = ' '.join(description_words)
        if len(description) > len(parsed_description):
            parsed_description += "..."

        return parsed_description

    def is_released_after_last_run(self, last_run_datetime: datetime) -> bool:
        demisto.debug(f'{self.id} pack was created at {self.created}')
        return self.created_datetime > last_run_datetime

    def to_context(self) -> dict:
        return {
            'name': self.name,
            'id': self.id,
            'is_private_pack': self._is_private_pack,
            'price': self.price,
            'support': self.support,
            'author': self.author,
            'description': self.description
        }


class Index:
    def __init__(self, index_file_entry_id: str):
        self.index_data: dict = get_file_data(index_file_entry_id)
        self.download_index_path: str = self.index_data['path']
        self.extract_destination_path: str = mkdtemp()
        self.index_folder_path: str = os.path.join(self.extract_destination_path, 'index')
        self.extract()
        self.packs: List[IndexPack] = self.get_packs()
        self.new_packs: List[IndexPack] = []

    def extract(self):
        if os.path.exists(self.download_index_path):
            demisto.debug('Found existing index.zip')
            with ZipFile(self.download_index_path, 'r') as index_zip:
                index_zip.extractall(self.extract_destination_path)
            demisto.debug(f'Extracted index.zip successfully to {self.index_folder_path}')
        else:
            error_msg = f'File was not found at path {self.download_index_path}'
            demisto.error(error_msg)
            raise Exception(error_msg)

        if not os.path.exists(self.index_folder_path):
            error_msg = 'Failed creating index folder with extracted data.'
            demisto.error(error_msg)
            raise Exception(error_msg)

    def get_packs(self) -> List[IndexPack]:
        packs = []

        for file in os.scandir(self.index_folder_path):
            if os.path.isdir(file):
                pack = IndexPack(file.path, file.name)
                packs.append(pack)

        return packs

    def get_new_packs_from_last_run(self, last_run_str: str) -> List[IndexPack]:
        last_run_datetime = parse(last_run_str).replace(tzinfo=pytz.UTC)
        demisto.debug(f'last message time was: {last_run_str}')

        for pack in self.packs:
            if pack.is_released_after_last_run(last_run_datetime):
                self.new_packs.append(pack)
                demisto.debug(f'{pack.name} pack is a new pack')

        return self.new_packs

    def get_latest_new_pack_created_time(self) -> str:
        latest_new_pack_created_datetime = datetime(1970, 1, 1, tzinfo=pytz.utc)
        for new_pack in self.new_packs:
            if new_pack.created_datetime > latest_new_pack_created_datetime:
                latest_new_pack_created_datetime = new_pack.created_datetime

        return latest_new_pack_created_datetime.strftime(DATE_FORMAT)


class SlackBlocks:
    def __init__(self, packs: List[IndexPack]):
        self.packs: List[IndexPack] = sorted(
            packs, key=lambda p: SUPPORT.index(p.support) if p.support in SUPPORT else 3
        )
        self._preview_packs: List[IndexPack] = self.packs[:NUM_FULL_PREVIEW]
        self._list_packs: List[IndexPack] = self.packs[NUM_FULL_PREVIEW:]

    def build(self) -> str:
        if self.packs:
            blocks = [self.build_header_block()]

            for pack in self._preview_packs:
                blocks.append(self.get_divider_block())
                blocks.append(
                    self.build_pack_section_block(pack.name, pack.pan_dev_mp_id, pack.author, pack.description)
                )
                blocks.append(self.build_pack_context_block(pack.price, pack.support))

            if self._list_packs:
                blocks.append(self.get_divider_block())
                blocks.append(self.build_list_packs_block())

            blocks.append(self.get_divider_block())
            blocks.append(self.get_bottom_block())

            return json.dumps(blocks)

        return "no new packs"

    @staticmethod
    def get_divider_block() -> dict:
        return {
            "type": "divider"
        }

    def build_header_block(self) -> dict:
        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"We have released *{len(self.packs)} New Packs* this week! :dbot-new:"
            }
        }

    @staticmethod
    def build_pack_section_block(pack_name: str, pan_dev_mp_id: str, pack_author: str, pack_description: str) -> dict:
        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*<{MP_PACK_LINK}/{pan_dev_mp_id}|{pack_name}>*\nBy: {pack_author}\n\n{pack_description}"
            }
        }

    @staticmethod
    def build_pack_context_block(price: int, support: str) -> dict:
        if support == "xsoar":
            support_text = ":cortexpeelable: XSOAR Supported"
        elif support == "partner":
            support_text = "Partner Supported"
        else:
            support_text = "Community Contributed"

        return {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": "FREE" if str(price) == "0" else f"{price} :cortex-coins:"
                },
                {
                    "type": "mrkdwn",
                    "text": support_text
                }
            ]
        }

    def build_list_packs_block(self) -> dict:
        text = "*More packs that have been released this week:*\n"
        for pack in self._list_packs:
            text += f"*<{MP_PACK_LINK}/{pack.pan_dev_mp_id}|{pack.name}>*\n"

        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": text
            }
        }

    @staticmethod
    def get_bottom_block() -> dict:
        return {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"See all of Palo Alto Networks XSOAR packs on our *<{MP_LINK}|Marketplace Site>*!"
            }
        }


def load_json(file_path: str) -> dict:
    try:
        if file_path and os.path.exists(file_path):
            with open(file_path, 'r') as json_file:
                result = json.load(json_file)
        else:
            result = {}
        return result
    except json.decoder.JSONDecodeError:
        return {}


def get_file_data(file_entry_id: str) -> dict:
    res = demisto.executeCommand('getFilePath', {'id': file_entry_id})

    if res[0]['Type'] == entryTypes['error']:
        raise Exception(f'Failed getting the file path for entry {file_entry_id}')

    return res[0]['Contents']


def return_results_to_context(new_packs, last_run, blocks, updated_last_run):
    return_results([
        CommandResults(
            outputs=new_packs,
            outputs_prefix='Pack',
            readable_output=tableToMarkdown(
                name=f'New Released Packs from {last_run}',
                t=new_packs,
                headers=['name', 'id', 'author', 'description', 'price', 'support']
            )
        ),
        CommandResults(
            outputs=updated_last_run,
            outputs_prefix='LastRun',
            readable_output=tableToMarkdown(
                name='Last Run',
                t=updated_last_run,
                headers=['LastRun']
            )
        ),
        CommandResults(
            outputs=blocks,
            outputs_prefix='Blocks',
            readable_output=tableToMarkdown(
                name="Slack blocks json",
                t=blocks,
                headers=['Blocks']
            )
        )
    ])


def main():
    try:
        args: dict = demisto.args()
        index_file_entry_id: str = args['entry_id']
        last_run: str = args['last_run_str']
        index: Index = Index(index_file_entry_id)
        new_packs: List[IndexPack] = index.get_new_packs_from_last_run(last_run)
        updated_last_run: str = index.get_latest_new_pack_created_time()
        blocks: str = SlackBlocks(new_packs).build()
        demisto.debug(blocks)
        return_results_to_context([new_pack.to_context() for new_pack in new_packs], last_run, blocks, updated_last_run)

    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute.\nError:\n{str(e)}')


if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
