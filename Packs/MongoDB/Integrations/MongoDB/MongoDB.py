from CommonServerPython import *

from json import JSONDecodeError
from typing import List, Union, Tuple

from bson.objectid import ObjectId
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import OperationFailure
from pymongo.results import InsertManyResult, UpdateResult, DeleteResult

CONTEXT_KEY = 'MongoDB.Entry(val._id === obj._id && obj.collection === val.collection)'


class Client:
    def __init__(
        self,
        urls: List[str],
        username: str,
        password: str,
        database: str,
        ssl: bool = False,
        insecure: bool = False,
        timeout: int = 5000
    ):
        if insecure and not ssl:
            raise DemistoException(f'"Trust any certificate (not secure)" must be ticked with "Use TLS/SSL secured connection"')
        if not insecure and not ssl:
            self._client = MongoClient(
                urls, username=username, password=password, ssl=ssl, socketTimeoutMS=timeout
            )
        else:
            self._client = MongoClient(
                urls, username=username, password=password, ssl=ssl, tlsAllowInvalidCertificates=insecure,
                socketTimeoutMS=timeout
            )
        self.db: Database = self._client.get_database(database)

    def is_collection_in_db(self, collection: str) -> bool:
        return collection in self.db.list_collection_names()

    def get_collection(self, collection: str) -> Collection:
        if self.is_collection_in_db(collection):
            return self.db.get_collection(collection)
        raise DemistoException(
            f'Collection \'{collection}\' has not found in database \'{self.db.name}\''
        )

    def get_entry_by_id(self, collection: str, alert_ids: List[str]) -> List[dict]:
        collection_obj = self.get_collection(collection)
        entries: List[dict] = list()
        for alert_id in alert_ids:
            results = collection_obj.find({'_id': ObjectId(alert_id)})
            entries.extend([self.normalize_id(entry) for entry in results])
        return entries

    def query(self, collection: str, query: dict, limit: int = 50) -> List[dict]:
        collection_obj = self.get_collection(collection)
        entries = collection_obj.find(query).limit(limit)
        return [self.normalize_id(entry) for entry in entries]

    @staticmethod
    def normalize_id(entry: dict):
        ''' Convert ObjectID to str in given dict

        Args:
            entry:

        Returns:
            object with `_id` key as str.

        Examples:
            >>> Client.normalize_id({'_id': ObjectId('5e4412f230c5b8f63a7356ba')})
            {'_id': '5e4412f230c5b8f63a7356ba'}
        '''
        entry['_id'] = str(entry.pop('_id'))
        return entry

    def insert_entry(self, collection: str, entries: List[dict]) -> InsertManyResult:
        collection_object = self.get_collection(collection)
        return collection_object.insert_many(entries)

    def update_entry(self, collection, filter, update, update_one) -> UpdateResult:
        collection_object = self.get_collection(collection)
        if update_one:
            return collection_object.update_one(filter, update)
        return collection_object.update_many(filter, update)

    def delete_entry(self, collection, filter, delete_one) -> DeleteResult:
        collection_object = self.get_collection(collection)
        if delete_one:
            return collection_object.delete_one(filter)
        return collection_object.delete_many(filter)

    def create_collection(self, collection) -> Collection:
        return self.db.create_collection(collection)

    def drop_collection(self, collection):
        return self.db.drop_collection(collection)


def convert_id_to_object_id(
    entries: Union[List[dict], dict]
) -> Union[List[dict], dict]:
    ''' Converts list or dict with `_id` key of type str to ObjectID

    Args:
        entries: The object contains list or dict with possible `_id` key.

    Returns:
        All '_id` key converted to ObjectID

    Examples:
        >>> convert_id_to_object_id([{'_id': '5e4412f230c5b8f63a7356ba'}])
        [{'_id': ObjectId('5e4412f230c5b8f63a7356ba')}]

        >>> convert_id_to_object_id({'_id': '5e4412f230c5b8f63a7356ba'})
        {'_id': ObjectId('5e4412f230c5b8f63a7356ba')}
    '''

    def _convert(entry: dict):
        if '_id' in entry:
            entry['_id'] = ObjectId(entry['_id'])
        return entry

    if isinstance(entries, list):
        return [_convert(entry) for entry in entries]
    return _convert(entries)


def convert_object_id_to_str(entries: List[ObjectId]) -> List[str]:
    ''' Converts list of ObjectID to list of str.

    Args:
        entries: list of ObjectIDs

    Returns:
        List of strs representing the ObjectID

    Examples:
        >>> convert_object_id_to_str([ObjectId('5e4412f230c5b8f63a7356ba')])
        ['5e4412f230c5b8f63a7356ba']  # guardrails-disable-line
    '''
    return list(map(str, entries))


def test_module(client: Client, **kwargs) -> Tuple[str, dict]:
    # Using kwargs so vulture will let it go
    kwargs.get("")
    try:
        _ = client.db.list_collection_names()
    except OperationFailure as e:
        raise DemistoException(str(e))
    # To the unpack in the return.
    return 'ok', {}


def get_entry_by_id_command(
    client: Client, collection: str, object_id: str, **kwargs
) -> Tuple[str, dict, list]:
    raw_response = client.get_entry_by_id(collection, argToList(object_id))
    if raw_response:
        readable_outputs = tableToMarkdown(
            f'Total of {len(raw_response)} found in MongoDB collection `{collection}`:',
            raw_response,
        )
        entries = list()
        for item in raw_response:
            item['collection'] = collection
            entries.append(item)
        outputs = {
            CONTEXT_KEY: entries
        }
        return readable_outputs, outputs, raw_response
    else:
        return 'MongoDB: No results found', {}, raw_response


def search_query(
    client: Client, collection: str, query: str, limit: str, **kwargs
) -> Tuple[str, dict, list]:
    # test if query is a valid json
    try:
        query_json = json.loads(query)
        raw_response = client.query(collection, query_json, int(limit))
    except JSONDecodeError:
        raise DemistoException('The `query` argument is not a valid json.')
    if raw_response:
        readable_outputs = tableToMarkdown(
            f'Total of {len(raw_response)} entries were found in MongoDB collection `{collection}` with query: {query}:',
            [entry.get('_id') for entry in raw_response],
            headers=['_id'],
        )
        outputs_objects = list()
        for item in raw_response:
            item.update({'collection': collection})
            outputs_objects.append(item)
        outputs = {CONTEXT_KEY: outputs_objects}
        return readable_outputs, outputs, raw_response
    else:
        return 'MongoDB: No results found', {}, raw_response


def insert_entry_command(
    client: Client, collection: str, entry: str, **kwargs
) -> Tuple[str, dict, list]:
    # test if query is a valid json
    try:
        entry_json = json.loads(entry)
        if not isinstance(entry_json, list):
            entry_json = [entry_json]
        entries = convert_id_to_object_id(entry_json)
        results = client.insert_entry(collection, entries)  # type: ignore[arg-type]
        if not results.acknowledged:
            raise Exception('Error occurred when trying to enter insert entries.')
        else:
            object_ids = convert_object_id_to_str(results.inserted_ids)
            human_readable = tableToMarkdown(
                f'MongoDB: Successfully entered {len(object_ids)} entry to the \'{collection}\' collection.',
                object_ids,
                headers=['_id'],
            )
            outputs = {
                CONTEXT_KEY: [
                    {'_id': _id, 'collection': collection} for _id in object_ids
                ]
            }
            return human_readable, outputs, object_ids
    except JSONDecodeError:
        raise DemistoException('The `entry` argument is not a valid json.')


def update_entry_command(
    client: Client,
    collection: str,
    filter: str,
    update: str,
    update_one=False,
    **kwargs,
) -> Tuple[str, None]:
    try:
        json_filter = json.loads(filter)
        json_filter = convert_id_to_object_id(json_filter)
    except JSONDecodeError:
        raise DemistoException('The `filter` argument is not a valid json.')
    try:
        json_update = json.loads(update)
    except JSONDecodeError:
        raise DemistoException('The `update` argument is not a valid json.')
    response = client.update_entry(
        collection, json_filter, json_update, argToBoolean(update_one)
    )
    if not response.acknowledged:
        raise DemistoException('Error occurred when trying to enter update entries.')
    return (
        f'MongoDB: Total of {response.modified_count} entries has been modified.',
        None,
    )


def delete_entry_command(
    client: Client, collection, filter, delete_one, **kwargs
) -> Tuple[str, None]:
    try:
        json_filter = json.loads(filter)
        json_filter = convert_id_to_object_id(json_filter)
    except JSONDecodeError:
        raise DemistoException('The `filter` argument is not a valid json.')
    results = client.delete_entry(collection, json_filter, argToBoolean(delete_one))
    if not results.acknowledged:
        raise DemistoException('Error occurred when trying to enter delete entries.')
    return f'MongoDB: Successfully deleted {results.deleted_count} entries.', None


def create_collection_command(
    client: Client, collection: str, **kwargs
) -> Tuple[str, None]:
    if client.is_collection_in_db(collection):
        raise DemistoException(f'Collection \'{collection}\' is already exists')
    _ = client.create_collection(collection)
    return (
        f'MongoDB: Collection \'{collection}\' has been successfully created.',
        None,
    )


def list_collections_command(client: Client, **kwargs) -> Tuple[str, dict, list]:
    raw_response = client.db.list_collection_names()
    if raw_response:
        readable_outputs = tableToMarkdown(
            'MongoDB: All collections in database', raw_response, headers=['Collection']
        )
        outputs = {
            'MongoDB.Collection(val.Name === obj.Name)': [
                {'Name': collection} for collection in raw_response
            ]
        }
        return readable_outputs, outputs, raw_response
    else:
        return 'MongoDB: No results found', {}, raw_response


def drop_collection_command(
    client: Client, collection: str, **kwargs
) -> Tuple[str, None]:
    response = client.drop_collection(collection)
    if (
        hasattr(response, 'acknowledged')
        and not response.acknowledged
        or isinstance(response, dict)
        and not response.get('ok') == 1.0
    ):
        raise DemistoException('Error occurred when trying to drop collection entries.')
    return f'MongoDB: Collection \'{collection}` has been successfully dropped.', None


def main():
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    client = Client(
        argToList(params.get('urls')),
        params.get('credentials', {}).get('identifier'),
        params.get('credentials', {}).get('password'),
        params['database'],
        bool(params.get('use_ssl', False)),
        bool(params.get('insecure', False))
    )
    commands = {
        'test-module': test_module,
        'mongodb-get-entry-by-id': get_entry_by_id_command,
        'mongodb-query': search_query,
        'mongodb-insert': insert_entry_command,
        'mongodb-update': update_entry_command,
        'mongodb-delete': delete_entry_command,
        'mongodb-list-collections': list_collections_command,
        'mongodb-create-collection': create_collection_command,
        'mongodb-drop-collection': drop_collection_command,
    }
    try:
        return_outputs(*commands[command](client, **args))  # type: ignore[operator]
    except Exception as e:
        return_error(f'MongoDB: {str(e)}', error=e)


if __name__ in ('builtins', '__builtin__'):
    main()
