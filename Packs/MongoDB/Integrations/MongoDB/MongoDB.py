from CommonServerPython import *

from json import JSONDecodeError
from typing import Any

from bson.objectid import ObjectId
from pymongo import UpdateMany, UpdateOne
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import OperationFailure
from pymongo.results import InsertManyResult, UpdateResult, DeleteResult, BulkWriteResult
from pymongo.cursor import Cursor

CONTEXT_KEY = 'MongoDB.Entry(val._id === obj._id && obj.collection === val.collection)'
SORT_TYPE_DICT = {'asc': 1,
                  'desc': -1}


class Client:
    def __init__(
            self,
            urls: list[str],
            username: str,
            password: str,
            database: str,
            ssl: bool = False,
            insecure: bool = False,
            timeout: int = 5000
    ):
        if insecure and not ssl:
            raise DemistoException(
                '"Trust any certificate (not secure)" must be ticked with "Use TLS/SSL secured connection"')
        if not insecure and not ssl:
            self._client = MongoClient(  # type: ignore[var-annotated]
                urls, username=username, password=password, ssl=ssl, socketTimeoutMS=timeout, authMechanism='SCRAM-SHA-256'
            )
        else:
            self._client = MongoClient(
                urls, username=username, password=password, ssl=ssl, tlsAllowInvalidCertificates=insecure,
                socketTimeoutMS=timeout, authMechanism='SCRAM-SHA-256'
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

    def get_entry_by_id(self, collection: str, alert_ids: list[str]) -> list[dict]:
        collection_obj = self.get_collection(collection)
        entries: list[dict] = []
        for alert_id in alert_ids:
            results = collection_obj.find({'_id': ObjectId(alert_id)})
            entries.extend([self.normalize_id(entry) for entry in results])
        entries = self.datetime_to_str(entries)
        return entries

    def query(self, collection: str, query: dict, limit: int = 50, sort_str: str = '', fields: str | None = None) \
            -> Cursor[Any]:
        collection_obj = self.get_collection(collection)
        if fields:
            entries = collection_obj.find(query, {field: 1 for field in argToList(fields)}).limit(limit)
        else:
            entries = collection_obj.find(query).limit(limit)
        if sort_str:
            entries = entries.sort(format_sort(sort_str))
        entries = self.datetime_to_str(entries)
        entries = [self.normalize_id(entry) for entry in entries]  # type: ignore[assignment]
        return entries

    @staticmethod
    def normalize_id(entry: dict):
        """ Convert ObjectID to str in given dict

        Args:
            entry:

        Returns:
            object with `_id` key as str.

        Examples:
            >>> Client.normalize_id({'_id': ObjectId('5e4412f230c5b8f63a7356ba')})
            {'_id': '5e4412f230c5b8f63a7356ba'}
        """
        entry['_id'] = str(entry.pop('_id'))
        return entry

    @classmethod
    def datetime_to_str(cls, obj: Any) -> Any:
        """ Converts any object with date value of type datetime to str

        Args:
            obj: The object contains possible date values.

        Returns:
            All Dates from type datetime converted to str in this format - %Y-%m-%dT%H:%M:%S.000Z

        Examples:
            >>> Client.datetime_to_str(datetime.strptime('2020-05-19T09:05:28.000Z', '%Y-%m-%dT%H:%M:%S.000Z'))
            '2020-05-19T09:05:28.000Z'
            >>> Client.datetime_to_str([datetime.strptime('2020-05-19T09:05:28.000Z', '%Y-%m-%dT%H:%M:%S.000Z')])
            ['2020-05-19T09:05:28.000Z']
            >>> Client.datetime_to_str({'date': datetime.strptime('2020-05-19T09:05:28.000Z', '%Y-%m-%dT%H:%M:%S.000Z')})
            {'date': '2020-05-19T09:05:28.000Z'}
        """
        if isinstance(obj, Cursor):
            return cls.datetime_to_str(list(obj))
        if isinstance(obj, list):
            return [cls.datetime_to_str(item) for item in obj]
        if isinstance(obj, dict):
            return {cls.datetime_to_str(k): cls.datetime_to_str(v) for k, v in obj.items()}
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%dT%H:%M:%S.000Z')
        else:
            return obj

    def insert_entry(self, collection: str, entries: list[dict]) -> InsertManyResult:
        collection_object = self.get_collection(collection)
        raw = collection_object.insert_many(entries)
        return self.datetime_to_str(raw)

    def update_entry(self, collection, filter, update, update_one, upsert) -> UpdateResult:
        collection_object = self.get_collection(collection)
        if update_one:
            raw = collection_object.update_one(filter, update, upsert)
        else:
            raw = collection_object.update_many(filter, update, upsert)
        return self.datetime_to_str(raw)

    def delete_entry(self, collection, filter, delete_one) -> DeleteResult:
        collection_object = self.get_collection(collection)
        if delete_one:
            raw = collection_object.delete_one(filter)
        else:
            raw = collection_object.delete_many(filter)
        return self.datetime_to_str(raw)

    def create_collection(self, collection) -> Collection:
        raw = self.db.create_collection(collection)
        return self.datetime_to_str(raw)

    def drop_collection(self, collection):
        return self.db.drop_collection(collection)

    def pipeline_query(self, collection: str, pipeline: Dict[Any, Any] | list[Any]) -> list[dict]:
        collection_obj = self.get_collection(collection)  # type: ignore[arg-type]
        entries = collection_obj.aggregate(pipeline=pipeline)  # type: ignore[arg-type]
        entries = self.datetime_to_str(entries)
        entries = [self.normalize_id(entry) for entry in entries]
        return entries

    def bulk_update_entries(self, collection, filter_update_zip, update_one, upsert) -> BulkWriteResult:
        """Bulk updates entries in a collection (Send a batch of write operations to the server).

        Args:
            collection (str): name of the collection.
            filter_update_zip (zip): a zip object of (filter,update) pairs of queries.
            update_one (boolean): whether to update one or many entries per query.
            upsert (boolean): whether to insert a new entry if no match is found per query.
        Returns:
            BulkWriteResult: An object wrapper for bulk API write results
        """
        collection_object = self.get_collection(collection)
        requests = []
        for filter, update in filter_update_zip:
            if update_one:
                requests.append(UpdateOne(filter, update, upsert))
            else:
                requests.append(UpdateMany(filter, update, upsert))  # type: ignore[arg-type]
        raw = collection_object.bulk_write(requests)
        return self.datetime_to_str(raw)


def convert_id_to_object_id(entries: list[dict] | dict) -> list[dict] | dict:
    """ Converts list or dict with `_id` key of type str to ObjectID

    Args:
        entries: The object contains list or dict with possible `_id` key.

    Returns:
        All '_id` key converted to ObjectID

    Examples:
        >>> convert_id_to_object_id([{'_id': '5e4412f230c5b8f63a7356ba'}])
        [{'_id': ObjectId('5e4412f230c5b8f63a7356ba')}]

        >>> convert_id_to_object_id({'_id': '5e4412f230c5b8f63a7356ba'})
        {'_id': ObjectId('5e4412f230c5b8f63a7356ba')}
    """

    def _convert(entry: dict):
        if '_id' in entry:
            id_data = entry['_id']
            if isinstance(id_data, str):
                entry['_id'] = ObjectId(id_data)
            if isinstance(id_data, dict):
                entry['_id'] = {key: ObjectId(id_data[key]) for key in id_data}

        return entry

    if isinstance(entries, list):
        return [_convert(entry) for entry in entries]
    return _convert(entries)


def convert_str_to_datetime(entries: Any) -> Any:
    """ Recursively searches for a string that fit a date format and converts it to string.

    Args:
        entries: An object that may contain a timestamp string with possible dates value.

    Returns:
        Same object with converted string date formats to datetime object.
    """
    # regex for finding timestamp in string
    regex_for_timestamp = re.compile(r'\d{4}-[01]\d-[0-3]\dT[0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?Z?')
    time_format = '%Y-%m-%dT%H:%M:%S.000Z'
    if isinstance(entries, str):
        matches = regex_for_timestamp.findall(entries)
        if len(matches) == 1:
            try:
                return datetime.strptime(matches[0], time_format)
            except ValueError:
                # If could not parse the date, it may not a date. Return entries
                return entries
        # If no match or more than 1, return itself
        return entries
    if isinstance(entries, dict):
        return {key: convert_str_to_datetime(value) for key, value in entries.items()}
    if isinstance(entries, list):
        return [convert_str_to_datetime(entry) for entry in entries]
    if isinstance(entries, Cursor):
        return convert_str_to_datetime(list(entries))
    return entries


def convert_object_id_to_str(entries: list[ObjectId]) -> list[str]:
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


def handle_bulk_update_string_query_arguments(
        argument: tuple[str, str],
        filter_valid_input_example: str, update_valid_input_example: str) -> list[dict]:
    """Handles the case where the filter or update arguments are strings when using mongodb-bulk-update command.
        (the other case is a list of dictionaries from context)

    Args:
        argument (Tuple[str, str]): a tuple containing the argument name and value.
        filter_valid_input_example (str): a string representing a valid filter argument.
        update_valid_input_example (str): a string representing a valid update argument.

    Raises:
        DemistoException: if the filter or update argument is not a json array.

    Returns:
        List[dict]: a list of dictionaries representing the parsed and validated filter or update argument.
    """
    argument_name, argument_value = argument
    if not argument_value.startswith('[') or not argument_value.endswith(']'):
        brackets_syntax_error_msg = 'The {} argument must be a json array. Valid input example: {}'
        raise DemistoException(
            brackets_syntax_error_msg.format(
                f'`{argument_name}`', filter_valid_input_example
                if argument_name == 'filter' else update_valid_input_example))
    return argToList(argument_value)


def parse_and_validate_bulk_update_arguments(filter: str | list, update: str | list) -> tuple[list, list]:
    """Parses and validates the bulk update queries (filter and update command arguments).

    Args:
        filter (str | list): raw string representing the filter command argument or a list object (from context).
        update (str | list): raw string representing the update command argument or a list object (from context).

    Raises:
        DemistoException: if filter or update command arguments have invalid syntax.
        DemistoException: if filter and update command arguments do not contain the same number of elements.
        DemistoException: if the filter command argument contains an invalid json.
        DemistoException: if the update command argument contains an invalid json.

    Returns:
        Tuple[List, List]: lists of dictionaries representing the parsed and validated filter and update arguments.
    """
    filter_valid_input_example = '`[{"key1": "value1"},{"key2": "value2"}]`'
    update_valid_input_example = '`[{"$set": {"key1": "value1"}},{"$set": {"key2": "value2"}}]`'
    json_validation_error_msg = 'The {} argument contains an invalid json. Valid input example: {}'

    filters = handle_bulk_update_string_query_arguments(
        ('filter', filter),
        filter_valid_input_example, update_valid_input_example) if isinstance(filter, str) else filter
    updates = handle_bulk_update_string_query_arguments(
        ('update', update),
        filter_valid_input_example, update_valid_input_example) if isinstance(update, str) else update

    if len(filters) != len(updates):
        raise DemistoException('The `filter` and `update` arguments must contain the same number of elements.')

    try:
        filter_list = [validate_json_objects(filter) for filter in filters]
    except JSONDecodeError as e:
        raise DemistoException(json_validation_error_msg.format('`filter`', filter_valid_input_example)) from e
    try:
        update_list = [validate_json_objects(update) for update in updates]
    except JSONDecodeError as e:
        raise DemistoException(json_validation_error_msg.format('`update`', update_valid_input_example)) from e

    return filter_list, update_list


def test_module(client: Client, **kwargs) -> tuple[str, dict]:
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
) -> tuple[str, dict, list]:
    raw_response = client.get_entry_by_id(collection, argToList(object_id))
    if raw_response:
        readable_outputs = tableToMarkdown(
            f'Total of {len(raw_response)} found in MongoDB collection `{collection}`:',
            raw_response,
        )
        entries = []
        for item in raw_response:
            item['collection'] = collection
            entries.append(item)
        outputs = {
            CONTEXT_KEY: entries
        }
        return readable_outputs, outputs, raw_response
    else:
        return 'MongoDB: No results found', {}, raw_response


def search_query(client: Client, collection: str, query: str, limit: str, sort: str = '', fields: str = None,
                 **kwargs) \
        -> tuple[str, dict, Cursor[Any]]:
    # test if query is a valid json
    try:
        query_json = validate_json_objects(json.loads(query))
        raw_response = client.query(collection, query_json, int(limit), sort, fields)  # type: ignore[arg-type]
    except JSONDecodeError:
        raise DemistoException('The `query` argument is not a valid json.')
    if raw_response:
        readable_outputs = tableToMarkdown(
            f'Total of {len(raw_response)} entries were found'  # type: ignore[arg-type]
            f' in MongoDB collection `{collection}` with query: {query}:',
            [entry.get('_id') for entry in raw_response],
            headers=['_id'],
        )
        outputs_objects = []
        for item in raw_response:
            item.update({'collection': collection})
            outputs_objects.append(item)
        outputs = {CONTEXT_KEY: outputs_objects}
        return readable_outputs, outputs, raw_response
    else:
        return 'MongoDB: No results found', {}, raw_response


def insert_entry_command(
        client: Client, collection: str, entry: str, **kwargs
) -> tuple[str, dict, list]:
    # test if query is a valid json
    try:
        entry_json = validate_json_objects(json.loads(entry))

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


def validate_json_objects(json_obj: dict | list) -> dict | list:
    """ Validate that all objects in the json are according to MongoDB convention.

    Args:
        json_obj: The json to send to MongoDB

    Returns:
        valid json according to MongoDB convention.
    """
    valid_mongodb_json = convert_str_to_datetime(convert_id_to_object_id(json_obj))  # type: ignore
    return valid_mongodb_json


def format_sort(sort_str: str) -> list:
    """
    Format a sort string from "field1:asc,field2:desc" to a list accepted by pymongo.sort()
    "field1:asc,field2:desc" => [("field1",1),("field2",-1)]
    Args:
        sort_str: a sort detailed as a string

    Returns:
        list accepted by pymongo.sort()
    """
    sort_fields = sort_str.split(',')
    sort_list = []
    for field in sort_fields:
        if ':' not in field:
            raise ValueError("`sort` is not in the correct format.")
        field, type = field.split(':', 1)
        if type not in SORT_TYPE_DICT.keys():
            raise ValueError("`sort` is not in the correct format. Please make sure it's either 'asc' or 'desc'")
        sort_list.append((field, SORT_TYPE_DICT[type]))
    return sort_list


def update_entry_command(
        client: Client,
        collection: str,
        filter: str | dict,
        update: str | dict,
        update_one=False,
        upsert=False,
        **kwargs,
) -> tuple[str, None]:

    filter_valid_input_example = '`{"key": "value"}`'
    update_valid_input_example = '`{"$set": {"key": "value"}`'
    invalid_json_error_msg = 'The {} argument is not a valid json. Valid input example: {}'

    try:
        json_filter = validate_json_objects(json.loads(filter)) if isinstance(filter, str) else validate_json_objects(filter)
    except JSONDecodeError:
        raise DemistoException(invalid_json_error_msg.format('`filter`', filter_valid_input_example))
    try:
        json_update = validate_json_objects(json.loads(update)) if isinstance(update, str) else validate_json_objects(update)
    except JSONDecodeError:
        raise DemistoException(invalid_json_error_msg.format('`update`', update_valid_input_example))
    response = client.update_entry(
        collection, json_filter, json_update, argToBoolean(update_one), argToBoolean(upsert)
    )
    if response and response.acknowledged:
        human_readable = "A new entry was inserted to the collection." if response.upserted_id \
            else f'MongoDB: Total of {response.modified_count} entries has been modified.'
        return (
            human_readable,
            None,
        )
    raise DemistoException('Error occurred when trying to enter update entries.')


def delete_entry_command(
        client: Client, collection, filter, delete_one, **kwargs
) -> tuple[str, None]:
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
) -> tuple[str, None]:
    if client.is_collection_in_db(collection):
        raise DemistoException(f'Collection \'{collection}\' is already exists')
    _ = client.create_collection(collection)
    return (
        f'MongoDB: Collection \'{collection}\' has been successfully created.',
        None,
    )


def list_collections_command(client: Client, **kwargs) -> tuple[str, dict, list]:
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
) -> tuple[str, None]:
    response = client.drop_collection(collection)
    if (
            hasattr(response, 'acknowledged')
            and not response.acknowledged
            or isinstance(response, dict)
            and not response.get('ok') == 1.0
    ):
        raise DemistoException('Error occurred when trying to drop collection entries.')
    return f'MongoDB: Collection \'{collection}` has been successfully dropped.', None


def pipeline_query_command(client: Client, collection: str, pipeline: str, limit: str = '50', offset: str = '0',
                           **kwargs) -> tuple[str, dict, list]:
    limit = arg_to_number(limit)
    offset = arg_to_number(offset)
    try:
        json_pipeline = validate_json_objects(json.loads(pipeline))
        raw_response = client.pipeline_query(
            collection=collection,
            pipeline=json_pipeline,
        )
    except JSONDecodeError:
        raise DemistoException('The `pipeline` argument is not a valid json.')

    if raw_response:
        raw_response = raw_response[offset:(offset + limit)]  # type: ignore
        readable_outputs = tableToMarkdown(
            f'Total of {len(raw_response)} entries were found in MongoDB collection: `{collection}` '
            f'with pipeline: {pipeline}:',
            t=[entry.get('_id') for entry in raw_response],
            headers=['_id'],
        )
        for item in raw_response:
            item.update({'collection': collection})
        outputs = {CONTEXT_KEY: raw_response}
        return readable_outputs, outputs, raw_response
    else:
        return 'MongoDB: No results found', {}, raw_response


def bulk_update_command(
        client: Client,
        collection: str,
        filter: str,
        update: str,
        update_one=True,
        upsert=False,
        **kwargs,
) -> tuple[str, None]:

    filter_list, update_list = parse_and_validate_bulk_update_arguments(filter, update)

    response = client.bulk_update_entries(
        collection, zip(filter_list, update_list), argToBoolean(update_one), argToBoolean(upsert)
    )
    if response and response.acknowledged:
        return (
            f'MongoDB: Total of {response.modified_count} entries has been modified.\
            \nMongoDB: Total of {response.upserted_count} entries has been inserted.',
            None,
        )
    raise DemistoException('Error occurred when trying to enter update entries.')


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
        'mongodb-pipeline-query': pipeline_query_command,
        'mongodb-bulk-update': bulk_update_command,
    }
    try:
        return_outputs(*commands[command](client, **args))  # type: ignore[operator]
    except Exception as e:
        return_error(f'MongoDB: {str(e)}', error=e)


if __name__ in ('builtins', '__builtin__', '__main__'):
    main()
