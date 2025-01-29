import demistomock as demisto
import XQLDSHelper
import pytest
import re
import sys
import json
import tarfile
import datetime
import fnmatch
import functools
import itertools
import freezegun
import os.path
import urllib.parse
from collections.abc import Iterator
from typing import Any
from types import TracebackType
from typing import Self
from pytest_mock import MockerFixture


def to_list(
    val: Any
) -> list:
    return val if isinstance(val, list) else [val]


def to_bool(
    val: Any
) -> bool:
    if isinstance(val, bool):
        return val
    elif isinstance(val, str):
        return val.lower() == 'true'
    else:
        return bool(val)


class ExpectedException(Exception):
    def __init__(
        self,
        message: str = ''
    ) -> None:
        self.__message = message


class MainTester:
    def __init__(
        self,
        mocker: MockerFixture,
        ent: dict[str, Any],
    ) -> None:
        self.__config = ent
        if now := demisto.get(ent, 'config.now'):
            now = datetime.datetime.fromisoformat(now)
            if not now.tzinfo:
                raise ValueError('config.now must be in ISO 8601 format, including the timezone.')

        self.__frozen_now = now
        self.__freezer_now = None

        self.__xql_responses = demisto.get(ent, 'xql.responses')
        self.__xql_last_resp = None
        self.__xql_resp_iter = None

        incident = {
            'id': '1'
        }
        if is_xsiam := to_bool(
            demisto.get(ent, 'config.is_xsiam', 'false')
        ):
            incident.update(ent.get('alert') or {})
        else:
            incident.update(ent.get('incident') or {})

        mocker.patch.object(
            XQLDSHelper,
            'is_xsiam',
            return_value=is_xsiam
        )
        mocker.patch.object(
            demisto,
            'incident',
            return_value=incident
        )
        mocker.patch.object(
            demisto,
            'args',
            return_value=ent.get('args') or {}
        )
        mocker.patch.object(
            demisto,
            'executeCommand',
            side_effect=self.__demisto_execute_command
        )
        mocker.patch.object(
            XQLDSHelper,
            'execute_command',
            side_effect=self.__execute_command
        )
        mocker.patch.object(
            XQLDSHelper,
            'return_error',
            side_effect=self.__return_error
        )
        mocker.patch.object(
            demisto,
            'dt',
            side_effect=self.__demisto_dt
        )
        mocker.patch.object(
            demisto,
            'context',
            return_value=ent.get('context') or {}
        )
        mocker.patch.object(
            demisto,
            'results'
        )

    def __enter__(
        self,
    ) -> Self:
        if self.__frozen_now:
            self.__freezer_now = freezegun.freeze_time(self.__frozen_now)
            self.__freezer_now.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if self.__freezer_now:
            self.__freezer_now.stop()
            self.__freezer_now = None

    @staticmethod
    def compare_obj(
        obj1: Any,
        obj2: Any,
        skip_keys: list[str] | None,
    ) -> int:
        if n := (str(type(obj1)) > str(type(obj2))) - (str(type(obj1)) < str(type(obj2))):
            return n
        elif isinstance(obj1, dict):
            keys1 = sorted(str(k) for k in obj1 if not skip_keys or k not in skip_keys)
            keys2 = sorted(str(k) for k in obj2 if not skip_keys or k not in skip_keys)
            if n := len(keys1) - len(keys2):
                return n
            elif n := next(((x > y) - (x < y) for x, y in zip(keys1, keys2)), None):
                return n
            else:
                return next(
                    filter(
                        None,
                        (
                            MainTester.compare_obj(
                                obj1[k],
                                obj2[k],
                                skip_keys=skip_keys,
                            ) for k in keys1
                        )
                    ),
                    0,
                )
        elif isinstance(obj1, list):
            # Compare lists (ignore order)
            return next(
                filter(
                    None,
                    (
                        MainTester.compare_obj(
                            v1,
                            v2,
                            skip_keys=skip_keys,
                        ) for v1, v2 in itertools.zip_longest(
                            sorted(
                                obj1,
                                key=functools.cmp_to_key(
                                    functools.partial(
                                        MainTester.compare_obj,
                                        skip_keys=skip_keys
                                    )
                                )
                            ),
                            sorted(
                                obj2,
                                key=functools.cmp_to_key(
                                    functools.partial(
                                        MainTester.compare_obj,
                                        skip_keys=skip_keys
                                    )
                                )
                            )
                        )
                    )
                ),
                0,
            )
        elif obj1 is None or obj2 is None:
            return bool(obj2 is None) - bool(obj1 is None)
        else:
            return (obj1 > obj2) - (obj1 < obj2)

    @staticmethod
    def equals_entry(
        obj1: Any,
        obj2: Any,
        skip_keys: list[str] | None,
    ) -> bool:
        return MainTester.compare_obj(obj1, obj2, skip_keys=skip_keys) == 0

    @staticmethod
    def __get_list_from_content_bundle(
        bundle_file: str,
        list_name: str,
    ) -> Any:
        with tarfile.open(bundle_file, 'r') as t:
            file_name = f'list-{list_name}.json'
            file_path = next(
                (x for x in t.getnames() if os.path.basename(x) == file_name),
                None
            )
            if not file_path:
                return None

            f = t.extractfile(file_path)
            if not f:
                raise RuntimeError(f'No file - {file_path}')

            list_data = json.loads(f.read())
            return list_data.get('data')

    def __next_query_response(
        self,
    ) -> Any:
        if self.__xql_responses is None:
            raise RuntimeError(
                "xql.response is not configured."
                " This test case may have been expected to hit the cache, but it didn't."
            )

        if self.__xql_resp_iter is None:
            self.__xql_resp_iter = iter(to_list(self.__xql_responses))

        conf = next(self.__xql_resp_iter)
        if isinstance(conf, str):
            conf = {
                'type': 'file',
                'path': conf
            }

        ec_key = (
            'PaloAltoNetworksXQL.GenericQuery'
            '(val.execution_id && val.execution_id == obj.execution_id)'
        )
        if isinstance(conf, dict):
            _type = conf.get('type')
            if _type == 'file':
                with open(conf.get('path')) as f:
                    resp = json.loads(f.read())

                self.__xql_last_resp = {
                    'Type': 1,  # EntryType.NOTE
                    'Contents': {},
                    'EntryContext': {
                        ec_key: resp
                    }
                }
            elif _type == 'data':
                self.__xql_last_resp = {
                    'Type': 1,  # EntryType.NOTE
                    'Contents': {},
                    'EntryContext': {
                        ec_key: conf.get('data')
                    }
                }
            elif _type == 'error':
                self.__xql_last_resp = {
                    'Type': 4,  # EntryType.ERROR
                    'Contents': conf.get('message')
                }
            else:
                raise ValueError(f'Invalid XQL response config - {conf}')
        else:
            raise ValueError(f'Invalid XQL response config - {conf}')

        return self.__xql_last_resp

    def __get_query_results(
        self,
    ) -> list:
        if not self.__xql_last_resp:
            return []

        ec = self.__xql_last_resp.get('EntryContext') or {}
        for k, v in ec.items():
            k, _, _ = k.partition('(')
            if k == 'PaloAltoNetworksXQL.GenericQuery' and isinstance(v, dict):
                return v['results']
        raise RuntimeError(f'Unable to get query results - {self.__xql_last_resp}')

    def __demisto_dt(
        self,
        obj: dict[str, Any],
        dt: str,
    ) -> Any:
        path, _, func = dt.partition('=')
        val = obj if path == '.' else demisto.get(obj, path)

        if not func:
            return val

        if path == 'recordset':
            recordset = self.__get_query_results()

            if m := re.fullmatch(r'>val.length \? val\[0\].([^)]+) : 0', func):
                return recordset[0].get(m[1]) if recordset else 0

            var = '>val[0].text'
            if var == func:
                return recordset[0].get('text')

            var = r'>val.map((record) => " - " + record.text).join("\n")'
            if var == func:
                return '\n'.join(
                    ' - ' + x.get('text') for x in recordset
                )

            var = (
                r'''>(()=>{letitems=[];for(leti=0;i<val.length;++i)'''
                r'''{items.push(`-${i+1}:${val[i].text}`);}returnitems.join("\n");})()'''
            )
            if var == ''.join(func.strip().split()):
                return '\n'.join(
                    f' - {x[0]+1}: ' + x[1].get('text') for x in enumerate(recordset)
                )

        var = r"""encodeURIComponent(val).replace('"', '%22')"""
        if var == func:
            return urllib.parse.quote(val).replace('\"', '%22')

        if m := re.search(r"decodeURIComponent\('([^']+)'\)", func):
            return urllib.parse.unquote(m[1])

        var = '>val ? val[0] : "255.255.255.255"'
        if var == func:
            return val[0] if val else '255.255.255.255'

        var = 'val.sourceip && val.destip'
        if var == func:
            return val.get('sourceip') and val.get('destip')

        if m := re.fullmatch(r'^val\.(\w+)$', func):
            return val.get(m[1])

        if func:
            raise RuntimeError(f'Not implemented - {dt}')
            sys.exit(1)

        return val

    def __demisto_execute_command(
        self,
        command: str,
        args: dict[str, Any],
    ) -> list[Any]:
        if command in ('xdr-xql-generic-query', 'xdr-xql-get-query-results'):
            return [self.__next_query_response()]
        elif command == 'executeCommandAt':
            return []
        else:
            raise RuntimeError(f'Not implemented - {command}')

    def __execute_command(
        self,
        command: str,
        args: dict[str, Any],
        extract_contents: bool = True,
        fail_on_error: bool = True,
    ) -> Any:
        if command == 'getList':
            lists = self.__config.get('lists') or {}
            list_name = args.get('listName')
            for ent in filter(
                None,
                [lists.get(list_name)] + to_list(lists.get('*'))
            ):
                data_type = ent.get('type')
                if data_type == 'raw':
                    return ent.get('data')
                elif data_type == 'content-bundle':
                    list_data = self.__get_list_from_content_bundle(
                        bundle_file=ent.get('data'),
                        list_name=list_name
                    )
                    if list_data is not None:
                        return list_data
                else:
                    raise RuntimeError(f'Invalid data type - {data_type}')
            raise RuntimeError('No List - {list_name}')
        else:
            raise RuntimeError(f'Not implemented - {command}')

    def __return_error(
        self,
        message: str,
        error: str = '',
        outputs: Any = None,
    ) -> Any:
        if errors := self.__config.get('errors'):
            assert any(
                re.match(fnmatch.translate(m), str(message))
                for m in to_list(errors.get('messages'))
            )
            raise ExpectedException(message)

        raise RuntimeError(message)

    def main(
        self,
    ) -> None:
        if self.__config.get('errors'):
            # Test for error occurrence
            with pytest.raises(ExpectedException):
                XQLDSHelper.main()
        else:
            # Test for success
            XQLDSHelper.main()

            # Validate Results
            assert demisto.results.call_count == 1
            results = demisto.results.call_args[0][0]

            # Validate 'Entry' - only when results.Entry is provided
            returned_entry = results.get('Contents').get('Entry')
            expected_entry = self.__config.get('results').get('Entry')
            if expected_entry is not None:
                skip_keys = []
                if to_bool(
                    demisto.get(self.__config, 'config.validation.skip-color', 'false')
                ):
                    skip_keys = ['color']

                ok = MainTester.equals_entry(
                    returned_entry,
                    expected_entry,
                    skip_keys=skip_keys,
                )
                """
                if not ok:
                    print(json.dumps(self.__config, indent=2))
                    print(json.dumps(returned_entry, indent=2))
                """
                assert ok

            # Validate 'QueryParams' - only when results.QueryParams is provided
            returned_qparams = results.get('Contents').get('QueryParams')
            expected_qparams = self.__config.get('results').get('QueryParams')
            if expected_qparams is not None:
                ok = MainTester.equals_entry(
                    returned_qparams,
                    expected_qparams,
                    skip_keys=False,
                )
                """
                if not ok:
                    print(json.dumps(self.__config, indent=2))
                    print(json.dumps(returned_qparams, indent=2))
                """
                assert ok


class TestXQLDSHelper:
    @staticmethod
    def __enum_test_config(
        file_path: str,
    ) -> Iterator[dict[str, Any]]:
        with open(file_path) as f:
            ents = json.load(f)
            assert isinstance(ents, list), f'Invalid test file - {file_path}'
            for ent in ents:
                if isinstance(ent, dict):
                    yield ent

    def test_main(
        self,
        mocker
    ) -> None:
        test_files = [
            './test_data/test-XQLDS_Sample.json',
            './test_data/test-entry-types.json',
            './test_data/test-others.json',
            './test_data/test-errors.json',
        ]
        for file_path in test_files:
            for ent in self.__enum_test_config(file_path):
                with MainTester(mocker=mocker, ent=ent) as main:
                    main.main()

    @pytest.mark.parametrize(
        argnames=(
            'triple_quotes_to_string'
            ', input_template'
            ', output_template'
        ),
        argvalues=[
            (
                'false',
                r'''
                {
                    "query": {
                        "xql": "dataset = xdr_data\n| fields _time\n"
                    }
                }
                ''',
                {
                    "query": {
                        "xql": "dataset = xdr_data\n| fields _time\n"
                    }
                }
            ),
            (
                'true',
                r'''
                {
                    "query": {
                        "xql":
"""
dataset = xdr_data
| fields _time
"""
                    }
                }
                ''',
                {
                    "query": {
                        "xql": "\ndataset = xdr_data\n| fields _time\n"
                    }
                }
            ),
            (
                'true',
                r"""
                {
                    "query": {
                        "xql":
'''
dataset = xdr_data
| fields _time
'''
                    }
                }
                """,
                {
                    "query": {
                        "xql": "\ndataset = xdr_data\n| fields _time\n"
                    }
                }
            )
        ]
    )
    def test_triple_quotes(
        self,
        mocker,
        triple_quotes_to_string,
        input_template,
        output_template
    ) -> None:
        args = {
            'triple_quotes_to_string': triple_quotes_to_string,
            'templates_type': 'raw',
            'template_name': 'test',
            'templates': '{"test":' + input_template + '}'
        }
        _, template = XQLDSHelper.Main._Main__get_template(args)
        ok = MainTester.equals_entry(template, output_template, skip_keys=None)
        assert ok
