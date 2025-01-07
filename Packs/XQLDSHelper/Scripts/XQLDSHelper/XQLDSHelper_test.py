import demistomock as demisto
import XQLDSHelper
import pytest
import re
import sys
import json
import gzip
import tarfile
import datetime
import fnmatch
import functools
import itertools
import freezegun
import os.path
import urllib.parse
from collections.abc import Iterator
from typing import Any, TypeVar
from types import TracebackType
from pytest_mock import MockerFixture


MainTester = TypeVar('MainTester')


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
    ) -> MainTester:
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
                raise RuntimeError('No file - {file_path}')

            list_data = json.loads(f.read())
            return list_data.get('data')

    def __get_query_response(
        self,
    ) -> Any:
        if file_name := demisto.get(self.__config, 'xql.response'):
            with open(file_name, 'r') as f:
                return json.loads(f.read())

        raise RuntimeError((
            "xql.response is not configured."
            " This test case may have been expected to hit the cache, but it didn't."
        ))

    def __get_query_results(
        self,
    ) -> list:
        resp = self.__get_query_response()
        return resp['results']

    def __demisto_dt(
        self,
        obj: dict[str, Any],
        dt: str,
    ) -> Any:
        path, _, func = dt.partition('=')
        val = demisto.get(obj, path)

        if not func:
            return val

        if path == 'dataset':
            dataset = self.__get_query_results()

            if m := re.fullmatch(r'>val.length \? val\[0\].([^)]+) : 0', func):
                return dataset[0].get(m[1]) if dataset else 0

            var = '>val[0].text'
            if var == func:
                return dataset[0].get('text')

            var = r'>val.map((record) => " - " + record.text).join("\n")'
            if var == func:
                return '\n'.join(
                    map(
                        lambda x: ' - ' + x.get('text'),
                        dataset
                    )
                )

            var = (
                r'''>(()=>{letitems=[];for(leti=0;i<val.length;++i)'''
                r'''{items.push(`-${i+1}:${val[i].text}`);}returnitems.join("\n");})()'''
            )
            if var == ''.join(func.strip().split()):
                return '\n'.join(
                    map(
                        lambda x: f' - {x[0]+1}: ' + x[1].get('text'),
                        enumerate(dataset)
                    )
                )

        var = r"""encodeURIComponent(val).replace('"', '%22')"""
        if var == func:
            return urllib.parse.quote(val).replace('\"', '%22')

        if m := re.search(r"decodeURIComponent\('([^']+)'\)", func):
            return urllib.parse.unquote(m[1])

        var = '>val ? val[0] : "255.255.255.255"'
        if var == func:
            return val[0] if val else '255.255.255.255'

        if func:
            raise RuntimeError(f'Not implemented - {dt}')
            sys.exit(1)

        return val

    def __execute_command(
        self,
        command: str,
        args: dict[str, Any],
        extract_contents: bool = True,
        fail_on_error: bool = True,
    ) -> Any:
        match command:
            case 'getList':
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

            case 'xdr-xql-generic-query':
                return self.__get_query_response()

            case _:
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
        with open(file_path, 'r') as f:
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
            './test_data/test-others.json',
            './test_data/test-errors.json',
        ]
        for file_path in test_files:
            for ent in self.__enum_test_config(file_path):
                with MainTester(mocker=mocker, ent=ent) as main:
                    main.main()
