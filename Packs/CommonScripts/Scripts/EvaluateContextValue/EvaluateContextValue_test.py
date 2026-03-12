import re
import json
import fnmatch
import pytest
from typing import Any
import EvaluateContextValue
import demistomock as demisto


def equals_object(obj1: Any, obj2: Any) -> bool:
    if type(obj1) is not type(obj2):
        return False
    elif isinstance(obj1, dict):
        for k1, v1 in obj1.items():
            if k1 not in obj2:
                return False
            if not equals_object(v1, obj2[k1]):
                return False
        return not (set(obj1.keys()) ^ set(obj2.keys()))
    elif isinstance(obj1, list):
        # Compare lists (ignore order)
        list2 = list(obj2)
        for _, v1 in enumerate(obj1):
            for i2, v2 in enumerate(list2):
                if equals_object(v1, v2):
                    list2.pop(i2)
                    break
            else:
                return False
        return not list2
    else:
        return obj1 == obj2


class TestEvaluateContextValue:
    def __side_effect_demisto_dt(
        self,
        obj: dict[str, Any],
        dt: str,
    ) -> Any:
        if dt in (".", ".=val"):
            return obj

        return demisto.get(obj, dt)

    def __side_effect_demisto_error(self, err):
        pass

    def __return_error(
        self,
        message: str,
        error: str = "",
        outputs: Any = None,
    ) -> Any:
        raise RuntimeError(message)

    def test_main(self, mocker):
        mocker.patch.object(demisto, "dt", side_effect=self.__side_effect_demisto_dt)
        mocker.patch.object(demisto, "error", side_effect=self.__side_effect_demisto_error)

        with open("./test_data/main.json") as f:
            test_cases = json.load(f)

        for case in test_cases:
            if not isinstance(case, dict):
                continue

            mocker.patch.object(demisto, "context", return_value=case.get("context") or {})
            mocker.patch.object(demisto, "args", return_value=case.get("args") or {})
            mocker.patch.object(EvaluateContextValue, "return_results")
            mocker.patch.object(EvaluateContextValue, "return_error", side_effect=self.__return_error)

            if errors := case.get("errors"):
                with pytest.raises(Exception) as e:
                    EvaluateContextValue.main()

                assert any(re.match(fnmatch.translate(m), str(e.value)) for m in errors)
            else:
                EvaluateContextValue.main()

                assert EvaluateContextValue.return_results.call_count == 1
                command_results = EvaluateContextValue.return_results.call_args[0][0]
                results_context = command_results.to_context()
                entry_context = results_context.get("EntryContext")
                results = entry_context.get("EvaluateContextValue(val.id && val.id == obj.id)")
                expected = case["results"]
                assert equals_object(results, expected)
