import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib.parse
import base64


def decode(
    value: str | None,
    encoding: str,
) -> str | None:
    if value is not None:
        if encoding == "url":
            value = urllib.parse.unquote(value)
        elif encoding == "base64":
            value = base64.b64decode(value.encode()).decode()
        elif encoding != "raw":
            raise DemistoException(f"Invalid encoding scheme - {encoding}")
    return value


def evaluate(
    id: str,
    value_dt: str,
    eval_dt: str | None,
    eval_key: str | None,
    context: dict[str, Any],
) -> CommandResults:
    value = demisto.dt(context, value_dt)
    if eval_dt:
        if eval_key:
            value = {eval_key: value}
        value = demisto.dt(value, eval_dt)

    if not value:
        ok = False
    elif isinstance(value, str):
        ok = value.lower() != "false"
    else:
        ok = True

    return CommandResults(
        outputs_key_field="id",
        outputs_prefix="EvaluateContextValue",
        outputs={"id": id, "ok": ok},
        readable_output=f"The conditions evaluated to {json.dumps(ok)}. id = {id}.",
    )


def main():
    try:
        args = demisto.args()
        dt_encoding = args.get("dt_encoding") or "raw"
        value_dt = decode(args.get("value_dt"), dt_encoding) or ""
        eval_dt = decode(args.get("eval_dt") or "", dt_encoding)

        context = demisto.context()
        if playbook_id := args.get("playbook_id"):
            context = context.get(f"subplaybook-{playbook_id}", {})

        return_results(
            evaluate(
                id=args.get("id"),
                value_dt=value_dt,
                eval_dt=eval_dt,
                eval_key=args.get("eval_key"),
                context=context,
            )
        )
    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute EvaluateContextValue script. Error: {err!s}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
