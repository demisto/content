import json
import re


def clean(val):
    # [www.example.com](https://www.example.com) -> www.example.com
    return re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', str(val))


def maybe_json(val):
    # "[\"CLOUD\",\"IT\"]" -> ['CLOUD', 'IT']
    if isinstance(val, str) and val.strip()[:1] in ('[', '{'):
        try:
            return json.loads(val)
        except Exception:
            return val
    return val


def render(key, val, indent=0):
    pad = '    ' * indent
    val = maybe_json(val)

    if isinstance(val, dict):
        lines = [f"{pad}{key}:"]
        for k, v in val.items():
            lines.extend(render(k, v, indent + 1))
        return lines

    if isinstance(val, list):
        if all(not isinstance(i, (dict, list)) for i in val):
            return [f"{pad}{key}: " + ', '.join(clean(i) for i in val)]
        lines = [f"{pad}{key}:"]
        for n, item in enumerate(val, 1):
            if isinstance(item, dict):
                lines.append(f"{pad}    #{n}")
                for k, v in item.items():
                    lines.extend(render(k, v, indent + 2))
            else:
                lines.append(f"{pad}    - {clean(item)}")
        return lines

    shown = clean(val) if str(val).strip() else 'Not configured'
    return [f"{pad}{key}: {shown}"]


def alert_to_text(alert):
    lines = []
    for k, v in alert.items():
        lines.extend(render(k, v))
    return '\n'.join(lines)


def main():
    try:
        data = demisto.args().get('data')

        if isinstance(data, str):
            data = json.loads(data.strip().rstrip("'"))

        if isinstance(data, dict) and 'data' in data:
            data = data['data']

        if isinstance(data, dict):
            data = [data]

        text = '\n\n'.join(alert_to_text(a) for a in data)

        return_results(CommandResults(
            outputs_prefix='Cyfirma.Alert.Jira',
            outputs={'Description': text},
            readable_output=text))

    except Exception as e:
        return_error(f"Failed to parse CyfirmaAlertStringParser : {e}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
