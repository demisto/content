import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import json

''' CLIENT CLASS '''


class Client(BaseClient):
    def test_module(self, args: dict):
        self.chat(args)

    def chat(self, args: dict):
        try:
            response = self._http_request(
                method="POST",
                url_suffix="/chat/completions",
                json_data=args
            )
        except Exception as e:
            msg = f"{demisto.command()}: exception - {e}"
            demisto.debug(msg)
            raise Exception(msg)
        return response


''' HELPER FUNCTIONS '''


def clean_think(text: str) -> str:
    start = "<think>"
    end = "</think>"
    start_index = text.find(start)
    if start_index == -1:
        return text
    end_index = text.find(end, start_index + len(start))
    if end_index == -1:
        return text
    return text[:start_index] + text[end_index + len(end):]


def DictMarkdown(nested, indent):
    md = ""
    if indent == "":
        indent = "-"
    else:
        indent = "  " + indent

    if isinstance(nested, dict):
        for key, val in nested.items():
            if isinstance(val, dict):
                md += f"{indent} {key}\n"
                md += DictMarkdown(val, indent)
            elif isinstance(val, list):
                md += f"{indent} {key}\n"
                md += DictMarkdown(val, indent)
            else:
                md += f"{indent} {key}: {val}\n"
    elif isinstance(nested, list):
        for val in nested:
            md += f"{indent} []\n"
            if isinstance(val, dict):
                md += DictMarkdown(val, indent)
            elif isinstance(val, list):
                md += f"{indent} {val}\n"
                md += DictMarkdown(val, indent)
            else:
                md += f"  {indent} {val}\n"

    return md


''' COMMAND FUNCTIONS '''


def test_module(client: Client, args: dict) -> str:
    try:
        client.test_module(args)
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: ensure API Key is correctly set'
        else:
            raise e
    return 'ok'


def deepresearch_chat_command(client: Client, args: dict, thinking: str, citations: str, jsonout: str) -> CommandResults:
    response = client.chat(args)
    content = response['choices'][0]['message']['content']
    if thinking == "no":
        content = clean_think(content)
    final_results = {'content': content}
    if citations == "yes":
        final_results['citations'] = response['citations']
    if jsonout == "no":
        return CommandResults(
            readable_output=DictMarkdown(final_results, ""),
        )
    else:
        return CommandResults(
            outputs_prefix='DeepResearch',
            outputs=final_results,
            readable_output=DictMarkdown(final_results, "")
        )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        headers = {
            'accept': "application/json",
            'Authorization': f"Bearer {params.get('apikey')['password']}",
            'Content-Type': "application/json"
        }

        # Support for Cloudflare authentication
        cf_auth = params.get('cf_auth', None)
        cf_client_id = None if cf_auth is None else cf_auth['identifier']
        cf_client_key = None if cf_auth is None else cf_auth['password']

        if cf_client_id is not None and cf_client_key is not None:
            headers.update({
                'CF-Access-Client-Id': cf_client_id,
                'CF-Access-Client-Secret': cf_client_key
            })

        client = Client(
            base_url=params.get('url'),
            verify=not params.get('insecure', False),
            headers=headers,
            proxy=params.get('proxy', False)
        )

        if command == 'test-module':
            result = test_module(client, {
                'model': params.get('model', 'sonar-deep-research'),
                'messages': [
                    {
                        'role': "system",
                        'content': "Be precise and concise."
                    },
                    {
                        'role': "user",
                        'content': "hello world"
                    }
                ]
            })
            return_results(result)
        elif command == "deepresearch-chat":
            args['model'] = params.get("model", "sonar-deep-research")
            syscontent = args.get("systemmessage", "Be precise and concise.")
            usrcontent = args.get("usermessage", "").strip()
            if usrcontent == "":
                raise Exception("No usermessage was provided")
            thinking = args.get("thinking", "no")
            citations = args.get("citations", "no")
            jsonout = args.get("jsonout", "no")
            args['web_search_options'] = {
                'search_context_size': args.get("contextsize", "medium")
            }
            args['search_recency_filter'] = args.get("recentfilter", "month")
            domainfilter = args.get("domainfilter", "").strip()
            if domainfilter != "":
                args['search_domain_filter'] = domainfilter.split(",", 3)
            args['messages'] = [
                {
                    'role': "system",
                    'content': syscontent
                },
                {
                    'role': "user",
                    'content': usrcontent
                }
            ]
            for key in ['systemmessage', 'usermessage', 'citations', 'thinking', 
                        'jsonout', 'contextsize', 'recentfilter', 'domainfilter']:
                if key in args:
                    del args[key]
            return_results(deepresearch_chat_command(client, args, thinking, citations, jsonout))
        else:
            raise NotImplementedError(f'Command {command} is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError: {e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
