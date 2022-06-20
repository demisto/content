from http import client

import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa

import requests
from requests.auth import HTTPBasicAuth
import traceback
from typing import Dict, Any

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


''' CONSTANTS '''


''' CLIENT CLASS '''


class Client(BaseClient):
    
    def list_posts(self, args: dict = {}):
        url_suffix = '/wp-json/wp/v2/posts'
        response = self._http_request('GET', url_suffix, params=args)
        return response

    def list_events(self):
        url_suffix = 'wp-json/tribe/events/v1/events'
        response = self._http_request('GET', url_suffix)
        return response

    def get_post(self, post_id, params: dict = {}):
        url_suffix = f"wp-json/wp/v2/posts/{post_id}"
        response = self._http_request('GET', url_suffix, params=params)
        return response

    def url_request(self, method, url, body: dict = None, params: dict = None):
        response = self._http_request(
            method,
            url,
            json_data=body,
            params=params
        )
        return response

    def create_post(self, args: dict):
        url_suffix = "/wp-json/wp/v2/posts"
        response = self._http_request('POST', url_suffix=url_suffix, json_data=args)
        return response

    def update_post(self, post_id, args: dict):
        url_suffix = f"/wp-json/wp/v2/posts/{post_id}"
        response = self._http_request('POST', url_suffix=url_suffix, json_data=args)
        return response

    def delete_post(self, post_id, force):
        url_suffix = f"/wp-json/wp/v2/posts/{post_id}"
        params = {
            "force": force
        }
        response = self._http_request('DELETE', url_suffix=url_suffix, params=params)
        return response

    def list_categories(self):
        url_suffix = "wp-json/wp/v2/categories"
        response = self._http_request('GET', url_suffix)
        return response

    def create_category(self, params: dict):
        url_suffix = "wp-json/wp/v2/categories"
        response = self._http_request('POST', url_suffix, params=params)
        return response

    def get_category(self, category_id, params: dict):
        url_suffix = f"wp-json/wp/v2/categories/{category_id}"
        response = self._http_request('GET', url_suffix, params=params)
        return response

    def update_category(self, category_id, args: dict):
        url_suffix = f"wp-json/wp/v2/categories/{category_id}"
        response = self._http_request('POST', url_suffix, json_data=args)
        return response

    def delete_category(self, category_id):
        url_suffix = f"/wp-json/wp/v2/categories/{category_id}"
        params = {
            "force": True
        }
        response = self._http_request('DELETE', url_suffix=url_suffix, params=params)
        return response

    def list_tags(self):
        url_suffix = "wp-json/wp/v2/tags"
        response = self._http_request('GET', url_suffix)
        return response

    def create_tag(self, params: dict):
        url_suffix = "wp-json/wp/v2/tags"
        response = self._http_request('POST', url_suffix, params=params)
        return response

    def get_tag(self, tag_id, params: dict):
        url_suffix = f"wp-json/wp/v2/tags/{tag_id}"
        response = self._http_request('GET', url_suffix, params=params)
        return response

    def update_tag(self, tag_id, args: dict):
        url_suffix = f"wp-json/wp/v2/tags/{tag_id}"
        response = self._http_request('POST', url_suffix, json_data=args)
        return response

    def delete_tag(self, tag_id):
        url_suffix = f"/wp-json/wp/v2/tags/{tag_id}"
        params = {
            "force": True
        }
        response = self._http_request('DELETE', url_suffix=url_suffix, params=params)
        return response


''' HELPER FUNCTIONS '''

# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    client.list_posts()
    return ('ok')


def list_posts_command(client: Client, args: dict = {}):
    response = client.list_posts(args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Posts',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown("Posts:", response)
    )
    return_results(command_results)


def get_post_command(client: Client, args: dict = {}):
    post_id = args.get('id')
    params = {k: v for k, v in args.items() if k != "id"}
    response = client.get_post(post_id, params=params)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Posts',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown("Posts:", response)
    )
    return_results(command_results)


def url_request_command(client: Client, args: dict = {}):
    url = args.get('url')
    method = args.get('method').lower()
    body = args.get('body')
    if body:
        try:
            body = json.loads(body)
        except Exception as err:
            return_error(f'There was an error parsing the body:\n{err}')
    params = args.get('params')
    if params:
        try:
            params = json.loads(params)
        except Exception as err:
            return_error(f'There was an error parsing the params:\n{err}')
    response = client.url_request(method, url, body=body, params=params)
    outputs = {
        'url': url,
        'data': response
    }
    command_results = CommandResults(
        outputs_prefix='Wordpress.URL',
        outputs_key_field=['url'],
        outputs=outputs,
        readable_output=tableToMarkdown(f"{url}:", response)
    )
    return_results(command_results)


def create_post_command(client: Client, args: dict):
    if args.get('sticky'):
        args['sticky'] = argToBoolean(args.get('sticky'))
    if args.get('meta'):
        try:
            args['meta'] = json.loads(args.get('meta'))
        except Exception as err:
            return_error(f"Error converting meta: {err}")
    if args.get('categories'):
        args['categories'] = [arg_to_number(x) for x in args.get('categories').split(",")]
    if args.get('tags'):
        args['tags'] = [arg_to_number(x) for x in args.get('tags').split(",")]
    response = client.create_post(args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Posts',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown("Post created:", response)
    )
    return_results(command_results)


def update_post_command(client: Client, args: dict):
    post_id = args.get('id')
    if args.get('sticky'):
        args['sticky'] = argToBoolean(args.get('sticky'))
    if args.get('meta'):
        try:
            args['meta'] = json.loads(args.get('meta'))
        except Exception as err:
            return_error(f"Error converting meta: {err}")
    if args.get('categories'):
        args['categories'] = [arg_to_number(x) for x in args.get('categories').split(",")]
    if args.get('tags'):
        args['tags'] = [arg_to_number(x) for x in args.get('tags').split(",")]
    args = {k: v for k, v in args.items() if k != "id"}
    response = client.update_post(post_id, args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Posts',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Post {post_id} updated:", response)
    )
    return_results(command_results)


def delete_post_command(client: Client, args: dict):
    post_id = args.get('id')
    force = argToBoolean(args.get('force'))
    response = client.delete_post(post_id, force)
    command_results = CommandResults()
    if force:
        command_results.readable_output = f"Post {post_id} permanently deleted."
    else:
        command_results.readable_output = tableToMarkdown(f"Post {post_id} moved to trash:", response)
        command_results.outputs_prefix = 'Wordpress.Posts'
        command_results.outputs_key_field='id'
        command_results.outputs=response
    return_results(command_results)


def list_categories_command(client: Client, args: dict):
    response = client.list_categories()
    command_results = CommandResults(
        outputs_prefix='Wordpress.Categories',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown("Categories:", response)
    )
    return_results(command_results)


def create_category_command(client: Client, args: dict):
    response = client.create_category(args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Categories',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Created new category:", response)
    )
    return_results(command_results)


def get_category_command(client: Client, args: dict):
    category_id = args.get('id')
    params = {k: v for k, v in args.items() if k != 'id'}
    response = client.get_category(category_id, params)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Categories',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Category {category_id}:", response)
    )
    return_results(command_results)


def update_category_command(client: Client, args: dict):
    category_id = args.get('id')
    args = {k: v for k, v in args.items() if k != "id"}
    response = client.update_category(category_id, args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Categories',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Category {category_id} updated:", response)
    )
    return_results(command_results)


def delete_category_command(client: Client, args: dict):
    post_id = args.get('id')
    client.delete_category(post_id)
    command_results = CommandResults(
        readable_output=f"Category {post_id} permanently deleted."
    )
    return_results(command_results)


def list_tags_command(client: Client, args: dict):
    response = client.list_tags()
    command_results = CommandResults(
        outputs_prefix='Wordpress.Tags',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown("Tags:", response)
    )
    return_results(command_results)


def create_tag_command(client: Client, args: dict):
    response = client.create_tag(args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Tags',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Created new tag:", response)
    )
    return_results(command_results)


def get_tag_command(client: Client, args: dict):
    tag_id = args.get('id')
    params = {k: v for k, v in args.items() if k != 'id'}
    response = client.get_tag(tag_id, params)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Tags',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Tag {tag_id}:", response)
    )
    return_results(command_results)


def update_tag_command(client: Client, args: dict):
    tag_id = args.get('id')
    args = {k: v for k, v in args.items() if k != "id"}
    response = client.update_tag(tag_id, args)
    command_results = CommandResults(
        outputs_prefix='Wordpress.Tags',
        outputs_key_field='id',
        outputs=response,
        readable_output=tableToMarkdown(f"Tag {tag_id} updated:", response)
    )
    return_results(command_results)


def delete_tag_command(client: Client, args: dict):
    tag_id = args.get('id')
    client.delete_tag(tag_id)
    command_results = CommandResults(
        readable_output=f"Tag {tag_id} permanently deleted."
    )
    return_results(command_results)


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    base_url = params.get('url')
    user = params.get('username')
    app_password = params.get('app_password')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:

        commands = {
            'wordpress-list-posts': list_posts_command,
            'wordpress-get-post': get_post_command,
            'wordpress-url-request': url_request_command,
            'wordpress-create-post': create_post_command,
            'wordpress-update-post': update_post_command,
            'wordpress-delete-post': delete_post_command,
            'wordpress-list-categories': list_categories_command,
            'wordpress-create-category': create_category_command,
            'wordpress-get-category': get_category_command,
            'wordpress-update-category': update_category_command,
            'wordpress-delete-category': delete_category_command,
            'wordpress-list-tags': list_tags_command,
            'wordpress-create-tag': create_tag_command,
            'wordpress-get-tag': get_tag_command,
            'wordpress-update-tag': update_tag_command,
            'wordpress-delete-tag': delete_tag_command
        }

        headers: Dict = {}
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            auth=(user, app_password)
        )

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in commands:
            commands[command](client, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
