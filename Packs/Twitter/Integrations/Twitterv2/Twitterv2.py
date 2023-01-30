import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):

    def tweet_search(self, query: str, start_time: Optional[str],
                     end_time: Optional[str], limit: Optional[int],
                     next_token: Optional[str]) -> tuple[dict, List[dict], Optional[str]]:
        """ Gets tweets according to the query.
            Args:
                query: str - The query from the user.
                start_time: str - Start date from which the Tweets will be provided.
                end_time: str - The most recent date to which the Tweets will be provided.
                limit: int - Maximum number of results to return.
                next_token: str - A value that encodes the next 'page' of results that can be requested.

            Returns:
                A tuple[dict, dict, Optional[str]] with:
                List[dict]: raw response.
                List[dict]: context data.
                str: next token.
        """
        result: List[dict] = []
        query_params = {'query': ''.join(f'"{item}"' for item in query),
                        'tweet.fields': 'id,text,attachments,author_id,conversation_id,created_at,public_metrics',
                        'expansions': 'attachments.media_keys,author_id',
                        'media.fields': 'media_key,type,url,public_metrics,alt_text',
                        'user.fields': 'id,name,username,created_at,description,verified',
                        'max_results': f'{limit}',
                        'start_time': start_time,
                        'end_time': end_time,
                        'next_token': next_token}
        try:
            response = self._http_request(method="GET", url_suffix='/tweets/search/recent',
                                          headers=self._headers, params=query_params,
                                          ok_codes=[200])
            result, next_token = create_context_data_search_tweets(response)
        except Exception as e:
            raise e
        return response, result, next_token

    def twitter_user_get(self, users_names: list[str], return_pinned_tweets: str) -> tuple[dict, list[dict]]:
        """ Gets users according to the provided user names.
            Args:
                user_name: list[str] - List of users names.
                return_pinned_tweets: str - Indicates whether to return user's pinned Tweets.
                limit: int - Maximum number of results to return.

            Returns:
                A tuple[dict, dict, Optional[str]] with:
                dict: raw response.
                dict: context data.
        """
        result = []
        query_params = {'usernames': ','.join(f'{item}' for item in users_names),
                        'user.fields': 'created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url'
                        ',protected,public_metrics,url,username,verified,withheld'}
        if return_pinned_tweets == 'true':
            query_params['expansions'] = 'pinned_tweet_id'
        try:
            response = self._http_request(method="GET", url_suffix='/users/by',
                                          headers=self._headers, params=query_params,
                                          ok_codes=[200])
            result = create_context_data_get_user(response)
        except Exception as e:
            raise e
        return response, result


''' HELPER FUNCTIONS '''


def create_context_data_search_tweets(response: dict) -> tuple[List[dict], str]:
    """ Gets raw response form Twitter API and extracts the relevent data.
        The data matched by
        attachments.media_keys == includes.media.media_key
        and author_id == includes.users.id.
            Args:
                response: dict - raw response form Twitter API.
            Returns:
                A tuple[dict, str] with:
                dict: context data.
                str: next token.
    """
    if response:
        data = response.get('data', {})
        include = response.get('includes', {})
        include_media = include.get('media')
        include_users = include.get('users')
        for item_in_data in data:
            author_id = item_in_data.get('author_id')
            attachments = item_in_data.get('attachments', {})
            item_in_data.pop('author_id', None)
            item_in_data.pop('attachments', None)
            if attachments:
                media_keys = attachments.get('media_keys')
                for item_in_include_media in include_media:
                    media_key = item_in_include_media.get('media_key')
                    for item_in_media_keys in media_keys:
                        if item_in_media_keys == media_key:
                            item_in_include_media.pop('public_metrics', None)
                            item_in_data['media'] = item_in_include_media
            for item_in_include_user in include_users:
                id = item_in_include_user.get('id')
                if id == author_id:
                    item_in_data['author'] = item_in_include_user
        next_token = response.get('meta', {}).get('next_token')
        response.pop('includes', None)
        response.pop('meta', None)
    return data, next_token


def create_context_data_get_user(response: dict) -> list[dict]:
    """ Gets raw response form Twitter API and extracts the relevent data.
        The data matched by pinned_tweet_id == includes.tweets.id
            Args:
                response: dict - raw response form Twitter API.
            Returns:
                dict: context data.
    """
    if response:
        data: list[dict] = response.get('data', {})
        include = response.get('includes', {})
        for item_in_data in data:
            entities = item_in_data.get('entities', {})
            url = entities.get('url', {}).get('urls', {})
            if entities and url:
                for url_detail in url:
                    url_detail.pop('start', None)
                    url_detail.pop('end', None)
                item_in_data['entities'] = url
            pinned_tweet_id = item_in_data.get('pinned_tweet_id')
            if pinned_tweet_id:
                if include:
                    include_tweets = include.get('tweets')
                    for item_in_include_tweets in include_tweets:
                        id = item_in_include_tweets.get('id')
                        if pinned_tweet_id == id:
                            item_in_data['Pinned_Tweets'] = item_in_include_tweets
        response.pop('includes', None)
        response.pop('meta', None)
    return data


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        query_params = {'query': 'Twitter'}
        client._http_request(method="GET", url_suffix='/tweets/search/recent',
                             headers=client._headers, params=query_params, ok_codes=[200])
        message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return message


def date_to_iso_format(date: str) -> str:
    """ Retrieves date string or relational expression to iso format date.
        Args:
            date: str - date or relational expression.
        Returns:
            A str in ISO format.
    """
    date = dateparser.parse(date)
    date = date.strftime("%Y-%m-%dT%H:%M:%SZ") if date else ''
    return date


def create_human_readable(dict_list: list[dict]) -> list[dict]:
    """ Gets list of dictionaries with a dictionaries inside for example [{key1: {key2: value}}, {key1: {key2: value}}]
        and changes it to a list of dictionaries without any dictionaries inside
        for example [{key1.key2: value}, {key1.key2: value}].
        Args:
            dict_list: list[dict] -  A list of dictionaries.
        Returns:
            A header string.
    """
    list_dict_response: list = []
    for dict_value in dict_list:
        dict_to_append = {}
        for key, value in dict_value.items():
            if isinstance(value, dict):
                dict_to_append.update({f'{key}.{k}': v for k, v in value.items()})
            else:
                dict_to_append[key] = value
        list_dict_response.append(dict_to_append)
    return list_dict_response


def header_transform_tweet_search(header: str) -> str:
    """ Gets header and transform it to another header according to tweet_search command.
        Args:
            header: str -  A header string.
        Returns:
            A header string.
    """
    if header == 'id':
        return 'Tweet ID'
    if header == 'text':
        return 'Text'
    if header == 'created_at':
        return 'Created At'
    if header == 'author.name':
        return 'Author Name'
    if header == 'author.username':
        return 'Author Username'
    if header == 'public_metrics.like_count':
        return 'Likes Count'
    if header == 'next_token':
        return 'Next Token'
    if header == 'media.url':
        return 'Attachments URL'
    else:
        return stringEscapeMD(header, True, True)
    return ""


def header_transform_get_user(header: str) -> str:
    """ Gets header and transform it to another header according to get_user command.
        Args:
            header: str -  A header string.
        Returns:
            A header string.
    """
    if header == 'name':
        return 'Name'
    if header == 'username':
        return 'User name'
    if header == 'created_at':
        return 'Created At'
    if header == 'description':
        return 'Description'
    if header == 'public_metrics.followers_count':
        return 'Followers Count'
    if header == 'public_metrics.tweet_count':
        return 'Tweet Count'
    if header == 'verified':
        return 'verified'
    else:
        return stringEscapeMD(header, True, True)
    return ""


def twitter_tweet_search_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Gets args and client and returns CommandResults of Tweets according to the reqested search.
        Args:
            client: client -  A Twitter client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with Tweets data according to to the reqested.
    """
    headers = ['id', 'text', 'created_at', 'author.name', 'author.username', 'public_metrics.like_count', 'media.url']
    query = argToList(args.get('query'))
    start_time = date_to_iso_format(args.get('start_time', '')) if args.get('start_time', None) else None
    end_time = date_to_iso_format(args.get('end_time', '')) if args.get('end_time', None) else None
    limit = arg_to_number(args.get('limit', 50))
    if limit and (limit > 100 or limit < 10):
        raise ValueError('Twitter: Limit should be a value between 10 and 100')
    next_token = args.get('next_token', None)
    raw_response, result, next_token = client.tweet_search(query, start_time, end_time, limit, next_token)
    dict_to_tableToMarkdown = create_human_readable(result)
    human_readable = tableToMarkdown("Tweets search results:", dict_to_tableToMarkdown,
                                     headers=headers, removeNull=False, headerTransform=header_transform_tweet_search)
    if next_token:
        outputs = {
            'Twitter.Tweet(val.next_token)': {'next_token': next_token},
            'Twitter.Tweet.TweetList(val.id === obj.id)': result
        }
        readable_output_next_token = tableToMarkdown("Tweet Next Token:", {'next_token': next_token},
                                                     headers=['next_token'], removeNull=False,
                                                     headerTransform=header_transform_tweet_search)
        return CommandResults(
            outputs=outputs,
            readable_output=human_readable + readable_output_next_token,
            raw_response=raw_response
        )
    elif result:
        return CommandResults(
            outputs_prefix='Twitter.Tweet.TweetList',
            outputs_key_field='id',
            outputs=result,
            readable_output=human_readable,
            raw_response=raw_response)
    else:
        return CommandResults(
            outputs_prefix='Twitter.Tweet.TweetList',
            outputs_key_field='id',
            readable_output=human_readable,
            raw_response=raw_response
        )


def twitter_user_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """ Retruns users information according to the requested user's names.
        Args:
            client: client -  A Twitter client.
            args: Dict - The function arguments.
        Returns:
            A CommandResult object with users data according to to the reqested.
    """
    headers = ['name', 'username', 'created_at', 'description', 'public_metrics.followers_count',
               'public_metrics.tweet_count', 'verified']
    user_name = argToList(args.get('user_name'))
    return_pinned_tweets = args.get('return_pinned_tweets', 'false')
    raw_response, result = client.twitter_user_get(user_name, return_pinned_tweets)
    dict_to_tableToMarkdown = create_human_readable(result)
    human_readable = tableToMarkdown("twitter user get results:", dict_to_tableToMarkdown,
                                     headers=headers, removeNull=False,
                                     headerTransform=header_transform_get_user)
    return CommandResults(
        outputs_prefix='Twitter.User',
        outputs_key_field='id',
        outputs=result,
        readable_output=human_readable,
        raw_response=raw_response
    )


''' MAIN FUNCTION '''


def main() -> None:

    bearer_token = demisto.params().get('credentials', {}).get('password')

    # get the service API url
    base_url = urljoin(demisto.params()['url'], '/2')
    verify_certificate = not demisto.params().get('insecure', False)
    proxy = demisto.params().get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        headers: Dict = {'Authorization': f'Bearer {bearer_token}'}
        headers
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'twitter-tweet-search':
            return_results(twitter_tweet_search_command(client, demisto.args()))

        elif demisto.command() == 'twitter-user-get':
            return_results(twitter_user_get_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
