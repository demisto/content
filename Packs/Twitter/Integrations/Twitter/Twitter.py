''' IMPORTS '''
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import tweepy
import urllib
import requests


class Client:
    def auth(self):
        auth = tweepy.OAuthHandler(demisto.params().get('apikey'), demisto.params().get('apikey_secret'))
        auth.set_access_token(demisto.params().get('access_token'), demisto.params().get('access_token_secret'))
        api = tweepy.API(auth)
        return api

# Build a search URL using the usernames argument and a preset list of all of the user fields of interest
# Link to Twitter reference under Apache 2.0:
# https://github.com/twitterdev/Twitter-API-v2-sample-code/blob/master/User-Lookup/get_users_with_bearer_token.py
# Changes made: changed function name to "create_users_info_url", added extra user fields and made user_fields a constant,
# usernames is no longer a static variable, removed the print statement from connect_to_endpoint
    def create_users_info_url(self, usernames):
        USER_FIELDS = "user.fields=description,pinned_tweet_id,protected,created_at,id,location,name,url,public_metrics,profile_image_url,username,verified,withheld"  # noqa: E501
        TWITTER_APIV2_URL = "https://api.twitter.com/2/users/by?{}&{}"
        url = TWITTER_APIV2_URL.format(usernames, USER_FIELDS)
        return url

    def create_headers(self, bearer_token):
        headers = {"Authorization": "Bearer {}".format(bearer_token)}
        return headers

    def connect_to_endpoint(self, url, headers):
        response = requests.request("GET", url, headers=headers)
        if response.status_code != 200:
            raise Exception(
                "Request returned an error: {} {}".format(
                    response.status_code, response.text
                )
            )
        return response.json()

    def get_tweets(self, q):
        TWITTER_APIV1_TWEETS_URL = "https://api.twitter.com/1.1/search/tweets.json?q="
        search_url = TWITTER_APIV1_TWEETS_URL + q
# Query arguments are set to have no default value. If the user does not input a value, the integration will check for if
# a value for the argument exists and append it to the HTTP request if so.
        if demisto.args().get('from_user'):
            search_url += urllib.parse.quote(f" from:{demisto.args().get('from_user')}")  # type: ignore[attr-defined]
        if demisto.args().get('to_user'):
            search_url += urllib.parse.quote(f" to:{demisto.args().get('to_user')}")  # type: ignore[attr-defined]
        if demisto.args().get('geocode'):
            search_url += "&geocode=" + demisto.args().get('geocode')
            geocode_check = demisto.args().get('geocode').split(',')
            try:
                float(geocode_check[0])
                float(geocode_check[1])
                float(geocode_check[2][:-2])
            except ValueError:
                return_error('Incorrect geocode syntax. Geocode syntax is Lat,Long,RadiusUnits\
                - Where Units = mi or km. \nExample Syntax: 60,324321,-27.98789,400mi')
            if geocode_check[2][-2:] != 'mi' and geocode_check[2][-2:] != 'km':
                return_error('Incorrect geocode syntax. Geocode syntax is Lat,Long,RadiusUnits\
                - Where Units = mi or km. \nExample Syntax: 60,324321,-27.98789,400mi')
        if demisto.args().get('lang'):
            search_url += "&lang=" + demisto.args().get('lang')
            SUPPORTED_LANGS = ['en', 'ar', 'bn', 'cs', 'da', 'de', 'el', 'es', 'fa', 'fi', 'fil', 'fr',
                               'he', 'hi', 'hu', 'id', 'it', 'ja', 'ko', 'msa', 'nl', 'no', 'pl', 'pt',
                               'ro', 'ru', 'sv', 'th', 'tr', 'uk', 'ur', 'vi', 'zh-cn', 'zh-tw']
            if demisto.args().get('lang') not in SUPPORTED_LANGS:
                return_error('Language code is not supported. For a list of supported language codes, visit\
                 https://developer.twitter.com/en/docs/twitter-for-websites/supported-languages')
        if demisto.args().get('result_type'):
            search_url += "&result_type=" + (demisto.args().get('result_type')).lower()
            SUPPORTED_RESULT_TYPES = ['popular', 'recent', 'mixed']
            if demisto.args().get('result_type') not in SUPPORTED_RESULT_TYPES:
                return_error("Entered result_type is not supported. Please use 'recent', 'popular', or 'mixed'.")
        if demisto.args().get('count'):
            try:
                int(demisto.args().get('count'))
            except ValueError:
                return_error("Count must be an integer less than or equal to 100.")
            if int(demisto.args().get('count')) < 100:
                search_url += "&count=" + demisto.args().get('count')
            else:
                search_url += "&count=100"
        search_url += "&tweet_mode=extended"
        headers = Client.create_headers(self, demisto.params().get('bearer_token'))
        json_response = Client.connect_to_endpoint(self, search_url, headers)
        table = []

        def get_entity(value, entity, subentity):
            entity_list = []
            if value.get('entities').get(entity) != []:
                for item in value.get('entities').get(entity):
                    entity_list.append(item[subentity])
            return entity_list

        for value in json_response.get('statuses'):
            obj = {
                'Tweet Text': value.get('full_text'),
                'Post ID': value.get('id_str'),
                'User Full Name': value.get('user').get('name'),
                'Username': value.get('user').get('screen_name'),
                'Date of Creation': value.get('created_at'),
                'User Verified Status': value.get('user').get('verified'),
                'Post Retweet Count': value.get('retweet_count'),
                'Post Favorite Count': value.get('favorite_count')
            }
            if demisto.args().get('include_entities') == "True":
                obj['Hashtags'] = get_entity(value, 'hashtags', 'text')
                obj['User Mentions'] = get_entity(value, 'user_mentions', 'screen_name')
                obj['Expanded URL'] = get_entity(value, 'urls', 'expanded_url')
                obj['Media'] = get_entity(value, 'media', 'media_url_https') if 'media' in value.get('entities').keys() else None
            table.append(obj)
        if demisto.args().get('include_entities') == "True":
            headers = ['Tweet Text', 'Post ID', 'User Full Name', 'Username', 'Date of Creation', 'User Verified Status',
                       'Post Retweet Count', 'Post Favorite Count', 'Hashtags', 'User Mentions', 'Expanded URL', 'Media']
        else:
            headers = ['Tweet Text', 'Post ID', 'User Full Name', 'Username',
                       'Date of Creation', 'User Verified Status', 'Post Retweet Count', 'Post Favorite Count']
        name = "Twitter-get-tweets Search Results"
        results_to_markdown(table, headers, name)

# Documentation for the tweepy search_users api call: https://docs.tweepy.org/en/stable/api.html#API.search_users

    def get_users(self, name):
        table = []
        try:
            int(demisto.args().get('count'))
        except ValueError:
            return_error("Count must be an integer less than or equal to 20.")
        try:
            int(demisto.args().get('page'))
        except ValueError:
            return_error("Page must be an integer.")
        for user in ((Client.auth(self).search_users(q=name, page=int(demisto.args().get('page')),
                                                     count=int(demisto.args().get('count')), include_entities=True))):
            if 'url' in user.entities.keys():
                user_url = user.entities.get('url').get('urls')[0].get('expanded_url')
            else:
                user_url = None
            obj = {
                'Username': user.screen_name,
                'User ID': user.id,
                'Follower Count': user.followers_count,
                'Verified Status': user.verified,
                'User URL': user_url
            }
            table.append(obj)
        headers = ['Username', 'User ID', 'Follower Count', 'Verified Status', 'User URL']
        name = "Twitter-get-users Search Results"
        results_to_markdown(table, headers, name)

# Documentation on the user class used: https://developer.twitter.com/en/docs/twitter-api/data-dictionary/object-model/user

    def get_user_info(self, usernames):
        url = Client.create_users_info_url(self, usernames)
        headers = Client.create_headers(self, demisto.params().get('bearer_token'))
        json_response = Client.connect_to_endpoint(self, url, headers)
        table = []
        for value in json_response.get('data'):
            obj = {
                'Name': value.get('name'),
                'Username': value.get('username'),
                'ID': value.get('id'),
                'Description': value.get('description'),
                'Verified': value.get('verified'),
                'Date of Creation': value.get('created_at'),
                'Follower Count': value.get('public_metrics').get('followers_count'),
                'Following Count': value.get('public_metrics').get('following_count'),
                'Listed Count': value.get('public_metrics').get('listed_count'),
                'Tweet Count': value.get('public_metrics').get('tweet_count'),
                'Location': value.get('location'),
                'Protected': value.get('protected'),
                'URL': value.get('url'),
                'Profile Image URL': value.get('profile_image_url')
            }
            table.append(obj)
            headers = ['Name', 'Username', 'ID', 'Description', 'Verified', 'Date of Creation',
                       'Follower Count', 'Following Count', 'Listed Count', 'Tweet Count',
                       'Location', 'Protected', 'URL', 'Profile Image URL']
            name = "Twitter-get-user-info Search Results"
        results_to_markdown(table, headers, name)


def results_to_markdown(table, headers, name):
    markdown = tableToMarkdown(name, table, headers=headers)
    results = CommandResults(
        readable_output=markdown,
        outputs_prefix='Twitter',
        outputs_key_field="SearchResults",
        outputs=table
    )
    return_results(results)


def test_module(client):
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test
    """

    result = client.say_hello('DBot')
    if 'Hello DBot' == result:
        return 'ok'
    else:
        return 'Test failed because ......'


def main():
    client = Client()
    if demisto.command() == 'test-module':
        result = test_module(client)
        return_results(result)
    if demisto.command() == 'twitter-get-users':
        name = demisto.args().get('name')
        client.get_users(name)
    if demisto.command() == 'twitter-get-user-info':
        usernames = "usernames=" + demisto.args().get('usernames')
        client.get_user_info(usernames)
    if demisto.command() == 'twitter-get-tweets':
        if demisto.args().get('q')[0] == '#':
            q = urllib.parse.quote(' ') + demisto.args().get('q')[1:]  # type: ignore[attr-defined]
        else:
            q = demisto.args().get('q')
        client.get_tweets(q)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
