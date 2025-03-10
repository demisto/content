import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO8601 format with UTC, default in XSOAR

""" CLIENT CLASS """


class Client(BaseClient):
    def tweet_search(
        self, query: str, start_time: Optional[str], end_time: Optional[str], limit: Optional[int], next_token: Optional[str]
    ) -> dict:
        """Gets tweets according to the query.
        Args:
            query: str - The query from the user.
            start_time: str - Start date from which the Tweets will be provided.
            end_time: str - The most recent date to which the Tweets will be provided.
            limit: int - Maximum number of results to return.
            next_token: str - A value that encodes the next 'page' of results that can be requested.

        Returns:
            List[dict]: raw response.
        """
        query_params = {
            "query": "".join(f'"{item}"' for item in query),
            "tweet.fields": "id,text,attachments,author_id,conversation_id,created_at,public_metrics",
            "expansions": "attachments.media_keys,author_id",
            "media.fields": "media_key,type,url,public_metrics,alt_text",
            "user.fields": "id,name,username,created_at,description,verified",
            "max_results": f"{limit}",
            "start_time": start_time,
            "end_time": end_time,
            "next_token": next_token,
        }
        response = self._http_request(
            method="GET", url_suffix="/tweets/search/recent", headers=self._headers, params=query_params, ok_codes=[200]
        )
        return response

    def twitter_user_get(self, users_names: list[str], return_pinned_tweets: str) -> dict:
        """Gets users according to the provided user names.
        Args:
            user_name: list[str] - List of users names.
            return_pinned_tweets: str - Indicates whether to return user's pinned Tweets.
            limit: int - Maximum number of results to return.

        Returns:
            dict: raw response.
        """
        response = {}
        query_params = {
            "usernames": ",".join(f"{item}" for item in users_names),
            "user.fields": "created_at,description,entities,id,location,name,pinned_tweet_id,profile_image_url"
            ",protected,public_metrics,url,username,verified,withheld",
        }
        if return_pinned_tweets == "true":
            query_params["expansions"] = "pinned_tweet_id"
            query_params["tweet.fields"] = "id,text,attachments,conversation_id,created_at,public_metrics"
        response = self._http_request(
            method="GET", url_suffix="/users/by", headers=self._headers, params=query_params, ok_codes=[200]
        )
        return response


""" HELPER FUNCTIONS """


def create_context_data_search_tweets(response: dict) -> tuple[List[dict], str]:
    """Gets raw response form Twitter API and extracts the relevent data.
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
    include = response.get("includes", {})
    data = response.get("data", [])
    users = include.get("users", [])
    media = include.get("media", [])
    next_token = response.get("meta", {}).get("next_token")
    list_dict_response = []
    for data_item in data:
        author_id = data_item.get("author_id")
        for user in users:
            id = user.get("id")
            if author_id == id:
                dict_to_append = {
                    "id": data_item.get("id"),
                    "text": data_item.get("text"),
                    "conversation_id": data_item.get("conversation_id"),
                    "created_at": data_item.get("created_at"),
                    "edit_history_tweet_ids": data_item.get("edit_history_tweet_ids"),
                    "author": {
                        "id": user.get("id"),
                        "description": user.get("description"),
                        "name": user.get("name"),
                        "verified": user.get("verified"),
                        "username": user.get("username"),
                        "created_at": user.get("created_at"),
                    },
                    "public_metrics": data_item.get("public_metrics", {}),
                    "media": [],
                }
                attachments = data_item.get("attachments", {})
                if attachments:
                    media_to_append = []
                    media_keys = attachments.get("media_keys", [])
                    for media_key in media_keys:
                        for media_item in media:
                            media_key_attachments = media_item.get("media_key")
                            if media_key == media_key_attachments:
                                media_to_append.append(
                                    {
                                        "url": media_item.get("url"),
                                        "media_key": media_item.get("media_key"),
                                        "alt_text": media_item.get("alt_text"),
                                        "type": media_item.get("type"),
                                    }
                                )
                    dict_to_append["media"] = media_to_append
                list_dict_response.append(remove_empty_elements(dict_to_append))
    return list_dict_response, next_token


def create_context_data_get_user(response: dict, pinned_tweets: str) -> list[dict]:
    """Gets raw response form Twitter API and extracts the relevent data.
    The data matched by pinned_tweet_id == includes.tweets.id
        Args:
            response: dict - raw response form Twitter API.
        Returns:
            dict: context data.
    """
    include = response.get("includes", {})
    data = response.get("data", {})
    tweets = include.get("tweets")
    list_dict_response = []
    for data_item in data:
        pinned_tweet_id = data_item.get("pinned_tweet_id")
        dict_to_append = {
            "name": data_item.get("name"),
            "username": data_item.get("username"),
            "created_at": data_item.get("created_at"),
            "description": data_item.get("description"),
            "id": data_item.get("id"),
            "location": data_item.get("location"),
            "pinned_tweet_id": data_item.get("pinned_tweet_id"),
            "profile_image_url": data_item.get("profile_image_url"),
            "protected": data_item.get("protected"),
            "url": data_item.get("url"),
            "verified": data_item.get("verified"),
            "withheld": data_item.get("withheld"),
            "public_metrics": data_item.get("public_metrics", {}),
            "entities": [
                {"url": item.get("url"), "expanded_url": item.get("expanded_url"), "display_url": item.get("display_url")}
                for item in data_item.get("entities", {}).get("url", {}).get("urls", {})
            ],
        }
        if tweets and pinned_tweet_id and pinned_tweets:
            for tweet in tweets:
                tweet_id = tweet.get("id")
                if pinned_tweet_id == tweet_id:
                    dict_to_append["pinned_Tweets"] = {
                        "id": tweet.get("id"),
                        "text": tweet.get("text"),
                        "conversation_id": tweet.get("conversation_id"),
                        "edit_history_tweet_ids": tweet.get("edit_history_tweet_ids"),
                    }
        list_dict_response.append(remove_empty_elements(dict_to_append))
    return list_dict_response


""" COMMAND FUNCTIONS """


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

    client.tweet_search("Twitter", None, None, 10, None)
    message = "ok"
    return message


def date_to_iso_format(date: Optional[str]) -> Optional[str]:
    """Retrieves date string or relational expression to iso format date.
    Args:
        date: str - date or relational expression.
    Returns:
        A str in ISO format or None.
    """
    if date:
        datetime = dateparser.parse(date)
        if datetime:
            date = datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            raise DemistoException("Twitter: Date format is invalid")
    return date


def create_human_readable_search(dict_list: list[dict]) -> list[dict]:
    """Gets list of dictionaries and creates a human readable from it.
    Args:
        dict_list: list[dict] -  A list of dictionaries.
    Returns:
        human readable: list[dict].
    """
    list_dict_response: list = []
    for dict_value in dict_list:
        list_dict_response.append(
            {
                "Tweet ID": dict_value.get("id", {}),
                "Text": dict_value.get("text", ""),
                "Created At": dict_value.get("created_at", {}),
                "Author Name": dict_value.get("author", {}).get("name"),
                "Author Username": dict_value.get("author", {}).get("username"),
                "Likes Count": dict_value.get("public_metrics", {}).get("like_count"),
                "Attachments URL": [item.get("url", "") for item in dict_value.get("media", [])]
                if dict_value.get("media", [])
                else [],
            }
        )
    return list_dict_response


def twitter_tweet_search_command(client: Client, args: Dict[str, Any]) -> List[CommandResults]:
    """Gets args and client and returns CommandResults of Tweets according to the reqested search.
    Args:
        client: client -  A Twitter client.
        args: Dict - The function arguments.
    Returns:
        A list of CommandResults with Tweets data according to to the reqest.
    """
    headers = ["Tweet ID", "Text", "Created At", "Author Name", "Author Username", "Likes Count", "Attachments URL"]
    query = argToList(args.get("query"))
    start_time = date_to_iso_format(args.get("start_time"))
    end_time = date_to_iso_format(args.get("end_time"))
    limit = arg_to_number(args.get("limit", 50))
    next_token = args.get("next_token")
    raw_response = client.tweet_search(query, start_time, end_time, limit, next_token)
    context_data, next_token = create_context_data_search_tweets(raw_response)
    dict_to_tableToMarkdown = create_human_readable_search(context_data)
    human_readable = tableToMarkdown("Tweets search results:", dict_to_tableToMarkdown, headers=headers, removeNull=False)
    command_results = []
    command_results.append(
        CommandResults(
            outputs_prefix="Twitter.Tweet",
            outputs_key_field="id",
            outputs=context_data,
            readable_output=human_readable,
            raw_response=raw_response,
        )
    )
    if next_token:
        readable_output_next_token = tableToMarkdown(
            "Tweet Next Token:", {"next_token": next_token}, headers=["next_token"], removeNull=False
        )
        command_results.append(
            CommandResults(
                outputs={"Twitter(true)": {"TweetNextToken": next_token}},
                readable_output=readable_output_next_token,
            )
        )

    return command_results


def twitter_user_get_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    """Retruns users information according to the requested user's names.
    Args:
        client: client -  A Twitter client.
        args: Dict - The function arguments.
    Returns:
        A CommandResult object with users' data according to the request.
    """
    headers = ["Name", "User name", "Created At", "Description", "Followers Count", "Tweet Count", "Verified"]
    user_name = argToList(args.get("user_name"))
    return_pinned_tweets = args.get("return_pinned_tweets", "false")
    raw_response = client.twitter_user_get(user_name, return_pinned_tweets)
    context_data = create_context_data_get_user(raw_response, return_pinned_tweets)
    contents: list = []
    for dict_value in context_data:
        contents.append(
            {
                "Name": dict_value.get("name"),
                "User name": dict_value.get("username"),
                "Created At": dict_value.get("created_at"),
                "Description": dict_value.get("description"),
                "Followers Count": dict_value.get("public_metrics", {}).get("followers_count"),
                "Tweet Count": dict_value.get("public_metrics", {}).get("tweet_count"),
                "Verified": dict_value.get("verified"),
            }
        )
    human_readable = tableToMarkdown("Twitter user get results:", contents, headers=headers, removeNull=False)
    return CommandResults(
        outputs_prefix="Twitter.User",
        outputs_key_field="id",
        outputs=context_data,
        readable_output=human_readable,
        raw_response=raw_response,
    )


""" MAIN FUNCTION """


def main() -> None:
    bearer_token = demisto.params().get("credentials", {}).get("password")

    # get the service API url
    base_url = urljoin(demisto.params()["url"], "/2")
    verify_certificate = not demisto.params().get("insecure", False)
    proxy = demisto.params().get("proxy", False)

    demisto.debug(f"Command being called is {demisto.command()}")
    try:
        headers: Dict = {"Authorization": f"Bearer {bearer_token}"}
        headers
        client = Client(base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy)

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == "twitter-tweet-search":
            return_results(twitter_tweet_search_command(client, demisto.args()))

        elif demisto.command() == "twitter-user-get":
            return_results(twitter_user_get_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}")


""" ENTRY POINT """


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
