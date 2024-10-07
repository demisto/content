Twitter integration provides access to searching recent Tweets (in last 7 days) and user information using the Twitter v2 API.
This integration was integrated and tested with version v2 of Twitter API.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-twitter-v2).

## Configure Twitter v2 in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL |  | True |
| Bearer Token | The Bearer Token to use for connection | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### twitter-tweet-search
***
This command will search for Tweets from the last 7 days and return all information available.


#### Base Command

`twitter-tweet-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A comma-seperated list of keywords to submit to the recent search endpoint. | Required | 
| start_time | The oldest UTC timestamp (from most recent seven days) from which the Tweets will be provided. Date format will be in ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ) or relational expressions like “7 days ago”. | Optional | 
| end_time | The most recent UTC timestamp to which the Tweets will be provided. Date format will be in ISO 8601 format (YYYY-MM-DDTHH:mm:ssZ) or relational expressions like “7 days ago”. | Optional | 
| limit | Maximum number of results to return. Value can be between 10 and 100. Default is 50. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Twitter returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twitter.Tweet.conversation_id | String | The Tweet ID of the original Tweet of the conversation \(which includes direct replies, replies of replies\). | 
| Twitter.Tweet.id | String | Unique identifier of this Tweet. | 
| Twitter.Tweet.created_at | Date | Creation time of the Tweet. | 
| Twitter.Tweet.text | String | The content of the Tweet. | 
| Twitter.Tweet.edit_history_tweet_ids | String | Unique identifiers indicating all versions of an edited Tweet. | 
| Twitter.Tweet.public_metrics.impression_count | Number | Number of times the Tweet has been seen. | 
| Twitter.Tweet.public_metrics.retweet_count | Number | Number of times this Tweet has been Retweeted. | 
| Twitter.Tweet.public_metrics.reply_count | Number | Number of replies to this Tweet. | 
| Twitter.Tweet.public_metrics.like_count | Number | Number of Likes to this Tweet. | 
| Twitter.Tweet.public_metrics.quote_count | Number | Number of times this Tweet has been Retweeted with a comment. | 
| Twitter.Tweet.author.name | String | The unique identifier of this user. | 
| Twitter.Tweet.author.verified | Boolean | Indicates if this user is a verified Twitter user. | 
| Twitter.Tweet.author.description | String | The text of this user's profile description \(also known as bio\), if the user provided one. | 
| Twitter.Tweet.author.id | String | The unique identifier of this user. | 
| Twitter.Tweet.author.created_at | Date | The UTC datetime when the user account was created on Twitter. | 
| Twitter.Tweet.author.username | String | The Twitter screen name, handle, or alias that this user identifies themselves with. | 
| Twitter.Tweet.media.type | String | Type of content \(animated_gif, photo, video\). | 
| Twitter.Tweet.media.url | String | A direct URL to the media file on Twitter. | 
| Twitter.Tweet.media.media_key | String | Unique identifier of the expanded media content | 
| Twitter.Tweet.media.alt_text | String | A description of an image to enable and support accessibility. Can be up to 1000 characters long. | 
| Twitter.TweetNextToken | String | A value that encodes the next 'page' of results that can be requested, via the next_token request parameter. | 

#### Command example
```!twitter-tweet-search query="twitter" limit="10"```
#### Context Example
```json
{
    "Twitter": {
        "Tweet":  [
                {
                    "author": {
                        "created_at": "2023-01-18T23:35:28.000Z",
                        "description": "some_description",
                        "id": "2929292929292929292",
                        "name": "some_name_1",
                        "username": "some_username_1",
                        "verified": false
                    },
                    "conversation_id": "2323232323232323232",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "2323232323232323232"
                    ],
                    "id": "2323232323232323232",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 5822
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2017-10-19T18:40:34.000Z",
                        "description": "some_description",
                        "id": "2020202020202020202",
                        "name": "some_name_2",
                        "username": "some_username_2",
                        "verified": false
                    },
                    "conversation_id": "1010101010101010101",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "1010101010101010101"
                    ],
                    "id": "1010101010101010101",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 20
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2023-02-02T07:40:50.000Z",
                        "description": "some_description",
                        "id": "1313131313131313131",
                        "name": "some_name_3",
                        "username": "some_username_3",
                        "verified": false
                    },
                    "conversation_id": "1515151515151515151",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "1515151515151515151"
                    ],
                    "id": "1515151515151515151",
                    "media": [
                        {
                            "media_key": "4_4444444444444444444",
                            "type": "photo",
                            "url": "https://url.jpg"
                        }
                    ],
                    "public_metrics": {
                        "impression_count": 1,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 0
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2017-03-25T01:59:34.000Z",
                        "description": "some_description",
                        "id": "845455085635293184",
                        "name": "some_name_5",
                        "username": "some_username_5",
                        "verified": false
                    },
                    "conversation_id": "1212121212121212121",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "1212121212121212121"
                    ],
                    "id": "1212121212121212121",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 114
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2014-04-21T09:26:32.000Z",
                        "description": "some_description",
                        "id": "2456260950",
                        "name": "some_name_4",
                        "username": "some_username_4",
                        "verified": false
                    },
                    "conversation_id": "0808080808080808080",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "0808080808080808080"
                    ],
                    "id": "0808080808080808080",
                    "media": [
                        {
                            "media_key": "5_5555555555555555555",
                            "type": "photo",
                            "url": "https://url.jpg"
                        }
                    ],
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 846
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2017-07-18T14:56:15.000Z",
                        "description": "some_description",
                        "id": "2424242424242424242",
                        "name": "some_name_6",
                        "username": "some_username_6",
                        "verified": false
                    },
                    "conversation_id": "0707070707070707070",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "0707070707070707070"
                    ],
                    "id": "0707070707070707070",
                    "media": [
                        {
                            "media_key": "3_3333333333333333333",
                            "type": "photo",
                            "url": "https://url.jpg"
                        }
                    ],
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 0
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2022-05-08T07:49:51.000Z",
                        "description": "some_description",
                        "id": "6060606060606006060",
                        "name": "some_name_7",
                        "username": "some_username_7",
                        "verified": false
                    },
                    "conversation_id": "5050505050505050505",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "5050505050505050505"
                    ],
                    "id": "5050505050505050505",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 73
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2022-10-11T11:11:10.000Z",
                        "description": "some_description",
                        "id": "4040404040404040404",
                        "name": "some_name_8",
                        "username": "some_username_8",
                        "verified": false
                    },
                    "conversation_id": "3030303030303030303",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "3030303030303030303"
                    ],
                    "id": "3030303030303030303",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 37
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2020-07-09T13:06:54.000Z",
                        "description": "",
                        "id": "2727272727272727272",
                        "name": "some_name_9",
                        "username": "some_username_9",
                        "verified": false
                    },
                    "conversation_id": "2626262626262626262",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "2626262626262626262"
                    ],
                    "id": "2626262626262626262",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 4273
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2017-01-15T11:11:11.000Z",
                        "description": "some_description",
                        "id": "2828282828282828282",
                        "name": "some_name_10",
                        "username": "some_username_10",
                        "verified": false
                    },
                    "conversation_id": "2525252525252525252",
                    "created_at": "2023-04-05T08:49:23.000Z",
                    "edit_history_tweet_ids": [
                        "2525252525252525252"
                    ],
                    "id": "2525252525252525252",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 22741
                    },
                    "text": "some_text_twitter"
                }
            ],
        "TweetNextToken": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    }
}
```

#### Human Readable Output

>### Tweet Next Token:
>|next_token|
>|---|
>| xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |

>### Tweets search results:
>|Tweet ID|Text|Created At|Author Name|Author Username|Likes Count|Attachments URL|
>|---|---|---|---|---|---|---|
>| 2323232323232323232 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_1 | some_username_1 | 0 |  |
>| 1010101010101010101 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_2 | some_username_2 | 0 |  |
>| 1515151515151515151 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_3 | some_username_3 | 0 | https://url.jpg |
>| 1212121212121212121 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_5 | some_username_5 | 0 |  |
>| 0808080808080808080 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_4 | some_username_4 | 0 | https://url.jpg |
>| 0707070707070707070 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_6 | some_username_6 | 0 | https://url.jpg |
>| 5050505050505050505 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_7 | some_username_7 | 0 |  |
>| 3030303030303030303 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_8 | some_username_8 | 0 |  |
>| 2626262626262626262 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_9 | some_username_9 | 0 |  |
>| 2525252525252525252 | some_text_twitter | 2023-04-05T08:49:23.000Z | some_name_10 | some_username_10 | 0 |  |
### twitter-user-get
***
Lookup users by name to display information about them. Search multiple users simultaneously by separating them by commas. Ex: 'name='user1,user2,user3'


#### Base Command

`twitter-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_name | A comma-separated list of Twitter usernames (handles). Up to 100 are allowed in a single request. | Required | 
| return_pinned_tweets | Indicates whether to return a user's pinned Tweets. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twitter.User.name | String | The friendly name of this user, as shown on their profile. | 
| Twitter.User.username | String | The Twitter handle \(screen name\) of this user. | 
| Twitter.User.created_at | Date | Creation time of this account. | 
| Twitter.User.description | String | The text of this user's profile description \(also known as bio\), if the user provided one. | 
| Twitter.User.id | String | Unique identifier of this user. | 
| Twitter.User.location | String | The location specified in the user's profile. | 
| Twitter.User.pinned_tweet_id | String | Unique identifier of this user's pinned Tweet. | 
| Twitter.User.profile_image_url | String | The URL to the profile image for this user, as shown on the user's profile. | 
| Twitter.User.protected | Boolean | Indicates if this user has chosen to protect their Tweets \(in other words, if this user's Tweets are private\). | 
| Twitter.User.public_metrics.followers_count | Number | Number of users who follow this user. | 
| Twitter.User.public_metrics.following_count | Number | Number of users this user is following. | 
| Twitter.User.public_metrics.tweet_count | Number | Number of Tweets \(including Retweets\) posted by this user. | 
| Twitter.User.public_metrics.listed_count | Number | Number of lists that include this user. | 
| Twitter.User.url | String | The URL specified in the user's profile, if present. | 
| Twitter.User.verified | Boolean | Indicates if this user is a verified Twitter user. | 
| Twitter.User.withheld | String | Contains withholding details for withheld content. | 
| Twitter.User.entities.url | String | Contains details about the user's profile website. | 
| Twitter.User.entities.expanded_url | String | The fully resolved URL. | 
| Twitter.User.entities.display_url | String | The URL as displayed in the user's profile. | 
| Twitter.User.pinned_tweets.id | String | Unique identifier of this user's pinned Tweet. | 
| Twitter.User.pinned_tweets.text | String | The content of the Tweet. | 
| Twitter.User.pinned_tweets.conversation_id | String | The Tweet ID of the original Tweet of the conversation \(which includes direct replies, replies of replies\). | 
| Twitter.User.pinned_tweets.created_at | Date | Creation time of the Tweet. | 
| Twitter.User.pinned_tweets.edit_history_tweet_ids | String | Unique identifiers indicating all versions of an edited Tweet. | 
| Twitter.User.pinned_tweets.retweet_count | Number | Number of times this Tweet has been Retweeted. | 
| Twitter.User.pinned_tweets.reply_count | Number | Number of Replies to this Tweet. | 
| Twitter.User.Pinned_tweets.like_count | Number | Number of Likes to this Tweet. | 
| Twitter.User.pinned_tweets.quote_count | Number | Number of times this Tweet has been Retweeted with a comment. | 

#### Command example
```!twitter-user-get user_name="Twitter"```
#### Context Example
```json
{
    "Twitter": {
        "User": {
            "created_at": "2006-06-15T14:35:54.000Z",
            "description": "description",
            "entities": [
                {
                    "display_url": "url.com",
                    "expanded_url": "https://url.com/",
                    "url": "https://url"
                }
            ],
            "id": "111111",
            "location": "everywhere",
            "name": "Twitter",
            "profile_image_url": "https://url.jpg",
            "protected": false,
            "public_metrics": {
                "followers_count": 65450397,
                "following_count": 5,
                "listed_count": 87323,
                "tweet_count": 15046
            },
            "url": "https://url",
            "username": "Twitter",
            "verified": true
        }
    }
}
```

#### Human Readable Output

>### twitter user get results:
>|Name|User name|Created At|Description|Followers Count|Tweet Count|verified|
>|---|---|---|---|---|---|---|
>| Twitter | Twitter | 2006-06-15T14:35:54.000Z | description | 11111111 | 15046 | true |


## Breaking changes from the previous version of this integration - Twitter v2
The following sections lists the changes in this version.

### Commands
#### The following commands were removed in this version:
* ***twitter-get-user-info*** - this command was removed.
* ***twitter-get-users*** - this command was replaced by ***twitter-user-get***.
* ***twitter-get-tweets*** - this command was replaced by ***twitter-tweet-search***.

## Additional Considerations for this version
Only a Bearer Token is needed in order to configure this integration.