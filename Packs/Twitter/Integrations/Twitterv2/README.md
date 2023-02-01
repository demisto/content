Twitter integration provides access to searching recent Tweets (in last 7 days) and user information using the Twitter v2 API.
This integration was integrated and tested with version v2 of Twitter API.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration---twitter-v2).

## Configure Twitter v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Twitter v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | Bearer Token | The Bearer Token to use for connection | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### twitter-tweet-search
***
This command will search for Tweets posted over the past week and return all information available.


#### Base Command

`twitter-tweet-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query to submit to the recent search endpoint. | Required | 
| start_time | The oldest UTC timestamp (from most recent seven days) from which the Tweets will be provided. Date format will be in ISO 8601 format or relational expressions like “7 days ago”. | Optional | 
| end_time | The most recent UTC timestamp to which the Tweets will be provided. Date format will be in ISO 8601 format or relational expressions like “7 days ago”. | Optional | 
| limit | Maximum number of results to return. Value can be between 10 and 100. Default is 50. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Twitter returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twitter.Tweet.TweetList.conversation_id | String | The Tweet ID of the original Tweet of the conversation \(which includes direct replies, replies of replies\). | 
| Twitter.Tweet.TweetList.id | String | Unique identifier of this Tweet. | 
| Twitter.Tweet.TweetList.created_at | Date | Creation time of the Tweet. | 
| Twitter.Tweet.TweetList.text | String | The content of the Tweet. | 
| Twitter.Tweet.TweetList.edit_history_tweet_ids | String | Unique identifiers indicating all versions of an edited Tweet. | 
| Twitter.Tweet.TweetList.public_metrics.impression_count | Number | Number of times the Tweet has been seen. | 
| Twitter.Tweet.TweetList.public_metrics.retweet_count | Number | Number of times this Tweet has been Retweeted. | 
| Twitter.Tweet.TweetList.public_metrics.reply_count | Number | Number of replies to this Tweet. | 
| Twitter.Tweet.TweetList.public_metrics.like_count | Number | Number of Likes to this Tweet. | 
| Twitter.Tweet.TweetList.public_metrics.quote_count | Number | Number of times this Tweet has been Retweeted with a comment. | 
| Twitter.Tweet.TweetList.author.name | String | The unique identifier of this user. | 
| Twitter.Tweet.TweetList.author.verified | Boolean | Indicates if this user is a verified Twitter user. | 
| Twitter.Tweet.TweetList.author.description | String | The text of this user's profile description \(also known as bio\), if the user provided one. | 
| Twitter.Tweet.TweetList.author.id | String | The unique identifier of this user. | 
| Twitter.Tweet.TweetList.author.created_at | Date | The UTC datetime when the user account was created on Twitter. | 
| Twitter.Tweet.TweetList.author.username | String | The Twitter screen name, handle, or alias that this user identifies themselves with. | 
| Twitter.Tweet.TweetList.media.type | String | Type of content \(animated_gif, photo, video\). | 
| Twitter.Tweet.TweetList.media.url | String | A direct URL to the media file on Twitter. | 
| Twitter.Tweet.TweetList.media.media_key | String | Unique identifier of the expanded media content. | 
| Twitter.Tweet.TweetList.media.alt_text | String | A description of an image to enable and support accessibility. Can be up to 1000 characters long. | 
| Twitter.Tweet.NextToken.next_token | String | A value that encodes the next 'page' of results that can be requested, via the next_token request parameter. | 

#### Command example
```!twitter-tweet-search query="twitter" limit="10"```
#### Context Example
```json
{
    "Twitter": {
        "Tweet": {
            "TweetList": [
                {
                    "author": {
                        "created_at": "2006-03-21T06:33:38.000Z",
                        "description": "some_description",
                        "id": "1111111111",
                        "name": "some_name_1",
                        "username": "some_username_1",
                        "verified": false
                    },
                    "conversation_id": "2323232323232323232",
                    "created_at": "2024-01-19T12:58:27.000Z",
                    "edit_history_tweet_ids": [
                        "2323232323232323232"
                    ],
                    "id": "2323232323232323232",
                    "media": {
                        "media_key": "3_3333333333333333333",
                        "type": "photo",
                        "url": "https://url.jpg"
                    },
                    "public_metrics": {
                        "impression_count": 59,
                        "like_count": 2,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 0
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2006-02-12T12:12:07.000Z",
                        "description": "some_description",
                        "id": "2222222222",
                        "name": "some_name_2",
                        "username": "some_username_2",
                        "verified": false
                    },
                    "conversation_id": "2626262626262626262",
                    "created_at": "2024-01-18T23:37:11.000Z",
                    "edit_history_tweet_ids": [
                        "2626262626262626262"
                    ],
                    "id": "2626262626262626262",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 2
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2006-09-29T19:59:28.000Z",
                        "description": "some_description",
                        "id": "3333333333",
                        "name": "some_name_3",
                        "username": "some_username_3",
                        "verified": false
                    },
                    "conversation_id": "2828282828282828282",
                    "created_at": "2024-01-19T16:45:42.000Z",
                    "edit_history_tweet_ids": [
                        "2828282828282828282"
                    ],
                    "id": "2828282828282828282",
                    "public_metrics": {
                        "impression_count": 0,
                        "like_count": 0,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 2
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2006-04-24T20:56:19.000Z",
                        "description": "some_description",
                        "id": "4444444444",
                        "name": "some_name_4",
                        "username": "some_username_4",
                        "verified": false
                    },
                    "conversation_id": "4040404040404040404",
                    "created_at": "2024-01-17T15:30:22.000Z",
                    "edit_history_tweet_ids": [
                        "2525252525252525252"
                    ],
                    "id": "2525252525252525252",
                    "public_metrics": {
                        "impression_count": 1402,
                        "like_count": 27,
                        "quote_count": 0,
                        "reply_count": 1,
                        "retweet_count": 2
                    },
                    "text": "some_text_twitter"
                },
                {
                    "author": {
                        "created_at": "2006-05-14T08:59:05.000Z",
                        "description": "some_description",
                        "id": "5555555555",
                        "name": "some_name_5",
                        "username": "some_username_5",
                        "verified": false
                    },
                    "conversation_id": "2424242424242424242",
                    "created_at": "2024-01-20T20:54:50.000Z",
                    "edit_history_tweet_ids": [
                        "2424242424242424242"
                    ],
                    "id": "2424242424242424242",
                    "public_metrics": {
                        "impression_count": 43,
                        "like_count": 2,
                        "quote_count": 0,
                        "reply_count": 0,
                        "retweet_count": 0
                    },
                    "text": "some_text_twitter"
                }
            ],
            "next_token":  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        }
    }
}
```

#### Human Readable Output

>### Tweets search results:
>|Tweet ID|Text|Created At|Author Name|Author Username|Likes Count|Attachments URL|
>|---|---|---|---|---|---|---|
>| 2323232323232323232 | some_text_twitter | 2024-01-19T12:58:27.000Z | some_name_1 | some_username_1 | 2 | https:<span>//</span>url.jpg |
>| 2626262626262626262 | some_text_twitter | 2024-01-18T23:37:11.000Z | some_name_2 | some_username_2 | 0 |  |
>| 2828282828282828282 | some_text_twitter | 2024-01-19T16:45:42.000Z | some_name_3 | some_username_3 | 0 |  |
>| 2525252525252525252 | some_text_twitter | 2024-01-17T15:30:22.000Z | some_name_4 | some_username_4 | 27 |  |
>| 2424242424242424242 | some_text_twitter | 2024-01-20T20:54:50.000Z | some_name_5 | some_username_5 | 2 |  |

>### Tweet Next Token:
>|Next Token|
>|---|
>| xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx |

### twitter-user-get
***
Lookup users by name to display information about them. Search multiple users simultaneously by separating them by commas. Ex: 'name='user1,user2,user3'.


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
| Twitter.User.pinned_tweets.reply_count | Number | Number of replies to this Tweet. | 
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
