Twitter integration provide access to searching recent tweets (in last 7 days) and user information using twitter v2 API
This integration was integrated and tested with version v2 of Twitter API.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-twitter-v2).

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
This command will search for tweets posted over the past week and return all information available


#### Base Command

`twitter-tweet-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Search query to submit to the recent search endpoint. | Required | 
| start_time | The oldest UTC timestamp (from most recent seven days) from which the Tweets will be provided. | Optional | 
| end_time | The most recent UTC timestamp to which the Tweets will be provided. | Optional | 
| limit | Maximum number of results to return a number between 10 and 100. Default value is 50. Default is 50. | Optional | 
| next_token | When you request a list of objects with a MaxResults setting, if the number of objects that are still available for retrieval exceeds the maximum you requested, Twitter returns a NextToken value in the response. To retrieve the next batch of objects, use the token returned from the prior request in your next request. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twitter.Tweet.conversation_id | String | The Tweet ID of the original Tweet of the conversation \(which includes direct replies, replies of replies\). | 
| Twitter.Tweet.id | String | Unique identifier of this Tweet. | 
| Twitter.Tweet.created_at | Date | Creation time of the Tweet. | 
| Twitter.Tweet.text | String | The content of the Tweet. | 
| Twitter.Tweet.edit_history_tweet_ids | String | Unique identifiers indicating all versions of an edited Tweet. | 
| Twitter.Tweet.next_token | String | A value that encodes the next 'page' of results that can be requested, via the next_token request parameter. | 
| Twitter.Tweet.public_metrics.retweet_count | Number | Number of times this Tweet has been Retweeted. | 
| Twitter.Tweet.public_metrics.reply_count | Number | Number of Replies of this Tweet. | 
| Twitter.Tweet.public_metrics.like_count | Number | Number of Likes of this Tweet. | 
| Twitter.Tweet.public_metrics.quote_count | Number | Number of times this Tweet has been Retweeted with a comment. | 
| Twitter.Tweet.author.name | String | The unique identifier of this user. | 
| Twitter.Tweet.author.verified | Boolean | Indicates if this user is a verified Twitter User. | 
| Twitter.Tweet.author.description | String | The text of this user's profile description \(also known as bio\), if the user provided one. | 
| Twitter.Tweet.author.id | String | The unique identifier of this user. | 
| Twitter.Tweet.author.created_at | Date | The UTC datetime that the user account was created on Twitter. | 
| Twitter.Tweet.author.username | String | The Twitter screen name, handle, or alias that this user identifies themselves with. | 
| Twitter.Tweet.media.type | String | Type of content \(animated_gif, photo, video\). | 
| Twitter.Tweet.media.url | String | A direct URL to the media file on Twitter. | 
| Twitter.Tweet.media.media_key | String | Unique identifier of the expanded media content | 
| Twitter.Tweet.media.alt_text | String | A description of an image to enable and support accessibility. Can be up to 1000 characters long. | 
| Twitter.tweet_next_token | String | A value that encodes the next 'page' of results that can be requested, via the next_token request parameter. | 

#### Command example
```!twitter-tweet-search query="twitter" limit="10"```

### twitter-user-get
***
Lookup users by name to display information about them.Search multiple users simultaneously by separating them by commas. Ex: 'name='user1,user2,user3'


#### Base Command

`twitter-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_name | A comma separated list of Twitter usernames (handles). Up to 100 are allowed in a single request. | Required | 
| return_pinned_tweets | Indicates whether to return user's pinned Tweets. Possible values are: true, false. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Twitter.User.name | String | The friendly name of this user, as shown on their profile. | 
| Twitter.User.username | String | The Twitter handle \(screen name\) of this user. | 
| Twitter.User.created_at | Date | Creation time of this account. | 
| Twitter.User.description | String | The text of this user's profile description \(also known as bio\), if the user provided one. | 
| Twitter.User.id | String | Unique identifier of this user. | 
| Twitter.User.location | String | The location specified in the user's profile. | 
| Twitter.User.pinned_tweet_id | String | nique identifier of this user's pinned Tweet. | 
| Twitter.User.profile_image_url | String | The URL to the profile image for this user, as shown on the user's profile. | 
| Twitter.User.protected | Boolean | Indicates if this user has chosen to protect their Tweets \(in other words, if this user's Tweets are private\). | 
| Twitter.User.public_metrics.followers_count | Number | Number of users who follow this user. | 
| Twitter.User.public_metrics.following_count | Number | Number of users this user is following. | 
| Twitter.User.public_metrics.tweet_count | Number | Number of Tweets \(including Retweets\) posted by this user. | 
| Twitter.User.public_metrics.listed_count | Number | Number of lists that include this user. | 
| Twitter.User.url | String | The URL specified in the user's profile, if present. | 
| Twitter.User.verified | Boolean | Indicate if this user is a verified Twitter user. | 
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
| Twitter.User.pinned_tweets.reply_count | Number | Number of Replies of this Tweet. | 
| Twitter.User.Pinned_tweets.like_count | Number | Number of Likes of this Tweet. | 
| Twitter.User.pinned_tweets.quote_count | Number | Number of times this Tweet has been Retweeted with a comment. | 

#### Command example
```!twitter-user-get user_name="Twitter"```

## Breaking changes from the previous version of this integration - Twitter v2
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.