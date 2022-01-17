## Definitions
Entities: Provide metadata about context posted on Twitter. Examples of entities include hashtags, user mentions, links, stock images, symbols, polls, and attached media.

Relevant Result - A result that may be of interest to the person conducting the search; Any result that appears within the first 30 results of the customized search

Non-Relevant Result - Any result that is does not classify as a Relevant-Result

Public Account - A Twitter account that anyone can view. All of the information shared by the account is viewable by the general public.

Public Metrics - Public information about the account. Includes Followers Count, Following Count, Listed Count, and Tweet count.

Private Account - A Twitter account that only an approved list of people can view. All of the information shared by the account is viewable by only those who have sent requests to follow the private account and the owner of the account has accepted the request

# Requirements
## Authentication
Twitter requires authentication for most of its endpoints. There are 5 main credentials within Twitter’s Authentication:

API Key - Like a username, this allows you to make a request on behalf of your app when combined with API Key Secret.
API Key Secret - Like a password, this allows you to make a request on behalf of your app when combined with API Key.
Access Token - This token allows you to make a request on behalf of the Twitter account that owns the App when combined with the Access token secret.
Access Token Secret - This token allows you to make a request on behalf of the Twitter account that owns the App when combined with the Access token.
Bearer Token - A credential used to allow the app to authenticate requests that do not require the API Keys or Access tokens.

Clients will need to provide their own API Key, API Key Secret, Access token,  Access Token Secret, and Bearer Token. Since Twitter has a request limit, the customer will need to use their own keys. This allows each user to have their own rate limit rather than the community sharing a rate limit. In cases where API keys are not needed, just the Bearer Token will suffice. Tweepy has a built-in OAuth handler; and Twitter uses OAuth to authenticate its users. By storing the user’s API Key, API Secret Key, Access token, and Access Token Secret in an integration parameter and passing them to Tweepy’s OAuth Handler, the user’s requests can get authenticated automatically. The stored keys/tokens will be encrypted to protect the confidentiality of the user’s information. After installing the integration, the user can navigate to Settings > Integrations > Twitter Integration > Add Instance, and enter their keys/tokens in the corresponding text boxes under the “Instance Settings” tab on the left of the window.

Clients can apply for a Twitter Developer Account to obtain these credentials here: https://developer.twitter.com/en/apply-for-access

# Commands:

## twitter-get-users
This command executes a search for users given a specified query. It will then return the results of the search in markdown format in the war room. This command uses Tweepy’s API to authenticate using OAuth 1.0 and then to perform the search function.

## Arguments: 

### name **Required**
The name of accounts to search; Twitter will return accounts with similar names to the one enetered in this argument
### page
The search page to retrieve results from
### count
The maximum number of potential users to retrieve per page. The maximum value is 20. The default value is 15.
### include_entities
The entities node will not be displayed when set to false. The default value is false.

Underlying design:
Makes an API call to Twitter API v1.1 GET users/search, which provides relevance-based search results of public user accounts. This search is performed through Tweepy using the api call API.search_users. The results are returned in JSON format. The JSON results will then be neatly displayed in the War Room in Markdown format.

## Example
!twitter-get-users name=”Palo Alto Networks” page=”1” count=”5” include_entities=”True”
Returns user accounts with names matching or similar to “Palo Alto Networks” located on page 1 of Twitter’s search results, and a maximum of 5 accounts will be displayed. 

### twitter-get-user-info
This command returns detailed account information about specified accounts.
 
## Arguments: 

### usernnames **Required**
The username of a given account to search for additional information.

Underlying design:
Makes an API call to Twitter API v2 GET /2/users/ which provides information about a specified user. The information provided includes the user’s description, entities, date of creation, id, location, name, pinned tweet id, profile image url, protected status, public metrics, url, username, and verified status. 

## Example
!twitter-get-user-info usernames=”PaloAltoNtwks”
Returns the description, entities, date of creation, id, location, name, pinned tweet id, profile image url, protected status, public metrics, url, username, and verified status of the account whose username is “PaloAltoNtwks”.

## twitter-get-tweets
This command executes a search for tweets given a specified query. It will then return the results of the search in markdown format in the war room.

## Arguments:
### q **Required**
The tweet content to search; Twitter will return tweets containing strings matching or similar to the one entered in this argument.
### geocode
Returns tweets by users located within a specified radius of a specified latitude/longitude.
### lang
Only displays tweets of the specified language, given in ISO 639-1 code.
### result_type
Specifies which type of search results the user would like to display. Recent: Returns only the most recent results. Popular: Returns only the most popular results Mixed: Returns a mix of both recent and popular results.
### count
The number of tweets to return per page. Max: 100
### include_entities
The entities node will not be displayed when set to false. The default value is true.
### from_user
The name of the user to search tweets by. All tweets returned will only have been made from the specified account.
### to_user
The name of the user to search replies by. All tweets returned will only have been made in reply to the specified account.

Underlying design:
Makes an API call to Twitter API v1.1 search tweets, (https://api.twitter.com/1.1/search/tweets.json) which provides relevance-based search results of public tweets. The results are returned in JSON format. The JSON results will then be neatly displayed in the War Room in Markdown format.

## Example
!twitter-get-tweets content=”xsoar” geocode=”28.738659 -111.193820 10mi” lang=”ru” result_type=”recent” count=”10” include_entities=”True”
Returns the 10 most recent tweets (in the russian language) containing the string “xsoar” that are located within 10 miles of 28.738659 -111.193820. 
