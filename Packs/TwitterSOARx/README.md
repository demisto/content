# TwitterSOARx

twitter-get-users
This command executes a search for users given a specified query. It will then return the results of the search in markdown format in the war room. This command uses Tweepy’s API to authenticate using OAuth 1.0 and then to perform the search function.

Arguments: 
name, page, count, include_entities

Underlying design:
Makes an API call to Twitter API v1.1 GET users/search, which provides relevance-based search results of public user accounts. This search is performed through Tweepy using the api call API.search_users. The results are returned in JSON format. The JSON results will then be neatly displayed in the War Room in Markdown format.

twitter-get-user-info
This command returns detailed account information about specified accounts.
 
Arguments: 
usernnames

Underlying design:
Makes an API call to Twitter API v2 GET /2/users/ which provides information about a specified user. The information provided includes the user’s description, entities, date of creation, id, location, name, pinned tweet id, profile image url, protected status, public metrics, url, username, and verified status. 

twitter-get-tweets
This command executes a search for tweets given a specified query. It will then return the results of the search in markdown format in the war room.

Arguments:
q, geocode, lang, result_type, count, include_entities, from_user, to_user

Underlying design:
Makes an API call to Twitter API v1.1 search tweets, (https://api.twitter.com/1.1/search/tweets.json) which provides relevance-based search results of public tweets. The results are returned in JSON format. The JSON results will then be neatly displayed in the War Room in Markdown format.

Please visit the TwitterSOARx Design Document for more information.
