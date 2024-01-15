import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import urllib3
# Disable insecure warnings
urllib3.disable_warnings()

RAPIDAPI_HOST = 'imdb8.p.rapidapi.com'
URL_FIX = 'https://'


class Client(BaseClient):
    def __init__(self, api_key: str, base_url: str, proxy: bool, verify: bool, rapidapi_host: str):
        super().__init__(base_url=base_url, proxy=proxy, verify=verify)
        self.api_key = api_key
        self.rapidapi_host = rapidapi_host

        self._headers = {
            'X-RapidAPI-Key': self.api_key,
            'X-RapidAPI-Host': self.rapidapi_host
        }

    def auto_complete(self, q: str):
        params = {'q': q}
        return self._http_request(method='GET', url_suffix='auto-complete', params=params)

    def most_popular_movies(self, limit: int):
        params = {'limit': limit}
        return self._http_request(method='GET', url_suffix='title/get-most-popular-movies', params=params)

    def get_popular_movies_by_genre(self, genre: str, limit: int):
        params = {'genre': genre, 'limit': limit}
        return self._http_request(method='GET', url_suffix='title/v2/get-popular-movies-by-genre', params=params)

    def get_top_rated_movies(self, limit: int):
        params = {'limit': limit}
        return self._http_request(method='GET', url_suffix='title/get-top-rated-movies', params=params)

    def get_top_rated_shows(self, limit: int):
        params = {'limit': limit}
        return self._http_request(method='GET', url_suffix='title/get-top-rated-tv-shows', params=params)

    def get_reviews(self, tconst: str):
        params = {'tconst': tconst}
        return self._http_request(method='GET', url_suffix='title/get-reviews', params=params)

    def get_overview_details(self, tconst: str):
        params = {'tconst': tconst}
        return self._http_request(method='GET', url_suffix='title/get-overview-details', params=params)

    def get_full_credits(self, tconst: str):
        params = {'tconst': tconst}
        return self._http_request(method='GET', url_suffix='title/get-full-credits', params=params)

    def most_popular_celebs(self, limit: int):
        params = {'limit': limit}
        return self._http_request(method='GET', url_suffix='actors/list-most-popular-celebs', params=params)

    def get_bio(self, nconst: str):
        params = {'nconst': nconst}
        return self._http_request(method='GET', url_suffix='actors/get-bio', params=params)

    def get_known_for(self, nconst: str):
        params = {'nconst': nconst}
        return self._http_request(method='GET', url_suffix='actors/get-known-for', params=params)

    def list_born_today(self, month: int, day: int):
        params = {'month': month, 'day': day}
        return self._http_request(method='GET', url_suffix='actors/list-born-today', params=params)

    def get_all_filmography(self, nconst: str):
        params = {'nconst': nconst}
        return self._http_request(method='GET', url_suffix='actors/get-all-filmography', params=params)


def test_module(client: Client) -> str:

    try:
        response = client.auto_complete('1234567890')

        success = demisto.get(response, 'v')
        if success != 1:
            return f'Unexpected result from the service: success={success} (expected success=1)'

        return 'ok'

    except Exception as e:
        exception_text = str(e).lower()
        if 'message' in exception_text:
            return 'You are not subscribed to this API. Authorization Error: make sure API Key is correctly set.'
        else:
            raise e


def auto_complete_command(client: Client, q: str) -> CommandResults:
    if not q:
        raise DemistoException('The q argument cannot be empty.')

    response = client.auto_complete(q)

    if response is None:
        raise DemistoException('Search query failed: the response from server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'Search query results for {q}', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb',
        outputs_key_field='d',
        outputs={'AutoComplete': response}
    )


def most_popular_movies_command(client: Client, limit: int) -> CommandResults:

    all_response = client.most_popular_movies(limit)

    response = all_response[:int(limit)]

    if response is None:
        raise DemistoException('Get popular movies failed: the response from the server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'{limit} most popular movies this week are:', response, headers=['Movies'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='title',
        outputs={'MostPopularMovies': response}
    )


def get_popular_movies_by_genre_command(client: Client, genre: str, limit: int) -> CommandResults:

    if not genre:
        raise DemistoException('The genre argument cannot be empty.')

    response = client.get_popular_movies_by_genre(genre, limit)

    if response is None:
        raise DemistoException('Get popular movies failed: the response from the server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'Most popular {genre} movies:', response, headers=['Movies'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='title',
        outputs={'MostPopularByGenre': response}
    )


def get_top_rated_movies_command(client: Client, limit: int) -> CommandResults:

    all_response = client.get_top_rated_movies(limit)
    response = all_response[:int(limit)]

    if response is None:
        raise DemistoException('Get top rated movies failed: the response from the server did not return anything.', res=response)
    readable_output = tableToMarkdown(f'{limit} top rated movies:', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='chartRating',
        outputs={'TopRatedMovies': response}
    )


def get_top_rated_shows_command(client: Client, limit: int) -> CommandResults:

    all_response = client.get_top_rated_shows(limit)
    response = all_response[:int(limit)]

    if response is None:
        raise DemistoException('Get top rated shows failed: the response from the server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'{limit} top rated shows:', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='chartRating',
        outputs={'TopRatedShows': response}
    )


def get_reviews_command(client: Client, tconst: str) -> CommandResults:

    if not tconst:
        raise DemistoException('The tconst argument cannot be empty.')

    response = client.get_reviews(tconst)

    if response is None:
        raise DemistoException('Get reviews failed: the response from the server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'Reviews for {tconst}:', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='id',
        outputs={'Reviews': response}
    )


def get_overview_details_command(client: Client, tconst: str) -> CommandResults:

    if not tconst:
        raise DemistoException('The tconst argument cannot be empty.')

    response = client.get_overview_details(tconst)

    if response is None:
        raise DemistoException('Get movie overview details failed: the response from the server did not return anything.',
                               res=response)

    readable_output = tableToMarkdown(f'{tconst} movie overview details', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='id',
        outputs={'Overview': response}
    )


def get_full_credits_command(client: Client, tconst: str) -> CommandResults:

    if not tconst:
        raise DemistoException('The tconst argument cannot be empty.')

    response = client.get_full_credits(tconst)

    if response is None:
        raise DemistoException('Get full credits failed: the response from the server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'Full credits for {tconst}', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Title',
        outputs_key_field='id',
        outputs={'Credits': response}
    )


def most_popular_celebs_command(client: Client, limit: int) -> CommandResults:

    all_response2 = client.most_popular_celebs(limit)

    response = all_response2[:int(limit)]

    if response is None:
        raise DemistoException('Get most popular celebs failed: the response from the server did not return anything.',
                               res=response)

    readable_output = tableToMarkdown(f'{limit} most popular celebs this week are:', response, headers=['Celebs'])

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Celebs',
        outputs_key_field='name',
        outputs={'MostPopular': response}
    )


def get_bio_command(client: Client, nconst: str) -> CommandResults:

    if not nconst:
        raise DemistoException('The nconst argument cannot be empty.')

    response = client.get_bio(nconst)

    if response is None:
        raise DemistoException('Search query failed: the response from server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'Short actor bio for {nconst}:', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Celebs',
        outputs_key_field='id',
        outputs={'Bio': response}
    )


def get_known_for_command(client: Client, nconst: str) -> CommandResults:

    if not nconst:
        raise DemistoException('The nconst argument cannot be empty.')

    response = client.get_known_for(nconst)

    if response is None:
        raise DemistoException('Search query failed: the response from server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'The {nconst} is known for:', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Celebs',
        outputs_key_field='title',
        outputs={'KnownFor': response}
    )


def list_born_today_command(client: Client, month: int, day: int) -> CommandResults:

    if not month or not day:
        raise DemistoException('Month or Day arguments cannot be empty.')

    response = client.list_born_today(month, day)

    if response is None:
        raise DemistoException('List actors born today failed: the response from the server did not return anything.',
                               res=response)

    readable_output = tableToMarkdown(f'Celebrities born {month}/{day}', response, headers=['Celebrity'])  # War Room

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Celebs',
        outputs_key_field='name',
        outputs={'BornToday': response}
    )


def get_all_filmography_command(client: Client, nconst: str) -> CommandResults:

    if not nconst:
        raise DemistoException('The nconst argument cannot be empty.')

    response = client.get_all_filmography(nconst)

    if response is None:
        raise DemistoException('Search query failed: the response from server did not return anything.', res=response)

    readable_output = tableToMarkdown(f'All filmography for {nconst}:', response)

    return CommandResults(
        readable_output=readable_output,
        outputs_prefix='IMDb.Celebs',
        outputs_key_field='id',
        outputs={'AllFilm': response}
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    api_key = params.get('apikey', {}).get('password')
    rapidapi_host = RAPIDAPI_HOST
    base_url = URL_FIX + rapidapi_host
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {command}')
    try:
        client = Client(api_key=api_key, base_url=base_url, rapidapi_host=rapidapi_host, verify=verify, proxy=proxy)

        if command == 'test-module':
            # This is the call made when clicking the integration Test button.
            return_results(test_module(client))

        elif command == 'imdb-auto-complete':
            return_results(auto_complete_command(client, **args))

        elif command == 'imdb-get-most-popular-movies':
            return_results(most_popular_movies_command(client, **args))

        elif command == 'imdb-get-popular-movies-by-genre':
            return_results(get_popular_movies_by_genre_command(client, **args))

        elif command == 'imdb-get-top-rated-movies':
            return_results(get_top_rated_movies_command(client, **args))

        elif command == 'imdb-get-top-rated-shows':
            return_results(get_top_rated_shows_command(client, **args))

        elif command == 'imdb-get-reviews':
            return_results(get_reviews_command(client, **args))

        elif command == 'imdb-get-overview-details':
            return_results(get_overview_details_command(client, **args))

        elif command == 'imdb-get-full-credits':
            return_results(get_full_credits_command(client, **args))

        elif command == 'imdb-list-most-popular-celebs':
            return_results(most_popular_celebs_command(client, **args))

        elif command == 'imdb-get-bio':
            return_results(get_bio_command(client, **args))

        elif command == 'imdb-get-known-for':
            return_results(get_known_for_command(client, **args))

        elif command == 'imdb-list-born-today':
            return_results(list_born_today_command(client, **args))

        elif command == 'imdb-get-all-filmography':
            return_results(get_all_filmography_command(client, **args))

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error("\n".join((f"Failed to execute {command} command.",
                                "Error:",
                                str(e))))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
