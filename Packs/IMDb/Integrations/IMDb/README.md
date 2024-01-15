IMDb helps to query for all information about films, actors, characters, etc & as on official websites.
This integration was integrated and tested with version xx of IMDb.

## Configure IMDb on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IMDb.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | API Key | Your API key after you subscribe to IMDb freemium in RapidAPI | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### imdb-auto-complete

***
Get auto complete suggestion by term or phrase

#### Base Command

`imdb-auto-complete`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| q | Anything that you are familiar with, such as : name of title, album, song, etc. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.AutoComplete.d.i.imageUrl | String | URL of the image | 
| IMDb.AutoComplete.d.id | String | ID of the query result | 
| IMDb.AutoComplete.d.l | String | Name of the movie, tv show, video... | 
| IMDb.AutoComplete.d.s | String | Stars | 
| IMDb.AutoComplete.d.q | String | E.g. TV short, Video... | 
| IMDb.AutoComplete.d.qid | String | E.g. movie, tvSeries, tvshort, video... | 
| IMDb.AutoComplete.d.rank | Number | Rank of the show or movie | 
| IMDb.AutoComplete.d.y | Number | Year | 
| IMDb.AutoComplete.d.yr | String | Years | 

#### Command example
```!imdb-auto-complete q=heat```
#### Context Example
```json
{
    "IMDb": {
        "AutoComplete": {
            "d": [
                {
                    "i": {
                        "height": 2956,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BYjZjNTJlZGUtZTE1Ny00ZDc4LTgwYjUtMzk0NDgwYzZjYTk1XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
                        "width": 2057
                    },
                    "id": "tt0113277",
                    "l": "Heat",
                    "q": "feature",
                    "qid": "movie",
                    "rank": 336,
                    "s": "Al Pacino, Robert De Niro",
                    "y": 1995
                },
                {
                    "i": {
                        "height": 375,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BMjQzNjM5OTYzM15BMl5BanBnXkFtZTgwNDkxMzEyOTE@._V1_.jpg",
                        "width": 500
                    },
                    "id": "tt0094484",
                    "l": "In the Heat of the Night",
                    "q": "TV series",
                    "qid": "tvSeries",
                    "rank": 2830,
                    "s": "Carroll O'Connor, Alan Autry",
                    "y": 1988,
                    "yr": "1988-1995"
                },
                {
                    "i": {
                        "height": 2885,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BZDM1MTM4NGYtZDNjYy00ZDA5LTk4NTctYzg2OTVjZGRiODY3XkEyXkFqcGdeQXVyMTUzMDUzNTI3._V1_.jpg",
                        "width": 1889
                    },
                    "id": "tt0061811",
                    "l": "In the Heat of the Night",
                    "q": "feature",
                    "qid": "movie",
                    "rank": 3009,
                    "s": "Sidney Poitier, Rod Steiger",
                    "y": 1967
                },
                {
                    "i": {
                        "height": 1500,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BZGY2YzliN2ItYzM1MS00MjVlLWFhNDYtODE1NzI2ZjJmYjdjL2ltYWdlL2ltYWdlXkEyXkFqcGdeQXVyNzc5MjA3OA@@._V1_.jpg",
                        "width": 985
                    },
                    "id": "tt0071266",
                    "l": "Caged Heat",
                    "q": "feature",
                    "qid": "movie",
                    "rank": 2999,
                    "s": "Juanita Brown, Erica Gavin",
                    "y": 1974
                },
                {
                    "i": {
                        "height": 400,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BMTI2NTY0NzA4MF5BMl5BanBnXkFtZTYwMjE1MDE0._V1_.jpg",
                        "width": 267
                    },
                    "id": "nm0005132",
                    "l": "Heath Ledger",
                    "rank": 679,
                    "s": "Actor, Brokeback Mountain (2005)"
                },
                {
                    "i": {
                        "height": 1838,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BMjA2MDQ2ODM3MV5BMl5BanBnXkFtZTcwNDUzMTQ3OQ@@._V1_.jpg",
                        "width": 1240
                    },
                    "id": "tt2404463",
                    "l": "The Heat",
                    "q": "feature",
                    "qid": "movie",
                    "rank": 5653,
                    "s": "Sandra Bullock, Michael McDonald",
                    "y": 2013
                },
                {
                    "i": {
                        "height": 2218,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BZmI3MjllNmEtZjI5Yi00YWI3LTkxMDctZTJlYmNlYmMyYjQwXkEyXkFqcGdeQXVyMjUzOTY1NTc@._V1_.jpg",
                        "width": 1467
                    },
                    "id": "tt0082089",
                    "l": "Body Heat",
                    "q": "feature",
                    "qid": "movie",
                    "rank": 4179,
                    "s": "William Hurt, Kathleen Turner",
                    "y": 1981
                },
                {
                    "i": {
                        "height": 400,
                        "imageUrl": "https://m.media-amazon.com/images/M/MV5BMjAwMzk5MTM4NV5BMl5BanBnXkFtZTcwNTMxOTkwNA@@._V1_.jpg",
                        "width": 287
                    },
                    "id": "nm0001287",
                    "l": "Heather Graham",
                    "rank": 756,
                    "s": "Actress, Austin Powers: The Spy Who Shagged Me (1999)"
                }
            ],
            "q": "heat",
            "v": 1
        }
    }
}
```

#### Human Readable Output

>### Search query results for heat
>|d|q|v|
>|---|---|---|
>| {'i': {'height': 2956, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BYjZjNTJlZGUtZTE1Ny00ZDc4LTgwYjUtMzk0NDgwYzZjYTk1XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg', 'width': 2057}, 'id': 'tt0113277', 'l': 'Heat', 'q': 'feature', 'qid': 'movie', 'rank': 336, 's': 'Al Pacino, Robert De Niro', 'y': 1995},<br/>{'i': {'height': 375, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BMjQzNjM5OTYzM15BMl5BanBnXkFtZTgwNDkxMzEyOTE@._V1_.jpg', 'width': 500}, 'id': 'tt0094484', 'l': 'In the Heat of the Night', 'q': 'TV series', 'qid': 'tvSeries', 'rank': 2830, 's': "Carroll O'Connor, Alan Autry", 'y': 1988, 'yr': '1988-1995'},<br/>{'i': {'height': 2885, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BZDM1MTM4NGYtZDNjYy00ZDA5LTk4NTctYzg2OTVjZGRiODY3XkEyXkFqcGdeQXVyMTUzMDUzNTI3._V1_.jpg', 'width': 1889}, 'id': 'tt0061811', 'l': 'In the Heat of the Night', 'q': 'feature', 'qid': 'movie', 'rank': 3009, 's': 'Sidney Poitier, Rod Steiger', 'y': 1967},<br/>{'i': {'height': 1500, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BZGY2YzliN2ItYzM1MS00MjVlLWFhNDYtODE1NzI2ZjJmYjdjL2ltYWdlL2ltYWdlXkEyXkFqcGdeQXVyNzc5MjA3OA@@._V1_.jpg', 'width': 985}, 'id': 'tt0071266', 'l': 'Caged Heat', 'q': 'feature', 'qid': 'movie', 'rank': 2999, 's': 'Juanita Brown, Erica Gavin', 'y': 1974},<br/>{'i': {'height': 400, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BMTI2NTY0NzA4MF5BMl5BanBnXkFtZTYwMjE1MDE0._V1_.jpg', 'width': 267}, 'id': 'nm0005132', 'l': 'Heath Ledger', 'rank': 679, 's': 'Actor, Brokeback Mountain (2005)'},<br/>{'i': {'height': 1838, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BMjA2MDQ2ODM3MV5BMl5BanBnXkFtZTcwNDUzMTQ3OQ@@._V1_.jpg', 'width': 1240}, 'id': 'tt2404463', 'l': 'The Heat', 'q': 'feature', 'qid': 'movie', 'rank': 5653, 's': 'Sandra Bullock, Michael McDonald', 'y': 2013},<br/>{'i': {'height': 2218, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BZmI3MjllNmEtZjI5Yi00YWI3LTkxMDctZTJlYmNlYmMyYjQwXkEyXkFqcGdeQXVyMjUzOTY1NTc@._V1_.jpg', 'width': 1467}, 'id': 'tt0082089', 'l': 'Body Heat', 'q': 'feature', 'qid': 'movie', 'rank': 4179, 's': 'William Hurt, Kathleen Turner', 'y': 1981},<br/>{'i': {'height': 400, 'imageUrl': 'https:<span>//</span>m.media-amazon.com/images/M/MV5BMjAwMzk5MTM4NV5BMl5BanBnXkFtZTcwNTMxOTkwNA@@._V1_.jpg', 'width': 287}, 'id': 'nm0001287', 'l': 'Heather Graham', 'rank': 756, 's': 'Actress, Austin Powers: The Spy Who Shagged Me (1999)'} | heat | 1 |


### imdb-get-most-popular-movies

***
Get most popular movies

#### Base Command

`imdb-get-most-popular-movies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit results. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.MostPopularMovies | String | Most Popular Movies | 

#### Command example
```!imdb-get-most-popular-movies limit=3```
#### Context Example
```json
{
    "IMDb": {
        "Title": {
            "MostPopularMovies": [
                "/title/tt17351924/",
                "/title/tt14998742/",
                "/title/tt14230458/"
            ]
        }
    }
}
```

#### Human Readable Output

>### Most Popular Movies this week are:
>|Movies|
>|---|
>| /title/tt17351924/ |
>| /title/tt14998742/ |
>| /title/tt14230458/ |


### imdb-get-popular-movies-by-genre

***
Get popular movies by genre

#### Base Command

`imdb-get-popular-movies-by-genre`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| genre | One of the following: action \| adventure \| animation \| biography \| comedy \| crime \| documentary \| drama \| family \| fantasy \| film-noir \| game-show \| history \| horror \| music \| musical \| mystery \| news \| reality-tv \| romance \| sci-fi \| short \| sport \| talk-show \| thriller \| war \| western. Default is western. | Required | 
| limit | Limit results. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.MostPopularByGenre | String | Most Popular Movies By Genre | 

#### Command example
```!imdb-get-popular-movies-by-genre genre=drama limit=5```
#### Context Example
```json
{
    "IMDb": {
        "Title": {
            "MostPopularByGenre": [
                "/title/tt17351924/",
                "/title/tt14998742/",
                "/title/tt14230458/",
                "/title/tt12747748/",
                "/title/tt15398776/"
            ]
        }
    }
}
```

#### Human Readable Output

>### Most Popular drama Movies:
>|Movies|
>|---|
>| /title/tt17351924/ |
>| /title/tt14998742/ |
>| /title/tt14230458/ |
>| /title/tt12747748/ |
>| /title/tt15398776/ |


### imdb-get-top-rated-movies

***
Get top rated 250 movies

#### Base Command

`imdb-get-top-rated-movies`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | To limit original list of 250 movies returned. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.TopRatedMovies | String | Top Rated Movies | 

#### Command example
```!imdb-get-top-rated-movies limit=10```
#### Context Example
```json
{
    "IMDb": {
        "Title": {
            "TopRatedMovies": [
                {
                    "chartRating": 9.2,
                    "id": "/title/tt0111161/"
                },
                {
                    "chartRating": 9.2,
                    "id": "/title/tt0068646/"
                },
                {
                    "chartRating": 9,
                    "id": "/title/tt0468569/"
                },
                {
                    "chartRating": 9,
                    "id": "/title/tt0071562/"
                },
                {
                    "chartRating": 9,
                    "id": "/title/tt0050083/"
                },
                {
                    "chartRating": 8.9,
                    "id": "/title/tt0108052/"
                },
                {
                    "chartRating": 8.9,
                    "id": "/title/tt0167260/"
                },
                {
                    "chartRating": 8.8,
                    "id": "/title/tt0110912/"
                },
                {
                    "chartRating": 8.8,
                    "id": "/title/tt0120737/"
                },
                {
                    "chartRating": 8.8,
                    "id": "/title/tt0060196/"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Top Rated Movies:
>|chartRating|id|
>|---|---|
>| 9.2 | /title/tt0111161/ |
>| 9.2 | /title/tt0068646/ |
>| 9.0 | /title/tt0468569/ |
>| 9.0 | /title/tt0071562/ |
>| 9.0 | /title/tt0050083/ |
>| 8.9 | /title/tt0108052/ |
>| 8.9 | /title/tt0167260/ |
>| 8.8 | /title/tt0110912/ |
>| 8.8 | /title/tt0120737/ |
>| 8.8 | /title/tt0060196/ |


### imdb-get-top-rated-shows

***
Get top rated 250 tv shows

#### Base Command

`imdb-get-top-rated-shows`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | To limit original list of 250 tv shows returned. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.TopRatedShows | String | Top Rated TV Shows | 

#### Command example
```!imdb-get-top-rated-shows limit=5```
#### Context Example
```json
{
    "IMDb": {
        "Title": {
            "TopRatedShows": [
                {
                    "chartRating": 9.4,
                    "id": "/title/tt0903747/"
                },
                {
                    "chartRating": 9.4,
                    "id": "/title/tt5491994/"
                },
                {
                    "chartRating": 9.4,
                    "id": "/title/tt0795176/"
                },
                {
                    "chartRating": 9.4,
                    "id": "/title/tt0185906/"
                },
                {
                    "chartRating": 9.3,
                    "id": "/title/tt7366338/"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Top Rated Shows:
>|chartRating|id|
>|---|---|
>| 9.4 | /title/tt0903747/ |
>| 9.4 | /title/tt5491994/ |
>| 9.4 | /title/tt0795176/ |
>| 9.4 | /title/tt0185906/ |
>| 9.3 | /title/tt7366338/ |


### imdb-get-reviews

***
Get reviews

#### Base Command

`imdb-get-reviews`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tconst | You need to extract the value started with "tt" of id field returned from imdb-auto-complete, imdb-get-most-popular-movies or imdb-get-top-rated-shows commands. Ex: tt0113277. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.Reviews.imdbrating.id | String | ID of the title | 
| IMDb.Title.Reviews.imdbrating.title | String | Name of the title | 
| IMDb.Title.Reviews.imdbrating.titleType | String | Type of the title, e.g. movie, show... | 
| IMDb.Title.Reviews.imdbrating.year | Number | Year of the title release | 
| IMDb.Title.Reviews.imdbrating.bottomRank | Number | Bottom rank | 
| IMDb.Title.Reviews.imdbrating.canRate | Boolean | True or False | 
| IMDb.Title.Reviews.imdbrating.rating | Number | Rating | 
| IMDb.Title.Reviews.imdbrating.ratingCount | Number | Rating count | 
| IMDb.Title.Reviews.imdbrating.topRank | Number | Top rank | 
| IMDb.Title.Reviews.metacritic.metaScore | Number | Metacritic score | 
| IMDb.Title.Reviews.metacritic.metacriticUrl | String | Metacritic critic URL | 
| IMDb.Title.Reviews.metacritic.reviewCount | Number | Metacritic review count | 
| IMDb.Title.Reviews.metacritic.userRatingCount | Number | Metacritic user rating count | 
| IMDb.Title.Reviews.metacritic.userScore | Number | Metacritic user score | 
| IMDb.Title.Reviews.metacritic.reviews.quote | String | Metacritic quote | 
| IMDb.Title.Reviews.metacritic.reviews.reviewSite | String | Metacritic review site | 
| IMDb.Title.Reviews.metacritic.reviews.reviewer | String | Metacritic reviewer | 
| IMDb.Title.Reviews.metacritic.reviews.score | Number | Metacritic review score | 
| IMDb.Title.Reviews.criticreviews | String | Critic reviews | 
| IMDb.Title.Reviews.featuredUserReview.base.image.id | String | ID of the title image | 
| IMDb.Title.Reviews.featuredUserReview.base.image.url | String | URL of the title image | 
| IMDb.Title.Reviews.featuredUserReview.base.title | String | Name of the title | 
| IMDb.Title.Reviews.featuredUserReview.base.titleType | String | Type of the title, e.g. movie, show... | 
| IMDb.Title.Reviews.featuredUserReview.base.year | Number | Year of the title release | 
| IMDb.Title.Reviews.featuredUserReview.review.author.displayName | String | Review author user name | 
| IMDb.Title.Reviews.featuredUserReview.review.author.userId | String | Review author user id | 
| IMDb.Title.Reviews.featuredUserReview.review.authorRating | Number | Review author rating | 
| IMDb.Title.Reviews.featuredUserReview.review.helpfulnessScore | Number | Review author helpfulness score | 
| IMDb.Title.Reviews.featuredUserReview.review.interestingVotes.down | Number | Review down votes  | 
| IMDb.Title.Reviews.featuredUserReview.review.interestingVotes.up | Number | Review up votes | 
| IMDb.Title.Reviews.featuredUserReview.review.languageCode | String | Language code | 
| IMDb.Title.Reviews.featuredUserReview.review.reviewText | String | Review text | 
| IMDb.Title.Reviews.featuredUserReview.review.reviewTitle | String | Review title | 
| IMDb.Title.Reviews.featuredUserReview.review.spoiler | Boolean | True of False | 
| IMDb.Title.Reviews.featuredUserReview.review.submissionDate | Date | Review submission date | 
| IMDb.Title.Reviews.featuredUserReview.totalReviews | Number | Total reviews | 
| IMDb.Title.Reviews.certificate.certificate | String | E.g. 18\+ | 
| IMDb.Title.Reviews.hasParentsGuide | Boolean | True or False | 

#### Command example
```!imdb-get-reviews tconst=tt0113277```
#### Context Example
```json
{
    "IMDb": {
        "Title": {
            "Reviews": {
                "certificate": {
                    "attributes": [
                        "LV"
                    ],
                    "certificate": "TV-14"
                },
                "criticreviews": [
                    "rogerebert.com",
                    "ReelViews",
                    "ReelViews",
                    "BBCi - Films"
                ],
                "featuredUserReview": {
                    "@type": "imdb.api.userreviews.featuredreview",
                    "base": {
                        "id": "/title/tt0113277/",
                        "image": {
                            "height": 2956,
                            "id": "/title/tt0113277/images/rm2325426432",
                            "url": "https://m.media-amazon.com/images/M/MV5BYjZjNTJlZGUtZTE1Ny00ZDc4LTgwYjUtMzk0NDgwYzZjYTk1XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
                            "width": 2057
                        },
                        "title": "Heat",
                        "titleType": "movie",
                        "year": 1995
                    },
                    "review": {
                        "author": {
                            "displayName": "concrndone",
                            "userId": "/user/ur133028338/"
                        },
                        "authorRating": 10,
                        "helpfulnessScore": 0.805800755614513,
                        "id": "/title/tt0113277/userreviews/rw7398609",
                        "interestingVotes": {
                            "down": 8,
                            "up": 68
                        },
                        "languageCode": "eng",
                        "reviewText": "Wow. First saw this in the cinema back in 1996 and of course we all raved over how good it was but I don't think we really appreciated it back then or could have as twenty somethings.\n\nNow I'm late forties this made more sense. That obsession with something at the cost of relationships. McCauley could have been out of there a free man but something in him pulled him another way.\n\nIn the bible that something comes in the guise of a serpent. That's how subtle it creeps up upon us.\n\nThere's no black and white here (except for the cars). The good guys (Pacino) have a single-minded ruthless streak in them whilst the bad guys (De Niro etc) do have a heart.\n\nGreat film.",
                        "reviewTitle": "Is better now I'm middle aged",
                        "spoiler": false,
                        "submissionDate": "2021-10-01",
                        "titleId": "/title/tt0113277/"
                    },
                    "totalReviews": 1373
                },
                "hasParentsGuide": true,
                "imdbrating": {
                    "@type": "imdb.api.title.ratings",
                    "bottomRank": 10229,
                    "canRate": true,
                    "id": "/title/tt0113277/",
                    "rating": 8.3,
                    "ratingCount": 706839,
                    "ratingsHistograms": {
                        "Aged 18-29": {
                            "aggregateRating": 8.3,
                            "demographic": "Aged 18-29",
                            "histogram": {
                                "1": 171,
                                "10": 8000,
                                "2": 82,
                                "3": 108,
                                "4": 222,
                                "5": 650,
                                "6": 2014,
                                "7": 7332,
                                "8": 15725,
                                "9": 12014
                            },
                            "totalRatings": 46318
                        },
                        "Aged 30-44": {
                            "aggregateRating": 8.3,
                            "demographic": "Aged 30-44",
                            "histogram": {
                                "1": 1391,
                                "10": 61312,
                                "2": 527,
                                "3": 884,
                                "4": 1740,
                                "5": 4581,
                                "6": 13787,
                                "7": 45934,
                                "8": 92875,
                                "9": 77235
                            },
                            "totalRatings": 300266
                        },
                        "Aged 45+": {
                            "aggregateRating": 8.2,
                            "demographic": "Aged 45+",
                            "histogram": {
                                "1": 1326,
                                "10": 23914,
                                "2": 558,
                                "3": 791,
                                "4": 1330,
                                "5": 3162,
                                "6": 7754,
                                "7": 19013,
                                "8": 34021,
                                "9": 29276
                            },
                            "totalRatings": 121145
                        },
                        "Aged under 18": {
                            "aggregateRating": 8.1,
                            "demographic": "Aged under 18",
                            "histogram": {
                                "1": 2,
                                "10": 23,
                                "2": 0,
                                "3": 0,
                                "4": 0,
                                "5": 4,
                                "6": 7,
                                "7": 14,
                                "8": 43,
                                "9": 29
                            },
                            "totalRatings": 122
                        },
                        "Females": {
                            "aggregateRating": 7.9,
                            "demographic": "Females",
                            "histogram": {
                                "1": 724,
                                "10": 7037,
                                "2": 251,
                                "3": 342,
                                "4": 590,
                                "5": 1438,
                                "6": 3429,
                                "7": 7948,
                                "8": 11813,
                                "9": 8081
                            },
                            "totalRatings": 41653
                        },
                        "Females Aged 18-29": {
                            "aggregateRating": 8,
                            "demographic": "Females Aged 18-29",
                            "histogram": {
                                "1": 38,
                                "10": 610,
                                "2": 24,
                                "3": 28,
                                "4": 30,
                                "5": 83,
                                "6": 248,
                                "7": 684,
                                "8": 1080,
                                "9": 773
                            },
                            "totalRatings": 3598
                        },
                        "Females Aged 30-44": {
                            "aggregateRating": 7.8,
                            "demographic": "Females Aged 30-44",
                            "histogram": {
                                "1": 273,
                                "10": 3791,
                                "2": 109,
                                "3": 155,
                                "4": 312,
                                "5": 765,
                                "6": 1845,
                                "7": 4569,
                                "8": 6694,
                                "9": 4517
                            },
                            "totalRatings": 23030
                        },
                        "Females Aged 45+": {
                            "aggregateRating": 7.9,
                            "demographic": "Females Aged 45+",
                            "histogram": {
                                "1": 396,
                                "10": 2217,
                                "2": 112,
                                "3": 143,
                                "4": 213,
                                "5": 516,
                                "6": 1155,
                                "7": 2236,
                                "8": 3305,
                                "9": 2304
                            },
                            "totalRatings": 12597
                        },
                        "Females Aged under 18": {
                            "aggregateRating": 7.3,
                            "demographic": "Females Aged under 18",
                            "histogram": {
                                "1": 1,
                                "10": 3,
                                "2": 0,
                                "3": 0,
                                "4": 0,
                                "5": 1,
                                "6": 2,
                                "7": 5,
                                "8": 6,
                                "9": 4
                            },
                            "totalRatings": 22
                        },
                        "IMDb Staff": {
                            "aggregateRating": 8.7,
                            "demographic": "IMDb Staff",
                            "histogram": {
                                "1": 0,
                                "10": 4,
                                "2": 0,
                                "3": 0,
                                "4": 0,
                                "5": 0,
                                "6": 2,
                                "7": 3,
                                "8": 10,
                                "9": 10
                            },
                            "totalRatings": 29
                        },
                        "IMDb Users": {
                            "aggregateRating": 8.3,
                            "demographic": "IMDb Users",
                            "histogram": {
                                "1": 4146,
                                "10": 141135,
                                "2": 1759,
                                "3": 2626,
                                "4": 4903,
                                "5": 12532,
                                "6": 34800,
                                "7": 109025,
                                "8": 217172,
                                "9": 178741
                            },
                            "totalRatings": 706839
                        },
                        "Males": {
                            "aggregateRating": 8.3,
                            "demographic": "Males",
                            "histogram": {
                                "1": 2251,
                                "10": 90545,
                                "2": 951,
                                "3": 1484,
                                "4": 2813,
                                "5": 7284,
                                "6": 21112,
                                "7": 67842,
                                "8": 138300,
                                "9": 116639
                            },
                            "totalRatings": 449221
                        },
                        "Males Aged 18-29": {
                            "aggregateRating": 8.3,
                            "demographic": "Males Aged 18-29",
                            "histogram": {
                                "1": 129,
                                "10": 7099,
                                "2": 53,
                                "3": 76,
                                "4": 187,
                                "5": 551,
                                "6": 1706,
                                "7": 6409,
                                "8": 14101,
                                "9": 10811
                            },
                            "totalRatings": 41122
                        },
                        "Males Aged 30-44": {
                            "aggregateRating": 8.3,
                            "demographic": "Males Aged 30-44",
                            "histogram": {
                                "1": 1105,
                                "10": 56804,
                                "2": 414,
                                "3": 717,
                                "4": 1398,
                                "5": 3766,
                                "6": 11759,
                                "7": 40737,
                                "8": 85030,
                                "9": 71745
                            },
                            "totalRatings": 273475
                        },
                        "Males Aged 45+": {
                            "aggregateRating": 8.2,
                            "demographic": "Males Aged 45+",
                            "histogram": {
                                "1": 921,
                                "10": 21289,
                                "2": 438,
                                "3": 633,
                                "4": 1093,
                                "5": 2590,
                                "6": 6463,
                                "7": 16417,
                                "8": 30088,
                                "9": 26466
                            },
                            "totalRatings": 106398
                        },
                        "Males Aged under 18": {
                            "aggregateRating": 8.4,
                            "demographic": "Males Aged under 18",
                            "histogram": {
                                "1": 1,
                                "10": 20,
                                "2": 0,
                                "3": 0,
                                "4": 0,
                                "5": 3,
                                "6": 5,
                                "7": 9,
                                "8": 37,
                                "9": 24
                            },
                            "totalRatings": 99
                        },
                        "Non-US users": {
                            "aggregateRating": 8.2,
                            "demographic": "Non-US users",
                            "histogram": {
                                "1": 2045,
                                "10": 86252,
                                "2": 926,
                                "3": 1433,
                                "4": 2858,
                                "5": 7675,
                                "6": 22841,
                                "7": 75325,
                                "8": 151226,
                                "9": 121094
                            },
                            "totalRatings": 471675
                        },
                        "Top 1000 voters": {
                            "aggregateRating": 8,
                            "demographic": "Top 1000 voters",
                            "histogram": {
                                "1": 11,
                                "10": 138,
                                "2": 5,
                                "3": 4,
                                "4": 14,
                                "5": 24,
                                "6": 81,
                                "7": 143,
                                "8": 267,
                                "9": 147
                            },
                            "totalRatings": 834
                        },
                        "US users": {
                            "aggregateRating": 8.3,
                            "demographic": "US users",
                            "histogram": {
                                "1": 1427,
                                "10": 37235,
                                "2": 544,
                                "3": 772,
                                "4": 1354,
                                "5": 3181,
                                "6": 8220,
                                "7": 22674,
                                "8": 44387,
                                "9": 39566
                            },
                            "totalRatings": 159360
                        }
                    },
                    "title": "Heat",
                    "titleType": "movie",
                    "topRank": 111,
                    "year": 1995
                },
                "metacritic": {
                    "@type": "imdb.api.title.metacritic",
                    "id": "/title/tt0113277/",
                    "metaScore": 76,
                    "metacriticUrl": "https://www.metacritic.com/movie/heat?ftag=MCD-06-10aaa1c",
                    "reviewCount": 23,
                    "reviews": [
                        {
                            "quote": "Stunningly made and incisively acted by a large and terrific cast, Michael Mann's ambitious study of the relativity of good and evil stands apart from other films of its type by virtue of its extraordinarily rich characterizations and its thoughtful, deeply melancholy take on modern life.",
                            "reviewSite": "Variety",
                            "reviewer": "Todd McCarthy",
                            "score": 100
                        },
                        {
                            "quote": "One of the most intelligent crime-thrillers to come along in years.",
                            "reviewSite": "Austin Chronicle",
                            "score": 100
                        }
                    ],
                    "userRatingCount": 657,
                    "userScore": 8.6
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Reviews:
>|certificate|criticreviews|featuredUserReview|hasParentsGuide|imdbrating|metacritic|
>|---|---|---|---|---|---|
>| attributes: LV<br/>certificate: TV-14 | rogerebert.com,<br/>ReelViews,<br/>ReelViews,<br/>BBCi - Films | @type: imdb.api.userreviews.featuredreview<br/>base: {"id": "/title/tt0113277/", "image": {"height": 2956, "id": "/title/tt0113277/images/rm2325426432", "url": "https:<span>//</span>m.media-amazon.com/images/M/MV5BYjZjNTJlZGUtZTE1Ny00ZDc4LTgwYjUtMzk0NDgwYzZjYTk1XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg", "width": 2057}, "title": "Heat", "titleType": "movie", "year": 1995}<br/>review: {"author": {"displayName": "concrndone", "userId": "/user/ur133028338/"}, "authorRating": 10, "helpfulnessScore": 0.805800755614513, "id": "/title/tt0113277/userreviews/rw7398609", "interestingVotes": {"down": 8, "up": 68}, "languageCode": "eng", "reviewText": "Wow. First saw this in the cinema back in 1996 and of course we all raved over how good it was but I don't think we really appreciated it back then or could have as twenty somethings.\n\nNow I'm late forties this made more sense. That obsession with something at the cost of relationships. McCauley could have been out of there a free man but something in him pulled him another way.\n\nIn the bible that something comes in the guise of a serpent. That's how subtle it creeps up upon us.\n\nThere's no black and white here (except for the cars). The good guys (Pacino) have a single-minded ruthless streak in them whilst the bad guys (De Niro etc) do have a heart.\n\nGreat film.", "reviewTitle": "Is better now I'm middle aged", "spoiler": false, "submissionDate": "2021-10-01", "titleId": "/title/tt0113277/"}<br/>totalReviews: 1373 | true | @type: imdb.api.title.ratings<br/>id: /title/tt0113277/<br/>title: Heat<br/>titleType: movie<br/>year: 1995<br/>bottomRank: 10229<br/>canRate: true<br/>rating: 8.3<br/>ratingCount: 706839<br/>ratingsHistograms: {"Females Aged under 18": {"aggregateRating": 7.3, "demographic": "Females Aged under 18", "histogram": {"1": 1, "2": 0, "3": 0, "4": 0, "5": 1, "6": 2, "7": 5, "8": 6, "9": 4, "10": 3}, "totalRatings": 22}, "Males Aged 45+": {"aggregateRating": 8.2, "demographic": "Males Aged 45+", "histogram": {"1": 921, "2": 438, "3": 633, "4": 1093, "5": 2590, "6": 6463, "7": 16417, "8": 30088, "9": 26466, "10": 21289}, "totalRatings": 106398}, "Males Aged 18-29": {"aggregateRating": 8.3, "demographic": "Males Aged 18-29", "histogram": {"1": 129, "2": 53, "3": 76, "4": 187, "5": 551, "6": 1706, "7": 6409, "8": 14101, "9": 10811, "10": 7099}, "totalRatings": 41122}, "Non-US users": {"aggregateRating": 8.2, "demographic": "Non-US users", "histogram": {"1": 2045, "2": 926, "3": 1433, "4": 2858, "5": 7675, "6": 22841, "7": 75325, "8": 151226, "9": 121094, "10": 86252}, "totalRatings": 471675}, "Males Aged under 18": {"aggregateRating": 8.4, "demographic": "Males Aged under 18", "histogram": {"1": 1, "2": 0, "3": 0, "4": 0, "5": 3, "6": 5, "7": 9, "8": 37, "9": 24, "10": 20}, "totalRatings": 99}, "Males": {"aggregateRating": 8.3, "demographic": "Males", "histogram": {"1": 2251, "2": 951, "3": 1484, "4": 2813, "5": 7284, "6": 21112, "7": 67842, "8": 138300, "9": 116639, "10": 90545}, "totalRatings": 449221}, "Females Aged 18-29": {"aggregateRating": 8.0, "demographic": "Females Aged 18-29", "histogram": {"1": 38, "2": 24, "3": 28, "4": 30, "5": 83, "6": 248, "7": 684, "8": 1080, "9": 773, "10": 610}, "totalRatings": 3598}, "Females Aged 45+": {"aggregateRating": 7.9, "demographic": "Females Aged 45+", "histogram": {"1": 396, "2": 112, "3": 143, "4": 213, "5": 516, "6": 1155, "7": 2236, "8": 3305, "9": 2304, "10": 2217}, "totalRatings": 12597}, "Females": {"aggregateRating": 7.9, "demographic": "Females", "histogram": {"1": 724, "2": 251, "3": 342, "4": 590, "5": 1438, "6": 3429, "7": 7948, "8": 11813, "9": 8081, "10": 7037}, "totalRatings": 41653}, "Aged 18-29": {"aggregateRating": 8.3, "demographic": "Aged 18-29", "histogram": {"1": 171, "2": 82, "3": 108, "4": 222, "5": 650, "6": 2014, "7": 7332, "8": 15725, "9": 12014, "10": 8000}, "totalRatings": 46318}, "Aged under 18": {"aggregateRating": 8.1, "demographic": "Aged under 18", "histogram": {"1": 2, "2": 0, "3": 0, "4": 0, "5": 4, "6": 7, "7": 14, "8": 43, "9": 29, "10": 23}, "totalRatings": 122}, "Aged 45+": {"aggregateRating": 8.2, "demographic": "Aged 45+", "histogram": {"1": 1326, "2": 558, "3": 791, "4": 1330, "5": 3162, "6": 7754, "7": 19013, "8": 34021, "9": 29276, "10": 23914}, "totalRatings": 121145}, "Females Aged 30-44": {"aggregateRating": 7.8, "demographic": "Females Aged 30-44", "histogram": {"1": 273, "2": 109, "3": 155, "4": 312, "5": 765, "6": 1845, "7": 4569, "8": 6694, "9": 4517, "10": 3791}, "totalRatings": 23030}, "Aged 30-44": {"aggregateRating": 8.3, "demographic": "Aged 30-44", "histogram": {"1": 1391, "2": 527, "3": 884, "4": 1740, "5": 4581, "6": 13787, "7": 45934, "8": 92875, "9": 77235, "10": 61312}, "totalRatings": 300266}, "Top 1000 voters": {"aggregateRating": 8.0, "demographic": "Top 1000 voters", "histogram": {"1": 11, "2": 5, "3": 4, "4": 14, "5": 24, "6": 81, "7": 143, "8": 267, "9": 147, "10": 138}, "totalRatings": 834}, "IMDb Staff": {"aggregateRating": 8.7, "demographic": "IMDb Staff", "histogram": {"1": 0, "2": 0, "3": 0, "4": 0, "5": 0, "6": 2, "7": 3, "8": 10, "9": 10, "10": 4}, "totalRatings": 29}, "IMDb Users": {"aggregateRating": 8.3, "demographic": "IMDb Users", "histogram": {"1": 4146, "2": 1759, "3": 2626, "4": 4903, "5": 12532, "6": 34800, "7": 109025, "8": 217172, "9": 178741, "10": 141135}, "totalRatings": 706839}, "Males Aged 30-44": {"aggregateRating": 8.3, "demographic": "Males Aged 30-44", "histogram": {"1": 1105, "2": 414, "3": 717, "4": 1398, "5": 3766, "6": 11759, "7": 40737, "8": 85030, "9": 71745, "10": 56804}, "totalRatings": 273475}, "US users": {"aggregateRating": 8.3, "demographic": "US users", "histogram": {"1": 1427, "2": 544, "3": 772, "4": 1354, "5": 3181, "6": 8220, "7": 22674, "8": 44387, "9": 39566, "10": 37235}, "totalRatings": 159360}}<br/>topRank: 111 | @type: imdb.api.title.metacritic<br/>id: /title/tt0113277/<br/>metaScore: 76<br/>metacriticUrl: https:<span>//</span>www.metacritic.com/movie/heat?ftag=MCD-06-10aaa1c<br/>reviewCount: 23<br/>userRatingCount: 657<br/>userScore: 8.6<br/>reviews: {'quote': "Stunningly made and incisively acted by a large and terrific cast, Michael Mann's ambitious study of the relativity of good and evil stands apart from other films of its type by virtue of its extraordinarily rich characterizations and its thoughtful, deeply melancholy take on modern life.", 'reviewSite': 'Variety', 'reviewer': 'Todd McCarthy', 'score': 100},<br/>{'quote': 'One of the most intelligent crime-thrillers to come along in years.', 'reviewSite': 'Austin Chronicle', 'score': 100} |


### imdb-get-overview-details

***
Get overview information of the title

#### Base Command

`imdb-get-overview-details`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tconst | You need to extract the value started with "tt" of id field returned from imdb-auto-complete, imdb-get-most-popular-movies or imdb-get-top-rated-shows commands. Ex: tt0113277. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.Overview.id | String | ID of the title | 
| IMDb.Title.Overview.title.image.id | String | ID of the title image | 
| IMDb.Title.Overview.title.image.url | String | URL of the title image | 
| IMDb.Title.Overview.title.runningTimeInMinutes | Number | Movie duration | 
| IMDb.Title.Overview.title.title | String | Name of the title | 
| IMDb.Title.Overview.title.titleType | String | Type of the title, e.g. tvSeries... | 
| IMDb.Title.Overview.title.year | Number | Year of the title release | 
| IMDb.Title.Overview.certificates.US.certificate | String | E.g. 18\+ | 
| IMDb.Title.Overview.certificates.US.certificateNumber | Number | Certificate Number | 
| IMDb.Title.Overview.certificates.US.ratingReason | String | Rating Reason | 
| IMDb.Title.Overview.certificates.US.ratingsBody | String | Ratings Body | 
| IMDb.Title.Overview.certificates.US.country | String | Country | 
| IMDb.Title.Overview.ratings.canRate | Boolean | True or False | 
| IMDb.Title.Overview.ratings.rating | Number | Rating | 
| IMDb.Title.Overview.ratings.ratingCount | Number | Rating count | 
| IMDb.Title.Overview.ratings.topRank | Number | Top rank | 
| IMDb.Title.Overview.genres | String | Genres | 
| IMDb.Title.Overview.releaseDate | Date | Release Date | 
| IMDb.Title.Overview.plotOutline.id | String | Plot ID | 
| IMDb.Title.Overview.plotOutline.text | String | Plot text | 
| IMDb.Title.Overview.plotSummary.author | String | Plot summary author | 
| IMDb.Title.Overview.plotSummary.id | String | Plot summary author ID | 
| IMDb.Title.Overview.plotSummary.text | String | Plot summary text | 

#### Command example
```!imdb-get-overview-details tconst=tt0113277```
#### Context Example
```json
{
    "IMDb": {
        "Title": {
            "Overview": {
                "certificates": {
                    "US": [
                        {
                            "certificate": "R",
                            "certificateNumber": 34160,
                            "country": "US",
                            "ratingReason": "Rated R for violence and language",
                            "ratingsBody": "MPAA"
                        }
                    ]
                },
                "genres": [
                    "Action",
                    "Crime",
                    "Drama"
                ],
                "id": "/title/tt0113277/",
                "plotOutline": {
                    "id": "/title/tt0113277/plot/po0949166",
                    "text": "A group of high-end professional thieves start to feel the heat from the LAPD when they unknowingly leave a verbal clue at their latest heist."
                },
                "plotSummary": {
                    "author": "Tad Dibbern <DIBBERN_D@a1.mscf.upenn.edu>",
                    "id": "/title/tt0113277/plot/ps0096710",
                    "text": "Hunters and their prey--Neil and his professional criminal crew hunt to score big money targets (banks, vaults, armored cars) and are, in turn, hunted by Lt. Vincent Hanna and his team of cops in the Robbery/Homicide police division. A botched job puts Hanna onto their trail while they regroup and try to put together one last big 'retirement' score. Neil and Vincent are similar in many ways, including their troubled personal lives. At a crucial moment in his life, Neil disobeys the dictum taught to him long ago by his criminal mentor--'Never have anything in your life that you can't walk out on in thirty seconds flat, if you spot the heat coming around the corner'--as he falls in love. Thus the stage is set for the suspenseful ending...."
                },
                "ratings": {
                    "canRate": true,
                    "rating": 8.3,
                    "ratingCount": 706839,
                    "topRank": 111
                },
                "releaseDate": "1995-12-15",
                "title": {
                    "@type": "imdb.api.title.title",
                    "id": "/title/tt0113277/",
                    "image": {
                        "height": 2956,
                        "id": "/title/tt0113277/images/rm2325426432",
                        "url": "https://m.media-amazon.com/images/M/MV5BYjZjNTJlZGUtZTE1Ny00ZDc4LTgwYjUtMzk0NDgwYzZjYTk1XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
                        "width": 2057
                    },
                    "runningTimeInMinutes": 170,
                    "title": "Heat",
                    "titleType": "movie",
                    "year": 1995
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Movie Overview Details
>|certificates|genres|id|plotOutline|plotSummary|ratings|releaseDate|title|
>|---|---|---|---|---|---|---|---|
>| US: {'certificate': 'R', 'certificateNumber': 34160, 'ratingReason': 'Rated R for violence and language', 'ratingsBody': 'MPAA', 'country': 'US'} | Action,<br/>Crime,<br/>Drama | /title/tt0113277/ | id: /title/tt0113277/plot/po0949166<br/>text: A group of high-end professional thieves start to feel the heat from the LAPD when they unknowingly leave a verbal clue at their latest heist. | author: Tad Dibbern <DIBBERN_D@a1.mscf.upenn.edu><br/>id: /title/tt0113277/plot/ps0096710<br/>text: Hunters and their prey--Neil and his professional criminal crew hunt to score big money targets (banks, vaults, armored cars) and are, in turn, hunted by Lt. Vincent Hanna and his team of cops in the Robbery/Homicide police division. A botched job puts Hanna onto their trail while they regroup and try to put together one last big 'retirement' score. Neil and Vincent are similar in many ways, including their troubled personal lives. At a crucial moment in his life, Neil disobeys the dictum taught to him long ago by his criminal mentor--'Never have anything in your life that you can't walk out on in thirty seconds flat, if you spot the heat coming around the corner'--as he falls in love. Thus the stage is set for the suspenseful ending.... | canRate: true<br/>rating: 8.3<br/>ratingCount: 706839<br/>topRank: 111 | 1995-12-15 | @type: imdb.api.title.title<br/>id: /title/tt0113277/<br/>image: {"height": 2956, "id": "/title/tt0113277/images/rm2325426432", "url": "https:<span>//</span>m.media-amazon.com/images/M/MV5BYjZjNTJlZGUtZTE1Ny00ZDc4LTgwYjUtMzk0NDgwYzZjYTk1XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg", "width": 2057}<br/>runningTimeInMinutes: 170<br/>title: Heat<br/>titleType: movie<br/>year: 1995 |


### imdb-list-most-popular-celebs

***
List most popular celebs

#### Base Command

`imdb-list-most-popular-celebs`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit results. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Celebs.MostPopular | String | Most Popular Celebrities | 

#### Command example
```!imdb-list-most-popular-celebs limit=3```
#### Context Example
```json
{
    "IMDb": {
        "Celebs": {
            "MostPopular": [
                "/name/nm0646792/",
                "/name/nm2882021/",
                "/name/nm0929489/"
            ]
        }
    }
}
```

#### Human Readable Output

>### Most Popular Celebs This Week Are:
>|Celebs|
>|---|
>| /name/nm0646792/ |
>| /name/nm2882021/ |
>| /name/nm0929489/ |


### imdb-get-bio

***
Get biography of actor or actress

#### Base Command

`imdb-get-bio`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nconst | You need to extract the value started with "nm" returned in imdb-list-born-today or imdb-list-most-popular-celebs commands. Ex: nm0000174. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Celebs.Bio.akas | String | Also known as | 
| IMDb.Celebs.Bio.id | String | ID of the celebrity | 
| IMDb.Celebs.Bio.image.id | String | ID of the celebrity image | 
| IMDb.Celebs.Bio.image.url | String | URL of the celebrity image | 
| IMDb.Celebs.Bio.legacyNameText | String | Legacy name | 
| IMDb.Celebs.Bio.name | String | Name | 
| IMDb.Celebs.Bio.birthDate | Date | Birth date | 
| IMDb.Celebs.Bio.birthPlace | String | Place of birth | 
| IMDb.Celebs.Bio.gender | String | Gender | 
| IMDb.Celebs.Bio.heightCentimeters | Number | Height in centimeters | 
| IMDb.Celebs.Bio.nicknames | String | Nicknames | 
| IMDb.Celebs.Bio.realName | String | Real name | 
| IMDb.Celebs.Bio.spouses.attributes | String | E.g. 1 child | 
| IMDb.Celebs.Bio.spouses.current | Boolean | True or False | 
| IMDb.Celebs.Bio.spouses.fromDate | String | Year married | 
| IMDb.Celebs.Bio.spouses.id | String | Spouse id | 
| IMDb.Celebs.Bio.spouses.name | String | Spouse name | 
| IMDb.Celebs.Bio.trademarks | String | Trademarks | 
| IMDb.Celebs.Bio.miniBios.author | String | Bio author | 
| IMDb.Celebs.Bio.miniBios.id | String | Id of author | 
| IMDb.Celebs.Bio.miniBios.language | String | E.g. en, fr... | 
| IMDb.Celebs.Bio.miniBios.text | String | Mini bio text | 

#### Command example
```!imdb-get-bio nconst=nm0000174```
#### Context Example
```json
{
    "IMDb": {
        "Celebs": {
            "Bio": {
                "@type": "imdb.api.name.bio",
                "birthDate": "1959-12-31",
                "birthPlace": "Los Angeles, California, USA",
                "gender": "male",
                "heightCentimeters": 182,
                "id": "/name/nm0000174/",
                "image": {
                    "height": 605,
                    "id": "/name/nm0000174/images/rm1232583936",
                    "url": "https://m.media-amazon.com/images/M/MV5BMTk3ODIzMDA5Ml5BMl5BanBnXkFtZTcwNDY0NTU4Ng@@._V1_.jpg",
                    "width": 426
                },
                "legacyNameText": "Kilmer, Val",
                "miniBios": [
                    {
                        "author": "Denise P. Meyer < dpm1@cornell.edu>",
                        "id": "/name/nm0000174/bio/mb0019236",
                        "language": "en",
                        "text": "Val Kilmer was born in Los Angeles, California, to Gladys Swanette (Ekstadt) and Eugene Dorris Kilmer, who was a real estate developer and aerospace equipment distributor. His mother, born in Indiana, was from a Swedish family, and his father was from Texas. Val studied at Hollywood's Professional's School and, in his teens, entered Juilliard's drama program. His professional acting career began on stage, and he still participates in theater; he played Hamlet at the 1988 Colorado Shakespeare Festival. His film debut was in the 1984 spoof Top Secret! (1984), wherein he starred as blond rock idol Nick Rivers. He was in a number of films throughout the 1980s, including the 1986 smash Top Gun (1986). Despite his obvious talent and range, it wasn't until his astonishingly believable performance as Jim Morrison in Oliver Stone's The Doors (1991) that the world sat up and took notice. Kilmer again put his good baritone to use in the movie, performing all of the concert pieces. Since then, he has played two more American legends, Elvis Presley in True Romance (1993) and Doc Holliday in Tombstone (1993). In July 1994, it was announced that Kilmer would be taking over the role of Batman/Bruce Wayne from Michael Keaton."
                    }
                ],
                "name": "Val Kilmer",
                "realName": "Val Edward Kilmer",
                "spouses": [
                    {
                        "attributes": "(divorced) (2 children)",
                        "fromDate": "1988-02-28",
                        "id": "/name/nm0000695/",
                        "name": "Joanne Whalley",
                        "toDate": "1996-02-01"
                    }
                ],
                "trademarks": [
                    "In many of his movies, he twirls small objects (coins, pencils, etc.) with his fingers.",
                    "He rubs the first two fingers of his right hand together. Particularly  in tense scenes, but also where he is not speaking."
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### Short actor bio:
>|@type|birthDate|birthPlace|gender|heightCentimeters|id|image|legacyNameText|miniBios|name|realName|spouses|trademarks|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| imdb.api.name.bio | 1959-12-31 | Los Angeles, California, USA | male | 182.0 | /name/nm0000174/ | height: 605<br/>id: /name/nm0000174/images/rm1232583936<br/>url: https:<span>//</span>m.media-amazon.com/images/M/MV5BMTk3ODIzMDA5Ml5BMl5BanBnXkFtZTcwNDY0NTU4Ng@@._V1_.jpg<br/>width: 426 | Kilmer, Val | {'author': 'Denise P. Meyer < dpm1@cornell.edu>', 'id': '/name/nm0000174/bio/mb0019236', 'language': 'en', 'text': "Val Kilmer was born in Los Angeles, California, to Gladys Swanette (Ekstadt) and Eugene Dorris Kilmer, who was a real estate developer and aerospace equipment distributor. His mother, born in Indiana, was from a Swedish family, and his father was from Texas. Val studied at Hollywood's Professional's School and, in his teens, entered Juilliard's drama program. His professional acting career began on stage, and he still participates in theater; he played Hamlet at the 1988 Colorado Shakespeare Festival. His film debut was in the 1984 spoof Top Secret! (1984), wherein he starred as blond rock idol Nick Rivers. He was in a number of films throughout the 1980s, including the 1986 smash Top Gun (1986). Despite his obvious talent and range, it wasn't until his astonishingly believable performance as Jim Morrison in Oliver Stone's The Doors (1991) that the world sat up and took notice. Kilmer again put his good baritone to use in the movie, performing all of the concert pieces. Since then, he has played two more American legends, Elvis Presley in True Romance (1993) and Doc Holliday in Tombstone (1993). In July 1994, it was announced that Kilmer would be taking over the role of Batman/Bruce Wayne from Michael Keaton."} | Val Kilmer | Val Edward Kilmer | {'attributes': '(divorced) (2 children)', 'fromDate': '1988-02-28', 'id': '/name/nm0000695/', 'name': 'Joanne Whalley', 'toDate': '1996-02-01'} | In many of his movies, he twirls small objects (coins, pencils, etc.) with his fingers.,<br/>He rubs the first two fingers of his right hand together. Particularly  in tense scenes, but also where he is not speaking. |


### imdb-get-known-for

***
Get known-for of actor or actress

#### Base Command

`imdb-get-known-for`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nconst | You need to extract the value started with "nm" returned in imdb-list-born-today or imdb-list-most-popular-celebs commands. Ex: nm0000199. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Celebs.KnownFor.title.id | String | ID of the title | 
| IMDb.Celebs.KnownFor.title.image.id | String | ID of the title image | 
| IMDb.Celebs.KnownFor.title.image.url | String | URL of the title image | 
| IMDb.Celebs.KnownFor.title.title | String | Name of the title | 
| IMDb.Celebs.KnownFor.titleType | String | Type of the title, e.g. movie, show... | 
| IMDb.Celebs.KnownFor.title.year | Number | Year of the title release | 
| IMDb.Celebs.KnownFor.imdbRating | Number | IMDb rating | 
| IMDb.Celebs.KnownFor.summary.characters | String | Character | 
| IMDb.Celebs.KnownFor.categories | String | Category of work, e.g. actor, Director... | 

#### Command example
```!imdb-get-known-for nconst=nm0000199```
#### Context Example
```json
{
    "IMDb": {
        "Celebs": {
            "KnownFor": [
                {
                    "categories": [
                        "actor"
                    ],
                    "imdbRating": 7.7,
                    "summary": {
                        "category": "actor",
                        "characters": [
                            "Serpico"
                        ],
                        "displayYear": "1973"
                    },
                    "title": {
                        "@type": "imdb.api.title.base",
                        "id": "/title/tt0070666/",
                        "image": {
                            "height": 1548,
                            "id": "/title/tt0070666/images/rm433514241",
                            "url": "https://m.media-amazon.com/images/M/MV5BOTRkNjg3YzQtNGE3NC00M2U1LTg1ODItNmM3ZjMyOTYzYjEwXkEyXkFqcGdeQXVyMjUzOTY1NTc@._V1_.jpg",
                            "width": 1016
                        },
                        "title": "Serpico",
                        "titleType": "movie",
                        "year": 1973
                    },
                    "whereToWatch": {
                        "freeWithPrime": false,
                        "hasDigitalOffers": true,
                        "hasPhysicalOffers": true,
                        "hasShowtimes": false,
                        "hasTvShowings": false,
                        "releaseDate": "1973-12-05"
                    }
                },
                {
                    "categories": [
                        "actor"
                    ],
                    "imdbRating": 8,
                    "summary": {
                        "category": "actor",
                        "characters": [
                            "Sonny"
                        ],
                        "displayYear": "1975"
                    },
                    "title": {
                        "@type": "imdb.api.title.base",
                        "id": "/title/tt0072890/",
                        "image": {
                            "height": 2942,
                            "id": "/title/tt0072890/images/rm990909440",
                            "url": "https://m.media-amazon.com/images/M/MV5BODExZmE2ZWItYTIzOC00MzI1LTgyNTktMDBhNmFhY2Y4OTQ3XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg",
                            "width": 1960
                        },
                        "title": "Dog Day Afternoon",
                        "titleType": "movie",
                        "year": 1975
                    },
                    "whereToWatch": {
                        "freeWithPrime": false,
                        "hasDigitalOffers": true,
                        "hasPhysicalOffers": true,
                        "hasShowtimes": false,
                        "hasTvShowings": false,
                        "releaseDate": "1975-09-21"
                    }
                },
                {
                    "categories": [
                        "actor"
                    ],
                    "imdbRating": 9.2,
                    "summary": {
                        "category": "actor",
                        "characters": [
                            "Michael Corleone"
                        ],
                        "displayYear": "1972"
                    },
                    "title": {
                        "@type": "imdb.api.title.base",
                        "id": "/title/tt0068646/",
                        "image": {
                            "height": 1982,
                            "id": "/title/tt0068646/images/rm746868224",
                            "url": "https://m.media-amazon.com/images/M/MV5BM2MyNjYxNmUtYTAwNi00MTYxLWJmNWYtYzZlODY3ZTk3OTFlXkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg",
                            "width": 1396
                        },
                        "title": "The Godfather",
                        "titleType": "movie",
                        "year": 1972
                    },
                    "whereToWatch": {
                        "freeWithPrime": false,
                        "hasDigitalOffers": true,
                        "hasPhysicalOffers": true,
                        "hasShowtimes": false,
                        "hasTvShowings": false,
                        "releaseDate": "1972-03-24"
                    }
                },
                {
                    "categories": [
                        "actor"
                    ],
                    "imdbRating": 6.2,
                    "summary": {
                        "category": "actor",
                        "characters": [
                            "Big Boy Caprice"
                        ],
                        "displayYear": "1990"
                    },
                    "title": {
                        "@type": "imdb.api.title.base",
                        "id": "/title/tt0099422/",
                        "image": {
                            "height": 1344,
                            "id": "/title/tt0099422/images/rm3070956800",
                            "url": "https://m.media-amazon.com/images/M/MV5BMzA5MDg5ZDAtOWE1YS00Nzg2LTk5NzUtMDY3ZDZlN2U2M2ZlXkEyXkFqcGdeQXVyNjUwNzk3NDc@._V1_.jpg",
                            "width": 907
                        },
                        "title": "Dick Tracy",
                        "titleType": "movie",
                        "year": 1990
                    },
                    "whereToWatch": {
                        "freeWithPrime": false,
                        "hasDigitalOffers": false,
                        "hasPhysicalOffers": true,
                        "hasShowtimes": false,
                        "hasTvShowings": false,
                        "releaseDate": "1990-06-15"
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### The Person is Known for:
>|categories|imdbRating|summary|title|whereToWatch|
>|---|---|---|---|---|
>| actor | 7.7 | category: actor<br/>characters: Serpico<br/>displayYear: 1973 | @type: imdb.api.title.base<br/>id: /title/tt0070666/<br/>image: {"height": 1548, "id": "/title/tt0070666/images/rm433514241", "url": "https:<span>//</span>m.media-amazon.com/images/M/MV5BOTRkNjg3YzQtNGE3NC00M2U1LTg1ODItNmM3ZjMyOTYzYjEwXkEyXkFqcGdeQXVyMjUzOTY1NTc@._V1_.jpg", "width": 1016}<br/>title: Serpico<br/>titleType: movie<br/>year: 1973 | releaseDate: 1973-12-05<br/>hasShowtimes: false<br/>hasDigitalOffers: true<br/>freeWithPrime: false<br/>hasTvShowings: false<br/>hasPhysicalOffers: true |
>| actor | 8.0 | category: actor<br/>characters: Sonny<br/>displayYear: 1975 | @type: imdb.api.title.base<br/>id: /title/tt0072890/<br/>image: {"height": 2942, "id": "/title/tt0072890/images/rm990909440", "url": "https:<span>//</span>m.media-amazon.com/images/M/MV5BODExZmE2ZWItYTIzOC00MzI1LTgyNTktMDBhNmFhY2Y4OTQ3XkEyXkFqcGdeQXVyNjU0OTQ0OTY@._V1_.jpg", "width": 1960}<br/>title: Dog Day Afternoon<br/>titleType: movie<br/>year: 1975 | releaseDate: 1975-09-21<br/>hasShowtimes: false<br/>hasDigitalOffers: true<br/>freeWithPrime: false<br/>hasTvShowings: false<br/>hasPhysicalOffers: true |
>| actor | 9.2 | category: actor<br/>characters: Michael Corleone<br/>displayYear: 1972 | @type: imdb.api.title.base<br/>id: /title/tt0068646/<br/>image: {"height": 1982, "id": "/title/tt0068646/images/rm746868224", "url": "https:<span>//</span>m.media-amazon.com/images/M/MV5BM2MyNjYxNmUtYTAwNi00MTYxLWJmNWYtYzZlODY3ZTk3OTFlXkEyXkFqcGdeQXVyNzkwMjQ5NzM@._V1_.jpg", "width": 1396}<br/>title: The Godfather<br/>titleType: movie<br/>year: 1972 | releaseDate: 1972-03-24<br/>hasShowtimes: false<br/>hasDigitalOffers: true<br/>freeWithPrime: false<br/>hasTvShowings: false<br/>hasPhysicalOffers: true |
>| actor | 6.2 | category: actor<br/>characters: Big Boy Caprice<br/>displayYear: 1990 | @type: imdb.api.title.base<br/>id: /title/tt0099422/<br/>image: {"height": 1344, "id": "/title/tt0099422/images/rm3070956800", "url": "https:<span>//</span>m.media-amazon.com/images/M/MV5BMzA5MDg5ZDAtOWE1YS00Nzg2LTk5NzUtMDY3ZDZlN2U2M2ZlXkEyXkFqcGdeQXVyNjUwNzk3NDc@._V1_.jpg", "width": 907}<br/>title: Dick Tracy<br/>titleType: movie<br/>year: 1990 | releaseDate: 1990-06-15<br/>hasShowtimes: false<br/>hasDigitalOffers: false<br/>freeWithPrime: false<br/>hasTvShowings: false<br/>hasPhysicalOffers: true |


### imdb-list-born-today

***
List all actors and actresses by day and month

#### Base Command

`imdb-list-born-today`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| month | The month of birth of actors. | Required | 
| day | The day of birth of actors. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Celebs.BornToday | string | Celebrities Born Today | 

#### Command example
```!imdb-list-born-today month=4 day=25```
#### Context Example
```json
{
    "IMDb": {
        "Celebs": {
            "BornToday": [
                "/name/nm0000199/",
                "/name/nm0000250/",
                "/name/nm0047332/",
                "/name/nm5245722/",
                "/name/nm0868659/",
                "/name/nm3255459/",
                "/name/nm0603413/",
                "/name/nm0005134/",
                "/name/nm0001735/",
                "/name/nm0000279/",
                "/name/nm1285342/",
                "/name/nm3627601/",
                "/name/nm0375138/",
                "/name/nm0225483/",
                "/name/nm0004749/",
                "/name/nm1528476/",
                "/name/nm6414863/",
                "/name/nm0218810/",
                "/name/nm5969653/",
                "/name/nm0005556/",
                "/name/nm0363561/",
                "/name/nm0588225/",
                "/name/nm0503800/",
                "/name/nm0534205/",
                "/name/nm3275500/",
                "/name/nm5181257/",
                "/name/nm3072420/",
                "/name/nm0246686/",
                "/name/nm1502201/"
            ]
        }
    }
}
```

#### Human Readable Output

>### Celebrities Born Today
>|Celebrity|
>|---|
>| /name/nm0000199/ |
>| /name/nm0000250/ |
>| /name/nm0047332/ |
>| /name/nm5245722/ |
>| /name/nm0868659/ |
>| /name/nm3255459/ |
>| /name/nm0603413/ |
>| /name/nm0005134/ |
>| /name/nm0001735/ |
>| /name/nm0000279/ |
>| /name/nm1285342/ |
>| /name/nm3627601/ |
>| /name/nm0375138/ |
>| /name/nm0225483/ |
>| /name/nm0004749/ |
>| /name/nm1528476/ |
>| /name/nm6414863/ |
>| /name/nm0218810/ |
>| /name/nm5969653/ |
>| /name/nm0005556/ |
>| /name/nm0363561/ |
>| /name/nm0588225/ |
>| /name/nm0503800/ |
>| /name/nm0534205/ |
>| /name/nm3275500/ |
>| /name/nm5181257/ |
>| /name/nm3072420/ |
>| /name/nm0246686/ |
>| /name/nm1502201/ |


### imdb-get-all-filmography

***
Get all filmography of actor or actress

#### Base Command

`imdb-get-all-filmography`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| nconst | You need to extract the value started with "nm" returned in imdb-list-born-today or imdb-list-most-popular-celebs commands. Ex: nm0000134. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Celebs.AllFilm | string | All Filmography | 


### imdb-get-full-credits

***
Get full list of casts and Crews relating to specific title

#### Base Command

`imdb-get-full-credits`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tconst | You need to extract the value started with "tt" of id field returned from imdb-auto-complete, imdb-get-most-popular-movies or imdb-get-top-rated-shows commands. Ex: tt0113277. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IMDb.Title.Credits.id | String | ID of the title | 
| IMDb.Title.Credits.base.image.url | String | URL of the title image | 
| IMDb.Title.Credits.base.runningTimeInMinutes | Number | Movie duration | 
| IMDb.Title.Credits.base.title | String | Name of the title | 
| IMDb.Title.Credits.base.titleType | String | Type of the title, e.g. movie, show... | 
| IMDb.Title.Credits.base.year | Number | Year of the title release | 
| IMDb.Title.Credits.cast.id | String | ID of the actor | 
| IMDb.Title.Credits.cast.image.id | String | ID of the image | 
| IMDb.Title.Credits.cast.image.url | String | URL of the image | 
| IMDb.Title.Credits.cast.legacyNameText | String | Legacy name | 
| IMDb.Title.Credits.cast.name | String | Name | 
| IMDb.Title.Credits.cast.category | String | Category | 
| IMDb.Title.Credits.cast.characters | String | Characters played | 
| IMDb.Title.Credits.cast.roles.characterId | String | ID of the character | 
| IMDb.Title.Credits.cast.akas | String | Also known as | 
| IMDb.Title.Credits.crew.editor.akas | String | Also known as | 
| IMDb.Title.Credits.crew.editor.id | String | ID of the editor | 
| IMDb.Title.Credits.crew.editor.image.id | String | ID of the editor image | 
| IMDb.Title.Credits.crew.editor.image.url | String | URL of the editor image | 
| IMDb.Title.Credits.crew.editor.legacyNameText | String | Legacy name | 
| IMDb.Title.Credits.crew.editor.name | String | Name | 
| IMDb.Title.Credits.crew.editor.category | String | Category | 
| IMDb.Title.Credits.crew.director.id | String | ID of the director | 
| IMDb.Title.Credits.crew.director.image.id | String | ID of the director image | 
| IMDb.Title.Credits.crew.director.image.url | String | URL of the director image | 
| IMDb.Title.Credits.crew.director.legacyNameText | String | Legacy name | 
| IMDb.Title.Credits.crew.director.name | String | Name | 
| IMDb.Title.Credits.crew.director.category | String | Category | 
| IMDb.Title.Credits.crew.producer.id | String | ID of the producer | 
| IMDb.Title.Credits.crew.producer.image.id | String | ID of the producer image | 
| IMDb.Title.Credits.crew.producer.image.url | String | URL of the producer image | 
| IMDb.Title.Credits.crew.producer.legacyNameText | String | Legacy name | 
| IMDb.Title.Credits.crew.producer.name | String | Name | 
| IMDb.Title.Credits.crew.producer.category | String | Category | 
| IMDb.Title.Credits.crew.producer.job | String | E.g. executive or associate producer | 
| IMDb.Title.Credits.crew.producer.akas | String | Also known as | 
| IMDb.Title.Credits.crew.writer.id | String | ID of the writer | 
| IMDb.Title.Credits.crew.writer.image.id | String | ID of the writer image | 
| IMDb.Title.Credits.crew.writer.image.url | String | URL of the writer image | 
| IMDb.Title.Credits.crew.writer.legacyNameText | String | Legacy name | 
| IMDb.Title.Credits.crew.writer.name | String | Name | 
| IMDb.Title.Credits.crew.writer.category | String | Category | 
| IMDb.Title.Credits.crew.writer.job | String | Written by | 
