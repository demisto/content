import demistomock as demisto  # noqa: F401
import requests
from bs4 import BeautifulSoup
from CommonServerPython import *  # noqa: F401

TABLE = []
VERIFY = demisto.params()['insecure']


def scrape_kos():
    articles = []
    links = []
    dates = []
    response = requests.get("https://krebsonsecurity.com/", verify=VERIFY)
    soup = BeautifulSoup(response.text, "html.parser")

    for article in soup.select(".entry-title"):
        title = article.get_text().strip()
        articles.append(title)
        link = article.find('a').attrs['href']
        links.append(link)

    for date in soup.select(".adt"):
        dates.append(date.find('span').get_text().strip())

    return list(zip(articles, list(zip(links, dates))))


def scrape_thn():
    articles = []
    links = []
    dates = []
    response = requests.get("https://thehackernews.com/", verify=VERIFY)
    soup = BeautifulSoup(response.text, "html.parser")

    for article in soup.select(".home-title"):
        articles.append(article.get_text().strip())

    for link in soup.select(".story-link"):
        links.append(link["href"])

    for date in soup.select(".item-label"):
        date_got = date.get_text().split(",")[0][1:]  # February 23
        dates.append(date_got)

    return list(zip(articles, list(zip(links, dates))))


def scrape_tp():
    articles = []
    links = []
    dates = []
    response = requests.get("https://threatpost.com/", verify=VERIFY)
    soup = BeautifulSoup(response.text, "html.parser")

    for article in soup.select('.c-card__title'):
        articles.append(article.get_text().strip())
        links.append(article.find('a').attrs['href'])

    for date in soup.select('.c-card__time'):
        dates.append(date.get_text().strip())

    return list(zip(articles, list(zip(links, dates))))


def aggregate(feed, source):
    for elem in feed:
        clickable_link = "[" + elem[1][0] + "](" + elem[1][0] + ")"
        TABLE.append({"Article": elem[0], "Link": clickable_link, "Date": elem[1][1], "Source": source})


def main():
    # # The command demisto.command() holds the command sent from the user.
    if demisto.command() == 'get-news-KrebsOnSecurity':
        kos = scrape_kos()
        aggregate(kos, "Krebs on Security")
    elif demisto.command() == 'get-news-Threatpost':
        tp = scrape_tp()
        aggregate(tp, "Threatpost")
    elif demisto.command() == 'get-news-TheHackerNews':
        thn = scrape_thn()
        aggregate(thn, "The Hacker News")
    elif demisto.command() == 'test-module':
        # This is the call made when pressing the integration test button.
        test_response = requests.get("https://thehackernews.com/", verify=VERIFY)
        if str(test_response.status_code) == "200":
            demisto.results('ok')
        else:
            demisto.results(test_response)
    elif demisto.command() == 'get-news-generic-all':
        tp = scrape_tp()
        thn = scrape_thn()
        kos = scrape_kos()
        aggregate(kos, "Krebs on Security")
        aggregate(thn, "The Hacker News")
        aggregate(tp, "Threatpost")
    else:
        raise NotImplementedError('Command %s was not implemented.' % demisto.command())

    result = {
        'ContentsFormat': formats['table'],
        'Type': entryTypes['note'],
        'Contents': TABLE,
        'EntryContext': {},
        'IgnoreAutoExtract': True
    }

    if TABLE:
        result['ReadableContentsFormat'] = formats['markdown']
        result['HumanReadable'] = tableToMarkdown('Your popular cybersecurity digest', TABLE, ["Article", "Link", "Date"])
        result['EntryContext'] = {"News": TABLE}

    demisto.results(result)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
