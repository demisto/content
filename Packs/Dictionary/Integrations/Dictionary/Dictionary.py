import string
from collections import Counter

import demistomock as demisto  # noqa: F401
import nltk
from CommonServerPython import *  # noqa: F401
from nltk.corpus import brown, reuters, webtext
from nltk.stem import WordNetLemmatizer

# The image in the logo is from https://www.flaticon.com/free-icons/words
# Learn more about NLTK corpora here: https://www.nltk.org/api/nltk.corpus.html




lemmatizer = WordNetLemmatizer()


def test_module():
    # The test module runs nltk downloads and prints ok if successful
    try:
        nltk.download('punkt')
        nltk.download('words')
        nltk.download('book')
        nltk.download('brown')
        nltk.download('wordnet')
    except DemistoException as e:
        raise e
    return 'ok'


def english_words(args: Dict[str, str]):
    # The command needs test module to download associated corpora to run properly

    text = args.get('text')
    corpus = args.get('corpus')
    remove_punc = args.get('removePunctuation', 'yes')
    lemmatize = args.get('lemmatize', 'yes')

    if text:
        if remove_punc.lower() == 'yes':
            # Remove punctuation from text input
            text = text.translate(str.maketrans('', '', string.punctuation))

        # Tokenize the text input
        tokens = nltk.word_tokenize(text)

        if lemmatize.lower() == 'yes':
            # Lemmatize the text to bring each word to its base form
            tokenized_text = [lemmatizer.lemmatize(token) for token in tokens]
        else:
            tokenized_text = nltk.Text(tokens)

        if tokenized_text:
            counts = Counter(tokenized_text)
            ws = set(counts.keys())
        else:
            return 'Tokenized list was empty. Check the value of text and try again.'

        if corpus:
            if corpus == 'brown':
                es = set(brown.words())

            elif corpus == 'nltk-words':
                english = nltk.corpus.words.words('en')
                es = set(english)

            elif corpus == 'webtext':
                es = set(webtext.words())

            elif corpus == 'reuters':
                es = set(reuters.words())
        else:
            return 'Error! No Corpus selected.'

        try:
            overlap = ws.intersection(es)
            overlap_list = list(overlap)

            outliers = ws.difference(es)

            outputs = {
                'Original': args.get('text'),
                'Corpus': corpus,
                'English Words': str(overlap_list),
                'English Percentage': 100 * (len(overlap_list) / len(ws)),
                'Outliers': str(list(outliers))
            }

            return CommandResults(
                outputs={'Dictionary': outputs},
                readable_output=tableToMarkdown(name='Dictionary Words', t=outputs))
        except ZeroDivisionError:
            return 'ZeroDivisionError: Tokenized list was empty. Check the value of text and try again.'
        except ValueError:
            return 'ValueError: Check argument values and try again'

    else:
        return 'Text value cannot be empty or null. Please provide some text value and try again.'


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module())

        elif command == 'find-english-words':
            # This is the command that compares the text against NLTK corpora for English words
            # and displays the results in the war room.
            return_results(english_words(args))

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
