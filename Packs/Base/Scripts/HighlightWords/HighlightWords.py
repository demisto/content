import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

HIGHLIGHT_WORD_STYLE_TEMPLATE = '**%s**'


def main():
    TERMS = demisto.args()['terms'].split(",")
    WORDS, SENTENCES = [t.strip().lower() for t in TERMS if " " not in t.strip()], [t.strip().lower() for t in TERMS if
                                                                                    " " in t.strip()]
    WORDS.sort(reverse=True, key=lambda x: len(x))
    INIT_TEXT = demisto.args().get('text', '').lower()
    if not INIT_TEXT:
        return_error("The input text is empty")

    for word in WORDS:
        for sentence in SENTENCES:
            if word in sentence:
                return_error('The word "%s" is a substring of the sentance: "%s"' % (word, sentence))

    text_words = INIT_TEXT.lower().split(" ")
    marked_text_words = []

    found = False
    for text_word in text_words:
        found_word_match = False
        for word in WORDS:
            if word in text_word:
                found_word_match = True
                break
        if found_word_match:
            marked_text_words.append(HIGHLIGHT_WORD_STYLE_TEMPLATE % text_word)
            found = True
        else:
            marked_text_words.append(text_word)

    marked_text = " ".join(marked_text_words)
    for sentence in SENTENCES:
        if sentence in marked_text:
            marked_text = marked_text.replace(sentence, HIGHLIGHT_WORD_STYLE_TEMPLATE % sentence)
            found = True

    if found:
        entry = {
            'Type': entryTypes['note'],
            'Contents': marked_text,
            'ContentsFormat': formats['text'],
            'HumanReadable': marked_text,
            'ReadableContentsFormat': formats['markdown']
        }
        demisto.results(entry)
    else:
        demisto.results("The text does not contains any of the input words")


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
