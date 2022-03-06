switch (command) {
    case 'test-module':
        return 'ok';
    case 'clue':
        var res = '';
        switch ((args['magic-word'] || '').toLowerCase()) {
            case '':
                res = 'Finally! You found me. Although Demisto demystifies, we still have so many secrets waiting to be discovered. Let\'s play a little game. Try the same command, but now with a dash of \'mystery\'…';
                break;
            case 'mystery':
                res = 'We\'re full of mysteries, but you\'re on your way to uncovering them! It\'s not going to be easy. Say, what\'s the name of the icon we have for automated tasks? I remembered it a second ago, but then it was gone in a flash… \n\n---\n\n ![mystery](https://media.giphy.com/media/3ohhwg3O1TGRXHQYh2/source.gif)';
                break;
            case 'lightning':
                res = 'Wow, you\'re good! Is your name Lightning McAnalyst? Because that was fast. The lightning icon does represent automated tasks. Why? Some questions are best left unanswered (which is mystery-speak for \'nobody knows\').  \nTime for your next question. As you know, DBot speaks tons of languages. One such special language (and a personal favorite of mine) is denoted by M↓. Remind me what it\'s called again? \n\n---\n\n ![lightning](https://media.giphy.com/media/FZzbTJyRTwPuw/source.gif)';
                break;
            case 'markdown':
                res = 'That\'s a markdown touchdown! A follow-up language question. Another one of DBot\'s many languages (some would say the most important one) begins with an \'h\', I think. Any guesses?';
                break;
            case 'html':
                res = 'You\'re on fire! Sorry my memory\'s not so good today. Perhaps I need 16GB (or SSD?) to be faster, what with things changing so quickly around here...   \nNow for a tricky one. Find the answer to this riddle:  \nDemisto content updates are constantly shipped\nPlaybooks, widgets, integrations, scripts,\nWill you be a dear and tell me please,\nThe frequency of this content release?';
                break;
            case 'twice a month':
            case 'every fortnight':
            case 'every two weeks':
            case 'every-two-weeks':
            case 'everytwoweeks':
            case 'two weeks':
            case 'two-weeks':
            case 'twoweeks':
            case 'every 2 weeks':
            case 'every-2-weeks':
            case 'every2weeks':
            case '2 weeks':
            case '2-weeks':
            case '2weeks':
            case 'biweekly':
            case 'fortnightly':
                res = 'I can\'t believe it! Everyone else is just pretending, you\'re the real legend in this town. Congratulations for conquering my little game. As a treat, run /demisto and sit back.\n\n---\n\By the way, there are many more Easter eggs to find within these digital walls. Just use the magic words "dbot I love you" and we can have a rematch.';
                break;
            case 'dbot i love you':
                res = 'oh, that\'s nice... but try in another time... [meanwhile...](https://www.youtube.com/watch?v=dQw4w9WgXcQ)';
                break;
            default:
                res = 'no no...';
        }
        return { Contents: res, ContentsFormat: 'markdown', Type: 1 };
    default:
}
