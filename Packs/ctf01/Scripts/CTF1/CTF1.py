import random
import traceback

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

'''
           *//////
         ,////////*.                   ..,..              ,,,.
        //////     /////          .&&&&@@@@@&&(      /&&&&@@@&&&&&.      @&&@@@@@@&&&&     @@@@@&&&&@@@@@/    ,@&&@@@@@@@@@     ,@&&&    %&&@*
       /////,      //////.       &&&@.              @&&&,      #&&&(     @&&(      &&&#         /&&&          ,@&&.                &&&@&&&&
       /////       //////*       &&&/              .@&&&       .@&&%     @&&&@@@&&&&@(          /&&&          ,@&&&&&&&&@           (&&&&#
       ,/////      //////        *@&&%,      **     (@&&&,    /&&&@.     @&&(  .%&&&.           /&&&          ,@&&.               &&&@,*@&&&.
        ,//////.   ///,            .%@&&&&&&&@(       ,@@&&&&&&@%.       @&&(     #&&@/         /&&&          ,@&&&&&&&&&&@    ,&&&&.    .&&&@*
          *///////*
             ,/////
                                   .,,,,,,              ,,,,,,.           .,*//(///*,.                   .,*//(///*,.                     .,,,,,,,,.               ,,,,,,,,,,,,,,,,.
                                     /(((((/          /(((((*         ./(((((((((((((((((*           /(((((((((((((((((/,                ,((((((((((,              /((((((((((((((((((((,
                                       ((((((/      ((((((/          /((((((*.    ./(((((*        .((((((((*.    ./(((((((*              ((((((((((((.             /((((/////////(((((((((
                                         /(((((/  /(((((*           ,(((((,              ,       *(((((/             ,((((((           .(((((,  *(((((.            /((((/           ,(((((*
                                           /((((((((((*              (((((((/*,,.               .(((((*               .(((((*         .(((((,    ,(((((.           /((((/           .(((((*
                                             ((((((((                 ,((((((((((((((((/.       ,(((((,                /(((((        .(((((*      /(((((           /((((/          ,((((((.
                                           /((((((((((*                     ,/((((((((((((/     ,(((((,                (((((/       .(((((//////////(((((.         /((((((((((((((((((((/
                                         *(((((/  /(((((*                            /(((((.     ((((((.              /(((((.      .((((((((((((((((((((((.        /(((((((((((((((((,
                                       /(((((/      ((((((*         ,((/*.          ./(((((       /((((((*         ./((((((.       (((((*............/(((((        /((((/       .((((((.
                                     /(((((/         .((((((*       ,(((((((((((((((((((((          /((((((((((((((((((((,        (((((*              /((((/       /((((/         .(((((/
                                   ((((((/              ((((((/        /(((((((((((((((.               ,(((((((((((((/          .(((((*                /(((((      /((((/           *((((((


                                  ,*** .*  *,   ***,  ,*,  *,    */*     .**  .*  ,****  */*    .*  * .***, **** *. *, *. ,//.  ***. ,* ,* .*/,
                                  */,/*  /(     (((( ,/,/* /*   (  ,(    (*/* ,/    (.  (. */   ,(*(/ .(**   **   (**(*/ **  /,.(((* *///   */(
'''


good_images = [
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/deadpool-clapping.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/friends-joey.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/quality-quality-work.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/the-rock-dwayne-johnson.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/you-you-are.gif"
]

bad_images = [
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/idola-idola-industries.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/it-doesnt-work-that-way-john-edward.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/lion-king.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/robert-downey-jr-maybe.gif",
    "https://raw.githubusercontent.com/demisto/content/ctf/Packs/ctf01/doc_files/the-rock-look-the-rock-meme.gif"
]

HTML_MESSAGE_1 = '''
<img src="%s" alt="Robot">
<div style='font-size:18px;'>
Well Done!!!
</div>
''' % (good_images[random.randint(0, len(good_images) - 1)])

HTML_MESSAGE_BAD = '''
<img src="%s" alt="Error">
<div style='font-size:18px;'>
Nope!!! Try again.
Remember to overwrite the "secret" argument when you are re-running the task. To re-run the task - please click on the 'Run automation now' :)
</div>
''' % (bad_images[random.randint(0, len(bad_images) - 1)])

answers = {
    "01": ["4", "four", "04"],
    "02": ["se_summit_2023", "se summit 2023"],
    "03": ["<none>", "none", "nothing"],
    "04": ["ctf 01", "ctf01"],
    "05": ["reportsarecool"],
    "06": ["monkey", "baboon", "ape", "gorilla", "lemor", "chimpanzee", "orangutan"],
    "07": ["alt/option", "alt", "option"],
    "08": ["demisto", "downloads"]

}

# MAIN FUNCTION #


def main():
    try:
        args = demisto.args()
        # __Error handeling when there is an empty secret or question id__
        if (args.get("secret") == None or args.get("question_ID") == None):
            return_error(f'Please specify Secret and Question ID to proceed with the challange')

        if (args.get("secret").lower() in answers[args.get("question_ID")]):
            return_results({
                'ContentsFormat': EntryFormat.HTML,
                'Type': EntryType.NOTE,
                'Contents': HTML_MESSAGE_1,
            })
        # General Error handeling
        else:
            if (args.get("question_ID") == "03"):
                return_error(
                    f'In case the playbook is in "Quite Mode", no output will be displayed in the war-room.\n\nYou can skip this task if you want or re-run it with <none> :). ')
            else:
                #return_error(f'Nope... try again!!!\nRemember to overwrite the "secret" argument when you are re-running the task :)')
                demisto.results({
                    'Type': entryTypes['error'],
                    'ContentsFormat': formats['html'],
                    'Contents': HTML_MESSAGE_BAD,
                })

    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ERTokenReputation. Error: {str(exc)}')


# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()

register_module_line('CTF01_Task01', 'end', __line__())
