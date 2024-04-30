import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import traceback
import random


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
'''  # noqa: E501


good_images = [
    "https://raw.githubusercontent.com/demisto/content/10b88c87c2954c3b97108b3c07596fcf3cf128b7/Packs/ctf01/doc_files/F2.gif",
    "https://raw.githubusercontent.com/demisto/content/10b88c87c2954c3b97108b3c07596fcf3cf128b7/Packs/ctf01/doc_files/F.gif",
    "https://raw.githubusercontent.com/demisto/content/10b88c87c2954c3b97108b3c07596fcf3cf128b7/Packs/ctf01/doc_files/F3.gif",
    "https://raw.githubusercontent.com/demisto/content/10b88c87c2954c3b97108b3c07596fcf3cf128b7/Packs/ctf01/doc_files/F4.gif"
]

bad_images = [
    "https://raw.githubusercontent.com/demisto/content/9e0946e3f76ed1862c6e40ea79ab85a9449d7102/Packs/ctf01/doc_files/G2.gif",
    "https://raw.githubusercontent.com/demisto/content/9e0946e3f76ed1862c6e40ea79ab85a9449d7102/Packs/ctf01/doc_files/G3.gif",
    "https://raw.githubusercontent.com/demisto/content/9e0946e3f76ed1862c6e40ea79ab85a9449d7102/Packs/ctf01/doc_files/G4.gif",
    "https://raw.githubusercontent.com/demisto/content/9e0946e3f76ed1862c6e40ea79ab85a9449d7102/Packs/ctf01/doc_files/G5.gif"
]

HTML_MESSAGE_1 = '''
<img src="%s" alt="ok" width="350" height="200">
<div style='font-size:18px;'>
Well Done!!!
</div>
''' % (good_images[random.randint(0, len(good_images) - 1)])

HTML_MESSAGE_BAD = '''
<img src="%s" alt="Error" width="350" height="200">
<div style='font-size:18px;'>
Nope!!! Try again.
Remember to overwrite the "secret" argument when you are re-running the task.
To re-run this task -> Click on "Complete Task" -> clear the Secret value using the trash-can icon -> fill out the Secret value -> click on the 'Run script now' :)
</div>
''' % (bad_images[random.randint(0, len(bad_images) - 1)])  # noqa: E501

answers = {
    "01": ["no", "no errors", "nothing", "none"],
    "02": ["ip address", "ip", "address"],
    "03": ["12", "twelve", "13", "thirteen"],
    "04": ["2017", "two thousand seventeen", "two-thousand-seventeen"],
    "05": ["29", "twenty nine", "twenty-nine"],
    "06": ["true", "true positive"],
    "07": ["blocked"],
    "08": ["137.184.208.116"]

}


# Dec Functions #

def good_msg():
    return_results({
        'ContentsFormat': EntryFormat.HTML,
        'Type': EntryType.NOTE,
        'Contents': HTML_MESSAGE_1,
    })


def error_msg():
    return_results({
        'Type': EntryType.ERROR,
        'ContentsFormat': formats['html'],
        'Contents': HTML_MESSAGE_BAD,
    })


# MAIN FUNCTION #


def main():
    try:
        args = demisto.args()
        # __Error handling when there is an empty secret or question id__

        question_id = args.get("question_ID")
        secret = args.get("secret", "").lower()
        if not secret or not question_id:
            raise DemistoException('Please specify Secret and Question ID to proceed with the challenge')

        # __Validate Question number 03__
        match question_id:
            case "03":

                total_rel = str(
                    demisto.executeCommand("searchRelationships", {"filter": {"entities": ["137.184.208.116"]}}).get('total'))
                good_msg() if secret.lower() == total_rel else error_msg()

            case "05":
                total_rel = str(demisto.executeCommand("searchRelationships",
                                                       {"filter": {
                                                           "entities": ["IcedID Infection leads to DarkVNC"]}}).get('total'))
                good_msg() if secret.lower() == total_rel else error_msg()

            case _:
                good_msg() if secret.lower() in answers[question_id] else error_msg()

    except Exception as exc:  # pylint: disable=W0703
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute this script. Error: {str(exc)}')

# ENTRY POINT #


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
