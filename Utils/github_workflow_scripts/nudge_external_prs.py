import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Tuple

from blessings import Terminal
from github.Issue import Issue
from github.MainClass import Github
from github.PullRequest import PullRequest
from github.TimelineEvent import TimelineEvent
from slack import WebClient

from utils import get_env_var, timestamped_print

BOT_NAME = 'content-bot'
STALE_TIME = 5  # 5 days
GITHUB_TO_SLACK = {
    'Itay4': 'ikeren@paloaltonetworks.com',
    'yaakovi': 'syaakovi@paloaltonetworks.com',
    'ronykoz': 'rkozakish@paloaltonetworks.com',
    'yuvalbenshalom': 'ybenshalom@paloaltonetworks.com',
    'anara123': 'aazadaliyev@paloaltonetworks.com',
    'adi88d': 'adaud@paloaltonetworks.com',
    'amshamah419': 'ashamah@paloaltonetworks.com',
    'Arsenikr': 'akrupnik@paloaltonetworks.com',
    'bakatzir': 'bkatzir@paloaltonetworks.com',
    'dantavori': 'dtavori@paloaltonetworks.com',
    'DeanArbel': 'darbel@paloaltonetworks.com',
    'guykeller': 'gkeller@paloaltonetworks.com',
    'GalRabinDemisto': 'grabin@paloaltonetworks.com',
    'glicht': 'glichtman@paloaltonetworks.com',
    'guyfreund': 'gfreund@paloaltonetworks.com',
    'David-BMS': 'dbaumstein@paloaltonetworks.com',
    'idovandijk': 'ivandijk@paloaltonetworks.com',
    'IkaDemisto': 'igabashvili@paloaltonetworks.com',
    'liorblob': 'lblobstein@paloaltonetworks.com',
    'michalgold': 'mgoldshtein@paloaltonetworks.com',
    'mayagoldb': 'mgoldberg@paloaltonetworks.com',
    'orenzohar': 'ozohar@paloaltonetworks.com',
    'orlichter1': 'olichter@paloaltonetworks.com',
    'reutshal': 'rshalem@paloaltonetworks.com',
    'roysagi': 'rsagi@paloaltonetworks.com',
    'Shellyber': 'sberman@paloaltonetworks.com',
    'teizenman': 'teizenman@paloaltonetworks.com',
    'yardensade': 'ysade@paloaltonetworks.com',
    'avidan-H': 'ahessing@paloaltonetworks.com',
    'hod-alpert': 'halpert@paloaltonetworks.com',
    'ShahafBenYakir': 'sbenyakir@paloaltonetworks.com',
    'moishce': 'mgalitzki@paloaltonetworks.com'
}
SLACK_TO_GITHUB = {val: key for key, val in GITHUB_TO_SLACK.items()}
COMMENTERS_TO_IGNORE = ('CLAassistant', 'guardrails[bot]', 'welcome[bot]', 'lgtm-com[bot]')
NUDGE_AUTHOR_MSG = 'A lengthy period of time has transpired since the PR was reviewed. Please address the ' \
                   'reviewer\'s comments and push your committed changes.'
NEEDS_REVIEW_MSG = 'This PR won\'t review itself and I\'m not going to do it for you (I bet you\'d like ' \
                   'that wouldn\'t you) - look it over, eh?'
LOTR_NUDGE_MSG = '"And some things that should not have been forgotten were lost. History became legend. Legend ' \
                 'became myth. And for two and a half thousand years..." {reviewer} had not looked at this ' \
                 'beautiful PR - as they were meant to do.'
SUGGEST_CLOSE_MSG = 'These reminders don\'t seem to be working and the issue is getting pretty stale - ' \
                    'consider whether this PR is still relevant or should be closed.'
STALE_MSG = 'This PR is starting to get a little stale.'


print = timestamped_print


def determine_slack_msg(last_event: TimelineEvent) -> str:
    '''Determine which slack message to send depending on the age of the last event (which is a commit)

    Args:
        last_event (TimelineEvent): Commit event

    Returns:
        str: The message to use in the slack message to the reviewers of the given PR
    '''
    created = last_event.created_at

    stale_delta = timedelta(STALE_TIME)
    old_marker = datetime.utcnow() - stale_delta
    older_marker = old_marker - stale_delta
    oldest_marker = older_marker - stale_delta
    if created < oldest_marker:
        msg = SUGGEST_CLOSE_MSG
    elif created < older_marker:
        msg = LOTR_NUDGE_MSG
    else:
        msg = NEEDS_REVIEW_MSG
    return msg


def build_slack_blocks(msg: str, pr: PullRequest) -> List[Dict]:
    blocks = []
    header = {
        'type': 'section',
        'text': {
            'type': 'mrkdwn',
            'text': f'{msg}'
        }
    }
    divider = {'type': 'divider'}
    # About the drop some mean regex right now disable-secrets-detection-start
    context = {
        'type': 'context',
        'elements': [
            {
                'type': 'image',
                'image_url': 'https://github.githubassets.com/favicons/favicon.png',
                'alt_text': 'GitHub'
            },
            {
                'type': 'plain_text',
                'emoji': True,
                'text': 'GitHub'
            }
        ]
    }
    # Drops the mic disable-secrets-detection-end
    # format pr body section headers to be bold - slack markdown doesn't support header syntax like "## Some header"
    pr_body = re.sub('^(## )(.*?)($|\r)', lambda m: f'*{m.group(2)}*', pr.body, flags=re.MULTILINE)
    body = {
        'type': 'section',
        'text': {
            'type': 'mrkdwn',
            'text': f'*<{pr.html_url}|{pr.title} #{pr.number}>*\n{pr_body}'
        }
    }
    blocks.extend([header, divider, context, body, divider])
    return blocks


def main():
    """Notifies and nudges the appropriate users for stale external PRs

    Will use the following env vars:
    - CONTENTBOT_GH_ADMIN_TOKEN: token to use to update the PR
    - SLACK_API_TOKEN: token for the slack bot used to send slack messages
    """
    t = Terminal()
    print(f'{t.cyan}Starting external PR nudger{t.normal}')
    gh = Github(get_env_var('CONTENTBOT_GH_ADMIN_TOKEN'))
    content_repo = gh.get_repo('demisto/content')
    all_open_pulls = content_repo.get_pulls(state='OPEN')
    prs: List[Issue] = [
        pr.as_issue() for pr in all_open_pulls if pr.base.ref.startswith('contrib/') and pr.head.repo.fork
    ]
    stale_prs: List[Tuple[PullRequest, List[Any]]] = []
    for pr_issue in prs:
        pr_timeline = pr_issue.get_timeline()
        filtered_timeline = [event for event in pr_timeline if event.event in {'committed', 'commented', 'reviewed'}]
        refiltered_timeline = []
        for event in filtered_timeline:
            if event.event == 'commented':
                if event.actor.login in COMMENTERS_TO_IGNORE:
                    continue
                else:
                    refiltered_timeline.append(event)
            else:
                refiltered_timeline.append(event)
        filtered_timeline = refiltered_timeline

        stale_delta = timedelta(STALE_TIME)
        stale_marker = datetime.utcnow() - stale_delta
        last_event = filtered_timeline[-1]
        if last_event.created_at < stale_marker:
            stale_prs.append((pr_issue.as_pull_request(), filtered_timeline))

    # initialize slack client
    client = WebClient(token=get_env_var('SLACK_API_TOKEN'))

    for stale_pr, f_timeline in stale_prs:
        pr_opener = stale_pr.user.login
        if pr_opener == 'xsoar-bot':
            # in case we got contribution pr which was opened by xsoar-bot, we set the contributor to be the pr opener
            contributor = re.search(r"(?<=Description)\s{1,2}@([^']+)", stale_pr.body)
            if contributor:
                pr_opener = contributor.group(1)
        last_event = f_timeline[-1]

        reviewers, _ = stale_pr.get_review_requests()
        requested_reviewers = [requested_reviewer.login for requested_reviewer in reviewers]
        slack_handles = [
            GITHUB_TO_SLACK.get(reviewer, '') for reviewer in requested_reviewers if GITHUB_TO_SLACK.get(reviewer)
        ]
        if last_event.event.casefold() == 'committed'.casefold():
            msg = determine_slack_msg(last_event)
            if msg:
                # send slack message to right people
                print(f'{t.cyan}Sending slack message reminders for PR #{stale_pr.number}{t.normal}')
                for slack_handle in slack_handles:
                    response = client.users_lookupByEmail(email=slack_handle)
                    user_id = response.get('user', {}).get('id', '')
                    if msg == LOTR_NUDGE_MSG:
                        msg = msg.format(reviewer=SLACK_TO_GITHUB.get(slack_handle))
                    blocks_message = build_slack_blocks(msg, stale_pr)
                    client.chat_postMessage(channel=user_id, blocks=blocks_message)
        elif last_event.event.casefold() == 'reviewed'.casefold():
            if stale_pr.get_reviews()[-1].state.casefold() != 'approved'.casefold():
                print(f'{t.cyan}Nudging PR opener "{pr_opener}"{t.normal}')
                msg = f'@{pr_opener} {NUDGE_AUTHOR_MSG}'
                stale_pr.create_issue_comment(msg)
        elif last_event.event.casefold() == 'commented'.casefold():
            commenter = last_event.actor.login
            if commenter == BOT_NAME and last_event.body.contains(f'@{pr_opener} are there'):
                print(f'{t.cyan}Already nudged "{pr_opener}" - skipping nudge{t.normal}')
                # Bot already commented on the PR Nudging the author - do nothing
                continue
            elif commenter != pr_opener:
                # The last comment wasn't made by the PR opener (and is probably one of the requested reviewers) assume
                # that the PR opener needs a nudge
                print(f'{t.cyan}Nudging "{pr_opener}" since he wasn\'t the last commenter{t.normal}')
                nudge_author = f' @{pr_opener} are there any changes you wanted to make since @{commenter}\'s last ' \
                    f'comment? '
                msg = STALE_MSG + nudge_author
                stale_pr.create_issue_comment(msg)
            else:
                # Else assume the person who opened the PR is waiting on the response of one of the reviewers
                reviewers_to_ping = ' '.join(
                    ['@' + reviewer for reviewer in requested_reviewers if reviewer != commenter]
                )
                nudge_reviewer = f' {reviewers_to_ping} what\'s new ' \
                                 f'since @{commenter}\'s last comment?\n{stale_pr.html_url} '
                reviewer_nudge_msg = STALE_MSG + nudge_reviewer

                if last_event.body == reviewer_nudge_msg:
                    msg = reviewer_nudge_msg
                else:
                    msg = SUGGEST_CLOSE_MSG

                print(f'{t.cyan}Nudging the pr - {reviewers_to_ping} - reviewers over slack {t.normal}')

                # Send Slack message To requested reviewers
                for slack_handle in slack_handles:
                    response = client.users_lookupByEmail(email=slack_handle)
                    user_id = response.get('user', {}).get('id', '')
                    blocks_message = build_slack_blocks(msg, stale_pr)
                    client.chat_postMessage(channel=user_id, blocks=blocks_message)


if __name__ == '__main__':
    main()
