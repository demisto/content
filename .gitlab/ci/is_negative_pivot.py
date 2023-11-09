import gitlab
from datetime import datetime, timedelta
import sys
from dateutil import parser

GITLAB_URL = 'https://code.pan.run'
GITLAB_ACCESS_TOKEN = ''
PROJECT_ID = '2596'


def get_pipelines_and_commits(lookback_hours=48):
    """
    Get all pipelines and commits on the master branch in the last X hours,
    pipelines are filtered to only include successful and failed pipelines.
    Args:
        lookback_hours: int
    Return:
        a list of gitlab pipelines and a list of gitlab commits in ascending order
    """
    gl = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_ACCESS_TOKEN)
    project = gl.projects.get(PROJECT_ID)

    # Calculate the timestamp for 48 hours ago
    time_threshold = (
        datetime.now() - timedelta(hours=lookback_hours)).isoformat()

    commits = project.commits.list(all=True, since=time_threshold, order_by='updated_at', sort='asc')
    pipelines = project.pipelines.list(all=True, updated_after=time_threshold, ref='master',
                                       source='push', order_by='updated_at', sort='asc')

    # Filter out pipelines that are not done
    filtered_pipelines = [
        pipeline for pipeline in pipelines if pipeline.status in ('success', 'failed')]

    return filtered_pipelines, commits


def are_pipelines_in_order_as_commits(commits, current_pipeline_sha, previous_pipeline_sha):
    """
    This function checks if the commit that triggered the current pipeline was pushed
    after the commit that triggered the the previous pipeline,
    to avoid rare condition that pipelines are not in the same order as their commits.
    Args:
        commits: list of gitlab commits
        current_pipeline_sha: string
        previous_pipeline_sha: string

    Returns:
        boolean
    """
    current_pipeline_commit_timestamp = None
    previous_pipeline_commit_timestamp = None
    for commit in commits:
        if commit.id == current_pipeline_sha:
            current_pipeline_commit_timestamp = parser.parse(commit.created_at)
        if commit.id == previous_pipeline_sha:
            previous_pipeline_commit_timestamp = parser.parse(commit.created_at)
    if not current_pipeline_commit_timestamp or not previous_pipeline_commit_timestamp:
        return False
    return current_pipeline_commit_timestamp > previous_pipeline_commit_timestamp


def is_negative_pivot(single_pipeline_id, list_of_pipelines, commits):
    """
    Check if a given pipeline is a negative pivot, i.e. if the previous pipeline was successful and the current pipeline failed
   Args:
    single_pipeline_id: gitlab pipeline ID
    list_of_pipelines: list of gitlab pipelines
    commits: list of gitlab commits
    Return:
        boolean
    """
    pipeline_index = 0
    for pipeline in list_of_pipelines:
        if pipeline.id == single_pipeline_id:
            pipeline_index = list_of_pipelines.index(pipeline)
            break
    if pipeline_index == 0:
        return False
    previous_pipeline = list_of_pipelines[pipeline_index - 1]
    current_pipeline = list_of_pipelines[pipeline_index]

    # if previous pipeline was successful and current pipeline failed, and current pipeline was created after
    # previous pipeline (n), then it is a negative pivot
    return (
        previous_pipeline.status == 'success'
        and current_pipeline.status == 'failed'
        and are_pipelines_in_order_as_commits(commits, current_pipeline.sha, previous_pipeline.sha))


def main(args):
    list_of_pipelines, commits = get_pipelines_and_commits(48)
    res = is_negative_pivot(int(args[1]), list_of_pipelines, commits)
    print(res)


if __name__ == "__main__":
    main(sys.argv)
