import gitlab
from datetime import datetime, timedelta
import sys

GITLAB_URL = 'https://code.pan.run'
GITLAB_ACCESS_TOKEN = ''
PROJECT_ID = '2596'


def get_pipelines(lookback_hours=48):
    """
    Get all pipelines that are successful or failed and on the master branch
    Args:
        lookback_hours: int
    Return:
        list of gitlab pipelines
    """
    gl = gitlab.Gitlab(GITLAB_URL, private_token=GITLAB_ACCESS_TOKEN)

    # Calculate the timestamp for 48 hours ago
    time_threshold = (
        datetime.now() - timedelta(hours=lookback_hours)).isoformat()

    # Retrieve the project
    project = gl.projects.get(PROJECT_ID)

    # Get all pipelines
    pipelines = project.pipelines.list(all=True, updated_after=time_threshold)

    # Filter pipelines that are done and on the master branch
    filtered_pipelines = [
        pipeline for pipeline in pipelines if pipeline.status in ('success', 'failed') and pipeline.ref == 'master']

    # Sort the filtered pipelines by creation time
    sorted_pipelines = sorted(
        filtered_pipelines, key=lambda pipeline: pipeline.created_at)

    return sorted_pipelines


def is_negative_pivot(single_pipeline_id, list_of_pipelines):
    """
    Check if a given pipeline is a negative pivot, i.e. if the previous pipeline was successful and the current pipeline failed
   Args:
    single_pipeline_id: gitlab pipeline ID
    list_of_pipelines: list of gitlab pipelines
    Return:
        boolean
    """
    pipeline_index = 0
    for pipeline in list_of_pipelines:
        if pipeline.id == single_pipeline_id:
            pipeline_index = list_of_pipelines.index(pipeline.id)
    if pipeline_index == 0:
        return False
    previous_pipeline = list_of_pipelines[pipeline_index - 1]
    return (
        previous_pipeline.status == 'success'
        and single_pipeline_id.status == 'failed'
    )


def main(args):
    list_of_pipelines = get_pipelines(48)
    res = is_negative_pivot(int(args[1]), list_of_pipelines)
    print(res)


if __name__ == "__main__":
    main(sys.argv)
