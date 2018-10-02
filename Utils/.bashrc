export CONTENT=$HOME/dev/demisto/content

alias content="cd $CONTENT"

function trigger_content_nightly() {
    if [[ "$1" == "--help" ]]; then
      echo "Usage: trigger_content_nightly branch circle_token"
    else
      $HOME/dev/demisto/content/utils/trigger_content_nightly_build.sh $1 $2
    fi
}

function add_playbook_descriptions() {
    if [[ "$1" == "--help" ]]; then
      echo "Usage: add_playbook_descriptions <source playbook path>, <destination playbook path>"
    else
      python $HOME/dev/demisto/content/utils/add_playbook_descriptions.py $1 $2
    fi
}
