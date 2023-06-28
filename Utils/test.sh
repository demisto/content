
for _ in {1..3}; do
  echo "trigger ...."
  export pipeline_id="null"
  if [ $pipeline_id != "null" ]; then
    break
  fi
  echo "Sleeping for 10 seconds before retrying"
  sleep 1
done