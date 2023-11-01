CI_SERVER_URL=${CI_SERVER_URL:-https://code.pan.run} # disable-secrets-detection
CI_PROJECT_ID=${CI_PROJECT_ID:-2596}
export BUILD_TRIGGER_URL="${CI_SERVER_URL}/api/v4/projects/${CI_PROJECT_ID}/trigger/pipeline"
