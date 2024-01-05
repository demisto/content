CI_SERVER_URL=${CI_SERVER_URL:-https://gitlab.xdr.pan.local} # disable-secrets-detection
CI_PROJECT_ID=${CI_PROJECT_ID:-1061}
export BUILD_TRIGGER_URL="${CI_SERVER_URL}/api/v4/projects/${CI_PROJECT_ID}/trigger/pipeline"
