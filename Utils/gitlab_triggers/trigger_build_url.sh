CI_SERVER_URL=${CI_SERVER_URL:-https://code.pan.run}
CI_PROJECT_ID=${CI_PROJECT_ID:-2596}
echo "CI_SERVER_URL is set to: ${CI_SERVER_URL}"
echo "CI_PROJECT_ID is set to: ${CI_PROJECT_ID}"
export BUILD_TRIGGER_URL="${CI_SERVER_URL}/api/v4/projects/${CI_PROJECT_ID}/trigger/pipeline"  # disable-secrets-detection
echo "BUILD_TRIGGER_URL is set to: ${BUILD_TRIGGER_URL}"