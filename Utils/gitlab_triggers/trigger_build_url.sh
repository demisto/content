export BUILD_TRIGGER_URL="${CI_SERVER_URL}/api/v4/projects/${CI_PROJECT_ID}/trigger/pipeline"  # disable-secrets-detection
echo "BUILD_TRIGGER_URL is set to: ${BUILD_TRIGGER_URL}"