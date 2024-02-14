echo "Starting calculate override core packs"
python3 ./Tests/Marketplace/override_core_packs_versions.py -pa "${PACK_ARTIFACTS}" -n "${CI_PIPELINE_ID}" -mp "${MARKETPLACE_VERSION}"
echo "Finished calculate override core packs"

BUILD_BUCKET_PACKS_DIR_FULL_PATH="$GCS_BUILD_BUCKET/$BUILD_BUCKET_PACKS_DIR_PATH"

core_packs_files_count=$(find "${ARTIFACTS_FOLDER_SERVER_TYPE}" -name "corepacks*.json" | wc -l)
if [ "${core_packs_files_count}" -eq 0 ]; then
  echo "No core packs files were found, skipping uploading."
else
  echo "Uploading ${core_packs_files_count} core packs files."
  # Copy core packs files from the artifacts folder to the build bucket:
  find "${ARTIFACTS_FOLDER_SERVER_TYPE}" -name "corepacks*.json" -exec gsutil cp -z json "{}" "gs://$BUILD_BUCKET_PACKS_DIR_FULL_PATH" \;
  echo "Successfully uploaded core packs files."
fi

if [ -f "${ARTIFACTS_FOLDER_SERVER_TYPE}/versions-metadata.json" ]; then
  echo "Uploading versions-metadata.json."
  gsutil cp -z json "${ARTIFACTS_FOLDER_SERVER_TYPE}/versions-metadata.json" "gs://$BUILD_BUCKET_PACKS_DIR_FULL_PATH"
  echo "Successfully uploaded versions-metadata.json."
else
  echo "No versions-metadata.json file, skipping uploading."
fi

echo "Finished updating content packs successfully."

