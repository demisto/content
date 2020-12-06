<<<<<<< HEAD
#!/usr/bin/env bash
set -e

echo "CIRCLE_BRANCH: $CIRCLE_BRANCH CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [[ $CIRCLE_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]];
  then
    demisto-sdk validate -a
else
  demisto-sdk validate -g --post-commit
fi

=======
#!/usr/bin/env bash
set -e

echo "CIRCLE_BRANCH: $CIRCLE_BRANCH CHECK_BACKWARD: $CHECK_BACKWARD CI: $CI DEMISTO_README_VALIDATION: $DEMISTO_README_VALIDATION"

if [[ $CIRCLE_BRANCH = master ]] || [[ -n "${NIGHTLY}" ]] || [[ -n "${BUCKET_UPLOAD}" ]];
  then
    demisto-sdk validate -a

elif [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit

  else
     demisto-sdk validate -g --post-commit --no-backward-comp
fi
>>>>>>> 192e32561a2cc181939547693c9d08c196039d28
