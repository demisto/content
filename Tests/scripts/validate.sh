if [ "${CHECK_BACKWARD}" = "true" ] ;
  then
     demisto-sdk validate -g --post-commit

  else
     demisto-sdk validate -g --post-commit --no-backward-comp
fi