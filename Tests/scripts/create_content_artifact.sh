mkdir bundle

# move content to bundle dir
cd /Tools/ && for i in */ ; do zip -jr "../bundle/tools-${i%/}.zip" "$i"; done
cp /Integrations/* bundle/
cp /Misc/* bundle/
cp /Playbooks/* bundle/
cp /Reports/* bundle/

# move test playbooks if not master branch
if [ "$CIRCLE_BRANCH" != "master" ]; then cp /TestPlaybooks/* bundle/ ; fi

# create zip & move to artifacts
cp $(find Scripts -type f -print) bundle/
cd bundle/ && zip ../content.zip *
cp content.zip $CIRCLE_ARTIFACTS/content.zip