### Test plan for changes done in the commit hook:
Phase 1:

1. Create a new branch
2. Modify a Playbook, script, integration
3. Merge the changes done in the branch with the changes in the commit hook to the new branch
4. Check that the hook runs successfully(Also on Circle)

Phase 2 (On same branch):
1. Add new Playbook, script, integration
2. Check that the hook runs successfully(Also on Circle)

Phase 3 (On same branch):
1. Modify script package and create a new one
2. Check that the hook runs successfully(Also on Circle)

Phase 4 (On same branch):
1. Convert an integration/script to a package
2. Check that the hook runs successfully(Also on Circle)
