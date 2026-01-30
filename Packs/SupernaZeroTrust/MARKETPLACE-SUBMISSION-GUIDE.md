# Publishing SupernaZeroTrust Pack to XSOAR Marketplace

Guide for submitting your pack as an official Technology Partner contribution.

**References:**
- [Contributing to XSOAR Marketplace](https://xsoar.pan.dev/docs/contributing/marketplace)
- [Partner Contribution Process](https://xsoar.pan.dev/docs/contributing/contributing)
- [Become a Tech Partner](https://xsoar.pan.dev/docs/partners/become-a-tech-partner)

---

## Step 1: Contact XSOAR Alliances Team (REQUIRED FIRST)

**Before submitting your pack**, you MUST contact the Cortex XSOAR Alliances Team:

📧 **Email**: soar.alliances@paloaltonetworks.com

**What to include in your email:**
```
Subject: Technology Partner Pack Submission - Superna Zero Trust

Hello XSOAR Alliances Team,

We are Superna and would like to submit our "Superna Zero Trust" integration
pack to the Cortex XSOAR Marketplace as a Technology Partner.

Pack Details:
- Name: Superna Zero Trust
- Description: Ransomware response automation with critical path snapshots
  and user NAS lockout/unlock
- Categories: Incident Response, Network Security
- Support: Partner (Superna)
- Contact: support@superna.io
- Website: https://www.superna.io

We have developed and tested the integration and are ready for the review process.
Could you please:
1. Review our planned contribution
2. Provide us with a Partner ID for our Pull Request
3. Guide us through the partner submission process

Thank you,
[Your Name]
[Your Title]
Superna
```

**Wait for their response** before proceeding. They will:
- Review your use case
- Assign you a **Partner ID** (required for PR submission)
- Provide specific guidance for your submission

---

## Step 2: Pre-Submission Validation (Do This While Waiting)

### 2.1 Validate Your Pack

```bash
cd /Users/andrew/Documents/integrations/XSOAR/content
demisto-sdk validate -i Packs/SupernaZeroTrust
```

Fix any errors reported.

### 2.2 Run Linting and Unit Tests

```bash
demisto-sdk lint -i Packs/SupernaZeroTrust
```

This checks:
- Code quality
- Python best practices
- Unit test coverage
- Security issues

**Note**: You may need to improve unit tests in `SupernaZeroTrust_test.py`

### 2.3 Create Demo Video (REQUIRED)

**Requirements:**
- Length: 3-5 minutes
- Content:
  1. Show Superna Zero Trust product overview
  2. Demonstrate XSOAR integration configuration
  3. Show each command in action:
     - `!superna-zt-snapshot-critical-paths`
     - `!superna-zt-lockout-user`
     - `!superna-zt-unlock-user`
  4. Demonstrate at least one playbook
- Format: MP4, unlisted YouTube link, or similar
- Quality: HD (720p minimum)

Upload to YouTube (unlisted) or your company website.

### 2.4 Check Pack Files

Ensure these files exist and are correct:

```bash
ls -la Packs/SupernaZeroTrust/
```

**Required files:**
- ✅ `pack_metadata.json` - Pack information
- ✅ `README.md` - Pack documentation
- ✅ `Author_image.png` - 120x50, <4KB (YOU HAVE THIS)
- ✅ `SupernaZeroTrust_image.png` - 120x50 logo (YOU HAVE THIS)
- ✅ `Integrations/SupernaZeroTrust/` - Integration files
- ✅ `Playbooks/` - Your 4 playbooks
- ✅ `ReleaseNotes/` - Release notes

---

## Step 3: Prepare GitHub Fork and Branch

### 3.1 Verify Your Fork

```bash
cd /Users/andrew/Documents/integrations/XSOAR/content
git remote -v
```

Should show:
```
origin  https://github.com/demisto/content.git
```

### 3.2 Add Your Fork (If Needed)

If you need to fork the repo:

1. Go to: https://github.com/demisto/content
2. Click **Fork** (top right)
3. Add your fork as remote:

```bash
git remote add myfork https://github.com/YOUR_GITHUB_USERNAME/content.git
```

### 3.3 Create Feature Branch

**IMPORTANT**: Do NOT use master branch!

```bash
# Update master
git checkout master
git pull origin master

# Create new branch for your pack
git checkout -b superna-zerotrust-pack

# Verify you're on the new branch
git branch
```

### 3.4 Commit Your Pack

```bash
# Add your pack
git add Packs/SupernaZeroTrust/

# Commit with descriptive message
git commit -m "Add Superna Zero Trust integration pack

- Ransomware response automation
- Critical path snapshots
- User NAS lockout/unlock
- 4 incident response playbooks

Partner ID: [INSERT_PARTNER_ID_FROM_ALLIANCES_TEAM]
"

# Push to your fork
git push myfork superna-zerotrust-pack
```

---

## Step 4: Create Pull Request

### 4.1 Open PR on GitHub

1. Go to: https://github.com/demisto/content
2. Click **Pull Requests** tab
3. Click **New Pull Request**
4. Click **compare across forks**
5. Select:
   - **base repository**: `demisto/content`
   - **base branch**: `master`
   - **head repository**: `YOUR_USERNAME/content`
   - **compare branch**: `superna-zerotrust-pack`
6. Click **Create Pull Request**

### 4.2 Fill Out PR Description

**Title:**
```
Superna Zero Trust - Partner Pack Submission
```

**Description Template:**
```markdown
## Partner Pack Submission

**Partner**: Superna
**Partner ID**: [INSERT_ID_FROM_ALLIANCES_TEAM]
**Contact**: support@superna.io
**Website**: https://www.superna.io

## Pack Information

**Name**: Superna Zero Trust
**Version**: 1.0.10
**Support Type**: Partner

## Description

Automate ransomware response with critical path snapshots and user NAS
lockout/unlock via secure API integration.

## What's Included

- **Integration**: SupernaZeroTrust
  - `superna-zt-snapshot-critical-paths` - Create snapshots of critical paths
  - `superna-zt-lockout-user` - Lock out user from NAS storage
  - `superna-zt-unlock-user` - Unlock user from NAS storage

- **Playbooks**: (4)
  - Superna Zero Trust Snapshot
  - Superna Zero Trust User Lockout
  - Superna Zero Trust Request User Storage Lockout
  - Superna Zero Trust Request User Storage UnLockout

## Use Cases

- Ransomware incident response
- Proactive threat containment
- User access control during security events
- Employee termination workflows

## Demo Video

[Link to your demo video]

## Pre-Submission Checklist

- [x] Validated with `demisto-sdk validate`
- [x] Linted with `demisto-sdk lint`
- [x] Unit tests included
- [x] Demo video created
- [x] Author_image.png included (120x50, <4KB)
- [x] README.md documentation
- [x] Cortex XSOAR Alliances Team approval received
- [x] Partner ID obtained

## Support

For questions or issues with this integration:
- **Email**: support@superna.io
- **Website**: https://www.superna.io
```

---

## Step 5: Post-Submission Process

### 5.1 Sign CLA (Automated)

After creating the PR, a bot will comment with:
- **Contributor License Agreement (CLA)** - Sign this
- **Registration Form** - Fill this out

Complete both immediately.

### 5.2 Respond to Feedback

**Timeline**: You MUST respond within **14 days** or the PR will be closed.

**Review Process:**
- XSOAR team will review your code
- Automated tests will run
- They may request changes
- Address all feedback promptly

**Common Review Comments:**
- Code style improvements
- Additional unit tests
- Documentation clarifications
- Security best practices
- Error handling improvements

### 5.3 Approval and Merge

Once approved:
- Your PR will be merged to master
- Pack will go through certification
- Pack will appear in XSOAR Marketplace within 1-2 weeks
- You'll be notified when it's live

---

## Step 6: Maintenance

### After Publication

**Support Obligations:**
- Respond to customer issues via support@superna.io
- Provide updates and bug fixes
- Submit new versions via PR when needed

**Updating Your Pack:**

1. Increment version in `pack_metadata.json`
2. Add release notes in `ReleaseNotes/X_X_X.md`
3. Create new PR with changes
4. Follow same review process

---

## Current Pack Status

✅ **Ready for Submission:**
- Version: 1.0.10
- Integration: Complete with healthcheck test
- Playbooks: 4 incident response playbooks
- Logo: Professional Superna logo (120x50)
- Documentation: README files for all components
- Support: Partner support configured

**Next Action Required:**
📧 Email soar.alliances@paloaltonetworks.com to get Partner ID

---

## Quick Reference Commands

```bash
# Validate pack
demisto-sdk validate -i Packs/SupernaZeroTrust

# Lint and test
demisto-sdk lint -i Packs/SupernaZeroTrust

# Create new branch
git checkout -b superna-zerotrust-pack

# Commit changes
git add Packs/SupernaZeroTrust/
git commit -m "Add Superna Zero Trust pack - Partner ID: [ID]"

# Push to fork
git push myfork superna-zerotrust-pack
```

---

## Resources

- **Partner Program**: https://xsoar.pan.dev/docs/partners/become-a-tech-partner
- **Contributing Guide**: https://xsoar.pan.dev/docs/contributing/contributing
- **Developer Portal**: https://xsoar.pan.dev/
- **Slack Support**: #demisto-developers on DFIR Community Slack
- **Alliances Email**: soar.alliances@paloaltonetworks.com

---

## Timeline Estimate

1. **Alliances Team Response**: 3-5 business days
2. **PR Review**: 1-2 weeks
3. **Revisions** (if needed): Varies
4. **Certification**: 1-2 weeks after merge
5. **Marketplace Publication**: 1-2 weeks after certification

**Total**: ~4-8 weeks from initial contact to marketplace publication

---

Good luck with your submission! 🚀
