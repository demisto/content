from unittest.mock import MagicMock, patch

from github_workflow_scripts.create_internal_pr import (
    main,
    prepare_body,
    replace_fixes_with_relates_in_pr_body,
)


def _make_mock_pr(html_url: str, number: int, body: str = "", login: str = "contributor1"):
    """Create a minimal mock PullRequest."""
    pr = MagicMock()
    pr.html_url = html_url
    pr.number = number
    pr.body = body
    pr.user.login = login
    return pr


class TestCrossReferencePRs:
    """Tests for the cross-reference logic that links main and mapping PRs to each other."""

    EXTERNAL_URL = "https://github.com/demisto/content/pull/1234"
    MAIN_URL = "https://github.com/demisto/content/pull/1235"
    MAPPING_URL = "https://github.com/demisto/content/pull/1236"

    def test_cross_reference_main_pr_body_contains_mapping_link(self):
        """
        Given:
            - A main PR body generated from an external PR.
        When:
            - The cross-reference replace is applied to add the mapping PR link.
        Then:
            - The main PR body contains the mapping PR URL right after the external PR link.
        """
        ext_pr = _make_mock_pr(self.EXTERNAL_URL, 1234, body="description\n\nrelates: #999")
        body = prepare_body(ext_pr)

        updated = body.replace(
            f"**Original External PR:** {self.EXTERNAL_URL}",
            f"**Original External PR:** {self.EXTERNAL_URL}\r\n**Mapping Internal PR:** {self.MAPPING_URL}",
        )

        assert f"**Mapping Internal PR:** {self.MAPPING_URL}" in updated

    def test_cross_reference_mapping_pr_body_contains_main_link(self):
        """
        Given:
            - A mapping PR body generated from an external PR.
        When:
            - The cross-reference replace is applied to add the main PR link.
        Then:
            - The mapping PR body contains the main PR URL right after the external PR link.
        """
        ext_pr = _make_mock_pr(self.EXTERNAL_URL, 1234, body="description\n\nrelates: #999")
        body = replace_fixes_with_relates_in_pr_body(prepare_body(ext_pr))

        updated = body.replace(
            f"**Original External PR:** {self.EXTERNAL_URL}",
            f"**Original External PR:** {self.EXTERNAL_URL}\r\n**Main Internal PR:** {self.MAIN_URL}",
        )

        assert f"**Main Internal PR:** {self.MAIN_URL}" in updated

    def test_cross_reference_links_are_grouped_at_top(self):
        """
        Given:
            - Both a main and mapping PR body after cross-referencing.
        When:
            - Checking the position of the Related PRs section.
        Then:
            - The Related PRs section (with all links) appears before the Contributor section.
        """
        ext_pr = _make_mock_pr(self.EXTERNAL_URL, 1234, body="description\n\nrelates: #999")
        body = prepare_body(ext_pr)

        updated = body.replace(
            f"**Original External PR:** {self.EXTERNAL_URL}",
            f"**Original External PR:** {self.EXTERNAL_URL}\r\n**Mapping Internal PR:** {self.MAPPING_URL}",
        )

        assert updated.index("## Related PRs") < updated.index("## Contributor")
        assert updated.index("**Mapping Internal PR:**") < updated.index("## Contributor")

    def test_cross_reference_no_duplicate_external_link(self):
        """
        Given:
            - A PR body after cross-referencing.
        When:
            - Checking for the external PR marker.
        Then:
            - The Original External PR line appears exactly once.
        """
        ext_pr = _make_mock_pr(self.EXTERNAL_URL, 1234, body="description\n\nrelates: #999")
        body = prepare_body(ext_pr)

        updated = body.replace(
            f"**Original External PR:** {self.EXTERNAL_URL}",
            f"**Original External PR:** {self.EXTERNAL_URL}\r\n**Mapping Internal PR:** {self.MAPPING_URL}",
        )

        assert updated.count("**Original External PR:**") == 1

    @patch("github_workflow_scripts.create_internal_pr.get_env_var")
    @patch("github_workflow_scripts.create_internal_pr.Github")
    @patch("github_workflow_scripts.create_internal_pr.separate_pr_files")
    @patch("github_workflow_scripts.create_internal_pr.split_branch_with_git")
    @patch("github_workflow_scripts.create_internal_pr.create_pr")
    @patch("github_workflow_scripts.create_internal_pr.remove_branch_protection")
    @patch("github_workflow_scripts.create_internal_pr.get_content_roles", return_value=None)
    @patch("github_workflow_scripts.create_internal_pr.is_organization_member", return_value=False)
    def test_main_calls_edit_on_both_prs_when_both_created(
        self,
        mock_is_org_member,
        mock_get_content_roles,
        mock_remove_protection,
        mock_create_pr,
        mock_split_branch,
        mock_separate,
        mock_github_cls,
        mock_get_env_var,
    ):
        """
        Given:
            - An external PR that contains both XSOAR and XSIAM files.
        When:
            - main() creates both a main PR and a mapping PR.
        Then:
            - edit() is called on both PRs to cross-reference each other.
            - The main PR body contains the mapping PR URL.
            - The mapping PR body contains the main PR URL.
        """
        # -- setup env vars --
        import json

        payload = {"pull_request": {"number": 1234}}

        def env_side_effect(name):
            if name == "EVENT_PAYLOAD":
                return json.dumps(payload)
            return "fake-token"

        mock_get_env_var.side_effect = env_side_effect

        # -- setup GitHub mocks --
        ext_pr = _make_mock_pr(self.EXTERNAL_URL, 1234, body="description\n\nrelates: #999")
        ext_pr.base.ref = "contrib-branch"
        ext_pr.labels = []
        ext_pr.assignees = []
        ext_pr.merged_by = None
        ext_pr.get_review_requests.return_value = ([], [])
        ext_pr.get_files.return_value = []

        mock_repo = MagicMock()
        mock_repo.get_pull.return_value = ext_pr
        mock_github_cls.return_value.get_repo.return_value = mock_repo

        # -- both file types present --
        xsoar_file = MagicMock()
        xsiam_file = MagicMock()
        mock_separate.return_value = ([xsoar_file], [xsiam_file])
        mock_split_branch.return_value = ("contrib-branch-main", "contrib-branch-mapping")

        # -- mock created PRs --
        main_pr = _make_mock_pr(self.MAIN_URL, 1235)
        main_pr.body = prepare_body(ext_pr)
        main_pr.head.ref = "contrib-branch-main"

        mapping_pr = _make_mock_pr(self.MAPPING_URL, 1236)
        mapping_pr.body = replace_fixes_with_relates_in_pr_body(prepare_body(ext_pr))
        mapping_pr.head.ref = "contrib-branch-mapping"

        mock_create_pr.side_effect = [main_pr, mapping_pr]

        # -- run --
        main()

        # -- assert edit was called on both PRs --
        assert main_pr.edit.call_count == 1
        assert mapping_pr.edit.call_count == 1

        main_updated_body = main_pr.edit.call_args.kwargs.get("body", "")
        mapping_updated_body = mapping_pr.edit.call_args.kwargs.get("body", "")

        assert f"**Mapping Internal PR:** {self.MAPPING_URL}" in main_updated_body
        assert f"**Main Internal PR:** {self.MAIN_URL}" in mapping_updated_body

    @patch("github_workflow_scripts.create_internal_pr.get_env_var")
    @patch("github_workflow_scripts.create_internal_pr.Github")
    @patch("github_workflow_scripts.create_internal_pr.separate_pr_files")
    @patch("github_workflow_scripts.create_internal_pr.create_pr")
    @patch("github_workflow_scripts.create_internal_pr.remove_branch_protection")
    @patch("github_workflow_scripts.create_internal_pr.get_content_roles", return_value=None)
    @patch("github_workflow_scripts.create_internal_pr.is_organization_member", return_value=False)
    def test_no_cross_reference_when_only_one_pr_created(
        self,
        mock_is_org_member,
        mock_get_content_roles,
        mock_remove_protection,
        mock_create_pr,
        mock_separate,
        mock_github_cls,
        mock_get_env_var,
    ):
        """
        Given:
            - An external PR that contains only XSOAR files (no XSIAM).
        When:
            - main() creates only a main PR.
        Then:
            - edit() is never called (no cross-reference needed).
        """
        import json

        payload = {"pull_request": {"number": 1234}}

        def env_side_effect(name):
            if name == "EVENT_PAYLOAD":
                return json.dumps(payload)
            return "fake-token"

        mock_get_env_var.side_effect = env_side_effect

        ext_pr = _make_mock_pr(self.EXTERNAL_URL, 1234, body="description\n\nrelates: #999")
        ext_pr.base.ref = "contrib-branch"
        ext_pr.labels = []
        ext_pr.assignees = []
        ext_pr.merged_by = None
        ext_pr.get_review_requests.return_value = ([], [])
        ext_pr.get_files.return_value = []

        mock_repo = MagicMock()
        mock_repo.get_pull.return_value = ext_pr
        mock_github_cls.return_value.get_repo.return_value = mock_repo

        # Only XSOAR files
        xsoar_file = MagicMock()
        mock_separate.return_value = ([xsoar_file], [])

        main_pr = _make_mock_pr(self.MAIN_URL, 1235)
        main_pr.body = prepare_body(ext_pr)
        main_pr.head.ref = "contrib-branch"

        mock_create_pr.return_value = main_pr

        main()

        main_pr.edit.assert_not_called()
