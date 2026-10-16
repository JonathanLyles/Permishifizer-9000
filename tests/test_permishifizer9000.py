import io
import json
import sys
import tempfile
import unittest
import urllib.error
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from xml.etree import ElementTree as ET

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import permishifizer9000 as script


class Stream:
    def __init__(self, is_tty):
        self._is_tty = is_tty

    def isatty(self):
        return self._is_tty


class UserPermissionHelperTests(unittest.TestCase):
    def test_permission_set_field_name_uses_salesforce_convention(self):
        self.assertEqual(
            script.permission_set_field_name("ManageQuotas"),
            "PermissionsManageQuotas",
        )

    def test_unsupported_names_are_sorted(self):
        self.assertEqual(
            script.unsupported_user_permission_names(
                {"ViewSetup", "ManageQuotas", "ModifyAllData"},
                {"ViewSetup"},
            ),
            ["ManageQuotas", "ModifyAllData"],
        )

    def test_fetch_supported_permissions_translates_describe_fields(self):
        org = script.OrgContext("test-token", "https://example.my.salesforce.com", "65.0")
        response = {
            "fields": [
                {"name": "PermissionsManageQuotas"},
                {"name": "PermissionsViewSetup"},
                {"name": "Name"},
            ]
        }

        with patch.object(script, "http_get_json", return_value=response) as request:
            supported = script.fetch_supported_user_permission_names(org)

        self.assertEqual(supported, {"ManageQuotas", "ViewSetup"})
        self.assertEqual(request.call_args.kwargs["include_error_body"], False)

    def test_fetch_supported_permissions_rejects_incomplete_describe_data(self):
        org = script.OrgContext("test-token", "https://example.my.salesforce.com", "65.0")

        with patch.object(script, "http_get_json", return_value={"fields": [{"name": "Name"}]}):
            with self.assertRaisesRegex(script.ScriptError, "user-permission fields"):
                script.fetch_supported_user_permission_names(org)

    def test_permission_describe_error_does_not_include_raw_response(self):
        org = script.OrgContext("test-token", "https://example.my.salesforce.com", "65.0")
        response_body = io.BytesIO(b'{"secret":"test-token"}')
        http_error = urllib.error.HTTPError(
            "https://example.my.salesforce.com/describe",
            403,
            "Forbidden",
            None,
            response_body,
        )

        with patch("urllib.request.urlopen", side_effect=http_error):
            with self.assertRaises(script.ScriptError) as caught:
                script.fetch_supported_user_permission_names(org)

        self.assertIn("HTTP 403", str(caught.exception))
        self.assertNotIn("test-token", str(caught.exception))
        http_error.close()

    def test_interactive_terminal_requires_stdin_and_stderr_ttys(self):
        self.assertTrue(script.is_interactive_terminal(Stream(True), Stream(True)))
        self.assertFalse(script.is_interactive_terminal(Stream(False), Stream(True)))
        self.assertFalse(script.is_interactive_terminal(Stream(True), Stream(False)))

    def test_confirmation_requires_explicit_yes(self):
        for value in ("y", "Y", "yes", "YES"):
            with (
                self.subTest(value=value),
                redirect_stderr(io.StringIO()),
                patch("builtins.input", return_value=value),
            ):
                self.assertTrue(
                    script.confirm_unsupported_user_permissions(["ManageQuotas"])
                )

        for value in ("", "no", "anything else"):
            with (
                self.subTest(value=value),
                redirect_stderr(io.StringIO()),
                patch("builtins.input", return_value=value),
            ):
                self.assertFalse(
                    script.confirm_unsupported_user_permissions(["ManageQuotas"])
                )

    def test_confirmation_cancels_on_end_of_file_or_interrupt(self):
        for error in (EOFError, KeyboardInterrupt):
            with (
                self.subTest(error=error),
                redirect_stderr(io.StringIO()),
                patch("builtins.input", side_effect=error),
            ):
                self.assertFalse(
                    script.confirm_unsupported_user_permissions(["ManageQuotas"])
                )


class UserPermissionWorkflowTests(unittest.TestCase):
    def _args(self, output_file, *, deploy=False, check_only=False, json_output=False):
        return SimpleNamespace(
            json=json_output,
            output_file=output_file,
            target_org="test-org",
            target_org_positional=None,
            deploy=deploy,
            check_only=check_only,
            deploy_wait=1,
        )

    def _patch_main_dependencies(self, stack, args, supported_permissions):
        org_info = {
            "status": 0,
            "result": {
                "username": "test@example.com",
                "alias": "test-org",
                "instanceUrl": "https://example.my.salesforce.com",
                "apiVersion": "65.0",
            },
        }
        token_info = {"status": 0, "result": {"accessToken": "test-token"}}

        def tooling_response(soql, org):
            if "FROM EntityParticle" in soql:
                return [
                    {
                        "EntityDefinition": {"QualifiedApiName": "Account"},
                        "QualifiedApiName": "Name",
                        "IsComponent": False,
                    }
                ]
            return []

        stack.enter_context(patch.object(script, "ensure_python_version"))
        stack.enter_context(patch.object(script, "parse_args", return_value=args))
        stack.enter_context(patch.object(script, "resolve_sf_invoker", return_value=("direct", "sf")))
        stack.enter_context(
            patch.object(script, "run_sf_org_display", return_value=json.dumps(org_info))
        )
        stack.enter_context(
            patch.object(
                script,
                "run_sf_org_auth_show_access_token",
                return_value=json.dumps(token_info),
            )
        )
        stack.enter_context(
            patch.object(
                script,
                "fetch_supported_user_permission_names",
                return_value=set(supported_permissions),
            )
        )
        stack.enter_context(
            patch.object(script, "fetch_picklist_object_names", return_value=["Account"])
        )
        stack.enter_context(
            patch.object(
                script,
                "fetch_entity_definition_objects",
                return_value=[("Account", True)],
            )
        )
        stack.enter_context(patch.object(script, "tooling_query", side_effect=tooling_response))
        stack.enter_context(
            patch.object(
                script,
                "metadata_list_recordtype_fullnames",
                return_value=["Account.Business"],
            )
        )
        return stack.enter_context(patch.object(script, "run_sf_project_deploy"))

    def _run_main(self):
        stdout = io.StringIO()
        stderr = io.StringIO()
        original_stdout = sys.stdout
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                script.main()
        finally:
            sys.stdout = original_stdout
        return stdout.getvalue(), stderr.getvalue()

    def _xml_user_permissions(self, output_file):
        root = ET.parse(output_file).getroot()
        return {
            element.find(script.qtag("name")).text
            for element in root.findall(script.qtag("userPermissions"))
        }

    def test_all_supported_permissions_are_written_without_warning(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "SalesforceBackup.permissionset-meta.xml"
            configured = {"ManageQuotas", "ViewSetup"}

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(script, "USER_PERMISSION_NAMES", configured)
                )
                self._patch_main_dependencies(stack, self._args(output_file), configured)
                stdout, stderr = self._run_main()

            self.assertEqual(self._xml_user_permissions(output_file), configured)
            self.assertNotIn("Warning:", stdout)
            self.assertNotIn("Warning:", stderr)

    def test_empty_user_permission_configuration_skips_compatibility_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "SalesforceBackup.permissionset-meta.xml"

            with ExitStack() as stack:
                stack.enter_context(patch.object(script, "USER_PERMISSION_NAMES", set()))
                self._patch_main_dependencies(stack, self._args(output_file), set())
                lookup = stack.enter_context(
                    patch.object(script, "fetch_supported_user_permission_names")
                )
                self._run_main()

            self.assertEqual(self._xml_user_permissions(output_file), set())
            lookup.assert_not_called()

    def test_confirmed_omission_writes_partial_file_without_deploy_or_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "SalesforceBackup.permissionset-meta.xml"
            configured = {"ManageQuotas", "ViewSetup"}

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(script, "USER_PERMISSION_NAMES", configured)
                )
                deploy = self._patch_main_dependencies(
                    stack,
                    self._args(output_file, deploy=True),
                    {"ViewSetup"},
                )
                stack.enter_context(
                    patch.object(script, "is_interactive_terminal", return_value=True)
                )
                stack.enter_context(patch("builtins.input", return_value="yes"))
                validate = stack.enter_context(
                    patch.object(script, "validate_deploy_preconditions")
                )
                stdout, stderr = self._run_main()

            self.assertEqual(self._xml_user_permissions(output_file), {"ViewSetup"})
            self.assertIn("ManageQuotas", stderr)
            self.assertIn("Validate with:", stdout)
            self.assertIn("Deploy with:", stdout)
            deploy.assert_not_called()
            validate.assert_not_called()

    def test_declined_omission_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "SalesforceBackup.permissionset-meta.xml"
            original_contents = "<PermissionSet>known-good</PermissionSet>\n"
            output_file.write_text(original_contents, encoding="utf-8")

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(script, "USER_PERMISSION_NAMES", {"ManageQuotas"})
                )
                deploy = self._patch_main_dependencies(
                    stack,
                    self._args(output_file, check_only=True),
                    set(),
                )
                stack.enter_context(
                    patch.object(script, "is_interactive_terminal", return_value=True)
                )
                stack.enter_context(patch("builtins.input", return_value=""))
                validate = stack.enter_context(
                    patch.object(script, "validate_deploy_preconditions")
                )
                self._run_main()

            self.assertEqual(output_file.read_text(encoding="utf-8"), original_contents)
            deploy.assert_not_called()
            validate.assert_not_called()

    def test_noninteractive_unsupported_permissions_fail_without_output_or_prompt(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "SalesforceBackup.permissionset-meta.xml"

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(script, "USER_PERMISSION_NAMES", {"ManageQuotas"})
                )
                self._patch_main_dependencies(
                    stack,
                    self._args(output_file),
                    set(),
                )
                stack.enter_context(
                    patch.object(script, "is_interactive_terminal", return_value=False)
                )
                input_mock = stack.enter_context(patch("builtins.input"))
                with self.assertRaisesRegex(script.ScriptError, "Re-run interactively"):
                    self._run_main()

            self.assertFalse(output_file.exists())
            input_mock.assert_not_called()

    def test_json_unsupported_permissions_emit_machine_readable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            output_file = Path(directory) / "SalesforceBackup.permissionset-meta.xml"
            stdout = io.StringIO()
            stderr = io.StringIO()
            original_stdout = sys.stdout

            with ExitStack() as stack:
                stack.enter_context(
                    patch.object(script, "USER_PERMISSION_NAMES", {"ManageQuotas"})
                )
                self._patch_main_dependencies(
                    stack,
                    self._args(output_file, json_output=True),
                    set(),
                )
                input_mock = stack.enter_context(patch("builtins.input"))
                try:
                    with redirect_stdout(stdout), redirect_stderr(stderr):
                        with self.assertRaises(script.ScriptError):
                            script.main()
                finally:
                    sys.stdout = original_stdout

            payload = json.loads(stdout.getvalue())
            self.assertEqual(
                payload["unsupportedUserPermissions"],
                ["ManageQuotas"],
            )
            self.assertFalse(output_file.exists())
            self.assertNotIn("test-token", stdout.getvalue() + stderr.getvalue())
            input_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
