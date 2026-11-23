import asyncio
import unittest
from unittest.mock import patch

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError

from koderly_security_mcp import server as server_mod


class FakeColumn:
    def __init__(self, name):
        self.name = name


class FakeTable:
    def __init__(self, columns, rows):
        self.columns = columns
        self.rows = rows


class FakeResult:
    def __init__(self, tables):
        self.tables = tables


class ServerFeatureTests(unittest.TestCase):
    def test_build_signin_query_uses_hours_and_limit(self):
        query = server_mod.build_signin_query(hours=12, limit=25)
        self.assertIn("ago(12h)", query)
        self.assertIn("take 25", query.lower())

    def test_build_signin_query_includes_investigation_fields(self):
        query = server_mod.build_signin_query()
        for field in [
            "UserId",
            "ResourceDisplayName",
            "LocationDetails",
            "DeviceDetail",
            "ClientAppUsed",
            "AuthenticationRequirement",
            "RiskLevelDuringSignIn",
            "RiskState",
            "RiskDetail",
        ]:
            self.assertIn(field, query)

    def test_build_all_signins_query_has_no_row_limit(self):
        query = server_mod.build_all_signins_query(hours=24)
        self.assertIn("ago(24h)", query)
        self.assertNotIn("take ", query.lower())
        self.assertIn("order by TimeGenerated desc", query)

    def test_get_workspace_id_prefers_configured_value(self):
        previous = server_mod.os.environ.get("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
        server_mod.os.environ["AZURE_LOG_ANALYTICS_WORKSPACE_ID"] = "test-workspace-id"
        try:
            self.assertEqual(server_mod.get_workspace_id(), "test-workspace-id")
        finally:
            if previous is None:
                server_mod.os.environ.pop("AZURE_LOG_ANALYTICS_WORKSPACE_ID", None)
            else:
                server_mod.os.environ["AZURE_LOG_ANALYTICS_WORKSPACE_ID"] = previous

    def test_get_credential_uses_configured_cli_tenant(self):
        previous = server_mod.os.environ.get("AZURE_TENANT_ID")
        server_mod.os.environ["AZURE_TENANT_ID"] = "workspace-tenant-id"
        try:
            with patch.object(server_mod, "AzureCliCredential") as credential:
                self.assertIs(server_mod.get_credential(), credential.return_value)
                credential.assert_called_once_with(tenant_id="workspace-tenant-id")
        finally:
            if previous is None:
                server_mod.os.environ.pop("AZURE_TENANT_ID", None)
            else:
                server_mod.os.environ["AZURE_TENANT_ID"] = previous

    def test_rows_from_query_result_accepts_string_columns(self):
        result = FakeResult([
            FakeTable(["TimeGenerated", "UserPrincipalName"], [("2026-09-14T00:00:00Z", "alice@example.com")])
        ])
        rows = server_mod._rows_from_query_result(result)
        self.assertEqual(rows[0]["UserPrincipalName"], "alice@example.com")


class StorageAccessFeatureTests(unittest.TestCase):
    def test_build_storage_access_query_uses_account_hours_and_limit(self):
        query = server_mod.build_storage_access_query("examplestorage01", hours=12, limit=100)
        self.assertIn("ago(12h)", query)
        self.assertIn('AccountName == "examplestorage01"', query)
        self.assertIn("take 100", query.lower())

    def test_build_storage_access_query_includes_investigation_fields(self):
        query = server_mod.build_storage_access_query("examplestorage01")
        for field in [
            "OperationName",
            "AuthenticationType",
            "RequesterUpn",
            "RequesterObjectId",
            "CallerIpAddress",
            "ObjectKey",
            "StatusCode",
        ]:
            self.assertIn(field, query)

    def test_build_storage_access_query_rejects_invalid_account_name(self):
        with self.assertRaises(ValueError):
            server_mod.build_storage_access_query("Not_Valid!", hours=24, limit=100)

    def test_build_storage_access_query_rejects_non_positive_hours(self):
        with self.assertRaises(ValueError):
            server_mod.build_storage_access_query("examplestorage01", hours=0, limit=100)

    def test_build_storage_access_query_rejects_non_positive_limit(self):
        with self.assertRaises(ValueError):
            server_mod.build_storage_access_query("examplestorage01", hours=24, limit=0)

    def test_build_storage_access_query_clamps_lookback_window(self):
        query = server_mod.build_storage_access_query("examplestorage01", hours=999999, limit=100)
        self.assertIn(f"ago({server_mod.STORAGE_MAX_LOOKBACK_HOURS}h)", query)

    def test_build_storage_access_query_clamps_result_limit(self):
        query = server_mod.build_storage_access_query("examplestorage01", hours=24, limit=999999)
        self.assertIn(f"take {server_mod.STORAGE_MAX_RESULT_LIMIT}", query.lower())


class ErrorReportingTests(unittest.TestCase):
    """Failures must reach the MCP client with their message, not as a generic crash."""

    ENV = {"AZURE_LOG_ANALYTICS_WORKSPACE_ID": "test-workspace-id", "AZURE_TENANT_ID": "test-tenant-id"}

    def _call_tool_error(self, name, arguments):
        with self.assertRaises(ToolError) as raised:
            asyncio.run(server_mod.mcp.call_tool(name, arguments))
        self.assertNotIsInstance(raised.exception, UnexpectedToolError)
        return str(raised.exception)

    def test_tool_input_error_is_still_a_value_error(self):
        self.assertTrue(issubclass(server_mod.ToolInputError, ValueError))

    def test_missing_workspace_id_is_reported_to_client(self):
        with patch.dict(server_mod.os.environ, {}, clear=True):
            message = self._call_tool_error("get_recent_signins", {"hours": 1, "limit": 1})
        self.assertIn("AZURE_LOG_ANALYTICS_WORKSPACE_ID is not set", message)

    def test_invalid_argument_is_reported_to_client(self):
        with patch.dict(server_mod.os.environ, self.ENV, clear=True):
            message = self._call_tool_error("get_storage_account_access", {"account_name": "Not-Valid!"})
        self.assertIn("valid Azure Storage account name", message)

    def test_azure_sign_in_failure_is_reported_to_client(self):
        with patch.dict(server_mod.os.environ, self.ENV, clear=True),                 patch.object(server_mod, "AzureCliCredential"),                 patch.object(server_mod, "LogsQueryClient") as client:
            client.return_value.query_workspace.side_effect = ClientAuthenticationError("token expired")
            message = self._call_tool_error("get_all_recent_signins", {"hours": 1})
        self.assertIn("az login", message)
        self.assertIn("token expired", message)

    def test_query_failure_is_reported_to_client(self):
        with patch.dict(server_mod.os.environ, self.ENV, clear=True),                 patch.object(server_mod, "AzureCliCredential"),                 patch.object(server_mod, "LogsQueryClient") as client:
            client.return_value.query_workspace.side_effect = HttpResponseError("Forbidden")
            message = self._call_tool_error("get_recent_signins", {"hours": 1, "limit": 1})
        self.assertIn("Log Analytics Reader", message)
        self.assertIn("Forbidden", message)

    def test_successful_query_returns_rows(self):
        result = FakeResult([FakeTable(["UserPrincipalName"], [["alice@example.com"]])])
        with patch.dict(server_mod.os.environ, self.ENV, clear=True),                 patch.object(server_mod, "AzureCliCredential"),                 patch.object(server_mod, "LogsQueryClient") as client:
            client.return_value.query_workspace.return_value = result
            rows = server_mod.get_recent_signins(hours=1, limit=1)
        self.assertEqual(rows, [{"UserPrincipalName": "alice@example.com"}])


if __name__ == "__main__":
    unittest.main()
