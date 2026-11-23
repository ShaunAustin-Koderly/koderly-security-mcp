import unittest
from unittest.mock import patch, MagicMock

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


class QuarantineFeatureTests(unittest.TestCase):
    VALID_APP_ID = "00000000-0000-0000-0000-00000000a99e"
    VALID_ORG = "contoso.onmicrosoft.com"
    VALID_THUMBPRINT = "0123456789abcdef0123456789abcdef01234567"

    def _set_env(self, name, value):
        previous = server_mod.os.environ.get(name)
        if value is None:
            server_mod.os.environ.pop(name, None)
        else:
            server_mod.os.environ[name] = value
        self.addCleanup(
            lambda: server_mod.os.environ.pop(name, None)
            if previous is None
            else server_mod.os.environ.__setitem__(name, previous)
        )

    def test_get_exo_app_id_requires_guid_format(self):
        self._set_env("EXO_APP_ID", "not-a-guid")
        with self.assertRaises(ValueError):
            server_mod.get_exo_app_id()

    def test_get_exo_app_id_accepts_configured_guid(self):
        self._set_env("EXO_APP_ID", self.VALID_APP_ID)
        self.assertEqual(server_mod.get_exo_app_id(), self.VALID_APP_ID)

    def test_get_exo_app_id_missing_raises(self):
        self._set_env("EXO_APP_ID", None)
        with self.assertRaises(ValueError):
            server_mod.get_exo_app_id()

    def test_get_exo_organization_requires_onmicrosoft_domain(self):
        self._set_env("EXO_ORGANIZATION", "not-a-tenant-domain.com")
        with self.assertRaises(ValueError):
            server_mod.get_exo_organization()

    def test_get_exo_organization_accepts_configured_domain(self):
        self._set_env("EXO_ORGANIZATION", self.VALID_ORG)
        self.assertEqual(server_mod.get_exo_organization(), self.VALID_ORG)

    def test_get_exo_certificate_thumbprint_requires_hex40(self):
        self._set_env("EXO_CERTIFICATE_THUMBPRINT", "too-short")
        with self.assertRaises(ValueError):
            server_mod.get_exo_certificate_thumbprint()

    def test_get_exo_certificate_thumbprint_normalizes_case(self):
        self._set_env("EXO_CERTIFICATE_THUMBPRINT", self.VALID_THUMBPRINT)
        self.assertEqual(
            server_mod.get_exo_certificate_thumbprint(), self.VALID_THUMBPRINT.upper()
        )

    def test_build_quarantine_script_includes_transport_rule_type(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper(), days=7, limit=50
        )
        self.assertIn("-QuarantineTypes TransportRule", script)
        self.assertIn(f"-AppId '{self.VALID_APP_ID}'", script)
        self.assertIn(f"-Organization '{self.VALID_ORG}'", script)
        self.assertIn(f"-CertificateThumbprint '{self.VALID_THUMBPRINT.upper()}'", script)
        self.assertIn("AddDays(-7)", script)
        self.assertIn("-PageSize 50", script)

    def test_build_quarantine_script_defaults_to_transport_rule(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper()
        )
        self.assertIn("-QuarantineTypes TransportRule", script)

    def test_build_quarantine_script_uses_requested_type(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper(), quarantine_types=["Phish"]
        )
        self.assertIn("-QuarantineTypes Phish ", script)
        self.assertNotIn("TransportRule", script)

    def test_build_quarantine_script_joins_multiple_types(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID,
            self.VALID_ORG,
            self.VALID_THUMBPRINT.upper(),
            quarantine_types=["Phish", "Malware", "TransportRule"],
        )
        self.assertIn("-QuarantineTypes Phish,Malware,TransportRule ", script)

    def test_build_quarantine_script_all_omits_type_filter(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper(), quarantine_types=["All"]
        )
        self.assertNotIn("-QuarantineTypes", script)
        self.assertIn("Get-QuarantineMessage -StartReceivedDate", script)

    def test_normalize_quarantine_types_defaults_to_transport_rule(self):
        self.assertEqual(server_mod.normalize_quarantine_types(None), ["TransportRule"])

    def test_normalize_quarantine_types_is_case_insensitive_and_deduplicates(self):
        self.assertEqual(
            server_mod.normalize_quarantine_types(["highconfphish", "SPOMALWARE", "HighConfPhish"]),
            ["HighConfPhish", "SPOMalware"],
        )
        self.assertIsNone(server_mod.normalize_quarantine_types(["all"]))

    def test_normalize_quarantine_types_rejects_empty_list(self):
        with self.assertRaises(ValueError):
            server_mod.normalize_quarantine_types([])

    def test_normalize_quarantine_types_rejects_all_combined_with_other_types(self):
        with self.assertRaises(ValueError):
            server_mod.normalize_quarantine_types(["All", "Phish"])

    def test_build_quarantine_script_rejects_unknown_type(self):
        for bad_types in [["Unknown"], [""], ["Spam; Remove-Item C:\\"], ["Spam,Phish"], ["Phish", "Bogus"]]:
            with self.assertRaises(ValueError):
                server_mod.build_quarantine_script(
                    self.VALID_APP_ID,
                    self.VALID_ORG,
                    self.VALID_THUMBPRINT.upper(),
                    quarantine_types=bad_types,
                )

    def test_get_quarantine_messages_passes_types_to_script(self):
        self._set_env("EXO_APP_ID", self.VALID_APP_ID)
        self._set_env("EXO_ORGANIZATION", self.VALID_ORG)
        self._set_env("EXO_CERTIFICATE_THUMBPRINT", self.VALID_THUMBPRINT)
        with patch.object(server_mod, "run_quarantine_script", return_value=[]) as run:
            server_mod.get_quarantine_messages(days=3, limit=10, quarantine_types=["Spam", "Bulk"])
        script = run.call_args.args[0]
        self.assertIn("-QuarantineTypes Spam,Bulk ", script)
        self.assertIn("AddDays(-3)", script)
        self.assertIn("-PageSize 10", script)

    def test_build_quarantine_script_clamps_lookback_window(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper(), days=90, limit=50
        )
        self.assertIn(f"AddDays(-{server_mod.EXO_MAX_LOOKBACK_DAYS})", script)

    def test_build_quarantine_script_clamps_result_limit(self):
        script = server_mod.build_quarantine_script(
            self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper(), days=7, limit=5000
        )
        self.assertIn(f"-PageSize {server_mod.EXO_MAX_RESULT_LIMIT}", script)

    def test_build_quarantine_script_rejects_non_positive_days(self):
        with self.assertRaises(ValueError):
            server_mod.build_quarantine_script(
                self.VALID_APP_ID, self.VALID_ORG, self.VALID_THUMBPRINT.upper(), days=0, limit=50
            )

    def test_run_quarantine_script_parses_json_stdout(self):
        fake_result = MagicMock(returncode=0, stdout='[{"Subject": "Test"}]', stderr="")
        with patch.object(server_mod.subprocess, "run", return_value=fake_result) as run:
            rows = server_mod.run_quarantine_script("fake-script")
            run.assert_called_once()
        self.assertEqual(rows, [{"Subject": "Test"}])

    def test_run_quarantine_script_returns_empty_list_for_blank_stdout(self):
        fake_result = MagicMock(returncode=0, stdout="   ", stderr="")
        with patch.object(server_mod.subprocess, "run", return_value=fake_result):
            rows = server_mod.run_quarantine_script("fake-script")
        self.assertEqual(rows, [])

    def test_run_quarantine_script_raises_on_nonzero_exit(self):
        fake_result = MagicMock(returncode=1, stdout="", stderr="Connect-ExchangeOnline failed")
        with patch.object(server_mod.subprocess, "run", return_value=fake_result):
            with self.assertRaises(RuntimeError):
                server_mod.run_quarantine_script("fake-script")


if __name__ == "__main__":
    unittest.main()
