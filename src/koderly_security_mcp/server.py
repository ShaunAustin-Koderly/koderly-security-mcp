import json
import os
import re
import subprocess
from datetime import timedelta

from azure.identity import AzureCliCredential, DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("koderly-security-mcp")

EXO_DEFAULT_QUARANTINE_TYPE = "TransportRule"
EXO_ALL_QUARANTINE_TYPES = "All"
# Values accepted by Get-QuarantineMessage -QuarantineTypes. Interpolated into the
# PowerShell script, so only these exact values are allowed.
EXO_QUARANTINE_TYPES = [
    "Bulk",
    "HighConfPhish",
    "Malware",
    "Phish",
    "Spam",
    "SPOMalware",
    "TransportRule",
]
EXO_MAX_LOOKBACK_DAYS = 30
EXO_MAX_RESULT_LIMIT = 1000
EXO_QUARANTINE_FIELDS = [
    "Identity",
    "ReceivedTime",
    "SenderAddress",
    "RecipientAddress",
    "Subject",
    "Type",
    "PolicyName",
    "ReleaseStatus",
    "RecipientCount",
    "Expires",
    "Reported",
    "Direction",
    "Size",
]

_APP_ID_PATTERN = re.compile(r"^[0-9a-fA-F-]{36}$")
_THUMBPRINT_PATTERN = re.compile(r"^[0-9a-fA-F]{40}$")
_ORGANIZATION_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.onmicrosoft\.com$")
_STORAGE_ACCOUNT_NAME_PATTERN = re.compile(r"^[a-z0-9]{3,24}$")

STORAGE_MAX_LOOKBACK_HOURS = 30 * 24
STORAGE_MAX_RESULT_LIMIT = 1000
STORAGE_ACCESS_FIELDS = [
    "TimeGenerated",
    "AccountName",
    "OperationName",
    "Category",
    "AuthenticationType",
    "RequesterUpn",
    "RequesterObjectId",
    "RequesterAppId",
    "RequesterTenantId",
    "CallerIpAddress",
    "ObjectKey",
    "StatusCode",
    "StatusText",
    "DurationMs",
    "UserAgentHeader",
    "Uri",
]


def get_workspace_id() -> str:
    """Return the configured Log Analytics workspace ID or raise a clear error."""
    workspace_id = os.getenv("AZURE_LOG_ANALYTICS_WORKSPACE_ID")
    if not workspace_id:
        raise ValueError(
            "AZURE_LOG_ANALYTICS_WORKSPACE_ID is not set. "
            "Configure it with your Log Analytics workspace ID before querying SignInLogs."
        )
    return workspace_id


def get_credential():
    """Return an Azure credential configured for the workspace tenant."""
    tenant_id = os.getenv("AZURE_TENANT_ID")
    if tenant_id:
        return AzureCliCredential(tenant_id=tenant_id)
    return DefaultAzureCredential(exclude_interactive_browser_credential=False)


def build_signin_query(hours: int = 24, limit: int = 50) -> str:
    """Build a safe, read-only SignInLogs query for the recent activity window."""
    if hours <= 0:
        raise ValueError("hours must be greater than zero")
    if limit <= 0:
        raise ValueError("limit must be greater than zero")
    if limit > 500:
        limit = 500

    return f"""
    SigninLogs
    | where TimeGenerated >= ago({hours}h)
    | project TimeGenerated, UserPrincipalName, UserId, AppDisplayName, ResourceDisplayName, ResultType, ResultDescription, Status, IPAddress, LocationDetails, DeviceDetail, ClientAppUsed, AuthenticationRequirement, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState, RiskDetail, CorrelationId
    | order by TimeGenerated desc
    | take {limit}
    """.strip()


def build_all_signins_query(hours: int = 24) -> str:
    """Build a read-only SignInLogs query without a row limit."""
    if hours <= 0:
        raise ValueError("hours must be greater than zero")

    return f"""
    SigninLogs
    | where TimeGenerated >= ago({hours}h)
    | project TimeGenerated, UserPrincipalName, UserId, AppDisplayName, ResourceDisplayName, ResultType, ResultDescription, Status, IPAddress, LocationDetails, DeviceDetail, ClientAppUsed, AuthenticationRequirement, ConditionalAccessStatus, RiskLevelDuringSignIn, RiskState, RiskDetail, CorrelationId
    | order by TimeGenerated desc
    """.strip()


def build_storage_access_query(account_name: str, hours: int = 24, limit: int = 200) -> str:
    """Build a safe, read-only StorageBlobLogs query for data-plane access to the named
    Azure Storage Account. Requires blob resource logs to be routed to the configured
    Log Analytics workspace; accounts without that diagnostic setting return no rows."""
    if not _STORAGE_ACCOUNT_NAME_PATTERN.match(account_name):
        raise ValueError(
            "account_name must be a valid Azure Storage account name "
            "(3-24 lowercase letters and numbers)."
        )
    if hours <= 0:
        raise ValueError("hours must be greater than zero")
    if hours > STORAGE_MAX_LOOKBACK_HOURS:
        hours = STORAGE_MAX_LOOKBACK_HOURS
    if limit <= 0:
        raise ValueError("limit must be greater than zero")
    if limit > STORAGE_MAX_RESULT_LIMIT:
        limit = STORAGE_MAX_RESULT_LIMIT

    fields = ", ".join(STORAGE_ACCESS_FIELDS)
    return f"""
    StorageBlobLogs
    | where TimeGenerated >= ago({hours}h)
    | where AccountName == "{account_name}"
    | project {fields}
    | order by TimeGenerated desc
    | take {limit}
    """.strip()


def _rows_from_query_result(result) -> list[dict]:
    """Normalize Azure Monitor query rows into a simple list of dictionaries."""
    rows: list[dict] = []
    if not getattr(result, "tables", None):
        return rows

    for table in result.tables:
        raw_columns = table.columns if hasattr(table, "columns") else []
        columns = []
        for column in raw_columns:
            if isinstance(column, str):
                columns.append(column)
            elif hasattr(column, "name"):
                columns.append(column.name)
            elif isinstance(column, dict):
                columns.append(column.get("name") or column.get("columnName"))

        for row in table.rows:
            if isinstance(row, dict):
                rows.append(row)
            else:
                rows.append(dict(zip(columns, row)))
    return rows


def get_exo_app_id() -> str:
    """Return the configured Exchange Online app registration's Application (client) ID."""
    app_id = os.getenv("EXO_APP_ID")
    if not app_id:
        raise ValueError(
            "EXO_APP_ID is not set. Configure it with the Exchange Online app "
            "registration's Application (client) ID."
        )
    if not _APP_ID_PATTERN.match(app_id):
        raise ValueError("EXO_APP_ID must be a GUID.")
    return app_id


def get_exo_organization() -> str:
    """Return the configured tenant's initial *.onmicrosoft.com domain."""
    organization = os.getenv("EXO_ORGANIZATION")
    if not organization:
        raise ValueError(
            "EXO_ORGANIZATION is not set. Configure it with the tenant's "
            "*.onmicrosoft.com domain."
        )
    if not _ORGANIZATION_PATTERN.match(organization):
        raise ValueError("EXO_ORGANIZATION must be a *.onmicrosoft.com domain.")
    return organization


def get_exo_certificate_thumbprint() -> str:
    """Return the configured thumbprint of the app-only auth certificate."""
    thumbprint = os.getenv("EXO_CERTIFICATE_THUMBPRINT")
    if not thumbprint:
        raise ValueError(
            "EXO_CERTIFICATE_THUMBPRINT is not set. Configure it with the "
            "thumbprint of the certificate in the CurrentUser\\My store used "
            "for app-only Exchange Online authentication."
        )
    if not _THUMBPRINT_PATTERN.match(thumbprint):
        raise ValueError(
            "EXO_CERTIFICATE_THUMBPRINT must be a 40-character hexadecimal "
            "certificate thumbprint."
        )
    return thumbprint.upper()


def normalize_quarantine_types(quarantine_types: list[str] | None) -> list[str] | None:
    """Return the canonical, de-duplicated Get-QuarantineMessage quarantine types for a
    case-insensitive list of inputs, or None for ["All"] (meaning no type filter).
    Defaults to TransportRule when quarantine_types is None. Raises for an empty list,
    an unknown type, or "All" combined with other types."""
    if quarantine_types is None:
        return [EXO_DEFAULT_QUARANTINE_TYPE]
    if not quarantine_types:
        raise ValueError("quarantine_types must contain at least one quarantine type.")

    known_types = {known_type.lower(): known_type for known_type in EXO_QUARANTINE_TYPES}
    allowed = ", ".join([EXO_ALL_QUARANTINE_TYPES, *EXO_QUARANTINE_TYPES])
    normalized: list[str] = []
    for quarantine_type in quarantine_types:
        if quarantine_type.lower() == EXO_ALL_QUARANTINE_TYPES.lower():
            if len(quarantine_types) > 1:
                raise ValueError(
                    f'"{EXO_ALL_QUARANTINE_TYPES}" cannot be combined with other quarantine types.'
                )
            return None
        known_type = known_types.get(quarantine_type.lower())
        if known_type is None:
            raise ValueError(
                f"Unknown quarantine type '{quarantine_type}'. "
                f"quarantine_types values must be one of: {allowed}."
            )
        if known_type not in normalized:
            normalized.append(known_type)
    return normalized


def build_quarantine_script(
    app_id: str,
    organization: str,
    thumbprint: str,
    days: int = 7,
    limit: int = 50,
    quarantine_types: list[str] | None = None,
) -> str:
    """Build the PowerShell script that authenticates to Exchange Online with the
    app's certificate and returns quarantine messages of the given types (TransportRule
    by default, or every type for ["All"]) as JSON."""
    type_filter = normalize_quarantine_types(quarantine_types)
    if days <= 0:
        raise ValueError("days must be greater than zero")
    if days > EXO_MAX_LOOKBACK_DAYS:
        days = EXO_MAX_LOOKBACK_DAYS
    if limit <= 0:
        raise ValueError("limit must be greater than zero")
    if limit > EXO_MAX_RESULT_LIMIT:
        limit = EXO_MAX_RESULT_LIMIT

    fields = ", ".join(EXO_QUARANTINE_FIELDS)
    type_argument = f"-QuarantineTypes {','.join(type_filter)} " if type_filter else ""
    return f"""
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -AppId '{app_id}' -CertificateThumbprint '{thumbprint}' -Organization '{organization}' -ShowBanner:$false
try {{
    $messages = @(Get-QuarantineMessage {type_argument}-StartReceivedDate (Get-Date).AddDays(-{days}) -EndReceivedDate (Get-Date) -PageSize {limit} -Page 1)
    if ($messages.Count -eq 0) {{
        '[]'
    }} else {{
        $messages | Select-Object {fields} | ConvertTo-Json -Depth 5 -AsArray
    }}
}} finally {{
    Disconnect-ExchangeOnline -Confirm:$false | Out-Null
}}
""".strip()


def run_quarantine_script(script: str) -> list[dict]:
    """Run a quarantine PowerShell script and parse its JSON stdout."""
    completed = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Exchange Online quarantine query failed "
            f"(exit {completed.returncode}): {completed.stderr.strip()}"
        )

    output = completed.stdout.strip()
    if not output:
        return []
    return json.loads(output)


@mcp.tool()
def say_hello(name: str) -> str:
    """Says hello to the given name. A test tool to prove the MCP server works."""
    return f"Hello {name}, your MCP server is working."


@mcp.tool()
def get_recent_signins(hours: int = 24, limit: int = 50) -> list[dict]:
    """Return recent Entra SignInLogs rows from the configured Azure Log Analytics workspace."""
    workspace_id = get_workspace_id()
    credential = get_credential()
    client = LogsQueryClient(credential)
    query = build_signin_query(hours=hours, limit=limit)
    result = client.query_workspace(
        workspace_id,
        query,
        timespan=timedelta(hours=hours),
        server_timeout=30,
    )
    return _rows_from_query_result(result)


@mcp.tool()
def get_all_recent_signins(hours: int = 24) -> list[dict]:
    """Return every Entra SignInLogs row in the configured recent time window."""
    workspace_id = get_workspace_id()
    credential = get_credential()
    client = LogsQueryClient(credential)
    query = build_all_signins_query(hours=hours)
    result = client.query_workspace(
        workspace_id,
        query,
        timespan=timedelta(hours=hours),
        server_timeout=30,
    )
    return _rows_from_query_result(result)


@mcp.tool()
def get_storage_account_access(account_name: str, hours: int = 24, limit: int = 200) -> list[dict]:
    """Return recent data-plane access events (reads, writes, deletes) for the named Azure
    Storage Account, from its StorageBlobLogs resource logs in the configured Log Analytics
    workspace. Each row includes the operation, caller identity (UPN/object ID for
    Microsoft Entra callers, or the auth type for key/SAS/anonymous callers), source IP,
    and the blob path accessed, for spotting unusual or unexpected access. Only accounts
    with blob diagnostic logging routed to this workspace will return results; looks back
    up to 30 days."""
    workspace_id = get_workspace_id()
    credential = get_credential()
    client = LogsQueryClient(credential)
    query = build_storage_access_query(account_name, hours=hours, limit=limit)
    result = client.query_workspace(
        workspace_id,
        query,
        timespan=timedelta(hours=hours),
        server_timeout=30,
    )
    return _rows_from_query_result(result)


@mcp.tool()
def get_quarantine_messages(
    days: int = 7, limit: int = 50, quarantine_types: list[str] | None = None
) -> list[dict]:
    """Return Exchange Online quarantine messages for security review. By default only
    messages quarantined by a transport rule are returned. Set quarantine_types to a list
    of one or more of Bulk, HighConfPhish, Malware, Phish, Spam, SPOMalware, and
    TransportRule to choose which quarantine reasons to include (e.g. ["Phish",
    "Malware"]), or to ["All"] for every quarantined message regardless of reason. Each
    row's Type field gives its quarantine reason. Read-only; looks back up to 30 days and
    returns at most 1000 messages."""
    app_id = get_exo_app_id()
    organization = get_exo_organization()
    thumbprint = get_exo_certificate_thumbprint()
    script = build_quarantine_script(
        app_id,
        organization,
        thumbprint,
        days=days,
        limit=limit,
        quarantine_types=quarantine_types,
    )
    return run_quarantine_script(script)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()