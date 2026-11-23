import os
import re
from datetime import timedelta

from azure.identity import AzureCliCredential, DefaultAzureCredential
from azure.monitor.query import LogsQueryClient
from mcp.server.mcpserver import MCPServer

mcp = MCPServer("koderly-security-mcp")

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


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()