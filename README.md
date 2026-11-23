# koderly-security-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives an MCP client (e.g. Claude Desktop) **read-only** access to Azure security logs:

- Microsoft Entra ID sign-in logs (from Azure Log Analytics)
- Azure Storage blob data-plane access logs (from Azure Log Analytics)

It is designed for periodic security reviews: the client gathers the evidence, and you (or the model) review it. None of the tools change anything in your tenant.

Both kinds of log are read from an Azure Log Analytics workspace, so there's one sign-in method and one place to set up.

## Tools

| Tool | What it returns | Data source |
| --- | --- | --- |
| `say_hello` | A greeting. Use it to check the server is connected. | none |
| `get_recent_signins(hours=24, limit=50)` | Recent Entra sign-ins with identity, app, location, device, Conditional Access, and risk fields. `limit` is capped at 500. | `SigninLogs` in Log Analytics |
| `get_all_recent_signins(hours=24)` | Every sign-in in the window, with no row limit. Use it for bulk review. | `SigninLogs` in Log Analytics |
| `get_storage_account_access(account_name, hours=24, limit=200)` | Blob read/write/delete requests for one storage account: caller identity, source IP, and blob path. Looks back at most 30 days and returns at most 1000 rows. | `StorageBlobLogs` in Log Analytics |

## Requirements

- Python 3.12+
- The [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az`) on `PATH`, and a one-off `az login`. See [Authentication](#authentication).

### Azure data prerequisites

The tools don't read from Entra or your storage accounts directly. They read logs that Azure has copied into a **Log Analytics workspace**, so that workspace and the log copying must be set up first, or the tools will have nothing to return. See [Setting up Log Analytics](#setting-up-log-analytics).

### Permissions (least privilege)

The tools sign in as you, through the Azure CLI (see [Authentication](#authentication)), so they can only read what your user account is allowed to read. The role below goes to the person who will run the MCP client. If your account already has broader access to the workspace, such as Owner, Contributor, or Reader, the tools will work without any changes. Log Analytics Reader is the minimum needed, for when you'd rather not use a more powerful account.

To give an Azure role, open the resource in the Azure portal (the "Scope" column), go to **Access control (IAM) > Add > Add role assignment**, choose the role, and select the user. You need Owner or User Access Administrator on that resource to do this.

| Tool(s) | Granted to | Suggested role | Scope |
| --- | --- | --- | --- |
| All tools | Your user account | Log Analytics Reader | The Log Analytics workspace |

## Authentication

The server doesn't store passwords, keys, or tokens of its own. The tools act **as you**, using your Azure CLI sign-in:

1. Install the Azure CLI, then sign in once:

   ```sh
   az login --tenant <tenant-id>
   ```

   Using `--tenant` makes sure you sign in to the tenant that holds your resources, which matters if your account can access more than one.
2. Put the same tenant ID in `AZURE_TENANT_ID`, in the `env` section of your MCP client's configuration file. You'll fill this in with the other settings when you [connect your MCP client](#connecting-an-mcp-client). See [Configuration](#configuration) for the full list.

When a tool runs, the server gets an access token from the Azure CLI. The tool can then read anything your account can read, which is why the roles under [Permissions](#permissions-least-privilege) are reader-only.

**Your MCP client never signs in to Azure itself.** It just starts the server, and the server uses your saved Azure CLI sign-in.

**You don't need to sign in again after a restart.** `az login` saves a long-lived refresh token to disk, and the Azure CLI uses it to get new access tokens automatically. It survives reboots and MCP client restarts.

**When you do need to run `az login` again:**

- you ran `az logout`
- the sign-in hasn't been used for about 90 days (each use resets that timer)
- your password changed, or an administrator revoked your sessions
- your organisation's Conditional Access policy requires you to sign in again every so often

Until then, the tools return an authentication error. Run `az login --tenant <tenant-id>` again, and there's no need to restart the server.

**If `AZURE_TENANT_ID` isn't set**, the server leaves sign-in to Microsoft's [`DefaultAzureCredential`](https://learn.microsoft.com/python/api/azure-identity/azure.identity.defaultazurecredential). That library tries a series of sign-in methods, the Azure CLI among them, and uses the first that works. The server also allows it to fall back to a browser sign-in. This makes it harder to predict which identity the tools will run as, so we recommend setting `AZURE_TENANT_ID`.

## Setting up Log Analytics

### How it works

A **Log Analytics workspace** is an Azure resource that stores logs and lets you search them. Entra ID and Azure Storage don't send their logs anywhere by default. You add a **diagnostic setting** to each one, which tells Azure to copy new log entries into the workspace as they happen. The tools then run read-only searches against the workspace:

| Tool | Logs it needs | Where they come from | Table it reads |
| --- | --- | --- | --- |
| `get_recent_signins`, `get_all_recent_signins` | Entra interactive user sign-ins | A diagnostic setting on Entra ID | `SigninLogs` |
| `get_storage_account_access` | Blob reads, writes, and deletes | A diagnostic setting on each storage account | `StorageBlobLogs` |

Two things follow from this:

- **There's no history from before you start.** Logs are only copied from the moment a diagnostic setting is saved.
- **The tools can only look back as far as the workspace keeps data.** That's its retention period, 30 days by default.

You set this up once. If your organisation already sends sign-in logs to a workspace, for example for Microsoft Sentinel, you can use that one: skip to [step 2](#step-2-note-the-workspace-id) and check the settings in steps 3 and 4.

### Before you start

- **An Azure subscription** where you can create resources (Contributor on a resource group is enough).
- **A Microsoft Entra ID P1 or P2 licence** in your tenant. Without one, Entra won't let you export sign-in logs. P1 is included in Microsoft 365 Business Premium and E3/E5.
- **Security Administrator or Global Administrator** in Entra, to add the sign-in log diagnostic setting.

**Cost:** Log Analytics charges for each GB of data it takes in, and for keeping data longer than the included retention period. Sign-in logs for a small organisation are usually a small volume, but blob logs for a busy storage account can be large. Check [Azure Monitor pricing](https://azure.microsoft.com/pricing/details/monitor/) and set a daily cap on the workspace if you're unsure.

### Step 1: Create the workspace

1. In the [Azure portal](https://portal.azure.com), search for **Log Analytics workspaces** and select **Create**.
2. Choose a **subscription** and **resource group**, a **name** (for example `security-logs`), and the **region** closest to you.
3. Select **Review + Create**, then **Create**.

### Step 2: Note the workspace ID

Open the workspace. On its **Overview** page, copy the **Workspace ID**. It looks like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`. This is your `AZURE_LOG_ANALYTICS_WORKSPACE_ID`.

Use the Workspace ID, not the workspace's name or its resource ID (the long path that starts with `/subscriptions/`).

### Step 3: Send Entra sign-in logs to the workspace

For the sign-in tools.

1. In the [Microsoft Entra admin center](https://entra.microsoft.com), go to **Entra ID > Monitoring & health > Diagnostic settings** (in older versions of the admin center, **Identity > Monitoring & health > Diagnostic settings**).
2. If a setting already sends `SignInLogs` to your workspace, you're done. Otherwise select **Add diagnostic setting**.
3. Give it a name, for example `signin-logs-to-workspace`.
4. Under **Logs**, tick **SignInLogs**.
5. Under **Destination details**, tick **Send to Log Analytics workspace** and choose your subscription and workspace.
6. Select **Save**.

The tools only read `SignInLogs`, which holds interactive user sign-ins. The other categories on the page, such as `NonInteractiveUserSignInLogs` and `ServicePrincipalSignInLogs`, go into separate tables that the tools don't read. Ticking them adds cost without changing what the tools return.

### Step 4: Send blob access logs to the workspace

For the storage access tool. Repeat this for each storage account you want to review.

1. In the Azure portal, open the storage account and go to **Monitoring > Diagnostic settings**.
2. Select **blob**, then **Add diagnostic setting**.
3. Give it a name, for example `blob-access-to-workspace`.
4. Under **Logs**, tick **StorageRead**, **StorageWrite**, and **StorageDelete**.
5. Under **Destination details**, tick **Send to Log Analytics workspace**, choose the same workspace, and set **Destination table** to **Resource specific**. The tool reads the `StorageBlobLogs` table, which only exists with this option.
6. Select **Save**.

A storage account without this setting returns an empty list, not an error.

### Step 5: Give yourself read access

The tools search the workspace as you (see [Authentication](#authentication)), so your user account needs the **Log Analytics Reader** role on the workspace. If you already have Owner, Contributor, or Reader on it, you can skip this. See [Permissions](#permissions-least-privilege) for how to add a role.

### Step 6: Check the logs are arriving

New logs usually appear within about 15 minutes, but the first ones after you add a setting can take longer. To check, open the workspace, select **Logs**, and run:

```kusto
SigninLogs | take 10
```

or, for storage:

```kusto
StorageBlobLogs | take 10
```

If you get rows back, the tools will too. If you get an error that the table doesn't exist, no data has arrived yet: wait a little longer, and check the diagnostic setting.

## Configuration

All configuration is through environment variables. None of them are secrets.

**Where to set them:** in your MCP client's configuration file, in the `env` section of this server's entry. See [Connecting an MCP client](#connecting-an-mcp-client) for an example. Your MCP client starts the server and passes these values to it, so they only apply to this server. You don't need a `.env` file (the server doesn't read one), and you don't need to set them as system-wide environment variables on the machine.

A tool checks its variables when it's called, and returns an error naming any that are missing.

| Variable | Used by | Description |
| --- | --- | --- |
| `AZURE_LOG_ANALYTICS_WORKSPACE_ID` | all tools | Workspace (customer) ID of the Log Analytics workspace |
| `AZURE_TENANT_ID` | all tools | *Recommended.* The tenant to sign in to through the Azure CLI, so a CLI session signed in to another tenant can't be used by mistake. See [Authentication](#authentication) |

### Finding the Azure values

If you're not sure which resources to use, ask whoever manages your Azure environment. Or look them up yourself, after `az login`:

- **Tenant ID** (`AZURE_TENANT_ID`): run `az account show --query tenantId --output tsv`, or in the Microsoft Entra admin center, copy the **Tenant ID** from the Entra ID **Overview** page.
- **Log Analytics workspace ID** (`AZURE_LOG_ANALYTICS_WORKSPACE_ID`): see [step 2 of Setting up Log Analytics](#step-2-note-the-workspace-id).

## Installation

You'll need [Git](https://git-scm.com/downloads) and [Python 3.12 or later](https://www.python.org/downloads/) installed first. On Windows, tick **"Add python.exe to PATH"** in the Python installer. You don't need to know Python: it's only used to run the server.

Run the commands for your operating system, one line at a time. Lines starting with `#` are explanations, so you don't need to type them.

**Windows (PowerShell):**

```powershell
# Download a copy of this project into a new folder called koderly-security-mcp
git clone https://github.com/ShaunAustin-Koderly/koderly-security-mcp.git

# Move into that folder. Run the remaining commands from here.
cd koderly-security-mcp

# Create a "virtual environment": a private folder (venv) that holds this server's
# own copy of Python and its add-ons, so nothing else on the machine is affected
python -m venv venv

# Switch this PowerShell window over to that private copy of Python.
# Your prompt will then start with (venv). It only affects this window.
.\venv\Scripts\Activate.ps1

# Update pip, Python's installer tool, to its latest version
python -m pip install --upgrade pip

# Install the server and the Microsoft libraries it needs into the venv folder.
# This also creates the koderly-security-mcp.exe launcher your MCP client will run.
python -m pip install -e .
```

If PowerShell refuses to run `Activate.ps1` because "running scripts is disabled on this system", allow local scripts for your user account, then run the activate line again:

```powershell
# Allow scripts you've created on this machine to run (downloaded scripts must still be signed)
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**macOS/Linux (Terminal):**

```sh
# Download a copy of this project into a new folder called koderly-security-mcp
git clone https://github.com/ShaunAustin-Koderly/koderly-security-mcp.git

# Move into that folder. Run the remaining commands from here.
cd koderly-security-mcp

# Create a "virtual environment": a private folder (venv) that holds this server's
# own copy of Python and its add-ons, so nothing else on the machine is affected
python3 -m venv venv

# Switch this terminal window over to that private copy of Python.
# Your prompt will then start with (venv). It only affects this window.
source venv/bin/activate

# Update pip, Python's installer tool, to its latest version
python -m pip install --upgrade pip

# Install the server and the Microsoft libraries it needs into the venv folder.
# This also creates the koderly-security-mcp launcher your MCP client will run.
python -m pip install -e .
```

The `-e` in the last command means the installation uses the project folder directly. So when you download an update with `git pull`, you get the new version after restarting your MCP client. If an update adds new libraries, run the last command again.

There's no separate build step. `pip install` creates a `koderly-security-mcp` launcher inside the virtual environment:

- Windows: `venv\Scripts\koderly-security-mcp.exe`
- macOS/Linux: `venv/bin/koderly-security-mcp`

**Your MCP client's configuration needs the full path to this launcher** (see [Connecting an MCP client](#connecting-an-mcp-client)). It isn't a standalone program. It runs the server using the virtual environment's Python, so leave the `venv` folder in place. You can also start the server with `python -m koderly_security_mcp`.

The server talks MCP over stdio, so if you start it by hand it will just wait quietly for a client.

## Connecting an MCP client

The server uses the stdio transport, so any MCP client that can launch a local server can use it. Register it in your client's MCP configuration: give the path to the `koderly-security-mcp` command, and pass the settings from [Configuration](#configuration) as environment variables.

Many clients use an `mcpServers` JSON block like the one below, e.g. Claude Desktop's `claude_desktop_config.json` (**Settings → Developer → Edit Config**). Where that file lives, and its exact format, depends on your client, so check its documentation.

```json
{
  "mcpServers": {
    "koderly-security-mcp": {
      "command": "/absolute/path/to/koderly-security-mcp/venv/bin/koderly-security-mcp",
      "args": [],
      "env": {
        "AZURE_LOG_ANALYTICS_WORKSPACE_ID": "<workspace-id>",
        "AZURE_TENANT_ID": "<tenant-id>"
      }
    }
  }
}
```

On Windows the command is `...\\venv\\Scripts\\koderly-security-mcp.exe`. Restart your MCP client after you change its configuration. Most clients only read the server's list of tools when they start.

Example prompts:

```text
Use the say_hello tool with the name Alex.
```

```text
Use get_all_recent_signins to retrieve every Entra sign-in from the last 24 hours. Summarize normal activity and flag anything requiring attention. Do not treat unusual activity as confirmed malicious activity.
```

```text
Use get_storage_account_access to check who has accessed the <storage-account-name> storage account in the last 7 days. Summarize which identities and IP addresses accessed it, and flag any unexpected callers or delete operations.
```

### Example: a daily scheduled review

If your MCP client can run a prompt on a schedule (for example, a scheduled task in Claude Desktop), you can use the server for an automatic daily security check. Here's an example set of instructions to start from. Replace the values in angle brackets with your own:

- `<your country>`: where your users normally sign in from.
- `<storage-account-name>`: the storage account to review.
- `<expected-caller-object-id>`: the object ID of a service or Azure resource that accesses the account as part of normal operation. Take it from the `RequesterObjectId` field of earlier results.
- `<your name>`: who reads the report.

```text
General rule: scope all activity to the last 24 hours, unless today is Monday, in which case scope it to the last 72 hours so the weekend is covered. Where possible, only fetch data from within that window.

1. Retrieve all Entra sign-ins using the complete sign-in tool (get_all_recent_signins). Analyse every returned record. Summarise normal activity and flag records that need attention. Treat any successful sign-in from outside <your country> as very suspicious and flag it as a priority. Otherwise, don't treat unusual activity as confirmed malicious activity.

2. Use get_storage_account_access to check who has accessed <storage-account-name> in the scoped window. Summarise all access, with as much detail about each caller as possible. Caller ID <expected-caller-object-id> is an Azure resource, so its access is normal. Any other access should be by a named member of staff.

Always produce a clear, reportable result for this run, even when nothing unusual is found: confirm a clean run explicitly rather than leaving it silent. End with a one-line overall verdict, either "Nothing notable" or "N items worth a look", so <your name> can triage from the notification alone.
```

A few tips for writing your own:

- **Give the time window as a rule, not a fixed number of hours.** The tools take an `hours` argument, so the model can work out the window each day, including the longer one after a weekend.
- **Say what normal looks like.** Known service accounts, expected locations, and named callers reduce false alarms.
- **Ask for a verdict line.** A fixed final line makes the result easy to scan in a notification.

## Data handling

These tools return sensitive data: user principal names, IP addresses, locations, device details, and the names of files accessed in storage accounts. That data goes to whichever MCP client and model you connect the server to. Check that this is acceptable under your organisation's data protection policies before you use it.

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

The tests mock every Azure SDK call, so they need no Azure access.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
