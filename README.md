# koderly-security-mcp

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that gives an MCP client (e.g. Claude Desktop) **read-only** access to common Microsoft cloud security review data:

- Microsoft Entra ID sign-in logs (from Azure Log Analytics)
- Azure Storage blob data-plane access logs (from Azure Log Analytics)
- Exchange Online quarantined messages (by default, those quarantined by a transport rule)

It is designed for periodic security reviews: the client gathers the evidence, and you (or the model) review it. None of the tools change anything in your tenant.

## Tools

| Tool | What it returns | Data source |
| --- | --- | --- |
| `say_hello` | A greeting. Use it to check the server is connected. | none |
| `get_recent_signins(hours=24, limit=50)` | Recent Entra sign-ins with identity, app, location, device, Conditional Access, and risk fields. `limit` is capped at 500. | `SigninLogs` in Log Analytics |
| `get_all_recent_signins(hours=24)` | Every sign-in in the window, with no row limit. Use it for bulk review. | `SigninLogs` in Log Analytics |
| `get_storage_account_access(account_name, hours=24, limit=200)` | Blob read/write/delete requests for one storage account: caller identity, source IP, and blob path. Looks back at most 30 days and returns at most 1000 rows. | `StorageBlobLogs` in Log Analytics |
| `get_quarantine_messages(days=7, limit=50, quarantine_types=None)` | Exchange Online quarantined messages. If `quarantine_types` is left out, it returns only messages quarantined by a transport rule. Otherwise pass a list of one or more of `Bulk`, `HighConfPhish`, `Malware`, `Phish`, `Spam`, `SPOMalware` and `TransportRule` (for example `["Phish", "Malware"]`), or `["All"]` for every reason. Each row's `Type` field says why the message was quarantined. Looks back at most 30 days and returns at most 1000 rows. | `Get-QuarantineMessage` via PowerShell |

## Requirements

- Python 3.12+
- For the Azure tools: the [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az`) on `PATH`, and a one-off `az login`. See [Authentication](#authentication).
- For the quarantine tool only:
  - [PowerShell 7](https://learn.microsoft.com/powershell/scripting/install/installing-powershell) (`pwsh`) on `PATH`
  - The [`ExchangeOnlineManagement`](https://www.powershellgallery.com/packages/ExchangeOnlineManagement) module
  - An Entra app registration and a certificate. See [Setting up the quarantine tool](#setting-up-the-quarantine-tool).
  - Windows. The tool finds its certificate in the Windows certificate store, so it only works on Windows as written.

### Azure data prerequisites

This section lists settings in your own Azure tenant that must be switched on, or the matching tool will have nothing to return. They're one-off changes, made in the Azure portal by someone with admin rights. Your organisation may already have some of them in place, so check first.

You only need the ones for the tools you plan to use.

- **Sign-in and storage access tools: have a Log Analytics workspace.**
  Both tools read from a Log Analytics workspace, which must exist before you can send any logs to it. If your organisation doesn't already have one, create it in the Azure portal under **Log Analytics workspaces > Create**. One workspace is enough for both tools. Azure charges for the data the workspace takes in and for keeping it beyond the free retention period, so check the pricing and retention settings when you create it.
  
- **Sign-in tools: send Entra sign-in logs to Log Analytics.**
  In the Microsoft Entra admin center, go to **Monitoring & health > Diagnostic settings**. Check for a setting that sends `SignInLogs` to your Log Analytics workspace. If there isn't one, add it. You can also tick `NonInteractiveUserSignInLogs` and `ServicePrincipalSignInLogs` to include those sign-ins. This needs the Security Administrator or Global Administrator role. Note the workspace: its **Workspace ID** goes in `AZURE_LOG_ANALYTICS_WORKSPACE_ID` (see [Configuration](#configuration)).

- **Storage access tool: send blob access logs to the same workspace.**
  For each storage account you want to review, open it in the Azure portal and go to **Monitoring > Diagnostic settings**, then choose **blob**. Add a setting that sends `StorageRead`, `StorageWrite`, and `StorageDelete` to the same Log Analytics workspace, and set the destination table to **Resource specific**. Logging only starts once the setting is saved, so there is no history from before then.

### Permissions (least privilege)

Each tool can only read data that the identity it signs in as is allowed to read. These are the roles to give that identity:

- **Azure tools: give the roles to your own user account.** These tools sign in as you, through the Azure CLI (see [Authentication](#authentication)). So the roles go to the person who will run the MCP client, on the Azure resources listed below. If your account already has broader access, such as Owner or Contributor, the tools will work without any changes. The roles below are the minimum needed, for when you'd rather not use a more powerful account.
- **Quarantine tool: give the roles to an app registration, not a person.** This tool signs in as an Entra app you create for it. Its permissions are covered in [Setting up the quarantine tool](#setting-up-the-quarantine-tool).

To give an Azure role, open the resource in the Azure portal (the "Scope" column), go to **Access control (IAM) > Add > Add role assignment**, choose the role, and select the user. You need Owner or User Access Administrator on that resource to do this.

| Tool(s) | Granted to | Suggested role | Scope |
| --- | --- | --- | --- |
| Sign-in and storage access | Your user account | Log Analytics Reader | The Log Analytics workspace |
| Quarantine messages | The app registration | Security Reader (Microsoft Entra role), plus the `Exchange.ManageAsApp` API permission | Your tenant. See [Setting up the quarantine tool](#setting-up-the-quarantine-tool) |

## Authentication

The server doesn't store passwords, keys, or tokens of its own. The Azure tools and the quarantine tool sign in in different ways.

### Azure tools (sign-ins and storage access)

These tools act **as you**, using your Azure CLI sign-in:

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

Until then, the Azure tools return an authentication error. Run `az login --tenant <tenant-id>` again, and there's no need to restart the server.

**If `AZURE_TENANT_ID` isn't set**, the server leaves sign-in to Microsoft's [`DefaultAzureCredential`](https://learn.microsoft.com/python/api/azure-identity/azure.identity.defaultazurecredential). That library tries a series of sign-in methods, the Azure CLI among them, and uses the first that works. The server also allows it to fall back to a browser sign-in. This makes it harder to predict which identity the tools will run as, so we recommend setting `AZURE_TENANT_ID`.

### Quarantine tool

The quarantine tool doesn't use your Azure CLI sign-in. It signs in to Exchange Online as the app registration in `EXO_APP_ID`, using the certificate in your Windows certificate store whose thumbprint is `EXO_CERTIFICATE_THUMBPRINT`. Nothing interactive is involved, and it keeps working until the certificate expires or is removed from the app registration. See [Setting up the quarantine tool](#setting-up-the-quarantine-tool).

## Setting up the quarantine tool

Skip this section if you don't need `get_quarantine_messages`.

The quarantine tool signs in to Exchange Online as an **app registration**: an identity in Microsoft Entra that belongs to this tool rather than to a person. It proves who it is with a **certificate** stored on the computer that runs the server. You set this up once. You'll need an account that can register apps, grant admin consent, and assign Entra roles, such as Privileged Role Administrator or Global Administrator.

By the end you'll have three values: the app's ID, your tenant's `.onmicrosoft.com` domain, and the certificate's thumbprint. These go in your MCP client's configuration file (step 8), so note each one down as you go.

Do steps 1 and 2 on the computer that will run the server, signed in as the Windows user who runs your MCP client. The certificate is stored in that user's personal certificate store, so the tool can only find it there.

### Step 1: Install the Exchange Online PowerShell module

Open **PowerShell 7** (`pwsh`, not the older "Windows PowerShell") and run:

```powershell
# Install Microsoft's Exchange Online module for your Windows user only (no admin rights needed)
Install-Module ExchangeOnlineManagement -Scope CurrentUser
```

### Step 2: Create a certificate

In the same PowerShell window:

```powershell
# Create a certificate that's valid for one year, in your personal certificate store.
# -KeySpec KeyExchange is required: Exchange Online doesn't accept the newer default key type.
$cert = New-SelfSignedCertificate -Subject "CN=koderly-security-mcp" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(1) -KeySpec KeyExchange

# Save the certificate's public part to a .cer file in your user folder. You'll upload it in step 4.
# It contains no secrets.
$cert | Export-Certificate -FilePath "$HOME\koderly-security-mcp.cer"

# Show the certificate's thumbprint. Copy it: this is your EXO_CERTIFICATE_THUMBPRINT.
$cert.Thumbprint
```

The private key never leaves your certificate store, and it's what proves the tool's identity. Anyone who copies it can read your quarantine, so don't export it unless you need a backup. If you do, use `Export-PfxCertificate` with a strong password, and keep the `.pfx` file out of this project folder.

### Step 3: Register the app

1. Sign in to the [Microsoft Entra admin center](https://entra.microsoft.com) and go to **App registrations**, then **New registration**.
2. **Name:** anything descriptive, for example `koderly-security-mcp`.
3. **Supported account types:** *Accounts in this organizational directory only (single tenant)*.
4. Leave **Redirect URI** empty and select **Register**.
5. On the app's **Overview** page, copy the **Application (client) ID**. This is your `EXO_APP_ID`.

### Step 4: Upload the certificate

On the app's page, go to **Certificates & secrets**, then **Certificates**, then **Upload certificate**. Select the `koderly-security-mcp.cer` file from step 2, then select **Add**.

### Step 5: Allow the app to use Exchange Online PowerShell

1. On the app's page, go to **API permissions**, then **Add a permission**, then the **APIs my organization uses** tab.
2. Search for and select **Office 365 Exchange Online**.
3. Choose **Application permissions**, expand **Exchange**, tick **Exchange.ManageAsApp**, and select **Add permissions**.
4. Select **Grant admin consent for *your organisation***, then **Yes**. The status should change to *Granted*.

This lets the app connect to Exchange Online. On its own, it can't see anything yet.

### Step 6: Give the app read-only access to quarantine

1. In the Entra admin center, go to **Roles & admins** and select the **Security Reader** role. Select the role name, not the checkbox.
2. Select **Add assignments**, find your app, and select **Add**.

Security Reader gives read-only access to every user's quarantined messages. It's the narrowest built-in role that does, and one of the roles Microsoft supports for this kind of sign-in. It can also read other Microsoft 365 security data and preview quarantined messages, but it can't change anything.

> **Note:** Don't use Exchange Administrator or Global Administrator instead. They work, but anyone holding the certificate could then change your Exchange configuration.

Role changes can take a few minutes to apply.

### Step 7: Find your tenant's `.onmicrosoft.com` domain

In the Entra admin center, go to **Entra ID > Domain names** (in older versions of the admin center, **Identity > Settings > Domain names**). Copy the domain that ends in `.onmicrosoft.com`, for example `contoso.onmicrosoft.com`. This is your `EXO_ORGANIZATION`.

Don't use the **Primary domain** shown on the Entra ID **Overview** page unless it ends in `.onmicrosoft.com`. If your organisation has made a custom domain, such as `contoso.com`, the primary domain, that's what the Overview page shows. Exchange Online app-only sign-in needs the `.onmicrosoft.com` domain.

### Step 8: Add the three values to your MCP client's configuration

Put `EXO_APP_ID`, `EXO_ORGANIZATION`, and `EXO_CERTIFICATE_THUMBPRINT` in the `env` section of this server's entry in your MCP client's configuration file, alongside any Azure settings:

```json
"env": {
  "EXO_APP_ID": "<application-client-id-from-step-3>",
  "EXO_ORGANIZATION": "<tenant>.onmicrosoft.com",
  "EXO_CERTIFICATE_THUMBPRINT": "<thumbprint-from-step-2>"
}
```

If you haven't added the server to your MCP client yet, do the [Installation](#installation) first, then follow [Connecting an MCP client](#connecting-an-mcp-client), which shows the full configuration. Restart the client after you change its configuration.

**When the certificate expires** (after one year with the command above), the tool stops working. Repeat steps 2 and 4, then update `EXO_CERTIFICATE_THUMBPRINT`. Put a reminder in your calendar.

For more detail, see Microsoft's guide: [App-only authentication in Exchange Online PowerShell](https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2).

## Configuration

All configuration is through environment variables. None of them are secrets: the Exchange Online private key stays in the certificate store.

**Where to set them:** in your MCP client's configuration file, in the `env` section of this server's entry. See [Connecting an MCP client](#connecting-an-mcp-client) for an example. Your MCP client starts the server and passes these values to it, so they only apply to this server. You don't need a `.env` file (the server doesn't read one), and you don't need to set them as system-wide environment variables on the machine.

Only set the variables for the tools you use. A tool checks its variables when it's called, and returns an error naming any that are missing.

| Variable | Used by | Description |
| --- | --- | --- |
| `AZURE_LOG_ANALYTICS_WORKSPACE_ID` | sign-in, storage access | Workspace (customer) ID of the Log Analytics workspace |
| `AZURE_TENANT_ID` | all Azure tools | *Recommended.* The tenant to sign in to through the Azure CLI, so a CLI session signed in to another tenant can't be used by mistake. See [Authentication](#authentication) |
| `EXO_APP_ID` | quarantine | Application (client) ID of the Exchange Online app registration |
| `EXO_ORGANIZATION` | quarantine | Your tenant's initial `*.onmicrosoft.com` domain |
| `EXO_CERTIFICATE_THUMBPRINT` | quarantine | Thumbprint of the app-only auth certificate in `Cert:\CurrentUser\My` |

### Finding the Azure values

If you're not sure which resources to use, ask whoever manages your Azure environment. Or look them up yourself, after `az login`:

- **Tenant ID** (`AZURE_TENANT_ID`): run `az account show --query tenantId --output tsv`, or in the Microsoft Entra admin center, copy the **Tenant ID** from the Entra ID **Overview** page.
- **Log Analytics workspace ID** (`AZURE_LOG_ANALYTICS_WORKSPACE_ID`): in the Azure portal, open the workspace. The **Workspace ID** is on its **Overview** page. Use the workspace that your diagnostic settings send logs to (see [Azure data prerequisites](#azure-data-prerequisites)).

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
        "AZURE_TENANT_ID": "<tenant-id>",
        "EXO_APP_ID": "<app-client-id>",
        "EXO_ORGANIZATION": "<tenant>.onmicrosoft.com",
        "EXO_CERTIFICATE_THUMBPRINT": "<certificate-thumbprint>"
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
Use get_quarantine_messages with quarantine_types ["All"] to list every quarantined message from the last 7 days, grouped by quarantine reason.
```

```text
Use get_quarantine_messages with quarantine_types ["Phish", "HighConfPhish", "Malware"] to list phishing and malware quarantines from the last 14 days.
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

These tools return sensitive data: user principal names, IP addresses, locations, device details, email senders, recipients, and subjects. That data goes to whichever MCP client and model you connect the server to. Check that this is acceptable under your organisation's data protection policies before you use it.

## Development

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
```

The tests mock every Azure SDK call and subprocess call, so they need no Azure access.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To report a security issue, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
