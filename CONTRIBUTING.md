# Contributing

Thanks for your interest in improving koderly-security-mcp.

## Ground rules

- **Tools must be read-only.** New tools should gather evidence for review. They must never change tenant or resource state.
- **Bound every query.** Validate and cap inputs such as lookback windows, row limits, and names before interpolating them into KQL, following the existing `build_*` helpers.
- **No environment-specific values in code.** Tenant, subscription, workspace, and resource names come from environment variables. Document any new variable in `README.md`.
- **Least privilege.** Document the minimum role each new tool needs.

## Development setup

```sh
python -m venv venv
# Windows: .\venv\Scripts\Activate.ps1    macOS/Linux: source venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

Tests must not call Azure. Mock the SDK clients, as the existing tests do.

## Pull requests

- Keep each change focused, and add or update tests.
- Update `README.md` when you add or change tools, parameters, or environment variables.
- By contributing, you agree that your contributions are licensed under the MIT License.
