# MCP Apps static review

SkillGate inventories MCP Apps declarations as local static evidence. It reports
the app resource, UI assets, declared origins, browser permissions,
UI-callable tools, host bridge markers, and malformed declarations without
rendering the UI or contacting the declared origins.

## What SkillGate Reads

- Modern `_meta.ui.resourceUri` declarations and legacy
  `_meta["ui/resourceUri"]` declarations.
- `ui://` resources and `text/html;profile=mcp-app` UI MIME declarations.
- Declared CSP origins, browser permissions, app capabilities, and
  UI-callable tool metadata.
- Local HTML, CSS, and JavaScript assets reachable from a positive MCP Apps
  declaration, within the scan root and bounded to 100 assets, 1 MiB per asset,
  and 5 MiB total.
- Local `.mcpb` web assets in positively identified MCP Apps bundles, through
  the existing bounded archive inspection layer.

## Review Signals

MCP Apps evidence appears as the `mcp_apps` trust boundary and these capability
types:

- `mcp_app_resource`
- `mcp_app_asset`
- `mcp_app_origin`
- `mcp_app_permission`
- `mcp_app_tool_surface`
- `mcp_app_host_bridge`
- `mcp_app_unknown_declaration`

`SG011` remains the rule for MCP tool metadata risk. MCP Apps produce medium
`SG011` findings only for privileged app-callable tools, dynamic tool surfaces,
and browser permissions. CSP origins are app-origin evidence; they are not
reported as `SG003` network egress merely because they were declared.

## Boundaries

Local scans never dereference `ui://` resources, CSP origins, frame domains,
script URLs, package URLs, or MCP endpoints. SkillGate does not render HTML,
start a browser, import JavaScript, start an MCP server, call a resource API, or
run UI code. GitHub fetching remains an explicit remote-source operation and is
limited to eligible relative files from the requested repository and subtree.

Skipped, malformed, oversized, non-UTF-8, or redacted declarations remain review
evidence. They are not treated as proof that an app is safe or unsafe.
