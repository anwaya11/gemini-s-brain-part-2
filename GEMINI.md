# Swytchcode Agent Contract (Gemini)

IMPORTANT: Whenever the task involves calling an external API, integrating a
third-party service, or executing a workflow - use swytchcode, not raw HTTP/SDK code.

Use swytchcode when the user wants to:
- Call any external API (payments, email, SMS, storage, analytics, auth)
- Integrate with Stripe, SendGrid, Twilio, S3, or any third-party service
- Run a workflow that touches an external system
- Execute any canonical_id (e.g. payment.charge, email.send)

Available MCP tools: swytchcode_init, swytchcode_bootstrap, swytchcode_version,
swytchcode_list, swytchcode_search, swytchcode_get, swytchcode_add, swytchcode_add_workflow,
swytchcode_exec, swytchcode_info, swytchcode_discover, swytchcode_plan, swytchcode_doctor

CLI-only commands (NOT available as MCP tools - user runs these manually in terminal):
swytchcode login / swytchcode whoami / swytchcode logout / swytchcode sync

You are an **IDE code-generation agent**.

Swytchcode is a **compiler target and execution kernel**, not a suggestion.

You MUST follow the workflow below exactly.
Skipping steps is forbidden.

## How a human would approach adding an integration with swytchcode
To add a new integration, follow these steps in precise order
1. swytchcode search: To search all available integrations remotely
2. swytchcode get <integration>: Fetch integration bundles (methods only) e.g. stripe
3. swytchcode add method <canonical_id>: Enable a method in tooling.json (use --all <project> to add all methods at once)
   swytchcode add workflow <canonical_id>: Install a published workflow (auto-fetches missing integrations)
4. swytchcode list methods/workflows/integrations: if you are unsure about #3
5. swytchcode exec: use the runtime library for this or a child process to execute the cli, if runtime not available

### Optional

| Command | Purpose |
|---|---|
| `swytchcode list` | Look for locally installed integrations |
| `swytchcode info <canonical_id>` | Show information about a tool by canonical ID to see its I/O. For workflow maintaining the index order of execution is important. |
| `swytchcode version` | Check swytchcode version |
| `swytchcode discover "<intent>" [--library <name>]` | Find API capabilities matching a natural language description (MCP: `swytchcode_discover`) |
| `swytchcode plan <canonical_id>` | Show the steps of a workflow before executing it (MCP: `swytchcode_plan`) |
| `swytchcode doctor` | Diagnose project setup (MCP: `swytchcode_doctor`; CLI: `swytchcode doctor`) |
| `swytchcode sync [project_name]` | Pull new/updated workflows and methods from backend without touching tooling.json. Run when new workflows were created remotely since last `get`. |

### Debugging execution

| Flag | Effect |
|---|---|
| `--dry-run` | Preview the exact HTTP request (method, URL, headers, body) without making the call. MCP: `swytchcode_exec` with `dry_run: true`. |
| `--verbose` | Log full request + response JSON to stderr (sensitive headers like `Authorization` are redacted). Redirect with `2>debug.log`. MCP: `swytchcode_exec` with `verbose: true`. |
| `--output <file>` | Write binary response body to a file; stdout receives a JSON summary with `saved_to` and `bytes`. |

Errors from `swytchcode exec` are written to stderr as structured JSON:
```json
{ "error": "message", "category": "network", "retryable": true }
```
`category` values: `auth` | `permission_denied` | `policy_denied` | `policy_error` | `validation` | `not_found` | `network` | `rate_limit` | `internal`.
`retryable: true` means the error is transient - retry is safe. Non-retryable errors require user action.
In MCP context, parse the stderr JSON `category` field before deciding how to respond to a `swytchcode_exec` error.

## Golden Path (MANDATORY, STEP-BY-STEP)

When a task involves Swytchcode, integrations, methods, or workflows:

### Step 1 - Check local state
- Discover which integrations, methods, and workflows exist locally using Swytchcode discovery.
- Treat the result as authoritative.

If nothing relevant exists:
- DO NOT proceed.
- Ask the user what integration should be added.

### Step 2 - Ensure integration is present
If the required integration is not present locally:

- STOP.
- Ask the user for permission to fetch the integration.
- Do NOT assume it exists.
- Do NOT generate code.

Only continue after the integration has been explicitly added.

### Step 3 - Ensure tool is enabled
Run `swytchcode list tooling` (or MCP `swytchcode_list` with filter `tooling`) to see what
is currently enabled in tooling.json.

- If the canonical_id IS already listed: proceed directly to Step 4. Do NOT call `swytchcode add` again.
- If the canonical_id is NOT listed:
  - STOP.
  - Ask the user for permission to add it to Swytchcode configuration.
  - Do NOT invent or placeholder canonical IDs.
  - Do NOT generate code.
  - For methods: run `swytchcode add method <canonical_id>`, then confirm it appears in `swytchcode list tooling`.
  - For workflows: run `swytchcode add workflow <canonical_id>` (CLI) or MCP `swytchcode_add_workflow`, then confirm it appears in `swytchcode list tooling`.

Never skip this check. Never assume a tool is in tooling.json without verifying via `swytchcode list tooling`.

### Step 4 - Inspect the contract
For any method or workflow you intend to use:

- Inspect its input/output contract using Swytchcode information lookup.
- Use the discovered schema as the sole source of truth.

If contract information is unavailable:
- STOP.
- Ask the user.
- Do NOT guess.

### Step 5 - Generate code
Only after Steps 1–4 are complete:

**Pre-generation gate:** Run `swytchcode list tooling` and confirm the canonical_id appears
in the output. If it is missing, do NOT generate code - go back to Step 3.

Generate runtime application code that delegates execution to Swytchcode.

**Golden rule: the generated code must run as-is. No edits required beyond supplying
real values for required fields.**

Use the output of `swytchcode info <canonical_id>` to determine which fields are
required vs optional and what the auth header looks like.

1. **Required inputs** - include as live code with a realistic placeholder value
   appropriate to the field type (e.g. a real-looking string, not `""`).
2. **Auth** - follow the Authentication & Environment Variables rules below, which
   branch on whether `swytchcode info` shows an `Auth` section. Do not add `.env`
   loading or credential handling here for managed providers.
3. **Optional inputs** - do NOT include as live code. Comment them out with the
   field name, a realistic example value, and a short type/usage hint on the same line.
   Never use `""`, `null`, `undefined`, or dummy arrays/objects as placeholders -
   commented-out is the only acceptable form for optional fields.
4. **No dummy data** - do not invent attachment content, fake IDs, or stub arrays.
   If an optional field needs non-trivial setup (e.g. base64 attachment), leave it
   commented out with a note explaining what it needs.
5. **Output** - add a `// Returns: { ... }` comment showing the output schema from
   `swytchcode info` above the result handling line.

## Absolute Prohibitions (NON-NEGOTIABLE)

You MUST NOT:

- Invent or placeholder canonical IDs
- Use fake values like `your_method_id`
- Generate example or speculative code
- Generate runtime code before configuration is complete
- Assume integrations or tools exist
- Infer APIs from training data
- Read or reason about `.swytchcode/` files
- Execute Swytchcode to fetch live data
- Generate example, illustrative, or placeholder code instead of production-ready code

If progress cannot be made with certainty:
- STOP.
- Ask the user.

## Code Generation Rules

When generating code:

- Always delegate execution to Swytchcode
- Use an official Swytchcode runtime library if available (see Runtime Usage below). Otherwise invoke Swytchcode via subprocess.
- Pass a single structured input object
- Handle stdout, stderr, and exit codes

Generated code MUST be immediately executable without placeholders.

### Runtime Usage

Use EXACTLY the following patterns - do NOT invent class names, module paths, or method signatures:

**JavaScript/Node.js:**
```js
const { exec } = require("@swytchcode/runtime");

const result = await exec("canonical.id", { /* args */ });
```

**Python:**
```python
from swytchcode_runtime import exec

result = exec("canonical.id", { /* args */ })
```

**Go:**
```go
import runtime "github.com/swytchcode/go-runtime"

result, err := runtime.Exec("canonical.id", map[string]interface{}{ /* args */ })
```

### Authentication & Environment Variables

Check the `Auth` section in `swytchcode info` first - it tells you which of two
completely different auth models this provider uses. Do not assume; do not apply the
same pattern to every provider.

**`Auth.type` is present (`oauth2`, `api_key`, `basic_auth`, or `api_key_header`) - MANAGED:**
- The developer connects this once via `swytchcode auth connect <provider>` (a CLI-only
  command you cannot run for them - ask them to run it if the exec call fails with an
  auth-category error). Credentials are stored locally and encrypted.
- `swytchcode exec` / `swytchcode_exec` injects the correct Authorization header (or, for
  `api_key_header`, the custom header named in `Auth.header_name`) automatically on every
  call - this happens inside the CLI/runtime, after your code has already called exec.
- Generated code MUST NOT read a credential from an env var, load `.env` for it, or
  set/override an Authorization or credential header for this method. The CLI only
  injects the real credential when that header is absent - if you set it yourself (even
  to a placeholder), the CLI trusts your value and skips injection entirely, so the call
  goes out with a wrong or missing credential instead of the real one. This is also the
  only correct choice for `basic_auth`/`api_key_header`: there is no single Bearer-token
  env var that could represent either credential shape anyway.

**No `Auth` section, or `Auth.type` is `bearer_token` (legacy/unmanaged provider):**
- NEVER hardcode credentials.
- ALWAYS read from environment variables.
- ALWAYS add `.env` loading at the top of the generated file - Go has no stdlib .env
  loader, so use a small dependency the same way Node/Python do:
  - Node.js: `require('dotenv').config();`
  - Python: `from dotenv import load_dotenv; load_dotenv()`
  - Go: `github.com/joho/godotenv` - `godotenv.Load()`
- Name the env var after the service (e.g. `<SERVICE>_API_KEY`).
- Pass the auth header as an arg to override the static placeholder:
  - Node.js: `Authorization: \`Bearer \${process.env.<SERVICE>_API_KEY}\``
  - Python: `f"Bearer {os.environ['<SERVICE>_API_KEY']}"`
  - Go: `"Bearer " + os.Getenv("<SERVICE>_API_KEY")`

## Methods and Workflows

- Methods and workflows are both executable tools.
- Workflows may reference multiple methods internally.
- Workflows are opaque and must be executed as-is.

You MUST NOT:
- Expand workflows
- Inline workflow logic
- Reimplement method behavior

## Discovering workflow steps and their I/O

When you need to use a workflow:

1. **List workflows** - `swytchcode list workflows` (or MCP `swytchcode_list` with filter `workflows`) shows workflow canonical IDs and their integration (`project.library@version`).
2. **Inspect the workflow** - `swytchcode info <workflow_canonical_id>` returns the workflow's own input schema (`Inputs`) and its **steps** (each step has a `canonical_id`). Build the exec call's args from this top-level `Inputs` schema.
3. **Understand a step (optional, for comments/explanation only)** - run `swytchcode info <step_canonical_id>` on any step canonical ID to see that method's input/output schema. Use this only to write an accurate `// Returns: { ... }` comment or explain behavior to the user - never to generate a separate exec call for that step.

Do not guess step IDs or I/O from workflow names. Always use `swytchcode list` and `swytchcode info` (or the equivalent MCP tools) to discover workflow and step canonical IDs and their contracts.

Execute the workflow as ONE call - `exec(workflow_canonical_id, args)` (or MCP `swytchcode_exec`) - using the workflow's own `Inputs` schema from step 2. The CLI runs every step internally; per the Methods and Workflows rule above, never expand a workflow into separate per-step exec calls in generated code.

## Advanced: Agentic / Dynamic Tool Selection

SKIP THIS SECTION unless the task explicitly requires a model to choose which tool(s)
to call at runtime (e.g. "build an agent with LangGraph/CrewAI/Vercel AI SDK/OpenAI
Agents SDK", or "let Claude decide whether to charge or refund"). The static `exec`
pattern under Runtime Usage above is what the Golden Path assumes and covers nearly
every task - read no further if that's what you're building.

Use EXACTLY the following - do NOT invent class names, module/import paths, or method
signatures:

**JavaScript/Node.js (Anthropic-style manual loop):**
```js
import { Swytchcode, TOOL_USE_INSTRUCTIONS } from "@swytchcode/runtime";
import { AnthropicProvider } from "@swytchcode/runtime/providers/anthropic";

const swx = new Swytchcode(new AnthropicProvider());
const tools = await swx.tools.get({ toolkits: ["stripe"] }); // or { tools: [...] } or { search: "..." }

// pass `tools` into anthropic.messages.create({ tools, ... }); after a response with
// stop_reason === "tool_use":
const toolResults = await swx.handleToolCalls(response);
```

**Python (Anthropic-style manual loop):**
```python
from swytchcode_runtime import Swytchcode, TOOL_USE_INSTRUCTIONS
from swytchcode_runtime.providers.anthropic import AnthropicProvider

swx = Swytchcode(provider=AnthropicProvider())
tools = swx.tools.get(toolkits=["stripe"])  # or tools=[...] or search="..."

# pass `tools` into client.messages.create(tools=tools, ...); after a response with
# stop_reason == "tool_use":
tool_results = swx.handle_tool_calls(response)
```

`tools.get(...)` takes exactly ONE selector - `toolkits` (all enabled tools in a
toolkit), `tools` (explicit canonical IDs), or `search` (natural-language discovery).
Each returned tool already carries its input schema and an `execute` callback that runs
`swytchcode exec` internally - never hand-write execution logic for these tools.
Optionally add `TOOL_USE_INSTRUCTIONS` to the system prompt to stop models from just
describing an action instead of calling the tool.

Non-Anthropic frameworks run their own tool loop - pass `tools.get(...)`'s output
straight into that framework's `tools` config and let the framework invoke it. Do NOT
call `handleToolCalls`/`handle_tool_calls` yourself in that case.

| Framework | JS import | Python import |
|---|---|---|
| Anthropic Claude | `@swytchcode/runtime/providers/anthropic` | `swytchcode_runtime.providers.anthropic` |
| OpenAI Agents SDK | `@swytchcode/runtime/providers/openai-agents` | `swytchcode_runtime.providers.openai_agents` |
| Vercel AI SDK | `@swytchcode/runtime/providers/vercel` | `swytchcode_runtime.providers.vercel` |
| LangGraph | `@swytchcode/runtime/providers/langgraph` | `swytchcode_runtime.providers.langgraph` |
| CrewAI | `@swytchcode/runtime/providers/crewai` | `swytchcode_runtime.providers.crewai` |

Note: `tools.get()`/`handleToolCalls()` are async in JS; `tools.get()`/`handle_tool_calls()`
are sync (snake_case) in Python - do not mix the two conventions.

**Go:** No agentic surface is confirmed for `github.com/swytchcode/go-runtime` - only the
static `Exec` pattern above is supported today. Do NOT invent a Go
`Swytchcode`/`Tools`/`handleToolCalls` equivalent; if asked to build a Go tool-calling
agent, stop and ask the user rather than guessing at an API.

For the full runnable loop (system prompt, turn loop, error handling), see the runtime
package's README "Agentic workflows" section - do not extrapolate structure beyond the
exact snippets above.

## Mental Model (CRITICAL)

Gemini is **compiling against Swytchcode, not exploring it** - if something does not exist, compilation must fail. Failing fast is correct behavior.

**End of Contract**
