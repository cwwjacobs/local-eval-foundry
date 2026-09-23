# Configuration reference

`config.example.json` is a human-readable mapping of the values EvalFoundry
accepts on its launch command. It is intentionally **not** auto-loaded: model
endpoints and archive paths must be supplied explicitly by the person starting
the local service, so a stale file cannot silently point the engine at a wrong
dataset or provider.

Use the values as PowerShell launcher arguments instead:

```powershell
.\Start-EvalFoundry.ps1 -ArchivePath '...' -ModelEndpoint 'http://127.0.0.1:1234' -Model '...'
```

The default `openai_compatible` transport posts to `/v1/chat/completions`. To
use LM Studio's native `/api/v1/chat` endpoint, pass
`-ModelTransport lm_studio_chat`. The native transport keeps the benchmark
messages unchanged, serializes their role/content structure into the endpoint's
string `input`, disables reasoning and storage, and records returned `stats` in
the run receipt.

The frozen V1 archive hash is pinned in the command-line engine by default.
