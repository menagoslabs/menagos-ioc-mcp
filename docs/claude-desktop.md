# Claude Desktop integration

This server runs as an MCP subprocess over stdio. Claude Desktop spawns it, streams requests in, streams JSON responses out.

## Setup

1. Clone and install:
   ```bash
   git clone https://github.com/menagoslabs/menagos-ioc-mcp.git
   cd menagos-ioc-mcp
   cp .env.example .env
   # fill in VT_API_KEY, GREYNOISE_API_KEY, ABUSEIPDB_API_KEY
   make install-dev
   ```

2. Edit your Claude Desktop config.

   **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`

   **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

   Add an entry under `mcpServers`:
   ```json
   {
     "mcpServers": {
       "menagos-ioc": {
         "command": "python",
         "args": ["-m", "app", "--transport", "stdio"],
         "cwd": "C:/absolute/path/to/menagos-ioc-mcp",
         "env": {
           "VT_API_KEY": "...",
           "GREYNOISE_API_KEY": "...",
           "ABUSEIPDB_API_KEY": "..."
         }
       }
     }
   }
   ```

   You can instead omit the `env` block and rely on the `.env` file in `cwd`. If both are present, the explicit `env` block wins.

3. Restart Claude Desktop. The tool appears as `lookup_ioc` under the `menagos-ioc` server.

## Usage

Ask Claude something like:

> Look up 8.8.8.8 and tell me if it's clean.

> Is this hash known malicious? 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

Claude will invoke `lookup_ioc` and receive the normalized JSON verdict with per-source reports.

## Troubleshooting

- **Tool doesn't appear**: check `cwd` is an absolute path, check `python` is on `PATH` for the user that runs Claude Desktop, and look at Claude Desktop's MCP logs.
- **All providers return errors**: check that API keys in `.env` (or the explicit `env` block) are valid.
- **Slow responses**: lower `PROVIDER_TIMEOUT_S` in `.env` if the default (6s) is too generous for your environment.
