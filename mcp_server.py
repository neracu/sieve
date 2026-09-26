"""Launch the Security Guardian MCP server.

Stdio is the default. ``--http`` serves the same tools over streamable HTTP.
"""

from sieve.mcp.guardian import main

if __name__ == "__main__":
    main()
