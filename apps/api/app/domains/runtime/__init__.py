"""The Execution Runtime — the single, tenant-isolated egress for every Tool Call (AI_RUNTIME.md).

Bible tenet 3: the runtime is the *only* egress. Every Tool Call — REST today, MCP/SDK later —
funnels through one ordered pipeline (authenticate → resolve → policy → credential decrypt in memory
→ guarded outbound call → response normalization → mandatory audit). It is the *only* place in the
codebase where credential plaintext exists, and it exists there only in memory, only for the
duration of one outbound request. M1 implements the synchronous REST path for api_key/bearer/basic.
"""
