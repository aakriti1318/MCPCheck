"""
Adapters layer for MCPCheck.

Contains all infrastructure implementations: filesystem, HTTP, LLM, etc.
"""

from mcpcheck.adapters.fs import FileSystemAdapter
from mcpcheck.adapters.llm import LlmAdapter

__all__ = [
    "FileSystemAdapter",
    "LlmAdapter",
]
