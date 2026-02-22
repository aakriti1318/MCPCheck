"""
Filesystem adapter for MCPCheck.

Handles reading manifests, checking gitignore, and scanning auth stores.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class FileSystemAdapter:
    """
    Adapter for filesystem operations.

    All filesystem I/O in MCPCheck goes through this adapter,
    making it easy to mock for testing.
    """

    def __init__(self, base_path: Path | None = None) -> None:
        """
        Initialize the filesystem adapter.

        Args:
            base_path: Base path for relative file operations.
        """
        self.base_path = base_path or Path.cwd()

    def read_json(self, path: Path | str) -> dict[str, Any]:
        """
        Read and parse a JSON file.

        Args:
            path: Path to the JSON file.

        Returns:
            Parsed JSON data.

        Raises:
            FileNotFoundError: If file doesn't exist.
            json.JSONDecodeError: If file isn't valid JSON.
        """
        path = self._resolve_path(path)
        content = path.read_text(encoding="utf-8")
        return json.loads(content)

    def read_text(self, path: Path | str) -> str:
        """
        Read a text file.

        Args:
            path: Path to the file.

        Returns:
            File contents.
        """
        path = self._resolve_path(path)
        return path.read_text(encoding="utf-8")

    def exists(self, path: Path | str) -> bool:
        """Check if a path exists."""
        return self._resolve_path(path).exists()

    def is_file(self, path: Path | str) -> bool:
        """Check if path is a file."""
        return self._resolve_path(path).is_file()

    def is_dir(self, path: Path | str) -> bool:
        """Check if path is a directory."""
        return self._resolve_path(path).is_dir()

    def glob(self, pattern: str) -> list[Path]:
        """
        Find files matching a glob pattern.

        Args:
            pattern: Glob pattern (e.g., "**/*.json").

        Returns:
            List of matching paths.
        """
        return list(self.base_path.glob(pattern))

    def find_manifests(self, directory: Path | str | None = None) -> list[Path]:
        """
        Find MCP manifest files in a directory.

        Searches for common manifest patterns:
        - mcp.json
        - mcp-config.json
        - claude_desktop_config.json
        - .cursor/mcp.json

        Args:
            directory: Directory to search (defaults to base_path).

        Returns:
            List of found manifest paths.
        """
        directory = self._resolve_path(directory) if directory else self.base_path

        patterns = [
            "mcp.json",
            "mcp-config.json",
            "**/mcp.json",
            "**/.cursor/mcp.json",
            "**/claude_desktop_config.json",
        ]

        found: list[Path] = []
        for pattern in patterns:
            found.extend(directory.glob(pattern))

        return list(set(found))  # Deduplicate

    def is_gitignored(self, path: Path | str) -> bool:
        """
        Check if a path is in .gitignore.

        This is a simple implementation that checks if the path
        or its patterns exist in .gitignore files.

        Args:
            path: Path to check.

        Returns:
            True if the path is gitignored.
        """
        path = self._resolve_path(path)

        # Find .gitignore files
        gitignore_paths = [
            self.base_path / ".gitignore",
            path.parent / ".gitignore",
        ]

        patterns_to_check = [
            path.name,
            str(path.relative_to(self.base_path)) if path.is_relative_to(self.base_path) else str(path),
        ]

        for gitignore_path in gitignore_paths:
            if gitignore_path.exists():
                content = gitignore_path.read_text(encoding="utf-8")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    for pattern in patterns_to_check:
                        if line == pattern or line == f"/{pattern}" or line == f"{pattern}/":
                            return True

                        # Simple glob matching
                        if "*" in line:
                            import fnmatch
                            if fnmatch.fnmatch(pattern, line):
                                return True

        return False

    def find_auth_stores(self) -> list[tuple[Path, str]]:
        """
        Find common auth store locations.

        Returns:
            List of (path, store_type) tuples.
        """
        stores: list[tuple[Path, str]] = []

        common_locations = [
            (".env", "dotenv"),
            (".env.local", "dotenv"),
            (".env.production", "dotenv"),
            (".cursor/mcp.json", "cursor"),
            ("claude_desktop_config.json", "claude"),
            (".mcp-auth", "mcp"),
            ("secrets.json", "generic"),
            ("credentials.json", "generic"),
        ]

        home = Path.home()
        home_locations = [
            (".cursor/mcp.json", "cursor"),
            ("Library/Application Support/Claude/claude_desktop_config.json", "claude"),
            (".config/claude/config.json", "claude"),
        ]

        # Check workspace locations
        for filename, store_type in common_locations:
            path = self.base_path / filename
            if path.exists():
                stores.append((path, store_type))

        # Check home directory locations
        for filename, store_type in home_locations:
            path = home / filename
            if path.exists():
                stores.append((path, store_type))

        return stores

    def _resolve_path(self, path: Path | str) -> Path:
        """Resolve a path relative to base_path."""
        if isinstance(path, str):
            path = Path(path)

        if path.is_absolute():
            return path

        return self.base_path / path
