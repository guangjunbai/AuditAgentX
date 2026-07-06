"""AuditAgentX MCP tool server.

The project uses this module as the authoritative MCP tool boundary for
verification. The in-process server is used by tests and the backend runtime;
`backend.mcp.stdio_server` can expose the same tools through the official MCP
SDK when that optional dependency is installed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from backend.agents.verification_tools import (
    read_code_context,
    run_heuristic_static_verifier,
    run_local_sast_replay,
)
from backend.skills.harness_tools import (
    extract_function,
    build_template_harness,
    run_harness,
)


class AuditMCPServer:
    """Small MCP-compatible tool registry for verifier tools."""

    server_name = "auditagentx-verification-mcp"

    def __init__(self) -> None:
        self._tools: dict[str, dict[str, Any]] = {
            "read_code_context": {
                "name": "read_code_context",
                "description": "Read nearby source code around a candidate finding.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_root": {"type": ["string", "null"]},
                        "radius": {"type": "integer", "default": 8},
                    },
                },
                "handler": self._read_code_context,
            },
            "run_sast_replay": {
                "name": "run_sast_replay",
                "description": "Replay lightweight SAST checks on the local code window.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate", "code_context"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_context": {"type": "object"},
                    },
                },
                "handler": self._run_sast_replay,
            },
            "verify_source_sink": {
                "name": "verify_source_sink",
                "description": "Run deterministic source-to-sink and false-positive checks.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate", "code_context"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_context": {"type": "object"},
                    },
                },
                "handler": self._verify_source_sink,
            },
            "build_evidence_chain": {
                "name": "build_evidence_chain",
                "description": "Build a structured evidence chain from MCP tool outputs.",
                "input_schema": {
                    "type": "object",
                    "required": ["heuristic_result", "sast_replay", "tool_calls"],
                    "properties": {
                        "heuristic_result": {"type": "object"},
                        "sast_replay": {"type": "object"},
                        "tool_calls": {"type": "array"},
                    },
                },
                "handler": self._build_evidence_chain,
            },
            "extract_target_function": {
                "name": "extract_target_function",
                "description": "Extract the vulnerable function source around a finding for harness building.",
                "input_schema": {
                    "type": "object",
                    "required": ["candidate"],
                    "properties": {
                        "candidate": {"type": "object"},
                        "code_root": {"type": ["string", "null"]},
                    },
                },
                "handler": self._extract_target_function,
            },
            "generate_fuzzing_harness": {
                "name": "generate_fuzzing_harness",
                "description": "Generate a template-based mock fuzzing harness for a vulnerability type (offline fallback).",
                "input_schema": {
                    "type": "object",
                    "required": ["vuln_type"],
                    "properties": {
                        "vuln_type": {"type": "string"},
                        "code_snippet": {"type": ["string", "null"]},
                    },
                },
                "handler": self._generate_fuzzing_harness,
            },
            "run_fuzzing_harness": {
                "name": "run_fuzzing_harness",
                "description": "Execute a Python fuzzing harness in a sandbox and report whether the vulnerability was triggered.",
                "input_schema": {
                    "type": "object",
                    "required": ["harness_code"],
                    "properties": {
                        "harness_code": {"type": "string"},
                        "timeout": {"type": ["integer", "null"]},
                    },
                },
                "handler": self._run_fuzzing_harness,
            },
        }

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP-style tool descriptors without Python callables."""
        return [
            {key: value for key, value in tool.items() if key != "handler"}
            for tool in self._tools.values()
        ]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call one registered tool and return MCP-style structured content."""
        tool = self._tools.get(name)
        if not tool:
            available = ", ".join(sorted(self._tools))
            raise ValueError(f"Unknown MCP tool '{name}'. Available tools: {available}")
        handler: Callable[[dict[str, Any]], dict[str, Any]] = tool["handler"]
        result = handler(arguments)
        return {
            "content": [{"type": "text", "text": f"{name} completed"}],
            "structuredContent": result,
        }

    @staticmethod
    def _read_code_context(arguments: dict[str, Any]) -> dict[str, Any]:
        code_root = arguments.get("code_root")
        return read_code_context(
            arguments.get("candidate") or {},
            Path(code_root) if code_root else None,
            radius=int(arguments.get("radius") or 8),
        )

    @staticmethod
    def _run_sast_replay(arguments: dict[str, Any]) -> dict[str, Any]:
        return run_local_sast_replay(
            arguments.get("candidate") or {},
            arguments.get("code_context") or {},
        )

    @staticmethod
    def _verify_source_sink(arguments: dict[str, Any]) -> dict[str, Any]:
        return run_heuristic_static_verifier(
            arguments.get("candidate") or {},
            arguments.get("code_context") or {},
        )

    @staticmethod
    def _build_evidence_chain(arguments: dict[str, Any]) -> dict[str, Any]:
        heuristic = arguments.get("heuristic_result") or {}
        return {
            "tool_calls": arguments.get("tool_calls") or [],
            "call_path": heuristic.get("call_path") or [],
            "checks": heuristic.get("checks") or [],
            "sast_replay": arguments.get("sast_replay") or {},
        }

    @staticmethod
    def _extract_target_function(arguments: dict[str, Any]) -> dict[str, Any]:
        candidate = arguments.get("candidate") or {}
        code_root = arguments.get("code_root")
        return extract_function(
            Path(code_root) if code_root else None,
            candidate.get("file") or candidate.get("file_path"),
            candidate.get("start_line") or candidate.get("line"),
        )

    @staticmethod
    def _generate_fuzzing_harness(arguments: dict[str, Any]) -> dict[str, Any]:
        harness = build_template_harness(
            arguments.get("vuln_type"), arguments.get("code_snippet"))
        return {"harness_code": harness, "source": "template"}

    @staticmethod
    def _run_fuzzing_harness(arguments: dict[str, Any]) -> dict[str, Any]:
        return run_harness(
            arguments.get("harness_code") or "",
            timeout=arguments.get("timeout"),
        )
