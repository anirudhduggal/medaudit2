import pytest
import asyncio
from medaudit.mcp_server import mcp

def test_mcp_tools_registered():
    """Verify that MCP tools are registered correctly."""
    tools = asyncio.run(mcp.list_tools())
    tool_names = [tool.name for tool in tools]
    
    assert "start_mock_server" in tool_names
    assert "stop_mock_server" in tool_names
    assert "start_fuzzer" in tool_names
    assert "send_hl7_payload" in tool_names
    assert "analyze_pcap" in tool_names
