import logging
import json
import uuid

from mcp.server.fastmcp import FastMCP

from medaudit.hl7server.hl7_mock_server import HL7Server
from medaudit.fuzzer.engine import run_fuzzing_job, parse_fuzzing_config
from medaudit.hl7server.hl7_client import HL7Client
from medaudit.web.analyzer import analyze_pcap_detailed

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("Medaudit")

# Global state to keep track of the mock server
_mock_server = None


@mcp.tool()
def start_mock_server(port: int = 2575) -> str:
    """Starts the Medaudit HL7 mock server on the specified port.
    
    Args:
        port: The port to listen on (default 2575).
    """
    global _mock_server
    if _mock_server is not None and _mock_server.running:
        return f"Mock server is already running on port {_mock_server.port}."
    
    try:
        _mock_server = HL7Server(host="0.0.0.0", port=port, verbose=False)
        _mock_server.start()
        return f"Started HL7 mock server on port {port}."
    except Exception as e:
        return f"Failed to start mock server: {str(e)}"


@mcp.tool()
def stop_mock_server() -> str:
    """Stops the Medaudit HL7 mock server if it is running."""
    global _mock_server
    if _mock_server is not None and _mock_server.running:
        _mock_server.stop()
        _mock_server = None
        return "Mock server stopped."
    return "Mock server is not running."


@mcp.tool()
def start_fuzzer(config_yaml: str) -> str:
    """Runs a fuzzing job using the provided YAML configuration.
    
    Args:
        config_yaml: YAML configuration string defining the fuzzing rules, target host, and port.
    """
    try:
        import threading
        config = parse_fuzzing_config(config_yaml, "yaml")
        job_id = f"mcp-fuzz-{uuid.uuid4().hex[:8]}"

        def _run():
            try:
                run_fuzzing_job(job_id=job_id, config=config)
            except Exception as e:
                logger.error(f"Fuzzer job {job_id} failed: {e}")

        thread = threading.Thread(target=_run, daemon=True)
        thread.start()
        return json.dumps({"job_id": job_id, "status": "started", "message": "Fuzzing job launched in background."})
    except Exception as e:
        return f"Failed to run fuzzer: {str(e)}"


@mcp.tool()
def send_hl7_payload(target_host: str, target_port: int, message: str, use_tls: bool = False) -> str:
    """Sends an HL7 payload to the target and returns the ACK.
    
    Args:
        target_host: Target hostname or IP.
        target_port: Target port.
        message: The raw HL7 message to send.
        use_tls: Whether to use TLS encryption (default False).
    """
    client = HL7Client(host=target_host, port=target_port, use_tls=use_tls, timeout=10, verbose=False)
    if not client.connect():
        return "Failed to connect to target."
    
    ack = client.send_message(message)
    client.disconnect()
    
    return ack if ack else "No response received."


@mcp.tool()
def analyze_pcap(filepath: str) -> str:
    """Analyzes a PCAP file for HL7 traffic, encryption status, and PII.
    
    Args:
        filepath: Absolute path to the PCAP file.
    """
    try:
        result = analyze_pcap_detailed(filepath)
        # Simplify the output by removing huge raw messages to avoid context overflow
        if result.get("success") and "hl7_messages" in result:
            for msg in result["hl7_messages"]:
                if "raw_message" in msg:
                    del msg["raw_message"]

        def _default_serializer(obj):
            """Convert non-serializable types like sets to JSON-safe equivalents."""
            if isinstance(obj, set):
                return sorted(list(obj))
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")

        return json.dumps(result, indent=2, default=_default_serializer)
    except Exception as e:
        return f"Failed to analyze PCAP: {str(e)}"

if __name__ == "__main__":
    # Start the MCP stdio server
    mcp.run()
