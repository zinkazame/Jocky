"""
JOCKY Parsing Layer — v1.0
Turns raw binary forensic artifacts into structured JSON evidence.

All parsers follow the envelope schema:
  {
    "jocky_version": "1.0",
    "artifact": "<name>",
    "parser": "<module_name>",
    "parsed_at": "<ISO-8601>",
    "source_file": "<relative path to raw file>",
    "source_sha256": "<sha256 of raw file>",
    "record_count": <int>,
    "records": [ ... ]
  }
"""

__version__ = "1.0"
JOCKY_VERSION = "1.0"
