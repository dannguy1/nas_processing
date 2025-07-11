"""Tests for the NAS parser module."""

import pytest
import tempfile
import os
import re
from pathlib import Path
from src.core.parser import NASParser


class TestNASParser:
    """Test cases for NASParser class."""
    
    def test_parser_initialization(self):
        """Test parser initialization with default configuration."""
        parser = NASParser()
        assert parser is not None
        assert len(parser.fieldnames) > 0
        assert "timestamp" in parser.fieldnames
        assert "message_type" in parser.fieldnames
    
    def test_parser_with_custom_config(self):
        """Test parser initialization with custom configuration."""
        # Create a minimal test config
        test_config = {
            "timestamp": {
                "patterns": [r"^(\d{4} \w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\.\d{3})"],
                "validation": {"required": True}
            },
            "message_type": {
                "patterns": [r"LTE NAS [A-Z]+ [A-Z]+ (?:OTA )?(Incoming|Outgoing) Message\s+--\s+(.+?)(?: Msg)?$"],
                "validation": {"required": True}
            }
        }
        
        # Write test config to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(test_config, f)
            config_path = f.name
        
        try:
            parser = NASParser(config_path=config_path)
            assert parser is not None
            assert len(parser.fieldnames) == 2
            assert "timestamp" in parser.fieldnames
            assert "message_type" in parser.fieldnames
        finally:
            os.unlink(config_path)
    
    def test_parser_with_nonexistent_config(self):
        """Test parser initialization with nonexistent config file."""
        parser = NASParser(config_path="nonexistent_file.yaml")
        assert parser is not None
        # Should fall back to default configuration
        assert len(parser.fieldnames) > 0
    
    def test_compile_patterns(self):
        """Test pattern compilation."""
        parser = NASParser()
        assert "timestamp" in parser.compiled_patterns
        assert len(parser.compiled_patterns["timestamp"]) > 0
        assert isinstance(parser.compiled_patterns["timestamp"][0], type(re.compile("")))
    
    def test_extract_timestamp(self):
        """Test timestamp extraction."""
        parser = NASParser()
        
        # Valid timestamp
        line = "2024 Jan 15 10:30:45.123 LTE NAS EMM ESM OTA Incoming Message -- Attach request"
        timestamp = parser._extract_timestamp(line)
        assert timestamp == "2024 Jan 15 10:30:45.123"
        
        # Invalid timestamp
        line = "Invalid line without timestamp"
        timestamp = parser._extract_timestamp(line)
        assert timestamp is None
    
    def test_extract_message_info(self):
        """Test message information extraction."""
        parser = NASParser()
        
        # Valid message line
        line = "LTE NAS EMM ESM OTA Incoming Message -- Attach request"
        result = parser._extract_message_info(line)
        assert result is not None
        assert result[0] == "Incoming"
        assert result[1] == "Attach request"
        
        # Invalid message line
        line = "Invalid line without message info"
        result = parser._extract_message_info(line)
        assert result is None
    
    def test_parse_empty_file(self):
        """Test parsing empty file."""
        parser = NASParser()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write("")
            input_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            output_file = f.name
        
        try:
            stats = parser.parse_log(input_file, output_file)
            assert stats["total_lines"] == 0
            assert stats["messages_extracted"] == 0
            assert stats["validation_errors"] == 0
        finally:
            os.unlink(input_file)
            os.unlink(output_file)
    
    def test_parse_simple_log(self):
        """Test parsing a simple log with one message."""
        parser = NASParser()
        
        # Create test log content
        log_content = """2024 Jan 15 10:30:45.123 LTE NAS EMM ESM OTA Incoming Message -- Attach request
Bearer ID = 5
qci = 9
2024 Jan 15 10:30:46.456 LTE NAS EMM ESM OTA Outgoing Message -- Attach accept
Bearer ID = 5
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(log_content)
            input_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            output_file = f.name
        
        try:
            stats = parser.parse_log(input_file, output_file)
            assert stats["messages_extracted"] == 2
            assert stats["validation_errors"] == 0
            
            # Check output file exists and has content
            assert os.path.exists(output_file)
            with open(output_file, 'r') as f:
                content = f.read()
                assert "timestamp" in content
                assert "Attach request" in content
                assert "Attach accept" in content
        finally:
            os.unlink(input_file)
            os.unlink(output_file)
    
    def test_parse_nonexistent_file(self):
        """Test parsing nonexistent file raises appropriate error."""
        parser = NASParser()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            output_file = f.name
        
        try:
            with pytest.raises(FileNotFoundError):
                parser.parse_log("nonexistent_file.txt", output_file)
        finally:
            os.unlink(output_file)


if __name__ == "__main__":
    pytest.main([__file__]) 