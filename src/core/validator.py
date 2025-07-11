"""Data validation utilities for NAS Log Processing System."""

import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import structlog

logger = structlog.get_logger(__name__)


class DataValidator:
    """Validates extracted NAS log data according to configuration rules."""
    
    def __init__(self, validation_rules: Dict[str, Dict]):
        """
        Initialize validator with validation rules.
        
        Args:
            validation_rules: Dictionary of field validation rules
        """
        self.validation_rules = validation_rules
        self.validation_errors = []
        self.validation_warnings = []
    
    def validate_field(self, field_name: str, value: Any) -> bool:
        """
        Validate a single field value.
        
        Args:
            field_name: Name of the field to validate
            value: Value to validate
        
        Returns:
            True if validation passes, False otherwise
        """
        if field_name not in self.validation_rules:
            return True  # No validation rules for this field
        
        rules = self.validation_rules[field_name]
        
        # Check if field is required
        if rules.get("required", False) and not value:
            self.validation_errors.append(f"Required field '{field_name}' is empty")
            return False
        
        # Skip validation if value is empty and field is not required
        if not value and not rules.get("required", False):
            return True
        
        # Validate data type
        if "data_type" in rules:
            if not self._validate_data_type(value, rules["data_type"]):
                self.validation_errors.append(
                    f"Field '{field_name}' has invalid data type. Expected {rules['data_type']}, got {type(value).__name__}"
                )
                return False
        
        # Validate format
        if "format" in rules:
            if not self._validate_format(value, rules["format"]):
                self.validation_errors.append(
                    f"Field '{field_name}' has invalid format. Expected {rules['format']}"
                )
                return False
        
        # Validate allowed values
        if "allowed_values" in rules:
            if value not in rules["allowed_values"]:
                self.validation_errors.append(
                    f"Field '{field_name}' has invalid value '{value}'. Allowed: {rules['allowed_values']}"
                )
                return False
        
        # Validate range
        if "range" in rules:
            if not self._validate_range(value, rules["range"]):
                self.validation_errors.append(
                    f"Field '{field_name}' value '{value}' is outside allowed range {rules['range']}"
                )
                return False
        
        # Validate length
        if "length" in rules:
            if not self._validate_length(value, rules["length"]):
                self.validation_errors.append(
                    f"Field '{field_name}' has invalid length. Expected {rules['length']}, got {len(str(value))}"
                )
                return False
        
        # Validate minimum length
        if "min_length" in rules:
            if len(str(value)) < rules["min_length"]:
                self.validation_errors.append(
                    f"Field '{field_name}' is too short. Minimum length: {rules['min_length']}"
                )
                return False
        
        return True
    
    def _validate_data_type(self, value: Any, expected_type: str) -> bool:
        """Validate data type of a value."""
        if expected_type == "integer":
            try:
                int(value)
                return True
            except (ValueError, TypeError):
                return False
        elif expected_type == "string":
            return isinstance(value, str)
        elif expected_type == "float":
            try:
                float(value)
                return True
            except (ValueError, TypeError):
                return False
        return True
    
    def _validate_format(self, value: Any, format_type: str) -> bool:
        """Validate format of a value."""
        if format_type == "datetime":
            try:
                datetime.strptime(str(value), "%Y %b %d %H:%M:%S.%f")
                return True
            except ValueError:
                return False
        elif format_type == "ipv4":
            ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
            if not re.match(ipv4_pattern, str(value)):
                return False
            # Check each octet is in valid range
            octets = str(value).split('.')
            return all(0 <= int(octet) <= 255 for octet in octets)
        return True
    
    def _validate_range(self, value: Any, range_spec: List[int]) -> bool:
        """Validate value is within specified range."""
        try:
            num_value = int(value)
            return range_spec[0] <= num_value <= range_spec[1]
        except (ValueError, TypeError):
            return False
    
    def _validate_length(self, value: Any, expected_length: int) -> bool:
        """Validate length of a value."""
        return len(str(value)) == expected_length
    
    def validate_record(self, record: Dict[str, Any]) -> bool:
        """
        Validate a complete record.
        
        Args:
            record: Dictionary containing field-value pairs
        
        Returns:
            True if all fields pass validation
        """
        self.validation_errors = []
        self.validation_warnings = []
        
        all_valid = True
        for field_name, value in record.items():
            if not self.validate_field(field_name, value):
                all_valid = False
        
        if self.validation_errors:
            logger.warning(
                "Validation errors found",
                errors=self.validation_errors,
                record=record
            )
        
        return all_valid
    
    def get_validation_summary(self) -> Dict[str, Any]:
        """
        Get validation summary.
        
        Returns:
            Dictionary with validation statistics
        """
        return {
            "errors": self.validation_errors,
            "warnings": self.validation_warnings,
            "error_count": len(self.validation_errors),
            "warning_count": len(self.validation_warnings)
        }


def create_validator_from_config(config: Dict[str, Dict]) -> DataValidator:
    """
    Create a DataValidator instance from configuration.
    
    Args:
        config: Configuration dictionary with validation rules
    
    Returns:
        Configured DataValidator instance
    """
    validation_rules = {}
    
    for field_name, field_config in config.items():
        if "validation" in field_config:
            validation_rules[field_name] = field_config["validation"]
    
    return DataValidator(validation_rules) 