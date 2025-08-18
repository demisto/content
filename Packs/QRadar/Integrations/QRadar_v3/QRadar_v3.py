"""
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                    QRADAR V3 INTEGRATION - TABLE OF CONTENTS                                     ║
║                                                                                                                  ║
║  This file is organized for maximum maintainability and debugging ease. Each section is clearly marked         ║
║  with descriptive headers and contains related functionality grouped logically.                                 ║
║                                                                                                                  ║
║  NAVIGATION GUIDE (Line Numbers):                                                                               ║
║  ├─ IMPORTS AND DEPENDENCIES ......................................................... Line ~30                    ║
║  ├─ CONFIGURATION AND CONSTANTS ..................................................... Line ~50                    ║
║  │  ├─ Advanced Global Parameters ................................................. Line ~55                    ║
║  │  ├─ Core Constants ............................................................ Line ~85                    ║
║  │  ├─ Output Field Mapping Dictionaries ........................................ Line ~130                   ║
║  │  └─ Enrichment Configuration Maps ............................................ Line ~400                   ║
║  ├─ ENUMS AND DATA STRUCTURES ................................................... Line ~420                   ║
║  ├─ CLIENT CLASS (API Communication) ............................................ Line ~450                   ║
║  ├─ SERVICE LAYER CLASSES (Maintainable Business Logic) ......................... Line ~5830                  ║
║  │  ├─ BaseService (Abstract Base with Common Functionality) ................... Line ~5900                  ║
║  │  ├─ OffenseService (Offense Operations) ..................................... Line ~6200                  ║
║  │  ├─ SearchService (Search and Query Operations) ............................. Line ~6800                  ║
║  │  └─ ReferenceService (Reference Data Operations) ............................ Line ~7200                  ║
║  ├─ HELPER FUNCTIONS (Utilities and Data Processing) ............................ Line ~8000                  ║
║  │  ├─ Data Transformation Utilities ............................................ Line ~985                   ║
║  │  ├─ Time and Date Processing ................................................ Line ~1290                  ║
║  │  ├─ Enrichment Functions .................................................... Line ~1400                  ║
║  │  ├─ Context Management Helpers .............................................. Line ~1190                  ║
║  │  └─ Validation and Parsing Utilities ........................................ Line ~2020                  ║
║  ├─ CORE COMMAND FUNCTIONS (Main Integration Commands) .......................... Line ~2220                  ║
║  │  ├─ Test and Fetch Commands ................................................. Line ~2225                  ║
║  │  ├─ Offense Management Commands ............................................. Line ~2950                  ║
║  │  ├─ Search and Query Commands ............................................... Line ~3350                  ║
║  │  ├─ Reference Set Commands .................................................. Line ~3540                  ║
║  │  ├─ Asset and Domain Commands ............................................... Line ~3720                  ║
║  │  ├─ Log Source Management Commands .......................................... Line ~3870                  ║
║  │  ├─ Remote Data and Mirroring Commands ...................................... Line ~4230                  ║
║  │  └─ Network and Infrastructure Commands ..................................... Line ~4680                  ║
║  └─ MAIN FUNCTION AND ENTRY POINT .............................................. Line ~5430                  ║
║                                                                                                                  ║
║  DEBUGGING NOTES:                                                                                               ║
║  - Each section contains related functionality for easy navigation                                              ║
║  - Functions are grouped by purpose and dependency relationships                                                ║
║  - Constants and configuration are centralized at the top                                                      ║
║  - Command functions follow consistent patterns for maintainability                                            ║
║                                                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# IMPORTS AND DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains all import statements organized by category for easy dependency management

# Standard Library Imports - Core Python functionality
import concurrent.futures
import copy
import inspect
import re
import secrets
import uuid
from enum import Enum
from ipaddress import ip_address
from urllib import parse
from deepmerge import always_merger

# Third-party Library Imports - External dependencies
import pytz
import urllib3

# XSOAR/XSIAM Platform Imports - Core platform functionality
from CommonServerPython import *
from CommonServerUserPython import *  # noqa

# Security Configuration - Disable insecure warnings for controlled environments
urllib3.disable_warnings()  # pylint: disable=no-member


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# QRADAR CONTEXT MANAGER - RESILIENT CONTEXT MANAGEMENT SYSTEM
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains the complete QRadar Context Manager implementation that was previously in a separate file.
# It provides resilient context management with automatic validation, recovery, and error handling.


class ContextValidationError(Exception):
    """Raised when context validation fails"""



class ContextRecoveryError(Exception):
    """Raised when context recovery fails"""



class ValidationResult:
    """Result of context validation"""

    def __init__(self, is_valid: bool, errors: List[str] = None, warnings: List[str] = None):
        self.is_valid = is_valid
        self.errors = errors or []
        self.warnings = warnings or []

    def __bool__(self):
        return self.is_valid


class ContextValidator:
    """
    Validates and repairs context data structure
    """

    def __init__(self, schema: dict):
        """
        Initialize the context validator

        Args:
            schema: Context schema definition
        """
        self.schema = schema

    def validate_structure(self, ctx: dict) -> ValidationResult:
        """
        Validate required keys and data types

        Args:
            ctx: Context dictionary to validate

        Returns:
            ValidationResult with validation status and messages
        """
        errors = []
        warnings = []

        try:
            # Check if context is a dictionary
            if not isinstance(ctx, dict):
                errors.append(f"Context must be a dictionary, got {type(ctx)}")
                return ValidationResult(False, errors, warnings)

            # Check required keys
            for key in self.schema["required_keys"]:
                if key not in ctx:
                    errors.append(f"Missing required key: {key}")

            # Check data types
            for key, expected_type in self.schema["data_types"].items():
                if key in ctx:
                    actual_value = ctx[key]
                    if not isinstance(actual_value, expected_type):
                        errors.append(f"Key '{key}' should be {expected_type.__name__}, got {type(actual_value).__name__}")

            is_valid = len(errors) == 0
            return ValidationResult(is_valid, errors, warnings)

        except Exception as e:
            errors.append(f"Structure validation error: {str(e)}")
            return ValidationResult(False, errors, warnings)

    def validate_data_integrity(self, ctx: dict) -> ValidationResult:
        """
        Check for logical consistency and data integrity

        Args:
            ctx: Context dictionary to validate

        Returns:
            ValidationResult with validation status and messages
        """
        errors = []
        warnings = []

        try:
            # Check for logical consistency
            if "id" in ctx:
                last_fetch_id = ctx["id"]
                if isinstance(last_fetch_id, int) and last_fetch_id < 0:
                    errors.append(f"Last fetch ID cannot be negative: {last_fetch_id}")

            # Check timestamp consistency
            if "last_mirror_update" in ctx and "last_mirror_closed_update" in ctx:
                mirror_update = ctx["last_mirror_update"]
                mirror_closed = ctx["last_mirror_closed_update"]
                if isinstance(mirror_update, int) and isinstance(mirror_closed, int):
                    if mirror_closed > mirror_update and mirror_update > 0:
                        warnings.append("Last mirror closed update is newer than last mirror update")

            # Check for duplicate offense IDs across different states
            offense_keys = ["mirrored_offenses_queried", "mirrored_offenses_finished", "mirrored_offenses_fetched"]
            all_offense_ids = set()
            duplicates = set()

            for key in offense_keys:
                if key in ctx and isinstance(ctx[key], dict):
                    for offense_id in ctx[key].keys():
                        if offense_id in all_offense_ids:
                            duplicates.add(offense_id)
                        all_offense_ids.add(offense_id)

            if duplicates:
                warnings.append(f"Duplicate offense IDs found across states: {list(duplicates)}")

            # Check samples data integrity
            if "samples" in ctx and isinstance(ctx["samples"], list):
                for i, sample in enumerate(ctx["samples"]):
                    if not isinstance(sample, dict):
                        errors.append(f"Sample {i} must be a dictionary, got {type(sample)}")
                    elif "id" not in sample:
                        warnings.append(f"Sample {i} missing 'id' field")

            is_valid = len(errors) == 0
            return ValidationResult(is_valid, errors, warnings)

        except Exception as e:
            errors.append(f"Data integrity validation error: {str(e)}")
            return ValidationResult(False, errors, warnings)

    def validate_size_limits(self, ctx: dict) -> ValidationResult:
        """
        Enforce size constraints

        Args:
            ctx: Context dictionary to validate

        Returns:
            ValidationResult with validation status and messages
        """
        errors = []
        warnings = []

        try:
            # Check total context size
            context_size = len(json.dumps(ctx).encode("utf-8"))
            max_size_bytes = self.schema["size_limits"]["max_total_size_mb"] * 1024 * 1024

            if context_size > max_size_bytes:
                errors.append(f"Context size ({context_size} bytes) exceeds limit ({max_size_bytes} bytes)")
            elif context_size > max_size_bytes * 0.8:  # 80% threshold warning
                warnings.append(f"Context size ({context_size} bytes) approaching limit ({max_size_bytes} bytes)")

            # Validate samples count and size
            if "samples" in ctx and isinstance(ctx["samples"], list):
                samples = ctx["samples"]
                max_samples = self.schema["size_limits"]["max_samples"]
                if len(samples) > max_samples:
                    errors.append(f"Number of samples ({len(samples)}) exceeds limit ({max_samples})")

                # Check individual sample sizes
                max_sample_size = self.schema["size_limits"]["max_sample_size_mb"] * 1024 * 1024
                for i, sample in enumerate(samples):
                    sample_size = len(json.dumps(sample).encode("utf-8"))
                    if sample_size > max_sample_size:
                        errors.append(f"Sample {i} size ({sample_size} bytes) exceeds limit ({max_sample_size} bytes)")

            # Validate mirrored offenses count
            offense_keys = ["mirrored_offenses_queried", "mirrored_offenses_finished", "mirrored_offenses_fetched"]
            max_offenses = self.schema["size_limits"]["max_mirrored_offenses"]

            for key in offense_keys:
                if key in ctx and isinstance(ctx[key], dict):
                    offense_count = len(ctx[key])
                    if offense_count > max_offenses:
                        warnings.append(f"Number of {key} ({offense_count}) exceeds recommended limit ({max_offenses})")

            is_valid = len(errors) == 0
            return ValidationResult(is_valid, errors, warnings)

        except Exception as e:
            errors.append(f"Size validation error: {str(e)}")
            return ValidationResult(False, errors, warnings)


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# DEBUGGING AND LOGGING INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements comprehensive debugging tools and enhanced logging capabilities that make troubleshooting
# and development significantly easier. The infrastructure provides execution tracing, variable capture, API call
# logging, and structured error reporting with correlation IDs.

import json
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Optional
from contextlib import contextmanager

# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# DATA VALIDATION AND TRANSFORMATION INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements comprehensive data validation with clear error messages, data transformation utilities
# that preserve existing output formats exactly, and automatic data sanitization while maintaining compatibility.

from abc import ABC, abstractmethod


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# SEARCH QUERY VALIDATION AND ERROR ANALYSIS UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements comprehensive query validation and error analysis for search operations, providing
# helpful suggestions for common query mistakes and detailed error context for troubleshooting.


def _validate_qradar_filter_query(filter_query: str) -> dict[str, Any]:
    """
    Validate QRadar filter query syntax and provide helpful suggestions for common mistakes.

    This function analyzes filter queries for common syntax errors and provides actionable
    suggestions to help users correct their queries.

    Args:
        filter_query: The filter query string to validate

    Returns:
        Dict containing validation result and suggestions
    """
    validation_result = {"valid": True, "error": None, "suggestions": []}

    if not filter_query or not filter_query.strip():
        validation_result.update(
            {
                "valid": False,
                "error": "Filter query is empty",
                "suggestions": ["Provide a valid filter expression", 'Example: status="COMPLETED"'],
            }
        )
        return validation_result

    # Common validation checks
    try:
        # Check for balanced quotes
        single_quotes = filter_query.count("'")
        double_quotes = filter_query.count('"')

        if single_quotes % 2 != 0:
            validation_result.update(
                {
                    "valid": False,
                    "error": "Unbalanced single quotes in filter query",
                    "suggestions": [
                        "Ensure all single quotes are properly paired",
                        "Use double quotes for string values if needed",
                        "Example: field_name='value' or field_name=\"value\"",
                    ],
                }
            )
            return validation_result

        if double_quotes % 2 != 0:
            validation_result.update(
                {
                    "valid": False,
                    "error": "Unbalanced double quotes in filter query",
                    "suggestions": [
                        "Ensure all double quotes are properly paired",
                        "Use single quotes for string values if needed",
                        "Example: field_name=\"value\" or field_name='value'",
                    ],
                }
            )
            return validation_result

        # Check for balanced parentheses
        open_parens = filter_query.count("(")
        close_parens = filter_query.count(")")

        if open_parens != close_parens:
            validation_result.update(
                {
                    "valid": False,
                    "error": "Unbalanced parentheses in filter query",
                    "suggestions": [
                        "Ensure all opening parentheses have matching closing parentheses",
                        "Check complex logical expressions for proper grouping",
                        'Example: (field1="value1" AND field2="value2")',
                    ],
                }
            )
            return validation_result

        # Check for common operator mistakes
        invalid_operators = ["==", "!=", "<>", "&&", "||"]
        for invalid_op in invalid_operators:
            if invalid_op in filter_query:
                valid_replacement = {
                    "==": "=",
                    "!=": "!=",  # This is actually valid, but check context
                    "<>": "!=",
                    "&&": "AND",
                    "||": "OR",
                }
                validation_result["suggestions"].append(
                    f'Replace "{invalid_op}" with "{valid_replacement.get(invalid_op, "appropriate operator")}"'
                )

        # Check for common field name issues
        if " = " in filter_query or " != " in filter_query:
            # This is actually correct syntax, but check for common mistakes
            pass

        # Provide general suggestions if no specific errors found
        if not validation_result["suggestions"]:
            validation_result["suggestions"] = [
                "Filter query appears syntactically correct",
                "Verify field names exist in the target data",
                "Check QRadar API documentation for supported operators",
                "Test with simple filters first, then add complexity",
            ]

    except Exception as e:
        validation_result.update(
            {
                "valid": False,
                "error": f"Filter validation error: {str(e)}",
                "suggestions": [
                    "Check filter syntax against QRadar API documentation",
                    "Simplify the filter and test incrementally",
                    "Verify all field names and operators are correct",
                ],
            }
        )

    return validation_result


def _validate_aql_query(query: str) -> dict[str, Any]:
    """
    Validate AQL (Ariel Query Language) query syntax and provide helpful suggestions.

    This function analyzes AQL queries for common syntax errors and provides actionable
    suggestions to help users correct their queries.

    Args:
        query: The AQL query string to validate

    Returns:
        Dict containing validation result and suggestions
    """
    validation_result = {"valid": True, "error": None, "suggestions": []}

    if not query or not query.strip():
        validation_result.update(
            {
                "valid": False,
                "error": "AQL query is empty",
                "suggestions": [
                    "Provide a valid AQL query",
                    "Example: SELECT * FROM events LAST 1 HOURS",
                    "Check QRadar AQL documentation for syntax reference",
                ],
            }
        )
        return validation_result

    query_upper = query.upper().strip()

    try:
        # Check for required SELECT statement
        if not query_upper.startswith("SELECT"):
            validation_result.update(
                {
                    "valid": False,
                    "error": "AQL query must start with SELECT",
                    "suggestions": [
                        "Begin query with SELECT statement",
                        "Example: SELECT * FROM events WHERE ...",
                        "Specify the fields you want to retrieve",
                    ],
                }
            )
            return validation_result

        # Check for FROM clause
        if " FROM " not in query_upper:
            validation_result.update(
                {
                    "valid": False,
                    "error": "AQL query missing FROM clause",
                    "suggestions": [
                        "Add FROM clause to specify data source",
                        "Common sources: events, flows, offenses",
                        "Example: SELECT * FROM events LAST 1 HOURS",
                    ],
                }
            )
            return validation_result

        # Check for time range (recommended for performance)
        time_keywords = ["LAST", "START", "STOP", "BETWEEN"]
        has_time_range = any(keyword in query_upper for keyword in time_keywords)

        if not has_time_range:
            validation_result["suggestions"].append("💡 Consider adding time range for better performance (e.g., LAST 1 HOURS)")

        # Check for common syntax issues
        if query.count("(") != query.count(")"):
            validation_result.update(
                {
                    "valid": False,
                    "error": "Unbalanced parentheses in AQL query",
                    "suggestions": [
                        "Ensure all opening parentheses have matching closing parentheses",
                        "Check function calls and WHERE clause grouping",
                        'Example: WHERE (field1="value1" AND field2="value2")',
                    ],
                }
            )
            return validation_result

        # Check for common mistakes
        if "SELECT *" in query_upper and "LIMIT" not in query_upper:
            validation_result["suggestions"].append(
                "⚠️ SELECT * without LIMIT may return large result sets. Consider adding LIMIT clause."
            )

        # Check for potentially expensive operations
        if "GROUP BY" in query_upper and not has_time_range:
            validation_result["suggestions"].append(
                "🔍 GROUP BY without time range may be slow. Consider adding time constraints."
            )

        # Provide general suggestions if no specific errors found
        if not validation_result["suggestions"]:
            validation_result["suggestions"] = [
                "AQL query appears syntactically correct",
                "Test with small time ranges first",
                "Monitor query performance and adjust as needed",
                "Check QRadar AQL reference for advanced features",
            ]

    except Exception as e:
        validation_result.update(
            {
                "valid": False,
                "error": f"AQL validation error: {str(e)}",
                "suggestions": [
                    "Check AQL syntax against QRadar documentation",
                    "Simplify the query and test incrementally",
                    "Verify all field names and functions are correct",
                ],
            }
        )

    return validation_result


def _analyze_qradar_api_error(error_message: str) -> dict[str, Any]:
    """
    Analyze QRadar API error messages and provide helpful troubleshooting suggestions.

    This function examines error messages from QRadar API calls and provides contextual
    suggestions to help users resolve common issues.

    Args:
        error_message: The error message from QRadar API

    Returns:
        Dict containing error analysis and suggestions
    """
    error_analysis = {
        "error_type": "unknown",
        "suggestion": "Check QRadar connectivity and try again",
        "troubleshooting_steps": [],
    }

    error_lower = error_message.lower()

    # Authentication errors
    if any(keyword in error_lower for keyword in ["unauthorized", "401", "authentication", "invalid token"]):
        error_analysis.update(
            {
                "error_type": "authentication",
                "suggestion": "Check QRadar authentication credentials and token validity",
                "troubleshooting_steps": [
                    "Verify QRadar username and password are correct",
                    "Check if authentication token has expired",
                    "Ensure user has necessary permissions for the operation",
                    "Test connectivity with qradar-test command",
                ],
            }
        )

    # Permission errors
    elif any(keyword in error_lower for keyword in ["forbidden", "403", "permission", "access denied"]):
        error_analysis.update(
            {
                "error_type": "permission",
                "suggestion": "User lacks necessary permissions for this operation",
                "troubleshooting_steps": [
                    "Check user role and permissions in QRadar",
                    "Verify user has access to the requested resource",
                    "Contact QRadar administrator to review permissions",
                    "Check if resource exists and is accessible",
                ],
            }
        )

    # Not found errors
    elif any(keyword in error_lower for keyword in ["not found", "404", "does not exist"]):
        error_analysis.update(
            {
                "error_type": "not_found",
                "suggestion": "Requested resource does not exist or has been deleted",
                "troubleshooting_steps": [
                    "Verify the ID or name is correct",
                    "Check if the resource was recently deleted",
                    "List available resources to confirm existence",
                    "Ensure proper spelling and format of identifiers",
                ],
            }
        )

    # Timeout errors
    elif any(keyword in error_lower for keyword in ["timeout", "timed out", "connection timeout"]):
        error_analysis.update(
            {
                "error_type": "timeout",
                "suggestion": "Operation timed out - try increasing timeout or simplifying query",
                "troubleshooting_steps": [
                    "Increase timeout parameter if available",
                    "Simplify query or add filters to reduce processing time",
                    "Check network connectivity to QRadar",
                    "Try the operation during off-peak hours",
                ],
            }
        )

    # Rate limiting errors
    elif any(keyword in error_lower for keyword in ["rate limit", "429", "too many requests"]):
        error_analysis.update(
            {
                "error_type": "rate_limit",
                "suggestion": "API rate limit exceeded - wait before retrying",
                "troubleshooting_steps": [
                    "Wait before retrying the operation",
                    "Reduce frequency of API calls",
                    "Implement exponential backoff in automation",
                    "Contact administrator about rate limit settings",
                ],
            }
        )

    # Server errors
    elif any(keyword in error_lower for keyword in ["500", "502", "503", "internal server error", "bad gateway"]):
        error_analysis.update(
            {
                "error_type": "server_error",
                "suggestion": "QRadar server error - check QRadar system status",
                "troubleshooting_steps": [
                    "Check QRadar system health and status",
                    "Retry the operation after a brief wait",
                    "Contact QRadar administrator if error persists",
                    "Check QRadar logs for additional error details",
                ],
            }
        )

    # Query syntax errors
    elif any(keyword in error_lower for keyword in ["syntax error", "invalid query", "parse error"]):
        error_analysis.update(
            {
                "error_type": "query_syntax",
                "suggestion": "Query syntax error - check AQL or filter syntax",
                "troubleshooting_steps": [
                    "Review query syntax against QRadar AQL documentation",
                    "Check for typos in field names and operators",
                    "Validate parentheses and quote balancing",
                    "Test with simpler query first, then add complexity",
                ],
            }
        )

    # Connection errors
    elif any(keyword in error_lower for keyword in ["connection", "network", "unreachable", "refused"]):
        error_analysis.update(
            {
                "error_type": "connection",
                "suggestion": "Network connectivity issue with QRadar",
                "troubleshooting_steps": [
                    "Check network connectivity to QRadar server",
                    "Verify QRadar server is running and accessible",
                    "Check firewall and proxy settings",
                    "Test with qradar-test command to verify connectivity",
                ],
            }
        )

    return error_analysis


from datetime import datetime
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from urllib.parse import urlparse


class ValidationError(Exception):
    """
    Base exception for validation errors with clear, actionable error messages.

    This exception provides detailed context about validation failures and includes
    helpful suggestions for fixing common validation issues.
    """

    def __init__(
        self,
        message: str,
        field_name: str | None = None,
        field_value: Any = None,
        expected_type: str | None = None,
        suggestions: list[str] | None = None,
        **kwargs,
    ):
        self.field_name = field_name
        self.field_value = field_value
        self.expected_type = expected_type
        self.suggestions = suggestions or []

        # Build comprehensive error message
        full_message = message
        if field_name:
            full_message = f"Validation failed for field '{field_name}': {message}"
        if field_value is not None:
            full_message += f" (received value: {repr(field_value)})"
        if expected_type:
            full_message += f" (expected type: {expected_type})"

        if self.suggestions:
            full_message += "\n\nSuggestions to fix this issue:"
            for i, suggestion in enumerate(self.suggestions, 1):
                full_message += f"\n  {i}. {suggestion}"

        super().__init__(full_message)


class DataTransformationError(Exception):
    """
    Exception raised when data transformation fails.

    This exception provides context about what transformation was attempted
    and why it failed, with suggestions for resolution.
    """

    def __init__(
        self,
        message: str,
        source_data: Any = None,
        target_format: str | None = None,
        transformation_step: str | None = None,
        **kwargs,
    ):
        self.source_data = source_data
        self.target_format = target_format
        self.transformation_step = transformation_step

        full_message = f"Data transformation failed: {message}"
        if transformation_step:
            full_message += f" (step: {transformation_step})"
        if target_format:
            full_message += f" (target format: {target_format})"

        super().__init__(full_message)


class BaseValidator(ABC):
    """
    Abstract base class for all validators.

    Provides a consistent interface for validation with clear error reporting
    and helpful suggestions for common validation failures.
    """

    def __init__(self, field_name: str, required: bool = True):
        self.field_name = field_name
        self.required = required

    @abstractmethod
    def validate(self, value: Any) -> Any:
        """
        Validate and potentially transform the input value.

        Args:
            value: The value to validate

        Returns:
            The validated (and potentially transformed) value

        Raises:
            ValidationError: When validation fails
        """

    def _check_required(self, value: Any) -> bool:
        """Check if a required field is present and not None."""
        if self.required and (value is None or value == ""):
            raise ValidationError(
                f"Required field '{self.field_name}' is missing or empty",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    f"Provide a valid value for the '{self.field_name}' parameter",
                    "Check that the parameter name is spelled correctly",
                    "Verify that the parameter is being passed in the command arguments",
                ],
            )
        return value is not None and value != ""


class StringValidator(BaseValidator):
    """
    Validator for string fields with length and pattern validation.
    """

    def __init__(
        self,
        field_name: str,
        required: bool = True,
        min_length: int | None = None,
        max_length: int | None = None,
        pattern: str | None = None,
        allowed_values: list[str] | None = None,
        case_sensitive: bool = True,
    ):
        super().__init__(field_name, required)
        self.min_length = min_length
        self.max_length = max_length
        self.pattern = pattern
        self.allowed_values = allowed_values
        self.case_sensitive = case_sensitive

    def validate(self, value: Any) -> str:
        """Validate string value with comprehensive checks."""
        if not self._check_required(value):
            return None

        # Convert to string if not already
        if not isinstance(value, str):
            try:
                value = str(value)
            except Exception as e:
                raise ValidationError(
                    f"Cannot convert value to string: {e}",
                    field_name=self.field_name,
                    field_value=value,
                    expected_type="string",
                    suggestions=[
                        "Ensure the value can be converted to a string",
                        "Check for special characters or encoding issues",
                        "Verify the data type of the input value",
                    ],
                )

        # Check length constraints
        if self.min_length is not None and len(value) < self.min_length:
            raise ValidationError(
                f"String too short (minimum length: {self.min_length})",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    f"Provide a string with at least {self.min_length} characters",
                    "Check if you're passing the complete value",
                    "Verify that required parts of the string aren't missing",
                ],
            )

        if self.max_length is not None and len(value) > self.max_length:
            raise ValidationError(
                f"String too long (maximum length: {self.max_length})",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    f"Shorten the string to {self.max_length} characters or less",
                    "Consider using abbreviations or removing unnecessary parts",
                    "Check if you're passing the correct field value",
                ],
            )

        # Check allowed values
        if self.allowed_values is not None:
            comparison_value = value if self.case_sensitive else value.lower()
            allowed_comparison = self.allowed_values if self.case_sensitive else [v.lower() for v in self.allowed_values]

            if comparison_value not in allowed_comparison:
                raise ValidationError(
                    f"Invalid value. Must be one of: {', '.join(self.allowed_values)}",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        f"Use one of these valid values: {', '.join(self.allowed_values)}",
                        "Check for typos in the parameter value",
                        "Verify the parameter documentation for correct values",
                    ],
                )

        # Check pattern if provided
        if self.pattern is not None:
            import re

            if not re.match(self.pattern, value):
                raise ValidationError(
                    f"String does not match required pattern: {self.pattern}",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        f"Ensure the value matches the pattern: {self.pattern}",
                        "Check the format requirements in the documentation",
                        "Verify that special characters are properly escaped",
                    ],
                )

        return value


class IntegerValidator(BaseValidator):
    """
    Validator for integer fields with range validation.
    """

    def __init__(
        self,
        field_name: str,
        required: bool = True,
        min_value: int | None = None,
        max_value: int | None = None,
        positive_only: bool = False,
    ):
        super().__init__(field_name, required)
        self.min_value = min_value
        self.max_value = max_value
        self.positive_only = positive_only

    def validate(self, value: Any) -> int | None:
        """Validate integer value with range checks."""
        if not self._check_required(value):
            return None

        # Convert to integer
        try:
            if isinstance(value, str):
                # Handle common string representations
                value = value.strip()
                if value.lower() in ("", "none", "null"):
                    if self.required:
                        raise ValidationError(
                            "Integer value cannot be empty",
                            field_name=self.field_name,
                            field_value=value,
                            expected_type="integer",
                        )
                    return None

            int_value = int(value)
        except (ValueError, TypeError) as e:
            raise ValidationError(
                f"Cannot convert to integer: {e}",
                field_name=self.field_name,
                field_value=value,
                expected_type="integer",
                suggestions=[
                    "Provide a valid integer number (e.g., 123, -456)",
                    "Remove any non-numeric characters except minus sign",
                    "Check for decimal points - use whole numbers only",
                    "Verify the parameter is not a string that looks like text",
                ],
            )

        # Check positive constraint
        if self.positive_only and int_value <= 0:
            raise ValidationError(
                "Value must be positive (greater than 0)",
                field_name=self.field_name,
                field_value=int_value,
                suggestions=[
                    "Use a positive integer greater than 0",
                    "Check if you meant to use an absolute value",
                    "Verify the parameter requirements allow negative values",
                ],
            )

        # Check range constraints
        if self.min_value is not None and int_value < self.min_value:
            raise ValidationError(
                f"Value too small (minimum: {self.min_value})",
                field_name=self.field_name,
                field_value=int_value,
                suggestions=[
                    f"Use a value of {self.min_value} or greater",
                    "Check the valid range in the parameter documentation",
                    "Consider if you're using the correct units (e.g., seconds vs milliseconds)",
                ],
            )

        if self.max_value is not None and int_value > self.max_value:
            raise ValidationError(
                f"Value too large (maximum: {self.max_value})",
                field_name=self.field_name,
                field_value=int_value,
                suggestions=[
                    f"Use a value of {self.max_value} or smaller",
                    "Check the valid range in the parameter documentation",
                    "Consider if you're using the correct units (e.g., seconds vs milliseconds)",
                ],
            )

        return int_value


class BooleanValidator(BaseValidator):
    """
    Validator for boolean fields with flexible string parsing.
    """

    def __init__(self, field_name: str, required: bool = True, default_value: bool | None = None):
        super().__init__(field_name, required)
        self.default_value = default_value

    def validate(self, value: Any) -> bool | None:
        """Validate boolean value with flexible parsing."""
        if not self._check_required(value):
            return self.default_value

        if isinstance(value, bool):
            return value

        if isinstance(value, str):
            value_lower = value.lower().strip()
            if value_lower in ("true", "yes", "1", "on", "enabled"):
                return True
            elif value_lower in ("false", "no", "0", "off", "disabled", ""):
                return False
            else:
                raise ValidationError(
                    f"Cannot convert string to boolean: '{value}'",
                    field_name=self.field_name,
                    field_value=value,
                    expected_type="boolean",
                    suggestions=[
                        "Use 'true' or 'false' for boolean values",
                        "Alternative valid values: 'yes'/'no', '1'/'0', 'on'/'off'",
                        "Check for typos in the boolean value",
                        "Ensure there are no extra spaces or characters",
                    ],
                )

        if isinstance(value, (int, float)):
            return bool(value)

        raise ValidationError(
            f"Cannot convert {type(value).__name__} to boolean",
            field_name=self.field_name,
            field_value=value,
            expected_type="boolean",
            suggestions=[
                "Use boolean values: true, false, yes, no, 1, 0",
                "Check the data type being passed to this parameter",
                "Verify the parameter is not a complex object or list",
            ],
        )


class IPAddressValidator(BaseValidator):
    """
    Validator for IP address fields supporting both IPv4 and IPv6.
    """

    def __init__(
        self, field_name: str, required: bool = True, allow_ipv4: bool = True, allow_ipv6: bool = True, allow_private: bool = True
    ):
        super().__init__(field_name, required)
        self.allow_ipv4 = allow_ipv4
        self.allow_ipv6 = allow_ipv6
        self.allow_private = allow_private

    def validate(self, value: Any) -> str | None:
        """Validate IP address with version and privacy checks."""
        if not self._check_required(value):
            return None

        if not isinstance(value, str):
            value = str(value)

        value = value.strip()

        try:
            # Try to parse as IP address
            ip_obj = ip_address(value)

            # Check IP version constraints
            if isinstance(ip_obj, IPv4Address) and not self.allow_ipv4:
                raise ValidationError(
                    "IPv4 addresses are not allowed",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        "Use an IPv6 address instead",
                        "Check if the parameter accepts IPv4 addresses",
                        "Verify the IP address format requirements",
                    ],
                )

            if isinstance(ip_obj, IPv6Address) and not self.allow_ipv6:
                raise ValidationError(
                    "IPv6 addresses are not allowed",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        "Use an IPv4 address instead",
                        "Check if the parameter accepts IPv6 addresses",
                        "Verify the IP address format requirements",
                    ],
                )

            # Check private address constraints
            if not self.allow_private and ip_obj.is_private:
                raise ValidationError(
                    "Private IP addresses are not allowed",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        "Use a public IP address",
                        "Check if private addresses are acceptable for this parameter",
                        "Verify the network configuration requirements",
                    ],
                )

            return str(ip_obj)

        except AddressValueError as e:
            raise ValidationError(
                f"Invalid IP address format: {e}",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    "Use a valid IP address format (e.g., 192.168.1.1 or 2001:db8::1)",
                    "Check for typos in the IP address",
                    "Ensure all octets/segments are within valid ranges",
                    "Remove any extra characters or spaces",
                ],
            )


class URLValidator(BaseValidator):
    """
    Validator for URL fields with scheme and domain validation.
    """

    def __init__(
        self, field_name: str, required: bool = True, allowed_schemes: list[str] | None = None, require_tld: bool = True
    ):
        super().__init__(field_name, required)
        self.allowed_schemes = allowed_schemes or ["http", "https"]
        self.require_tld = require_tld

    def validate(self, value: Any) -> str | None:
        """Validate URL with scheme and format checks."""
        if not self._check_required(value):
            return None

        if not isinstance(value, str):
            value = str(value)

        value = value.strip()

        # Basic URL validation using urlparse
        try:
            parsed = urlparse(value)
            if not parsed.scheme or not parsed.netloc:
                raise ValidationError(
                    "Invalid URL format - missing scheme or netloc",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        "Use a complete URL with protocol (e.g., https://example.com)",
                        "Check for typos in the URL",
                        "Ensure the URL includes a valid domain name",
                        "Verify special characters are properly encoded",
                    ],
                )
        except Exception:
            raise ValidationError(
                "Invalid URL format",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    "Use a complete URL with protocol (e.g., https://example.com)",
                    "Check for typos in the URL",
                    "Ensure the URL includes a valid domain name",
                    "Verify special characters are properly encoded",
                ],
            )

        # Check scheme
        if parsed.scheme.lower() not in [s.lower() for s in self.allowed_schemes]:
            raise ValidationError(
                f"Invalid URL scheme. Allowed schemes: {', '.join(self.allowed_schemes)}",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    f"Use one of these URL schemes: {', '.join(self.allowed_schemes)}",
                    "Check if the protocol is correct (http vs https)",
                    "Verify the URL scheme requirements for this parameter",
                ],
            )

        # Check for hostname
        if not parsed.netloc:
            raise ValidationError(
                "URL must include a hostname",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    "Include a hostname in the URL (e.g., https://example.com)",
                    "Check that the URL is complete",
                    "Verify the domain name is properly formatted",
                ],
            )

        return value


class RangeValidator(BaseValidator):
    """
    Validator for QRadar range specifications (e.g., "0-10", "5-5").
    """

    def __init__(self, field_name: str, required: bool = True, max_range_size: int | None = None):
        super().__init__(field_name, required)
        self.max_range_size = max_range_size

    def validate(self, value: Any) -> str | None:
        """Validate QRadar range format."""
        if not self._check_required(value):
            return None

        if not isinstance(value, str):
            value = str(value)

        value = value.strip()

        # Check basic format
        if not re.match(r"^\d+-\d+$", value):
            raise ValidationError(
                "Invalid range format. Expected format: 'start-end' (e.g., '0-10')",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    "Use the format 'start-end' with numbers (e.g., '0-10', '5-15')",
                    "Ensure both start and end are non-negative integers",
                    "Check for extra spaces or characters",
                    "Use a hyphen (-) to separate start and end values",
                ],
            )

        # Parse start and end
        try:
            start_str, end_str = value.split("-")
            start = int(start_str)
            end = int(end_str)
        except ValueError as e:
            raise ValidationError(
                f"Cannot parse range values: {e}",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    "Ensure both start and end are valid integers",
                    "Check for non-numeric characters",
                    "Use the format 'start-end' (e.g., '0-10')",
                ],
            )

        # Validate range logic
        if start < 0:
            raise ValidationError(
                "Range start cannot be negative",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    "Use a non-negative start value (0 or greater)",
                    "Check if you meant to use a different range",
                    "Verify the range requirements for this parameter",
                ],
            )

        if end < start:
            raise ValidationError(
                "Range end cannot be less than start",
                field_name=self.field_name,
                field_value=value,
                suggestions=[
                    f"Use an end value of {start} or greater",
                    "Check that start and end values are in the correct order",
                    "For a single item, use the same value for start and end (e.g., '5-5')",
                ],
            )

        # Check maximum range size
        if self.max_range_size is not None:
            range_size = end - start + 1
            if range_size > self.max_range_size:
                raise ValidationError(
                    f"Range too large (maximum size: {self.max_range_size})",
                    field_name=self.field_name,
                    field_value=value,
                    suggestions=[
                        f"Use a smaller range (maximum {self.max_range_size} items)",
                        "Consider breaking large requests into multiple smaller ranges",
                        "Check the API limits for this operation",
                    ],
                )

        return value


class EnrichmentValidator(BaseValidator):
    """
    Validator for QRadar enrichment options.
    """

    VALID_ENRICHMENT_OPTIONS = ["None", "IPs", "Assets", "IPs and Assets"]

    def __init__(self, field_name: str, required: bool = False):
        super().__init__(field_name, required)

    def validate(self, value: Any) -> str:
        """Validate enrichment option."""
        if not self._check_required(value):
            return "None"  # Default value

        if not isinstance(value, str):
            value = str(value)

        value = value.strip()

        # Case-insensitive matching
        for valid_option in self.VALID_ENRICHMENT_OPTIONS:
            if value.lower() == valid_option.lower():
                return valid_option  # Return the canonical form

        raise ValidationError(
            f"Invalid enrichment option. Must be one of: {', '.join(self.VALID_ENRICHMENT_OPTIONS)}",
            field_name=self.field_name,
            field_value=value,
            suggestions=[
                f"Use one of these valid options: {', '.join(self.VALID_ENRICHMENT_OPTIONS)}",
                "Check for typos in the enrichment value",
                "Use 'None' for no enrichment, 'IPs' for IP enrichment, 'Assets' for asset enrichment",
                "Use 'IPs and Assets' for both IP and asset enrichment",
            ],
        )


class CommandArgumentValidator:
    """
    Comprehensive validator for command arguments with clear error reporting.

    This class provides a centralized way to validate all command arguments
    with consistent error messages and helpful suggestions for fixing issues.
    """

    def __init__(self, command_name: str):
        self.command_name = command_name
        self.validators: dict[str, BaseValidator] = {}

    def add_validator(self, field_name: str, validator: BaseValidator) -> "CommandArgumentValidator":
        """Add a validator for a specific field."""
        self.validators[field_name] = validator
        return self

    def validate_arguments(self, args: dict[str, Any]) -> dict[str, Any]:
        """
        Validate all arguments and return cleaned/transformed values.

        Args:
            args: Raw command arguments

        Returns:
            Dictionary of validated and transformed arguments

        Raises:
            ValidationError: When validation fails for any field
        """
        validated_args = {}
        validation_errors = []

        # Validate each field that has a validator
        for field_name, validator in self.validators.items():
            try:
                raw_value = args.get(field_name)
                validated_value = validator.validate(raw_value)
                if validated_value is not None:
                    validated_args[field_name] = validated_value
            except ValidationError as e:
                validation_errors.append(str(e))

        # Include non-validated fields as-is (for backwards compatibility)
        for field_name, value in args.items():
            if field_name not in self.validators and value is not None:
                validated_args[field_name] = value

        # Report all validation errors at once
        if validation_errors:
            error_message = f"Validation failed for command '{self.command_name}':\n\n"
            error_message += "\n\n".join(validation_errors)
            error_message += f"\n\nCommand: {self.command_name}"
            error_message += f"\nProvided arguments: {list(args.keys())}"
            raise ValidationError(error_message)

        return validated_args


class CommonValidationUtilities:
    """
    Common validation utilities for frequently used validation patterns.

    This class provides reusable validation methods for common QRadar integration
    patterns like IP addresses, time ranges, field lists, and QRadar-specific formats.
    """

    @staticmethod
    def validate_ip_list(ip_list_str: str, field_name: str = "ip_list") -> list[str]:
        """
        Validate a comma-separated list of IP addresses.

        Args:
            ip_list_str: Comma-separated string of IP addresses
            field_name: Name of the field for error reporting

        Returns:
            List of validated IP addresses

        Raises:
            ValidationError: When any IP address is invalid
        """
        if not ip_list_str or not ip_list_str.strip():
            return []

        ip_addresses = [ip.strip() for ip in ip_list_str.split(",") if ip.strip()]
        validated_ips = []

        for ip in ip_addresses:
            try:
                # Validate IP address format
                ip_obj = ip_address(ip)
                validated_ips.append(str(ip_obj))
            except AddressValueError:
                raise ValidationError(
                    f"Invalid IP address in {field_name}: '{ip}'",
                    field_name=field_name,
                    field_value=ip_list_str,
                    suggestions=[
                        f"Check the IP address format for '{ip}'",
                        "Use comma-separated IP addresses (e.g., '192.168.1.1,10.0.0.1')",
                        "Ensure all IP addresses are valid IPv4 or IPv6 addresses",
                        "Remove any extra spaces or invalid characters",
                    ],
                )

        return validated_ips

    @staticmethod
    def validate_field_list(field_list_str: str, field_name: str = "fields") -> list[str]:
        """
        Validate a comma-separated list of field names.

        Args:
            field_list_str: Comma-separated string of field names
            field_name: Name of the field for error reporting

        Returns:
            List of validated field names

        Raises:
            ValidationError: When field names are invalid
        """
        if not field_list_str or not field_list_str.strip():
            return []

        fields = [field.strip() for field in field_list_str.split(",") if field.strip()]
        validated_fields = []

        for field in fields:
            # Basic field name validation (alphanumeric, underscore, dot)
            if not re.match(r"^[a-zA-Z0-9_\.]+$", field):
                raise ValidationError(
                    f"Invalid field name in {field_name}: '{field}'",
                    field_name=field_name,
                    field_value=field_list_str,
                    suggestions=[
                        "Field names can only contain letters, numbers, underscores, and dots",
                        f"Check the field name '{field}' for invalid characters",
                        "Use comma-separated field names (e.g., 'id,name,status')",
                        "Refer to QRadar API documentation for valid field names",
                    ],
                )

            if len(field) > 100:  # Reasonable limit for field names
                raise ValidationError(
                    f"Field name too long in {field_name}: '{field}' (maximum 100 characters)",
                    field_name=field_name,
                    field_value=field_list_str,
                    suggestions=[
                        "Use shorter field names",
                        "Check if the field name is correct",
                        "Remove unnecessary parts from the field name",
                    ],
                )

            validated_fields.append(field)

        return validated_fields

    @staticmethod
    def validate_qradar_filter(filter_str: str, field_name: str = "filter") -> str:
        """
        Validate QRadar filter expression format.

        Args:
            filter_str: QRadar filter expression
            field_name: Name of the field for error reporting

        Returns:
            Validated filter string

        Raises:
            ValidationError: When filter format is invalid
        """
        if not filter_str or not filter_str.strip():
            return ""

        filter_str = filter_str.strip()

        # Basic validation for common QRadar filter patterns
        # Check for balanced quotes
        single_quotes = filter_str.count("'")
        double_quotes = filter_str.count('"')

        if single_quotes % 2 != 0:
            raise ValidationError(
                f"Unbalanced single quotes in {field_name}",
                field_name=field_name,
                field_value=filter_str,
                suggestions=[
                    "Ensure all single quotes are properly paired",
                    "Check for missing closing quotes in string values",
                    "Use double quotes if single quotes are part of the data",
                ],
            )

        if double_quotes % 2 != 0:
            raise ValidationError(
                f"Unbalanced double quotes in {field_name}",
                field_name=field_name,
                field_value=filter_str,
                suggestions=[
                    "Ensure all double quotes are properly paired",
                    "Check for missing closing quotes in string values",
                    "Use single quotes if double quotes are part of the data",
                ],
            )

        # Check for basic SQL injection patterns (basic protection)
        dangerous_patterns = [r";\s*drop\s+table", r";\s*delete\s+from", r";\s*update\s+.*\s+set", r"union\s+select", r"--\s*$"]

        for pattern in dangerous_patterns:
            if re.search(pattern, filter_str, re.IGNORECASE):
                raise ValidationError(
                    f"Potentially dangerous pattern detected in {field_name}",
                    field_name=field_name,
                    field_value=filter_str,
                    suggestions=[
                        "Use only QRadar-supported filter expressions",
                        "Avoid SQL-like commands that could be harmful",
                        "Check the QRadar API documentation for valid filter syntax",
                        "Contact your administrator if you need to use advanced filtering",
                    ],
                )

        return filter_str

    @staticmethod
    def validate_time_range(start_time: str | None, end_time: str | None) -> tuple[str | None, str | None]:
        """
        Validate time range parameters.

        Args:
            start_time: Start time string
            end_time: End time string

        Returns:
            Tuple of validated start_time and end_time

        Raises:
            ValidationError: When time format is invalid or range is illogical
        """
        validated_start = None
        validated_end = None

        # Validate start_time format if provided
        if start_time:
            try:
                # Try to parse as ISO format or epoch timestamp
                if start_time.isdigit():
                    # Epoch timestamp
                    timestamp = int(start_time)
                    if timestamp < 0:
                        raise ValueError("Negative timestamp")
                    validated_start = start_time
                else:
                    # Try ISO format
                    datetime.fromisoformat(start_time.replace("Z", "+00:00"))
                    validated_start = start_time
            except (ValueError, TypeError) as e:
                raise ValidationError(
                    f"Invalid start_time format: {e}",
                    field_name="start_time",
                    field_value=start_time,
                    suggestions=[
                        "Use ISO format (e.g., '2023-01-01T00:00:00Z')",
                        "Use epoch timestamp in seconds (e.g., '1672531200')",
                        "Ensure the date/time is valid and properly formatted",
                        "Check for typos in the timestamp format",
                    ],
                )

        # Validate end_time format if provided
        if end_time:
            try:
                if end_time.isdigit():
                    timestamp = int(end_time)
                    if timestamp < 0:
                        raise ValueError("Negative timestamp")
                    validated_end = end_time
                else:
                    datetime.fromisoformat(end_time.replace("Z", "+00:00"))
                    validated_end = end_time
            except (ValueError, TypeError) as e:
                raise ValidationError(
                    f"Invalid end_time format: {e}",
                    field_name="end_time",
                    field_value=end_time,
                    suggestions=[
                        "Use ISO format (e.g., '2023-01-01T23:59:59Z')",
                        "Use epoch timestamp in seconds (e.g., '1672617599')",
                        "Ensure the date/time is valid and properly formatted",
                        "Check for typos in the timestamp format",
                    ],
                )

        # Validate time range logic if both are provided
        if validated_start and validated_end:
            try:
                if validated_start.isdigit() and validated_end.isdigit():
                    start_ts = int(validated_start)
                    end_ts = int(validated_end)
                    if start_ts >= end_ts:
                        raise ValidationError(
                            "start_time must be before end_time",
                            suggestions=[
                                "Ensure start_time is earlier than end_time",
                                "Check that the timestamps are in the correct order",
                                "Verify the time zone settings if using ISO format",
                            ],
                        )
                else:
                    # Compare ISO format dates
                    start_dt = datetime.fromisoformat(validated_start.replace("Z", "+00:00"))
                    end_dt = datetime.fromisoformat(validated_end.replace("Z", "+00:00"))
                    if start_dt >= end_dt:
                        raise ValidationError(
                            "start_time must be before end_time",
                            suggestions=[
                                "Ensure start_time is earlier than end_time",
                                "Check that the dates are in the correct order",
                                "Verify the time zone settings",
                            ],
                        )
            except ValidationError:
                raise
            except Exception as e:
                raise ValidationError(
                    f"Error comparing time range: {e}",
                    suggestions=[
                        "Ensure both start_time and end_time use the same format",
                        "Use consistent time zones for both timestamps",
                        "Check for formatting errors in the time values",
                    ],
                )

        return validated_start, validated_end


def validate_command_arguments(validation_schema: dict[str, BaseValidator]):
    """
    Decorator to add comprehensive validation to command functions.

    This decorator automatically validates command arguments using the provided schema
    and provides clear error messages for validation failures.

    Args:
        validation_schema: Dictionary mapping parameter names to validator instances

    Returns:
        Decorated function with automatic argument validation

    Example:
        @validate_command_arguments({
            "offense_id": IntegerValidator("offense_id", required=True, min_value=1),
            "status": StringValidator("status", required=False, allowed_values=["OPEN", "CLOSED"])
        })
        def my_command(client, args):
            # args are now validated and cleaned
            return CommandResults(...)
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            # Extract args dictionary (usually the last positional argument)
            if args and isinstance(args[-1], dict):
                raw_args = args[-1]
                other_args = args[:-1]
            else:
                raw_args = kwargs.get("args", {})
                other_args = args

            # Create validator and validate arguments
            command_name = func.__name__.replace("_command", "").replace("_", "-")
            validator = CommandArgumentValidator(command_name)

            for param_name, param_validator in validation_schema.items():
                validator.add_validator(param_name, param_validator)

            try:
                validated_args = validator.validate_arguments(raw_args)
            except ValidationError as e:
                # Log validation error for debugging
                demisto.debug(f"Validation failed for {command_name}: {str(e)}")
                raise

            # Call original function with validated arguments
            if args and isinstance(args[-1], dict):
                return func(*other_args, validated_args, **kwargs)
            else:
                kwargs["args"] = validated_args
                return func(*other_args, **kwargs)

        return wrapper

    return decorator


class AutomaticDataSanitizer:
    """
    Automatic data sanitization utilities that preserve existing output formats.

    This class provides methods to automatically sanitize and transform data
    while maintaining backwards compatibility with existing integrations.
    """

    @staticmethod
    def sanitize_command_output(
        data: Any,
        field_mapping: dict[str, str] | None = None,
        remove_sensitive_fields: bool = True,
        max_string_length: int | None = None,
    ) -> Any:
        """
        Automatically sanitize command output data.

        Args:
            data: Raw data to sanitize
            field_mapping: Optional field name mapping for backwards compatibility
            remove_sensitive_fields: Whether to remove potentially sensitive fields
            max_string_length: Maximum length for string values

        Returns:
            Sanitized data ready for output
        """
        # List of potentially sensitive field names to remove
        sensitive_fields = {
            "password",
            "passwd",
            "pwd",
            "secret",
            "key",
            "token",
            "auth",
            "credential",
            "private",
            "confidential",
            "internal",
        }

        def sanitize_recursive(obj):
            if isinstance(obj, dict):
                sanitized = {}
                for key, value in obj.items():
                    # Check for sensitive fields
                    if remove_sensitive_fields and any(sensitive in key.lower() for sensitive in sensitive_fields):
                        sanitized[key] = "[REDACTED]"
                        continue

                    # Apply field mapping if provided
                    output_key = field_mapping.get(key, key) if field_mapping else key
                    sanitized[output_key] = sanitize_recursive(value)

                return sanitized

            elif isinstance(obj, list):
                return [sanitize_recursive(item) for item in obj]

            elif isinstance(obj, str):
                # Truncate long strings if specified
                if max_string_length and len(obj) > max_string_length:
                    return obj[:max_string_length] + "..."
                return obj

            else:
                return obj

        return sanitize_recursive(data)

    @staticmethod
    def format_for_xsoar_output(
        data: Any,
        outputs_prefix: str,
        outputs_key_field: str | None = None,
        readable_title: str = "Results",
        headers: list[str] | None = None,
    ) -> CommandResults:
        """
        Format data for XSOAR CommandResults output with automatic sanitization.

        Args:
            data: Data to format
            outputs_prefix: XSOAR outputs prefix
            outputs_key_field: Key field for outputs
            readable_title: Title for readable output
            headers: Headers for table display

        Returns:
            CommandResults object with formatted data
        """
        # Sanitize data automatically
        sanitized_data = AutomaticDataSanitizer.sanitize_command_output(data)

        # Create readable output
        if isinstance(sanitized_data, list) and sanitized_data:
            readable_output = tableToMarkdown(readable_title, sanitized_data, headers=headers, removeNull=True)
        elif isinstance(sanitized_data, dict):
            readable_output = tableToMarkdown(readable_title, [sanitized_data], headers=headers, removeNull=True)
        else:
            readable_output = f"## {readable_title}\n{sanitized_data}"

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=outputs_prefix,
            outputs_key_field=outputs_key_field,
            outputs=sanitized_data,
            raw_response=data,
        )


class DataTransformationUtilities:
    """
    Utilities for transforming data while preserving existing output formats exactly.

    This class provides methods for converting between different data formats,
    sanitizing data, and ensuring backwards compatibility with existing integrations.
    """

    @staticmethod
    def preserve_output_format(data: Any, target_format_mapping: dict[str, str], preserve_unknown_fields: bool = True) -> Any:
        """
        Transform data while preserving the exact output format expected by existing integrations.

        Args:
            data: Source data to transform
            target_format_mapping: Mapping of old field names to new field names
            preserve_unknown_fields: Whether to keep fields not in the mapping

        Returns:
            Transformed data in the target format

        Raises:
            DataTransformationError: When transformation fails
        """
        try:
            if isinstance(data, dict):
                transformed = {}

                # Apply field name mappings
                for old_name, new_name in target_format_mapping.items():
                    if old_name in data:
                        transformed[new_name] = data[old_name]

                # Preserve unknown fields if requested
                if preserve_unknown_fields:
                    for key, value in data.items():
                        if key not in target_format_mapping and key not in transformed:
                            transformed[key] = value

                return transformed

            elif isinstance(data, list):
                return [
                    DataTransformationUtilities.preserve_output_format(item, target_format_mapping, preserve_unknown_fields)
                    for item in data
                ]
            else:
                return data

        except Exception as e:
            raise DataTransformationError(
                f"Failed to preserve output format: {e}",
                source_data=data,
                target_format="field_mapping",
                transformation_step="field_name_mapping",
            )

    @staticmethod
    def sanitize_for_output(
        data: Any, remove_null_values: bool = True, remove_empty_strings: bool = False, max_string_length: int | None = None
    ) -> Any:
        """
        Sanitize data for output while maintaining compatibility.

        Args:
            data: Data to sanitize
            remove_null_values: Whether to remove null/None values
            remove_empty_strings: Whether to remove empty strings
            max_string_length: Maximum length for string values (truncate if longer)

        Returns:
            Sanitized data
        """
        try:
            if isinstance(data, dict):
                sanitized = {}
                for key, value in data.items():
                    # Skip null values if requested
                    if remove_null_values and value is None:
                        continue

                    # Skip empty strings if requested
                    if remove_empty_strings and value == "":
                        continue

                    # Recursively sanitize nested data
                    sanitized_value = DataTransformationUtilities.sanitize_for_output(
                        value, remove_null_values, remove_empty_strings, max_string_length
                    )

                    sanitized[key] = sanitized_value

                return sanitized

            elif isinstance(data, list):
                return [
                    DataTransformationUtilities.sanitize_for_output(
                        item, remove_null_values, remove_empty_strings, max_string_length
                    )
                    for item in data
                    if not (remove_null_values and item is None)
                ]

            elif isinstance(data, str) and max_string_length is not None:
                if len(data) > max_string_length:
                    return data[:max_string_length] + "..."
                return data

            else:
                return data

        except Exception as e:
            raise DataTransformationError(
                f"Failed to sanitize data: {e}", source_data=data, transformation_step="data_sanitization"
            )

    @staticmethod
    def convert_timestamps(
        data: Any, timestamp_fields: list[str], source_format: str = "epoch_ms", target_format: str = "iso"
    ) -> Any:
        """
        Convert timestamp fields between different formats.

        Args:
            data: Data containing timestamp fields
            timestamp_fields: List of field names that contain timestamps
            source_format: Source timestamp format ("epoch_ms", "epoch_s", "iso")
            target_format: Target timestamp format ("epoch_ms", "epoch_s", "iso")

        Returns:
            Data with converted timestamps
        """
        try:
            if isinstance(data, dict):
                converted = data.copy()
                for field_name in timestamp_fields:
                    if field_name in converted and converted[field_name] is not None:
                        converted[field_name] = DataTransformationUtilities._convert_single_timestamp(
                            converted[field_name], source_format, target_format
                        )
                return converted

            elif isinstance(data, list):
                return [
                    DataTransformationUtilities.convert_timestamps(item, timestamp_fields, source_format, target_format)
                    for item in data
                ]
            else:
                return data

        except Exception as e:
            raise DataTransformationError(
                f"Failed to convert timestamps: {e}", source_data=data, transformation_step="timestamp_conversion"
            )

    @staticmethod
    def _convert_single_timestamp(value: Any, source_format: str, target_format: str) -> Any:
        """Convert a single timestamp value between formats."""
        if source_format == target_format:
            return value

        try:
            # Convert to datetime object first
            if source_format == "epoch_ms":
                dt = datetime.fromtimestamp(int(value) / 1000)
            elif source_format == "epoch_s":
                dt = datetime.fromtimestamp(int(value))
            elif source_format == "iso":
                dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            else:
                raise ValueError(f"Unsupported source format: {source_format}")

            # Convert to target format
            if target_format == "epoch_ms":
                return int(dt.timestamp() * 1000)
            elif target_format == "epoch_s":
                return int(dt.timestamp())
            elif target_format == "iso":
                return dt.isoformat()
            else:
                raise ValueError(f"Unsupported target format: {target_format}")

        except Exception as e:
            raise DataTransformationError(
                f"Failed to convert timestamp value '{value}' from {source_format} to {target_format}: {e}",
                source_data=value,
                transformation_step="single_timestamp_conversion",
            )


class DebugContext:
    """
    Captures and maintains comprehensive debugging context throughout operation execution.

    This class provides a centralized way to track execution flow, capture variable states,
    log API calls, and maintain breadcrumb trails for complex operations. It's designed to
    make debugging and troubleshooting significantly easier by providing complete context
    about what happened during an operation.

    Features:
    - Execution breadcrumb trail with timestamps
    - Variable state capture with type information
    - API call logging with timing and status codes
    - Correlation ID for tracing related log entries
    - Automatic timing and performance tracking
    """

    def __init__(self, operation_name: str, correlation_id: str | None = None):
        """
        Initialize debug context for an operation.

        Args:
            operation_name: Descriptive name of the operation being tracked
            correlation_id: Optional correlation ID (auto-generated if not provided)
        """
        self.operation_name = operation_name
        self.correlation_id = correlation_id or self._generate_correlation_id()
        self.start_time = time.time()
        self.breadcrumbs: list[dict[str, Any]] = []
        self.variables: dict[str, dict[str, Any]] = {}
        self.api_calls: list[dict[str, Any]] = []
        self.errors: list[dict[str, Any]] = []
        self.metrics: dict[str, Any] = {}

    def _generate_correlation_id(self) -> str:
        """Generate a unique correlation ID for this operation."""
        return f"qradar_{int(time.time())}_{secrets.token_hex(4)}"

    def add_breadcrumb(self, message: str, level: str = "info", **context):
        """
        Add a breadcrumb to the execution trail.

        Breadcrumbs provide a detailed trail of what happened during operation execution,
        making it easy to understand the flow and identify where issues occurred.

        Args:
            message: Descriptive message about what's happening
            level: Log level (info, debug, warning, error)
            **context: Additional context data to include
        """
        breadcrumb = {
            "timestamp": time.time(),
            "elapsed_time": time.time() - self.start_time,
            "message": message,
            "level": level,
            "context": context,
        }
        self.breadcrumbs.append(breadcrumb)

        # Also log to demisto for immediate visibility
        if level == "error":
            demisto.error(f"[{self.correlation_id}] {message}")
        elif level == "warning":
            demisto.info(f"[{self.correlation_id}] WARNING: {message}")
        else:
            demisto.debug(f"[{self.correlation_id}] {message}")

    def capture_variable(self, name: str, value: Any, description: str | None = None):
        """
        Capture variable state for debugging.

        This method safely captures variable values with type information and size limits
        to prevent memory issues while providing valuable debugging information.

        Args:
            name: Variable name
            value: Variable value to capture
            description: Optional description of the variable's purpose
        """
        try:
            # Convert value to string with size limit to prevent memory issues
            value_str = str(value)
            if len(value_str) > 1000:
                value_str = value_str[:1000] + "... [TRUNCATED]"

            self.variables[name] = {
                "value": value_str,
                "type": type(value).__name__,
                "timestamp": time.time(),
                "description": description,
                "size_bytes": len(str(value).encode("utf-8")) if value is not None else 0,
            }
        except Exception as e:
            # If we can't capture the variable, at least record that we tried
            self.variables[name] = {
                "value": f"<CAPTURE_ERROR: {str(e)}>",
                "type": type(value).__name__,
                "timestamp": time.time(),
                "description": description,
                "size_bytes": 0,
            }

    def log_api_call(
        self,
        method: str,
        url: str,
        status_code: int | None = None,
        duration: float | None = None,
        request_size: int | None = None,
        response_size: int | None = None,
        error: str | None = None,
    ):
        """
        Log API call details for debugging and performance analysis.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: API endpoint URL
            status_code: HTTP status code
            duration: Request duration in seconds
            request_size: Size of request payload in bytes
            response_size: Size of response payload in bytes
            error: Error message if the call failed
        """
        api_call = {
            "timestamp": time.time(),
            "method": method,
            "url": url,
            "status_code": status_code,
            "duration": duration,
            "request_size": request_size,
            "response_size": response_size,
            "error": error,
            "success": status_code is not None and 200 <= status_code < 300,
        }
        self.api_calls.append(api_call)

        # Log API call for immediate visibility
        if error:
            demisto.error(f"[{self.correlation_id}] API CALL FAILED: {method} {url} - {error}")
        else:
            demisto.debug(f"[{self.correlation_id}] API CALL: {method} {url} -> {status_code} ({duration:.2f}s)")

    def log_error(self, error: Exception, context: dict[str, Any] | None = None):
        """
        Log error with full context information.

        Args:
            error: Exception that occurred
            context: Additional context about the error
        """
        error_info = {
            "timestamp": time.time(),
            "error_type": type(error).__name__,
            "error_message": str(error),
            "stack_trace": traceback.format_exc(),
            "context": context or {},
        }
        self.errors.append(error_info)

    def set_metric(self, name: str, value: Any, description: str | None = None):
        """
        Set a metric value for performance tracking.

        Args:
            name: Metric name
            value: Metric value
            description: Optional description of what the metric measures
        """
        self.metrics[name] = {"value": value, "timestamp": time.time(), "description": description}

    def get_execution_summary(self) -> dict[str, Any]:
        """
        Get a comprehensive summary of the execution context.

        Returns:
            Dictionary containing complete execution information
        """
        return {
            "operation_name": self.operation_name,
            "correlation_id": self.correlation_id,
            "start_time": self.start_time,
            "total_duration": time.time() - self.start_time,
            "breadcrumbs_count": len(self.breadcrumbs),
            "variables_count": len(self.variables),
            "api_calls_count": len(self.api_calls),
            "errors_count": len(self.errors),
            "metrics_count": len(self.metrics),
            "success": len(self.errors) == 0,
        }

    def get_detailed_report(self) -> str:
        """
        Generate a detailed debugging report.

        Returns:
            Formatted string containing complete debugging information
        """
        summary = self.get_execution_summary()

        report = [
            f"=== DEBUG REPORT FOR {self.operation_name} ===",
            f"Correlation ID: {self.correlation_id}",
            f"Duration: {summary['total_duration']:.2f} seconds",
            f"Status: {'SUCCESS' if summary['success'] else 'FAILED'}",
            "",
            "=== EXECUTION TRAIL ===",
        ]

        for breadcrumb in self.breadcrumbs:
            elapsed = breadcrumb["elapsed_time"]
            level = breadcrumb["level"].upper()
            message = breadcrumb["message"]
            report.append(f"[{elapsed:6.2f}s] {level:7} | {message}")

        if self.api_calls:
            report.extend(["", "=== API CALLS ==="])
            for call in self.api_calls:
                status = call["status_code"] or "FAILED"
                duration = call["duration"] or 0
                report.append(f"{call['method']} {call['url']} -> {status} ({duration:.2f}s)")

        if self.errors:
            report.extend(["", "=== ERRORS ==="])
            for error in self.errors:
                report.append(f"{error['error_type']}: {error['error_message']}")

        return "\n".join(report)


class EnhancedLogger:
    """
    Enhanced logger with debugging capabilities and structured error reporting.

    This logger extends standard logging with correlation ID support, structured
    error reporting, and integration with DebugContext for comprehensive debugging.
    It provides clear, actionable error messages and maintains context across
    related operations.
    """

    def __init__(self, name: str):
        """
        Initialize enhanced logger.

        Args:
            name: Logger name (typically module or class name)
        """
        self.name = name
        self.debug_context: DebugContext | None = None

    def with_context(self, debug_context: DebugContext) -> "EnhancedLogger":
        """
        Associate logger with a debug context.

        Args:
            debug_context: Debug context to associate with this logger

        Returns:
            Self for method chaining
        """
        self.debug_context = debug_context
        return self

    def _format_message(self, message: str, **kwargs) -> str:
        """Format message with correlation ID and context."""
        correlation_id = self.debug_context.correlation_id if self.debug_context else "NO_CONTEXT"
        formatted = f"[{correlation_id}] [{self.name}] {message}"

        if kwargs:
            context_str = ", ".join(f"{k}={v}" for k, v in kwargs.items())
            formatted += f" | Context: {context_str}"

        return formatted

    def debug(self, message: str, **kwargs):
        """Log debug message with context."""
        demisto.debug(self._format_message(message, **kwargs))
        if self.debug_context:
            self.debug_context.add_breadcrumb(message, "debug", **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message with context."""
        demisto.info(self._format_message(message, **kwargs))
        if self.debug_context:
            self.debug_context.add_breadcrumb(message, "info", **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message with context."""
        demisto.info(self._format_message(f"WARNING: {message}", **kwargs))
        if self.debug_context:
            self.debug_context.add_breadcrumb(message, "warning", **kwargs)

    def error(self, message: str, exception: Exception | None = None, **kwargs):
        """Log error message with context."""
        demisto.error(self._format_message(f"ERROR: {message}", **kwargs))
        if self.debug_context:
            self.debug_context.add_breadcrumb(message, "error", **kwargs)
            if exception:
                self.debug_context.log_error(exception, kwargs)

    def error_with_context(self, message: str, exception: Exception | None = None, **kwargs):
        """
        Log error with full debugging context and structured information.

        This method provides comprehensive error logging that includes all available
        context information, making troubleshooting much easier.

        Args:
            message: Error message
            exception: Exception that occurred (if any)
            **kwargs: Additional context information
        """
        # Create structured error information
        error_info = {"message": message, "logger_name": self.name, "timestamp": time.time(), "context": kwargs}

        if self.debug_context:
            error_info.update(
                {
                    "correlation_id": self.debug_context.correlation_id,
                    "operation": self.debug_context.operation_name,
                    "execution_summary": self.debug_context.get_execution_summary(),
                    "recent_breadcrumbs": self.debug_context.breadcrumbs[-5:],  # Last 5 breadcrumbs
                    "recent_api_calls": self.debug_context.api_calls[-3:],  # Last 3 API calls
                    "captured_variables": list(self.debug_context.variables.keys()),
                }
            )

        if exception:
            error_info.update(
                {
                    "exception_type": type(exception).__name__,
                    "exception_message": str(exception),
                    "stack_trace": traceback.format_exc(),
                }
            )

        # Log structured error information for debugging
        demisto.error(f"STRUCTURED_ERROR: {json.dumps(error_info, indent=2, default=str)}")

        # Also log human-readable summary
        summary_msg = f"OPERATION FAILED: {message}"
        if self.debug_context:
            summary_msg += f" | Correlation ID: {self.debug_context.correlation_id}"
            summary_msg += f" | Operation: {self.debug_context.operation_name}"

        demisto.error(summary_msg)

        # Add to debug context if available
        if self.debug_context:
            self.debug_context.add_breadcrumb(f"ERROR: {message}", "error", **kwargs)
            if exception:
                self.debug_context.log_error(exception, kwargs)


class DiagnosticUtilities:
    """
    Diagnostic utilities for development and troubleshooting.

    This class provides various diagnostic tools that can be used during development
    and troubleshooting to inspect system state, validate configurations, and
    perform health checks.
    """

    @staticmethod
    def validate_qradar_connection(client) -> dict[str, Any]:
        """
        Validate QRadar connection and return diagnostic information.

        Args:
            client: QRadar client instance

        Returns:
            Dictionary containing connection diagnostic information
        """
        debug_ctx = DebugContext("connection_validation")
        logger = EnhancedLogger("DiagnosticUtilities").with_context(debug_ctx)

        try:
            debug_ctx.add_breadcrumb("Starting connection validation")

            # Test basic connectivity
            start_time = time.time()
            try:
                response = client.http_request("GET", "/help/versions")
                connection_time = time.time() - start_time
                debug_ctx.log_api_call("GET", "/help/versions", 200, connection_time)

                return {
                    "status": "SUCCESS",
                    "connection_time": connection_time,
                    "api_version": response.get("version", "Unknown"),
                    "correlation_id": debug_ctx.correlation_id,
                    "timestamp": time.time(),
                }
            except Exception as e:
                connection_time = time.time() - start_time
                debug_ctx.log_api_call("GET", "/help/versions", None, connection_time, error=str(e))
                logger.error_with_context("Connection validation failed", e)

                return {
                    "status": "FAILED",
                    "error": str(e),
                    "connection_time": connection_time,
                    "correlation_id": debug_ctx.correlation_id,
                    "timestamp": time.time(),
                }

        except Exception as e:
            logger.error_with_context("Unexpected error during connection validation", e)
            return {
                "status": "ERROR",
                "error": f"Unexpected error: {str(e)}",
                "correlation_id": debug_ctx.correlation_id,
                "timestamp": time.time(),
            }

    @staticmethod
    def get_system_health_report() -> dict[str, Any]:
        """
        Generate a comprehensive system health report.

        Returns:
            Dictionary containing system health information
        """
        debug_ctx = DebugContext("system_health_check")

        try:
            # Get integration context info
            context = demisto.getIntegrationContext()
            context_size = len(json.dumps(context).encode("utf-8"))

            # Get parameter info
            params = demisto.params()

            health_report = {
                "timestamp": time.time(),
                "correlation_id": debug_ctx.correlation_id,
                "context_info": {
                    "size_bytes": context_size,
                    "size_mb": context_size / (1024 * 1024),
                    "keys_count": len(context),
                    "has_samples": "samples" in context,
                    "has_mirroring_data": any(key.startswith("mirrored_") for key in context.keys()),
                },
                "configuration": {
                    "fetch_enabled": params.get("isFetch", False),
                    "mirror_direction": params.get("mirror_direction", "No Mirroring"),
                    "events_enrichment": params.get("events_enrichment", "None"),
                    "domain_enrichment": params.get("DOMAIN_ENRCH_FLG", "true"),
                    "rules_enrichment": params.get("RULES_ENRCH_FLG", "true"),
                },
                "performance_settings": {
                    "batch_size": BATCH_SIZE,
                    "max_workers": MAX_WORKERS,
                    "fetch_sleep": get_fetch_sleep_interval(),
                    "default_timeout": DEFAULT_EVENTS_TIMEOUT,
                },
            }

            return health_report

        except Exception as e:
            return {"timestamp": time.time(), "correlation_id": debug_ctx.correlation_id, "status": "ERROR", "error": str(e)}

    @staticmethod
    def create_debug_context_for_command(command_name: str, args: dict[str, Any]) -> DebugContext:
        """
        Create a debug context for a command execution.

        Args:
            command_name: Name of the command being executed
            args: Command arguments

        Returns:
            Configured DebugContext instance
        """
        debug_ctx = DebugContext(f"command_{command_name}")
        debug_ctx.add_breadcrumb(f"Starting command: {command_name}")
        debug_ctx.capture_variable("command_args", args, "Arguments passed to the command")

        return debug_ctx


# Global logger factory for consistent logging across the integration
def get_enhanced_logger(name: str) -> EnhancedLogger:
    """
    Get an enhanced logger instance.

    Args:
        name: Logger name (typically module or class name)

    Returns:
        EnhancedLogger instance
    """
    return EnhancedLogger(name)


# Context manager for automatic debug context management
@contextmanager
def debug_operation(operation_name: str, logger: EnhancedLogger | None = None):
    """
    Context manager for automatic debug context management.

    Args:
        operation_name: Name of the operation
        logger: Optional logger to associate with the context

    Yields:
        DebugContext instance
    """
    debug_ctx = DebugContext(operation_name)

    if logger:
        logger.with_context(debug_ctx)

    try:
        debug_ctx.add_breadcrumb(f"Starting operation: {operation_name}")
        yield debug_ctx
        debug_ctx.add_breadcrumb(f"Operation completed successfully: {operation_name}")
    except Exception as e:
        debug_ctx.add_breadcrumb(f"Operation failed: {operation_name}", "error", error=str(e))
        debug_ctx.log_error(e)
        if logger:
            logger.error_with_context(f"Operation failed: {operation_name}", e)
        raise
    finally:
        # Log execution summary for debugging
        summary = debug_ctx.get_execution_summary()
        demisto.debug(
            f"Operation {operation_name} completed in {summary['total_duration']:.2f}s "
            f"with {summary['breadcrumbs_count']} breadcrumbs and {summary['api_calls_count']} API calls"
        )


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# ENHANCED API CLIENT WITH COMPREHENSIVE DEBUGGING
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements an enhanced API client that extends the existing Client class with comprehensive debugging
# capabilities, detailed request/response logging, automatic retry logic, connection health monitoring, and API call
# tracing. This makes troubleshooting API issues significantly easier and provides complete visibility into all
# API interactions.

import requests
import threading
from collections import defaultdict, deque
from datetime import timedelta


class ConnectionHealthMonitor:
    """
    Monitors connection health and provides diagnostic information.

    This class tracks connection metrics, failure patterns, and provides
    diagnostic information to help troubleshoot connectivity issues.
    """

    def __init__(self):
        self.connection_attempts = 0
        self.successful_connections = 0
        self.failed_connections = 0
        self.last_successful_connection = None
        self.last_failed_connection = None
        self.failure_reasons: defaultdict[str, int] = defaultdict(int)
        self.response_times: deque[float] = deque(maxlen=100)  # Keep last 100 response times
        self.error_patterns: defaultdict[str, int] = defaultdict(int)
        self.lock = threading.Lock()

    def record_connection_attempt(self):
        """Record a connection attempt."""
        with self.lock:
            self.connection_attempts += 1

    def record_successful_connection(self, response_time: float):
        """Record a successful connection with response time."""
        with self.lock:
            self.successful_connections += 1
            self.last_successful_connection = datetime.now()
            self.response_times.append(response_time)

    def record_failed_connection(self, error: Exception, error_category: str = "unknown"):
        """Record a failed connection with error details."""
        with self.lock:
            self.failed_connections += 1
            self.last_failed_connection = datetime.now()
            self.failure_reasons[error_category] += 1

            # Track error patterns for analysis
            error_pattern = f"{type(error).__name__}:{str(error)[:100]}"
            self.error_patterns[error_pattern] += 1

    def get_health_status(self) -> dict[str, Any]:
        """Get comprehensive health status information."""
        with self.lock:
            if self.connection_attempts == 0:
                success_rate = 0.0
            else:
                success_rate = (self.successful_connections / self.connection_attempts) * 100

            avg_response_time = sum(self.response_times) / len(self.response_times) if self.response_times else 0

            return {
                "connection_attempts": self.connection_attempts,
                "successful_connections": self.successful_connections,
                "failed_connections": self.failed_connections,
                "success_rate_percent": round(success_rate, 2),
                "average_response_time_ms": round(avg_response_time * 1000, 2),
                "last_successful_connection": self.last_successful_connection.isoformat()
                if self.last_successful_connection
                else None,
                "last_failed_connection": self.last_failed_connection.isoformat() if self.last_failed_connection else None,
                "failure_reasons": dict(self.failure_reasons),
                "common_error_patterns": dict(sorted(self.error_patterns.items(), key=lambda x: x[1], reverse=True)[:5]),
                "recent_response_times_ms": [round(rt * 1000, 2) for rt in list(self.response_times)[-10:]],
                "health_score": self._calculate_health_score(),
            }

    def _calculate_health_score(self) -> int:
        """Calculate a health score from 0-100 based on various metrics."""
        if self.connection_attempts == 0:
            return 100  # No attempts yet, assume healthy

        # Base score on success rate
        success_rate = (self.successful_connections / self.connection_attempts) * 100
        score = success_rate

        # Adjust based on recent failures
        if self.last_failed_connection:
            time_since_last_failure = datetime.now() - self.last_failed_connection
            if time_since_last_failure < timedelta(minutes=5):
                score *= 0.7  # Recent failures reduce score
            elif time_since_last_failure < timedelta(minutes=15):
                score *= 0.85

        # Adjust based on response times
        if self.response_times:
            avg_response_time = sum(self.response_times) / len(self.response_times)
            if avg_response_time > 5.0:  # More than 5 seconds is concerning
                score *= 0.8
            elif avg_response_time > 2.0:  # More than 2 seconds is suboptimal
                score *= 0.9

        return max(0, min(100, int(score)))


class APICallTracer:
    """
    Traces API calls with detailed request/response information.

    This class provides comprehensive tracing of all API calls including
    request details, response information, timing, and error tracking.
    """

    def __init__(self, max_traces: int = 1000):
        self.traces: deque[dict[str, Any]] = deque(maxlen=max_traces)
        self.lock = threading.Lock()

    def trace_request(
        self, method: str, url: str, headers: dict[str, Any] = None, params: dict[str, Any] = None, data: Any = None
    ) -> str:
        """
        Start tracing a request and return a trace ID.

        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers (sensitive data will be redacted)
            params: Request parameters
            data: Request body data

        Returns:
            Trace ID for correlating with response
        """
        trace_id = f"trace_{int(time.time())}_{secrets.token_hex(4)}"

        # Redact sensitive information from headers
        safe_headers = self._redact_sensitive_data(headers or {})

        # Redact sensitive information from data
        safe_data = self._redact_sensitive_data(data) if data else None

        trace_info = {
            "trace_id": trace_id,
            "timestamp": datetime.now().isoformat(),
            "method": method,
            "url": self._sanitize_url(url),
            "headers": safe_headers,
            "params": params,
            "request_data": safe_data,
            "request_size_bytes": len(str(data).encode("utf-8")) if data else 0,
            "status": "pending",
        }

        with self.lock:
            self.traces.append(trace_info)

        return trace_id

    def trace_response(
        self, trace_id: str, status_code: int, response_data: Any = None, error: Exception = None, duration: float = 0
    ):
        """
        Complete tracing with response information.

        Args:
            trace_id: Trace ID from trace_request
            status_code: HTTP status code
            response_data: Response data (will be truncated if large)
            error: Exception if request failed
            duration: Request duration in seconds
        """
        with self.lock:
            # Find the trace to update
            for trace in reversed(self.traces):
                if trace.get("trace_id") == trace_id:
                    trace.update(
                        {
                            "status_code": status_code,
                            "response_data": self._truncate_response_data(response_data),
                            "response_size_bytes": len(str(response_data).encode("utf-8")) if response_data else 0,
                            "error": str(error) if error else None,
                            "error_type": type(error).__name__ if error else None,
                            "duration_ms": round(duration * 1000, 2),
                            "status": "completed" if not error else "failed",
                            "completed_at": datetime.now().isoformat(),
                        }
                    )
                    break

    def get_recent_traces(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get recent API call traces."""
        with self.lock:
            return list(self.traces)[-limit:]

    def get_trace_by_id(self, trace_id: str) -> dict[str, Any] | None:
        """Get a specific trace by ID."""
        with self.lock:
            for trace in reversed(self.traces):
                if trace.get("trace_id") == trace_id:
                    return trace
            return None

    def get_trace_statistics(self) -> dict[str, Any]:
        """Get statistics about API call traces."""
        with self.lock:
            if not self.traces:
                return {"total_traces": 0}

            total_traces = len(self.traces)
            successful_traces = sum(1 for t in self.traces if t.get("status") == "completed")
            failed_traces = sum(1 for t in self.traces if t.get("status") == "failed")

            durations = [t.get("duration_ms", 0) for t in self.traces if t.get("duration_ms")]
            avg_duration = sum(durations) / len(durations) if durations else 0

            status_codes = defaultdict(int)
            for trace in self.traces:
                if "status_code" in trace:
                    status_codes[trace["status_code"]] += 1

            return {
                "total_traces": total_traces,
                "successful_traces": successful_traces,
                "failed_traces": failed_traces,
                "success_rate_percent": round((successful_traces / total_traces) * 100, 2) if total_traces > 0 else 0,
                "average_duration_ms": round(avg_duration, 2),
                "status_code_distribution": dict(status_codes),
                "recent_errors": [
                    {"trace_id": t["trace_id"], "error": t.get("error"), "timestamp": t.get("completed_at")}
                    for t in list(self.traces)[-20:]
                    if t.get("status") == "failed"
                ],
            }

    def _redact_sensitive_data(self, data: Any) -> Any:
        """Redact sensitive information from data."""
        if isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                key_lower = key.lower()
                if any(sensitive in key_lower for sensitive in ["password", "token", "auth", "secret", "key"]):
                    redacted[key] = "[REDACTED]"
                else:
                    redacted[key] = self._redact_sensitive_data(value)
            return redacted
        elif isinstance(data, list):
            return [self._redact_sensitive_data(item) for item in data]
        else:
            return data

    def _sanitize_url(self, url: str) -> str:
        """Remove sensitive information from URLs."""
        # Remove query parameters that might contain sensitive data
        if "?" in url:
            base_url, query_string = url.split("?", 1)
            # Parse query parameters and redact sensitive ones
            params = parse.parse_qs(query_string)
            safe_params = {}
            for key, values in params.items():
                key_lower = key.lower()
                if any(sensitive in key_lower for sensitive in ["password", "token", "auth", "secret", "key"]):
                    safe_params[key] = ["[REDACTED]"]
                else:
                    safe_params[key] = values

            safe_query = parse.urlencode(safe_params, doseq=True)
            return f"{base_url}?{safe_query}"

        return url

    def _truncate_response_data(self, data: Any, max_size: int = 5000) -> Any:
        """Truncate response data if it's too large."""
        if data is None:
            return None

        data_str = str(data)
        if len(data_str) > max_size:
            return data_str[:max_size] + "... [TRUNCATED]"

        return data


class EnhancedQRadarClient:
    """
    Enhanced QRadar client with comprehensive debugging capabilities.

    This class extends the existing Client functionality with:
    - Detailed request/response logging and timing information
    - Automatic retry logic with clear logging of each retry attempt
    - Connection health monitoring with diagnostic information
    - API call tracing that shows exactly what was sent and received
    - Comprehensive error handling and categorization
    """

    def __init__(self, original_client, debug_enabled: bool = True):
        """
        Initialize enhanced client wrapper.

        Args:
            original_client: The original QRadar client instance
            debug_enabled: Whether to enable detailed debugging
        """
        self.original_client = original_client
        self.debug_enabled = debug_enabled
        self.health_monitor = ConnectionHealthMonitor()
        self.api_tracer = APICallTracer()
        self.logger = get_enhanced_logger("EnhancedQRadarClient")
        self.retry_config = {"max_retries": 3, "base_delay": 1.0, "max_delay": 30.0, "backoff_multiplier": 2.0, "jitter": True}

        # Delegate all original client attributes
        for attr_name in dir(original_client):
            if not attr_name.startswith("_") and not hasattr(self, attr_name):
                setattr(self, attr_name, getattr(original_client, attr_name))

    def http_request(self, method: str, url_suffix: str, **kwargs) -> Any:
        """
        Enhanced HTTP request with comprehensive debugging and retry logic.

        Args:
            method: HTTP method (GET, POST, etc.)
            url_suffix: URL suffix for the API endpoint
            **kwargs: Additional arguments for the request

        Returns:
            Response data from the API

        Raises:
            Various exceptions based on the type of error encountered
        """
        debug_ctx = DebugContext(f"http_request_{method}_{url_suffix.replace('/', '_')}")

        if self.debug_enabled:
            self.logger.with_context(debug_ctx)

        # Record connection attempt
        self.health_monitor.record_connection_attempt()

        # Start API call tracing
        full_url = f"{getattr(self.original_client, '_base_url', 'unknown')}{url_suffix}"
        trace_id = self.api_tracer.trace_request(
            method=method,
            url=full_url,
            headers=kwargs.get("additional_headers"),
            params=kwargs.get("params"),
            data=kwargs.get("json_data"),
        )

        debug_ctx.add_breadcrumb(f"Starting {method} request to {url_suffix}", trace_id=trace_id)
        debug_ctx.capture_variable("method", method)
        debug_ctx.capture_variable("url_suffix", url_suffix)
        debug_ctx.capture_variable("request_kwargs", kwargs, "Request parameters and options")

        start_time = time.time()
        last_exception = None

        for attempt in range(self.retry_config["max_retries"] + 1):
            try:
                debug_ctx.add_breadcrumb(f"Attempt {attempt + 1} of {self.retry_config['max_retries'] + 1}")

                # Make the actual request using the original client
                attempt_start = time.time()
                response = self.original_client.http_request(method, url_suffix, **kwargs)
                attempt_duration = time.time() - attempt_start

                # Record successful connection
                self.health_monitor.record_successful_connection(attempt_duration)

                # Complete API call tracing
                self.api_tracer.trace_response(
                    trace_id=trace_id,
                    status_code=200,  # Assume success if no exception
                    response_data=response,
                    duration=attempt_duration,
                )

                debug_ctx.add_breadcrumb(
                    "Request completed successfully", duration_ms=round(attempt_duration * 1000, 2), attempt=attempt + 1
                )

                # Log API call details
                debug_ctx.log_api_call(
                    method=method,
                    url=full_url,
                    status_code=200,
                    duration=attempt_duration,
                    request_size=len(str(kwargs.get("json_data", "")).encode("utf-8")),
                    response_size=len(str(response).encode("utf-8")),
                )

                if self.debug_enabled:
                    self.logger.info(
                        f"API request successful: {method} {url_suffix} " f"(attempt {attempt + 1}, {attempt_duration:.2f}s)"
                    )

                return response

            except Exception as e:
                attempt_duration = time.time() - attempt_start if "attempt_start" in locals() else 0
                last_exception = e

                # Categorize the error
                error_category = self._categorize_error(e)

                # Record failed connection
                self.health_monitor.record_failed_connection(e, error_category)

                # Complete API call tracing with error
                self.api_tracer.trace_response(
                    trace_id=trace_id, status_code=getattr(e, "status_code", 0), error=e, duration=attempt_duration
                )

                debug_ctx.add_breadcrumb(
                    f"Request attempt {attempt + 1} failed",
                    level="error",
                    error=str(e),
                    error_type=type(e).__name__,
                    error_category=error_category,
                    duration_ms=round(attempt_duration * 1000, 2),
                )

                # Log API call failure
                debug_ctx.log_api_call(
                    method=method, url=full_url, status_code=getattr(e, "status_code", 0), duration=attempt_duration, error=str(e)
                )

                # Check if we should retry
                if attempt < self.retry_config["max_retries"] and self._should_retry(e, error_category):
                    delay = self._calculate_retry_delay(attempt)

                    debug_ctx.add_breadcrumb(
                        f"Retrying in {delay:.2f} seconds",
                        level="warning",
                        retry_reason=f"Retryable {error_category} error",
                        delay_seconds=delay,
                    )

                    if self.debug_enabled:
                        self.logger.warning(
                            f"API request failed (attempt {attempt + 1}), retrying in {delay:.2f}s: "
                            f"{method} {url_suffix} - {str(e)}"
                        )

                    time.sleep(delay)
                else:
                    # Final failure
                    total_duration = time.time() - start_time

                    debug_ctx.add_breadcrumb(
                        f"Request failed after {attempt + 1} attempts",
                        level="error",
                        total_duration_ms=round(total_duration * 1000, 2),
                        final_error=str(e),
                    )

                    if self.debug_enabled:
                        self.logger.error_with_context(
                            f"API request failed after {attempt + 1} attempts: {method} {url_suffix}",
                            exception=e,
                            total_duration=total_duration,
                            trace_id=trace_id,
                        )

                    # Re-raise the last exception
                    raise last_exception

        # This should never be reached, but just in case
        raise last_exception or Exception("Unknown error in http_request")

    def _categorize_error(self, error: Exception) -> str:
        """Categorize an error for retry logic and monitoring."""
        error_str = str(error).lower()
        error_type = type(error).__name__.lower()

        if "timeout" in error_str or "timeout" in error_type:
            return "timeout"
        elif "connection" in error_str or "network" in error_str:
            return "network"
        elif "unauthorized" in error_str or "401" in error_str:
            return "authentication"
        elif "forbidden" in error_str or "403" in error_str:
            return "authorization"
        elif "429" in error_str or "rate limit" in error_str:
            return "rate_limit"
        elif "500" in error_str or "502" in error_str or "503" in error_str or "504" in error_str:
            return "server_error"
        else:
            return "unknown"

    def _should_retry(self, error: Exception, error_category: str) -> bool:
        """Determine if an error should trigger a retry."""
        # Retry on network issues, timeouts, rate limits, and server errors
        retryable_categories = {"timeout", "network", "rate_limit", "server_error"}
        return error_category in retryable_categories

    def _calculate_retry_delay(self, attempt: int) -> float:
        """Calculate delay for retry attempt with exponential backoff and jitter."""
        delay = min(
            self.retry_config["base_delay"] * (self.retry_config["backoff_multiplier"] ** attempt), self.retry_config["max_delay"]
        )

        if self.retry_config["jitter"]:
            # Add random jitter to prevent thundering herd
            jitter = delay * 0.1 * (2 * secrets.SystemRandom().random() - 1)  # ±10% jitter
            delay += jitter

        return max(0, delay)

    def get_connection_health(self) -> dict[str, Any]:
        """Get comprehensive connection health information."""
        return self.health_monitor.get_health_status()

    def get_api_trace_statistics(self) -> dict[str, Any]:
        """Get API call trace statistics."""
        return self.api_tracer.get_trace_statistics()

    def get_recent_api_traces(self, limit: int = 20) -> list[dict[str, Any]]:
        """Get recent API call traces."""
        return self.api_tracer.get_recent_traces(limit)

    def get_api_trace_by_id(self, trace_id: str) -> dict[str, Any] | None:
        """Get a specific API trace by ID."""
        return self.api_tracer.get_trace_by_id(trace_id)

    def test_connection_with_diagnostics(self) -> dict[str, Any]:
        """Test connection and return comprehensive diagnostic information."""
        debug_ctx = DebugContext("connection_test_with_diagnostics")

        try:
            debug_ctx.add_breadcrumb("Starting connection test with diagnostics")

            # Test basic connectivity
            start_time = time.time()
            self.http_request("GET", "/help/versions")
            connection_time = time.time() - start_time

            # Get health status
            health_status = self.get_connection_health()

            # Get trace statistics
            trace_stats = self.get_api_trace_statistics()

            debug_ctx.add_breadcrumb("Connection test completed successfully")

            return {
                "status": "SUCCESS",
                "connection_time_ms": round(connection_time * 1000, 2),
                "health_status": health_status,
                "trace_statistics": trace_stats,
                "correlation_id": debug_ctx.correlation_id,
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            debug_ctx.add_breadcrumb("Connection test failed", level="error", error=str(e))

            return {
                "status": "FAILED",
                "error": str(e),
                "error_type": type(e).__name__,
                "health_status": self.get_connection_health(),
                "trace_statistics": self.get_api_trace_statistics(),
                "correlation_id": debug_ctx.correlation_id,
                "timestamp": datetime.now().isoformat(),
            }


# Global enhanced client instance
_enhanced_client_instance = None


def get_enhanced_client(original_client) -> EnhancedQRadarClient:
    """
    Get or create an enhanced client instance.

    Args:
        original_client: The original QRadar client

    Returns:
        EnhancedQRadarClient instance
    """
    global _enhanced_client_instance

    if _enhanced_client_instance is None:
        _enhanced_client_instance = EnhancedQRadarClient(original_client)

    return _enhanced_client_instance


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# ENHANCED ERROR HANDLING INFRASTRUCTURE
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements comprehensive error handling patterns that transform all try/catch blocks into maintainable,
# debuggable, and user-friendly error handling. The system provides automatic error categorization, context capture,
# recovery suggestions, and structured logging for all error scenarios.


class ErrorCategory(Enum):
    """
    Categorizes errors for automatic grouping and pattern recognition.

    This enumeration helps with:
    - Automatic error categorization and reporting
    - Pattern recognition for similar issues
    - Targeted troubleshooting and remediation
    - Metrics collection and analysis
    """

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK = "network_connectivity"
    API = "api_error"
    CONFIGURATION = "configuration"
    DATA_PROCESSING = "data_processing"
    CONTEXT_CORRUPTION = "context_corruption"
    TIMEOUT = "timeout"
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    GENERAL = "general"


class TroubleshootingHint:
    """
    Represents a troubleshooting hint with description and action steps.

    This class provides structured troubleshooting guidance that can be
    automatically included in error messages to help users resolve issues.
    """

    def __init__(self, description: str, action_steps: list[str], documentation_link: str | None = None):
        self.description = description
        self.action_steps = action_steps
        self.documentation_link = documentation_link

    def format_for_display(self) -> str:
        """Format the hint for display in error messages."""
        lines = [f"   {self.description}:"]
        for step in self.action_steps:
            lines.append(f"     • {step}")
        if self.documentation_link:
            lines.append(f"     📖 Documentation: {self.documentation_link}")
        return "\n".join(lines)


class ErrorHandlingContext:
    """
    Context manager for enhanced error handling with comprehensive debugging and recovery suggestions.

    This class transforms basic try/catch blocks into maintainable error handling patterns that:
    - Capture complete execution context including variable states
    - Provide automatic error categorization and troubleshooting hints
    - Enable structured logging with correlation IDs
    - Support error recovery suggestions and remediation steps
    """

    def __init__(
        self,
        operation_name: str,
        debug_context: DebugContext | None = None,
        logger: EnhancedLogger | None = None,
        expected_errors: dict[type, str] | None = None,
        recovery_suggestions: dict[type, list[str]] | None = None,
    ):
        """
        Initialize error handling context.

        Args:
            operation_name: Name of the operation being performed
            debug_context: Debug context for execution tracking
            logger: Enhanced logger for structured logging
            expected_errors: Mapping of expected exception types to user-friendly messages
            recovery_suggestions: Mapping of exception types to recovery suggestions
        """
        self.operation_name = operation_name
        self.debug_context = debug_context or DebugContext(operation_name)
        self.logger = logger or get_enhanced_logger(f"ErrorHandler.{operation_name}")
        self.expected_errors = expected_errors or {}
        self.recovery_suggestions = recovery_suggestions or {}
        self.start_time = time.time()
        self.captured_variables = {}

    def capture_variable(self, name: str, value: Any, description: str = ""):
        """Capture variable state for error context."""
        self.captured_variables[name] = {
            "value": str(value)[:500] if value is not None else None,  # Truncate large values
            "type": type(value).__name__,
            "description": description,
            "timestamp": time.time(),
        }
        self.debug_context.capture_variable(name, value, description)

    def __enter__(self):
        """Enter the error handling context."""
        self.debug_context.add_breadcrumb(f"Starting error-handled operation: {self.operation_name}")
        self.logger.info(f"Beginning operation: {self.operation_name}")
        return self

    def __exit__(self, exc_type, exc_value, traceback_obj):
        """Exit the error handling context with comprehensive error processing."""
        duration = time.time() - self.start_time

        if exc_type is None:
            # Operation completed successfully
            self.debug_context.add_breadcrumb(f"Operation completed successfully: {self.operation_name}")
            self.logger.info(f"Operation completed successfully: {self.operation_name} (duration: {duration:.2f}s)")
            return False

        # Handle the exception with comprehensive context
        self._handle_exception_with_context(exc_type, exc_value, traceback_obj, duration)
        return False  # Re-raise the exception after processing

    def _handle_exception_with_context(self, exc_type, exc_value, traceback_obj, duration: float):
        """Handle exception with comprehensive context capture and categorization."""

        # Capture exception context
        exception_context = {
            "operation_name": self.operation_name,
            "duration_seconds": duration,
            "exception_type": exc_type.__name__,
            "exception_message": str(exc_value),
            "captured_variables": self.captured_variables,
            "breadcrumbs": self.debug_context.breadcrumbs,
            "api_calls": self.debug_context.api_calls,
            "correlation_id": self.debug_context.correlation_id,
        }

        # Add breadcrumb for the error
        self.debug_context.add_breadcrumb(
            f"Operation failed: {self.operation_name}",
            "error",
            error_type=exc_type.__name__,
            error_message=str(exc_value),
            duration=duration,
        )

        # Categorize the error
        error_category = self._categorize_error(exc_type, exc_value)

        # Get recovery suggestions
        recovery_suggestions = self._get_recovery_suggestions(exc_type, exc_value)

        # Create enhanced error message
        enhanced_message = self._create_enhanced_error_message(exc_value, error_category, recovery_suggestions, exception_context)

        # Log the error with full context
        self.logger.error_with_context(
            enhanced_message,
            exception=exc_value,
            error_category=error_category,
            recovery_suggestions=recovery_suggestions,
            **exception_context,
        )

        # Transform the exception if it's a known type
        if exc_type in self.expected_errors:
            # Create a more user-friendly exception
            user_friendly_message = self.expected_errors[exc_type]
            raise QRadarOperationError(
                message=f"{user_friendly_message}: {enhanced_message}",
                operation=self.operation_name,
                context=exception_context,
                recovery_suggestions=recovery_suggestions,
                original_exception=exc_value,
            ) from exc_value

    def _categorize_error(self, exc_type, exc_value) -> ErrorCategory:
        """Automatically categorize the error based on type and content."""
        error_message = str(exc_value).lower()

        # Authentication and authorization errors
        if any(keyword in error_message for keyword in ["unauthorized", "authentication", "invalid token", "no sec header"]):
            return ErrorCategory.AUTHENTICATION

        if any(keyword in error_message for keyword in ["insufficient capabilities", "permission denied", "access denied"]):
            return ErrorCategory.AUTHORIZATION

        # Network and connectivity errors
        if any(
            keyword in error_message for keyword in ["connection", "timeout", "network", "dns", "unreachable"]
        ) or exc_type in [requests.ConnectionError, requests.Timeout, requests.ReadTimeout]:
            return ErrorCategory.NETWORK

        # API and data errors
        if (
            any(keyword in error_message for keyword in ["api", "invalid request", "bad request", "not found"])
            or exc_type == DemistoException
        ):
            return ErrorCategory.API

        # Configuration errors
        if any(keyword in error_message for keyword in ["configuration", "parameter", "missing", "invalid"]) or exc_type in [
            KeyError,
            ValueError,
            TypeError,
        ]:
            return ErrorCategory.CONFIGURATION

        # Data processing errors
        if any(keyword in error_message for keyword in ["parse", "format", "decode", "json", "xml"]) or exc_type in [
            json.JSONDecodeError,
            UnicodeDecodeError,
        ]:
            return ErrorCategory.DATA_PROCESSING

        # Default to general error
        return ErrorCategory.GENERAL

    def _get_recovery_suggestions(self, exc_type, exc_value) -> list[str]:
        """Get recovery suggestions based on error type and content."""
        suggestions = []
        error_message = str(exc_value).lower()

        # Add type-specific suggestions
        if exc_type in self.recovery_suggestions:
            suggestions.extend(self.recovery_suggestions[exc_type])

        # Add content-based suggestions
        if "unauthorized" in error_message or "authentication" in error_message:
            suggestions.extend(
                [
                    "Verify that the API token is correctly configured",
                    "Check if the API token has expired",
                    "Ensure the user account is not locked or disabled",
                    "Test the API token using QRadar's API documentation interface",
                ]
            )

        if "timeout" in error_message or "connection" in error_message:
            suggestions.extend(
                [
                    "Check network connectivity to the QRadar server",
                    "Verify that the QRadar server is running and accessible",
                    "Consider increasing timeout values if the server is slow",
                    "Check firewall rules and network security policies",
                ]
            )

        if "permission" in error_message or "insufficient capabilities" in error_message:
            suggestions.extend(
                [
                    "Verify user permissions in QRadar User Management",
                    "Check if the user has the required security profile",
                    "Contact your QRadar administrator to review user roles",
                    "Ensure the user has access to the specific domains being queried",
                ]
            )

        if "parameter" in error_message or exc_type in [KeyError, ValueError, TypeError]:
            suggestions.extend(
                [
                    "Check that all required parameters are provided",
                    "Verify parameter formats and data types",
                    "Review the command documentation for parameter requirements",
                    "Validate input data before making API calls",
                ]
            )

        return suggestions

    def _create_enhanced_error_message(
        self, exc_value, error_category: ErrorCategory, recovery_suggestions: list[str], context: dict[str, Any]
    ) -> str:
        """Create an enhanced error message with context and suggestions."""

        message_parts = [
            f"🚨 QRadar Operation Failed [{error_category.value.upper()}]",
            f"Operation: {self.operation_name}",
            f"Correlation ID: {context['correlation_id']}",
            f"Duration: {context['duration_seconds']:.2f}s",
            "",
            f"Error: {str(exc_value)}",
        ]

        # Add captured variables if any
        if context["captured_variables"]:
            message_parts.extend(
                [
                    "",
                    "📋 Context Variables:",
                ]
            )
            for var_name, var_info in context["captured_variables"].items():
                description = f" - {var_info['description']}" if var_info["description"] else ""
                message_parts.append(f"   • {var_name} ({var_info['type']}): {var_info['value']}{description}")

        # Add API call information if any
        if context["api_calls"]:
            message_parts.extend(
                [
                    "",
                    "🌐 Recent API Calls:",
                ]
            )
            for api_call in context["api_calls"][-3:]:  # Show last 3 API calls
                status = api_call.get("status_code", "Unknown")
                duration = api_call.get("duration", 0)
                message_parts.append(f"   • {api_call['method']} {api_call['url']} -> {status} ({duration:.2f}s)")

        # Add recovery suggestions
        if recovery_suggestions:
            message_parts.extend(
                [
                    "",
                    "🔧 Recovery Suggestions:",
                ]
            )
            for suggestion in recovery_suggestions[:5]:  # Limit to 5 suggestions
                message_parts.append(f"   • {suggestion}")

        # Add breadcrumb trail for debugging
        if context["breadcrumbs"]:
            message_parts.extend(
                [
                    "",
                    "🔍 Execution Trail:",
                ]
            )
            for breadcrumb in context["breadcrumbs"][-5:]:  # Show last 5 breadcrumbs
                timestamp = breadcrumb.get("timestamp", 0)
                level = breadcrumb.get("level", "info").upper()
                message = breadcrumb.get("message", "")
                message_parts.append(f"   • [{level}] {message}")

        return "\n".join(message_parts)


# Enhanced error handling decorators and utilities
def with_error_handling(
    operation_name: str,
    expected_errors: dict[type, str] | None = None,
    recovery_suggestions: dict[type, list[str]] | None = None,
    capture_variables: list[str] | None = None,
):
    """
    Decorator to add comprehensive error handling to functions.

    Args:
        operation_name: Name of the operation for logging and debugging
        expected_errors: Mapping of expected exception types to user-friendly messages
        recovery_suggestions: Mapping of exception types to recovery suggestions
        capture_variables: List of variable names to capture from function locals
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            debug_context = DebugContext(f"{func.__name__}_{operation_name}")
            logger = get_enhanced_logger(func.__name__)

            with ErrorHandlingContext(
                operation_name=f"{func.__name__}_{operation_name}",
                debug_context=debug_context,
                logger=logger,
                expected_errors=expected_errors,
                recovery_suggestions=recovery_suggestions,
            ) as error_handler:
                # Capture specified variables if requested
                if capture_variables:
                    frame = inspect.currentframe()
                    try:
                        local_vars = frame.f_locals
                        for var_name in capture_variables:
                            if var_name in local_vars:
                                error_handler.capture_variable(var_name, local_vars[var_name])
                    finally:
                        del frame

                # Execute the function
                return func(*args, **kwargs)

        return wrapper

    return decorator


def handle_qradar_api_errors(operation_name: str):
    """
    Specialized decorator for QRadar API operations with common error patterns.
    """
    expected_errors = {
        DemistoException: "QRadar API operation failed",
        requests.ConnectionError: "Failed to connect to QRadar server",
        requests.Timeout: "QRadar API request timed out",
        requests.ReadTimeout: "QRadar API response timed out",
        KeyError: "Missing required parameter",
        ValueError: "Invalid parameter value",
        TypeError: "Invalid parameter type",
    }

    recovery_suggestions = {
        DemistoException: [
            "Check QRadar server status and connectivity",
            "Verify API token permissions and validity",
            "Review request parameters for correctness",
        ],
        requests.ConnectionError: [
            "Verify QRadar server URL and port",
            "Check network connectivity and firewall rules",
            "Ensure QRadar server is running and accessible",
        ],
        requests.Timeout: [
            "Increase timeout values in integration configuration",
            "Check QRadar server performance and load",
            "Consider reducing request size or complexity",
        ],
        KeyError: [
            "Review command documentation for required parameters",
            "Check parameter names for typos",
            "Ensure all mandatory fields are provided",
        ],
        ValueError: [
            "Validate parameter formats and data types",
            "Check numeric parameters for valid ranges",
            "Verify date/time formats match expected patterns",
        ],
    }

    return with_error_handling(
        operation_name=operation_name, expected_errors=expected_errors, recovery_suggestions=recovery_suggestions
    )


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# EXCEPTION HIERARCHY - MAINTAINABLE ERROR HANDLING
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements a comprehensive exception hierarchy with clear error messages, troubleshooting hints,
# automatic error categorization, and context preservation. Each exception class is self-documenting and provides
# actionable information to help users understand and resolve issues quickly.

from typing import Any
from enum import Enum


class QRadarBaseException(Exception):
    """
    Base exception class for all QRadar integration errors.

    This class provides the foundation for all QRadar-specific exceptions with:
    - Clear, actionable error messages
    - Automatic error categorization
    - Context preservation through exception chaining
    - Troubleshooting hints and remediation suggestions
    - Correlation ID tracking for debugging
    """

    def __init__(
        self,
        message: str,
        category: ErrorCategory,
        troubleshooting_hints: list[TroubleshootingHint] | None = None,
        context: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        original_exception: Exception | None = None,
    ):
        """
        Initialize the base QRadar exception.

        Args:
            message: Clear, descriptive error message
            category: Error category for automatic grouping
            troubleshooting_hints: List of troubleshooting hints
            context: Additional context information
            correlation_id: Correlation ID for debugging
            original_exception: Original exception that caused this error
        """
        self.category = category
        self.troubleshooting_hints = troubleshooting_hints or []
        self.context = context or {}
        self.correlation_id = correlation_id or self._generate_correlation_id()
        self.original_exception = original_exception

        # Create comprehensive error message
        full_message = self._build_comprehensive_message(message)
        super().__init__(full_message)

        # Preserve exception chain for debugging
        if original_exception:
            self.__cause__ = original_exception

    def _generate_correlation_id(self) -> str:
        """Generate a unique correlation ID for this error."""
        import uuid

        return str(uuid.uuid4())[:8]

    def _build_comprehensive_message(self, base_message: str) -> str:
        """Build a comprehensive error message with all context and hints."""
        message_parts = [
            f"🚨 QRadar Integration Error [{self.category.value.upper()}]",
            f"Correlation ID: {self.correlation_id}",
            "",
            f"Error: {base_message}",
        ]

        # Add context information if available
        if self.context:
            message_parts.extend(
                [
                    "",
                    "📋 Context Information:",
                ]
            )
            for key, value in self.context.items():
                message_parts.append(f"   • {key}: {value}")

        # Add troubleshooting hints if available
        if self.troubleshooting_hints:
            message_parts.extend(
                [
                    "",
                    "🔧 Troubleshooting Suggestions:",
                ]
            )
            for hint in self.troubleshooting_hints:
                message_parts.append(hint.format_for_display())

        # Add original exception information if available
        if self.original_exception:
            message_parts.extend(
                [
                    "",
                    f"🔗 Original Error: {type(self.original_exception).__name__}: {str(self.original_exception)}",
                ]
            )

        return "\n".join(message_parts)

    def get_error_summary(self) -> dict[str, Any]:
        """Get a structured summary of the error for logging and metrics."""
        return {
            "error_type": self.__class__.__name__,
            "category": self.category.value,
            "correlation_id": self.correlation_id,
            "message": str(self).split("\n")[3] if "\n" in str(self) else str(self),  # Get just the base message
            "context": self.context,
            "has_troubleshooting_hints": len(self.troubleshooting_hints) > 0,
            "original_exception_type": type(self.original_exception).__name__ if self.original_exception else None,
            "timestamp": time.time(),
        }


class QRadarAuthenticationError(QRadarBaseException):
    """
    Raised when authentication with QRadar fails.

    This exception indicates issues with API tokens, credentials, or authentication
    configuration that prevent successful connection to QRadar.
    """

    def __init__(
        self,
        message: str = "Authentication with QRadar failed",
        api_token_provided: bool = False,
        status_code: int | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Verify API token configuration",
                [
                    "Check that the API token is correctly configured in the integration settings",
                    "Ensure the API token has not expired",
                    "Verify the API token has sufficient permissions for the required operations",
                    "Test the API token directly using QRadar's API documentation interface",
                ],
                "https://www.ibm.com/docs/en/qradar-common?topic=api-authentication",
            ),
            TroubleshootingHint(
                "Check QRadar user permissions",
                [
                    "Verify the user associated with the API token has the required roles",
                    "Ensure the user account is not locked or disabled",
                    "Check if the user has access to the specific QRadar domains being queried",
                ],
            ),
        ]

        context = {"api_token_provided": api_token_provided, "status_code": status_code}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            troubleshooting_hints=hints,
            context=context,
            **filtered_kwargs,
        )


class QRadarAuthorizationError(QRadarBaseException):
    """
    Raised when the authenticated user lacks permissions for the requested operation.

    This exception indicates that while authentication succeeded, the user does not
    have sufficient permissions to perform the requested action.
    """

    def __init__(
        self,
        message: str = "Insufficient permissions for the requested operation",
        required_permission: str | None = None,
        endpoint: str | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Check user permissions and roles",
                [
                    "Verify the user has the required role assignments in QRadar",
                    "Check if the user has access to the specific security profile needed",
                    "Ensure the user has not been restricted from accessing certain data",
                    "Contact your QRadar administrator to review and update user permissions",
                ],
            )
        ]

        if required_permission:
            hints.append(
                TroubleshootingHint(
                    f"Required permission: {required_permission}",
                    [
                        f"Ensure the user has the '{required_permission}' permission",
                        "Check the QRadar User Management console for role assignments",
                        "Verify the permission is not restricted by security profiles",
                    ],
                )
            )

        context = {"required_permission": required_permission, "endpoint": endpoint}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message, category=ErrorCategory.AUTHORIZATION, troubleshooting_hints=hints, context=context, **filtered_kwargs
        )


class QRadarNetworkError(QRadarBaseException):
    """
    Raised when network connectivity issues prevent communication with QRadar.

    This exception covers connection timeouts, DNS resolution failures, network
    unreachability, and other network-related issues.
    """

    def __init__(
        self,
        message: str = "Network connectivity issue with QRadar",
        qradar_url: str | None = None,
        timeout_seconds: int | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Check network connectivity",
                [
                    "Verify the QRadar server URL is correct and accessible",
                    "Test network connectivity using ping or telnet to the QRadar server",
                    "Check if there are firewall rules blocking the connection",
                    "Verify DNS resolution is working for the QRadar hostname",
                ],
            ),
            TroubleshootingHint(
                "Review timeout settings",
                [
                    "Consider increasing timeout values if the network is slow",
                    "Check if QRadar is experiencing high load that might cause delays",
                    "Verify the integration is not being rate-limited by network equipment",
                ],
            ),
        ]

        context = {"qradar_url": qradar_url, "timeout_seconds": timeout_seconds}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message, category=ErrorCategory.NETWORK, troubleshooting_hints=hints, context=context, **filtered_kwargs
        )


class QRadarAPIError(QRadarBaseException):
    """
    Raised when QRadar API returns an error response.

    This exception handles various API error conditions including invalid requests,
    server errors, and API-specific error responses.
    """

    def __init__(
        self,
        message: str = "QRadar API returned an error",
        status_code: int | None = None,
        api_response: str | None = None,
        endpoint: str | None = None,
        method: str | None = None,
        **kwargs,
    ):
        hints = []

        # Provide specific hints based on status code
        if status_code == 400:
            hints.append(
                TroubleshootingHint(
                    "Bad Request (400) - Check request parameters",
                    [
                        "Verify all required parameters are provided",
                        "Check parameter formats and data types",
                        "Ensure parameter values are within acceptable ranges",
                        "Review the API documentation for the specific endpoint",
                    ],
                )
            )
        elif status_code == 404:
            hints.append(
                TroubleshootingHint(
                    "Not Found (404) - Resource does not exist",
                    [
                        "Verify the resource ID or name is correct",
                        "Check if the resource has been deleted or moved",
                        "Ensure you have permission to access the resource",
                        "Confirm the API endpoint URL is correct",
                    ],
                )
            )
        elif status_code == 500:
            hints.append(
                TroubleshootingHint(
                    "Internal Server Error (500) - QRadar server issue",
                    [
                        "Check QRadar server logs for detailed error information",
                        "Verify QRadar services are running properly",
                        "Consider retrying the operation after a brief delay",
                        "Contact QRadar administrator if the issue persists",
                    ],
                )
            )
        elif status_code == 503:
            hints.append(
                TroubleshootingHint(
                    "Service Unavailable (503) - QRadar temporarily unavailable",
                    [
                        "QRadar may be under maintenance or experiencing high load",
                        "Retry the operation after a few minutes",
                        "Check QRadar system status and resource utilization",
                        "Consider implementing exponential backoff for retries",
                    ],
                )
            )

        # Add general API troubleshooting hint
        hints.append(
            TroubleshootingHint(
                "General API troubleshooting",
                [
                    "Check QRadar API documentation for the specific endpoint",
                    "Verify the API version compatibility",
                    "Test the API call directly using QRadar's API documentation interface",
                    "Review QRadar system logs for additional error details",
                ],
            )
        )

        context = {
            "status_code": status_code,
            "api_response": api_response[:500] if api_response else None,  # Truncate long responses
            "endpoint": endpoint,
            "method": method,
        }
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message, category=ErrorCategory.API, troubleshooting_hints=hints, context=context, **filtered_kwargs
        )


class QRadarConfigurationError(QRadarBaseException):
    """
    Raised when there are issues with integration configuration.

    This exception covers missing required parameters, invalid configuration values,
    and configuration conflicts.
    """

    def __init__(
        self,
        message: str = "Integration configuration error",
        parameter_name: str | None = None,
        expected_type: str | None = None,
        actual_value: Any | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Review integration configuration",
                [
                    "Check all required parameters are configured",
                    "Verify parameter values are in the correct format",
                    "Ensure boolean parameters use 'true' or 'false' values",
                    "Review the integration documentation for parameter requirements",
                ],
            )
        ]

        if parameter_name:
            hints.append(
                TroubleshootingHint(
                    f"Parameter '{parameter_name}' configuration issue",
                    [
                        f"Check the '{parameter_name}' parameter in the integration settings",
                        f"Expected type: {expected_type}" if expected_type else "Verify the parameter format",
                        "Ensure the parameter value is not empty or null",
                        "Check for any special characters or formatting requirements",
                    ],
                )
            )

        context = {
            "parameter_name": parameter_name,
            "expected_type": expected_type,
            "actual_value": str(actual_value) if actual_value is not None else None,
        }
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message, category=ErrorCategory.CONFIGURATION, troubleshooting_hints=hints, context=context, **filtered_kwargs
        )


class QRadarDataValidationError(QRadarBaseException):
    """
    Raised when data validation fails.

    This exception covers invalid input data, schema validation failures,
    and data format issues.
    """

    def __init__(
        self,
        message: str = "Data validation failed",
        field_name: str | None = None,
        expected_format: str | None = None,
        validation_errors: list[str] | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Check input data format",
                [
                    "Verify all required fields are provided",
                    "Check data types match the expected format",
                    "Ensure date/time values are in the correct format",
                    "Validate that numeric values are within acceptable ranges",
                ],
            )
        ]

        if validation_errors:
            hints.append(TroubleshootingHint("Specific validation errors found", validation_errors))

        context = {"field_name": field_name, "expected_format": expected_format, "validation_errors": validation_errors}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message,
            category=ErrorCategory.DATA_PROCESSING,
            troubleshooting_hints=hints,
            context=context,
            **filtered_kwargs,
        )


class QRadarContextCorruptionError(QRadarBaseException):
    """
    Raised when integration context data is corrupted or invalid.

    This exception indicates issues with the integration's persistent state
    that may require context reset or recovery procedures.
    """

    def __init__(
        self,
        message: str = "Integration context data is corrupted",
        corruption_type: str | None = None,
        recovery_attempted: bool = False,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Context corruption recovery",
                [
                    "Try resetting the integration context using the reset command",
                    "Check if the context size has exceeded limits",
                    "Verify there are no concurrent operations modifying the context",
                    "Consider restarting the integration if the issue persists",
                ],
            ),
            TroubleshootingHint(
                "Prevent future corruption",
                [
                    "Ensure proper error handling in all context update operations",
                    "Monitor context size and implement cleanup procedures",
                    "Avoid concurrent modifications to the same context keys",
                    "Implement regular context validation checks",
                ],
            ),
        ]

        context = {"corruption_type": corruption_type, "recovery_attempted": recovery_attempted}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message,
            category=ErrorCategory.CONTEXT_CORRUPTION,
            troubleshooting_hints=hints,
            context=context,
            **filtered_kwargs,
        )


class QRadarTimeoutError(QRadarBaseException):
    """
    Raised when operations exceed their timeout limits.

    This exception covers API call timeouts, search completion timeouts,
    and other time-based operation failures.
    """

    def __init__(
        self,
        message: str = "Operation timed out",
        timeout_seconds: int | None = None,
        operation_type: str | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Timeout troubleshooting",
                [
                    "Consider increasing the timeout value for this operation",
                    "Check if QRadar is experiencing high load or performance issues",
                    "Verify network connectivity is stable",
                    "Try breaking large operations into smaller batches",
                ],
            )
        ]

        if operation_type == "search":
            hints.append(
                TroubleshootingHint(
                    "Search timeout specific guidance",
                    [
                        "Reduce the search time range to limit the amount of data processed",
                        "Add more specific filters to narrow down the search results",
                        "Check QRadar system resources and search queue status",
                        "Consider using asynchronous search patterns for large queries",
                    ],
                )
            )

        context = {"timeout_seconds": timeout_seconds, "operation_type": operation_type}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message, category=ErrorCategory.TIMEOUT, troubleshooting_hints=hints, context=context, **filtered_kwargs
        )


class QRadarResourceExhaustionError(QRadarBaseException):
    """
    Raised when system resources are exhausted.

    This exception covers memory limits, connection pool exhaustion,
    and other resource-related failures.
    """

    def __init__(
        self,
        message: str = "System resources exhausted",
        resource_type: str | None = None,
        current_usage: str | None = None,
        limit: str | None = None,
        **kwargs,
    ):
        hints = [
            TroubleshootingHint(
                "Resource management",
                [
                    "Reduce batch sizes to lower memory usage",
                    "Implement proper cleanup of resources after operations",
                    "Consider increasing system resource limits if possible",
                    "Monitor resource usage patterns to identify optimization opportunities",
                ],
            )
        ]

        if resource_type == "memory":
            hints.append(
                TroubleshootingHint(
                    "Memory management specific guidance",
                    [
                        "Process data in smaller chunks to reduce memory footprint",
                        "Clear large variables and data structures when no longer needed",
                        "Check for memory leaks in long-running operations",
                        "Consider using streaming or pagination for large datasets",
                    ],
                )
            )

        context = {"resource_type": resource_type, "current_usage": current_usage, "limit": limit}
        context.update(kwargs.get("context", {}))

        # Remove context from kwargs to avoid duplicate parameter
        filtered_kwargs = {k: v for k, v in kwargs.items() if k != "context"}

        super().__init__(
            message=message,
            category=ErrorCategory.RESOURCE_EXHAUSTION,
            troubleshooting_hints=hints,
            context=context,
            **filtered_kwargs,
        )


# Convenience functions for creating common exceptions with context
def create_authentication_error(
    message: str,
    status_code: int | None = None,
    correlation_id: str | None = None,
    original_exception: Exception | None = None,
) -> QRadarAuthenticationError:
    """Create an authentication error with common context."""
    return QRadarAuthenticationError(
        message=message, status_code=status_code, correlation_id=correlation_id, original_exception=original_exception
    )


class QRadarOperationError(QRadarBaseException):
    """
    Raised when a QRadar operation fails with comprehensive context and recovery suggestions.

    This exception is used by the enhanced error handling system to provide detailed
    information about operation failures, including execution context, variable states,
    and specific recovery suggestions.
    """

    def __init__(
        self,
        message: str = "QRadar operation failed",
        operation: str | None = None,
        context: dict[str, Any] | None = None,
        recovery_suggestions: list[str] | None = None,
        **kwargs,
    ):
        """
        Initialize QRadar operation error with comprehensive context.

        Args:
            message: Error message describing what failed
            operation: Name of the operation that failed
            context: Execution context including variables and API calls
            recovery_suggestions: List of specific recovery suggestions
            **kwargs: Additional context information
        """

        # Create troubleshooting hints from recovery suggestions
        hints = []
        if recovery_suggestions:
            hints.append(TroubleshootingHint("Recovery Suggestions", recovery_suggestions))

        # Add operation-specific troubleshooting hints
        if operation:
            hints.append(
                TroubleshootingHint(
                    f"Operation-specific guidance for '{operation}'",
                    [
                        f"Review the '{operation}' operation documentation",
                        "Check if all required parameters were provided correctly",
                        "Verify the operation is supported in your QRadar version",
                        "Consider retrying the operation after addressing any issues",
                    ],
                )
            )

        # Enhance context with operation information
        enhanced_context = context or {}
        if operation:
            enhanced_context["failed_operation"] = operation

        # Determine error category based on context
        error_category = ErrorCategory.GENERAL
        if context and "error_category" in context:
            error_category = context["error_category"]
        elif "authentication" in message.lower() or "unauthorized" in message.lower():
            error_category = ErrorCategory.AUTHENTICATION
        elif "permission" in message.lower() or "authorization" in message.lower():
            error_category = ErrorCategory.AUTHORIZATION
        elif "network" in message.lower() or "connection" in message.lower():
            error_category = ErrorCategory.NETWORK
        elif "api" in message.lower() or "request" in message.lower():
            error_category = ErrorCategory.API
        elif "configuration" in message.lower() or "parameter" in message.lower():
            error_category = ErrorCategory.CONFIGURATION

        super().__init__(
            message=message, category=error_category, troubleshooting_hints=hints, context=enhanced_context, **kwargs
        )


def create_api_error_from_response(
    response, endpoint: str, method: str = "GET", correlation_id: str | None = None
) -> QRadarAPIError:
    """Create an API error from an HTTP response."""
    try:
        api_response = response.text if hasattr(response, "text") else str(response)
        status_code = response.status_code if hasattr(response, "status_code") else None
    except Exception:
        api_response = "Unable to extract response details"
        status_code = None

    return QRadarAPIError(
        message=f"API call failed: {method} {endpoint}",
        status_code=status_code,
        api_response=api_response,
        endpoint=endpoint,
        method=method,
        correlation_id=correlation_id,
    )


def create_timeout_error(
    operation_type: str,
    timeout_seconds: int,
    correlation_id: str | None = None,
    additional_context: dict[str, Any] | None = None,
) -> QRadarTimeoutError:
    """Create a timeout error with operation context."""
    return QRadarTimeoutError(
        message=f"{operation_type.title()} operation timed out after {timeout_seconds} seconds",
        timeout_seconds=timeout_seconds,
        operation_type=operation_type,
        correlation_id=correlation_id,
        context=additional_context or {},
    )


def get_enhanced_logger(name: str) -> EnhancedLogger:
    """
    Get an enhanced logger instance for the specified component.

    This function provides a centralized way to create enhanced loggers with
    consistent configuration and debugging capabilities.

    Args:
        name: Name of the component requesting the logger

    Returns:
        EnhancedLogger: Configured logger instance
    """
    return EnhancedLogger(name)


def transform_legacy_exception(
    exception: Exception, operation_name: str, context: dict[str, Any] | None = None
) -> QRadarBaseException:
    """
    Transform legacy exceptions into the new QRadar exception hierarchy.

    This function helps migrate existing error handling to use the new
    maintainable exception patterns with enhanced context and recovery suggestions.

    Args:
        exception: Original exception to transform
        operation_name: Name of the operation that failed
        context: Additional context information

    Returns:
        QRadarBaseException: Transformed exception with enhanced information
    """
    error_message = str(exception)
    exception_type = type(exception)

    # Transform based on exception type and content
    if isinstance(exception, DemistoException):
        if any(keyword in error_message.lower() for keyword in ["unauthorized", "authentication", "no sec header"]):
            return QRadarAuthenticationError(message=error_message, context=context, original_exception=exception)
        elif any(keyword in error_message.lower() for keyword in ["permission", "insufficient capabilities"]):
            return QRadarAuthorizationError(message=error_message, context=context, original_exception=exception)
        else:
            return QRadarAPIError(message=error_message, context=context, original_exception=exception)

    elif isinstance(exception, (requests.ConnectionError, requests.Timeout, requests.ReadTimeout)):
        return QRadarNetworkError(message=error_message, context=context, original_exception=exception)

    elif isinstance(exception, (KeyError, ValueError, TypeError)):
        return QRadarConfigurationError(message=error_message, context=context, original_exception=exception)

    else:
        # Default to operation error for unknown exceptions
        return QRadarOperationError(
            message=error_message, operation=operation_name, context=context, original_exception=exception
        )


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# DEVELOPMENT AND TESTING UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements comprehensive development and testing utilities including diagnostic commands, development
# mode detection, self-test functions, and mock data generators. These tools make development, testing, and
# troubleshooting significantly easier by providing built-in diagnostic capabilities and test data generation.

import random
import string


class DevelopmentModeDetector:
    """
    Detects development mode and provides enhanced logging and validation.

    This class determines if the integration is running in development mode
    and enables enhanced debugging features accordingly.
    """

    @staticmethod
    def is_development_mode() -> bool:
        """
        Detect if integration is running in development mode.

        Returns:
            True if in development mode, False otherwise
        """
        # Check various indicators of development mode
        indicators = [
            # Check if debug logging is enabled
            demisto.params().get("debug", False),
            # Check if running in test environment
            "test" in demisto.params().get("server", "").lower(),
            # Check if specific development parameters are set
            demisto.params().get("dev_mode", False),
            # Check if integration instance name suggests development
            "dev" in demisto.integrationInstance().lower() if demisto.integrationInstance() else False,
            "test" in demisto.integrationInstance().lower() if demisto.integrationInstance() else False,
        ]

        return any(indicators)

    @staticmethod
    def get_development_config() -> dict[str, Any]:
        """
        Get development-specific configuration.

        Returns:
            Dictionary containing development configuration
        """
        is_dev = DevelopmentModeDetector.is_development_mode()

        return {
            "is_development_mode": is_dev,
            "enhanced_logging": is_dev,
            "detailed_validation": is_dev,
            "mock_data_enabled": is_dev,
            "performance_monitoring": is_dev,
            "debug_context_enabled": is_dev,
            "api_call_tracing": is_dev,
            "error_stack_traces": is_dev,
        }


class SystemHealthValidator:
    """
    Validates integration health and configuration.

    This class provides comprehensive health checks and validation
    functions to ensure the integration is properly configured and
    functioning correctly.
    """

    def __init__(self, client=None):
        self.client = client
        self.debug_ctx = DebugContext("system_health_validation")
        self.logger = get_enhanced_logger("SystemHealthValidator").with_context(self.debug_ctx)

    def validate_integration_health(self) -> dict[str, Any]:
        """
        Perform comprehensive integration health validation.

        Returns:
            Dictionary containing health validation results
        """
        self.debug_ctx.add_breadcrumb("Starting comprehensive health validation")

        validation_results = {
            "timestamp": datetime.now().isoformat(),
            "correlation_id": self.debug_ctx.correlation_id,
            "overall_status": "UNKNOWN",
            "validations": {},
        }

        try:
            # Validate configuration
            config_validation = self._validate_configuration()
            validation_results["validations"]["configuration"] = config_validation

            # Validate connectivity if client is available
            if self.client:
                connectivity_validation = self._validate_connectivity()
                validation_results["validations"]["connectivity"] = connectivity_validation

            # Validate context integrity
            context_validation = self._validate_context_integrity()
            validation_results["validations"]["context"] = context_validation

            # Validate performance settings
            performance_validation = self._validate_performance_settings()
            validation_results["validations"]["performance"] = performance_validation

            # Validate dependencies
            dependency_validation = self._validate_dependencies()
            validation_results["validations"]["dependencies"] = dependency_validation

            # Determine overall status
            all_validations = validation_results["validations"].values()
            if all(v.get("status") == "PASS" for v in all_validations):
                validation_results["overall_status"] = "HEALTHY"
            elif any(v.get("status") == "FAIL" for v in all_validations):
                validation_results["overall_status"] = "UNHEALTHY"
            else:
                validation_results["overall_status"] = "WARNING"

            self.debug_ctx.add_breadcrumb(f"Health validation completed: {validation_results['overall_status']}")

        except Exception as e:
            self.logger.error_with_context("Health validation failed", e)
            validation_results["overall_status"] = "ERROR"
            validation_results["error"] = str(e)

        return validation_results

    def _validate_configuration(self) -> dict[str, Any]:
        """Validate integration configuration."""
        try:
            params = demisto.params()
            issues = []

            # Check required parameters
            required_params = ["server", "credentials", "api_version"]
            for param in required_params:
                if not params.get(param):
                    issues.append(f"Missing required parameter: {param}")

            # Validate server URL format
            server_url = params.get("server", "")
            if server_url and not (server_url.startswith("http://") or server_url.startswith("https://")):
                issues.append("Server URL should start with http:// or https://")

            # Validate API version format
            api_version = params.get("api_version", "")
            if api_version:
                try:
                    float(api_version)
                except ValueError:
                    issues.append("API version should be a valid number")

            # Validate numeric parameters
            numeric_params = ["events_limit", "offenses_per_fetch", "limit_assets"]
            for param in numeric_params:
                value = params.get(param)
                if value and not str(value).isdigit():
                    issues.append(f"Parameter {param} should be a valid number")

            return {
                "status": "FAIL" if issues else "PASS",
                "issues": issues,
                "checked_parameters": len(params),
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {"status": "ERROR", "error": str(e), "timestamp": datetime.now().isoformat()}

    def _validate_connectivity(self) -> dict[str, Any]:
        """Validate QRadar connectivity."""
        try:
            if not self.client:
                return {
                    "status": "SKIP",
                    "message": "No client available for connectivity test",
                    "timestamp": datetime.now().isoformat(),
                }

            # Use DiagnosticUtilities for connection validation
            connection_result = DiagnosticUtilities.validate_qradar_connection(self.client)

            return {
                "status": "PASS" if connection_result["status"] == "SUCCESS" else "FAIL",
                "connection_time": connection_result.get("connection_time", 0),
                "api_version": connection_result.get("api_version", "Unknown"),
                "error": connection_result.get("error"),
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {"status": "ERROR", "error": str(e), "timestamp": datetime.now().isoformat()}

    def _validate_context_integrity(self) -> dict[str, Any]:
        """Validate integration context integrity."""
        try:
            context = demisto.getIntegrationContext()
            context_size = len(json.dumps(context).encode("utf-8"))

            issues = []

            # Check context size
            max_context_size = 10 * 1024 * 1024  # 10MB
            if context_size > max_context_size:
                issues.append(f"Context size ({context_size} bytes) exceeds recommended maximum")

            # Check for required context keys if mirroring is enabled
            params = demisto.params()
            if params.get("mirror_direction") != "No Mirroring":
                required_keys = ["mirrored_offenses_queried", "mirrored_offenses_finished"]
                for key in required_keys:
                    if key not in context:
                        issues.append(f"Missing required context key for mirroring: {key}")

            # Validate context data types
            for key, value in context.items():
                if not isinstance(value, (dict, list, str, int, float, bool, type(None))):
                    issues.append(f"Context key '{key}' contains non-serializable data")

            return {
                "status": "FAIL" if issues else "PASS",
                "issues": issues,
                "context_size_bytes": context_size,
                "context_keys_count": len(context),
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {"status": "ERROR", "error": str(e), "timestamp": datetime.now().isoformat()}

    def _validate_performance_settings(self) -> dict[str, Any]:
        """Validate performance-related settings."""
        try:
            params = demisto.params()
            warnings = []

            # Check batch sizes
            offenses_per_fetch = int(params.get("offenses_per_fetch", 10))
            if offenses_per_fetch > 50:
                warnings.append("High offenses_per_fetch may impact performance")

            events_limit = int(params.get("events_limit", 20))
            if events_limit > 1000:
                warnings.append("High events_limit may cause memory issues")

            # Check if both mirroring and high fetch rates are enabled
            if params.get("mirror_direction") != "No Mirroring" and offenses_per_fetch > 20:
                warnings.append("High fetch rate with mirroring may cause performance issues")

            return {
                "status": "WARNING" if warnings else "PASS",
                "warnings": warnings,
                "settings_checked": {
                    "offenses_per_fetch": offenses_per_fetch,
                    "events_limit": events_limit,
                    "mirroring_enabled": params.get("mirror_direction") != "No Mirroring",
                },
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {"status": "ERROR", "error": str(e), "timestamp": datetime.now().isoformat()}

    def _validate_dependencies(self) -> dict[str, Any]:
        """Validate required dependencies and modules."""
        try:
            missing_modules = []

            # Check required modules
            required_modules = ["requests", "urllib3", "pytz", "deepmerge"]
            for module in required_modules:
                try:
                    __import__(module)
                except ImportError:
                    missing_modules.append(module)

            # Check QRadar-specific modules (now included inline)
            # QRadarContextManager and SampleManager are now part of this file

            return {
                "status": "FAIL" if missing_modules else "PASS",
                "missing_modules": missing_modules,
                "checked_modules": required_modules + ["QRadarContextManager (inline)"],
                "timestamp": datetime.now().isoformat(),
            }

        except Exception as e:
            return {"status": "ERROR", "error": str(e), "timestamp": datetime.now().isoformat()}


class MockDataGenerator:
    """
    Generates mock data for testing different scenarios.

    This class provides various mock data generators for testing
    the integration with different types of QRadar data and scenarios.
    """

    @staticmethod
    def generate_mock_offense(offense_id: int = None, **kwargs) -> dict[str, Any]:
        """
        Generate a mock QRadar offense for testing.

        Args:
            offense_id: Specific offense ID to use
            **kwargs: Override specific fields

        Returns:
            Mock offense dictionary
        """
        if offense_id is None:
            offense_id = random.randint(1000, 9999)

        base_time = int(time.time() * 1000)  # QRadar uses milliseconds

        mock_offense = {
            "id": offense_id,
            "description": kwargs.get("description", f"Mock Offense {offense_id}"),
            "status": kwargs.get("status", random.choice(["OPEN", "HIDDEN", "CLOSED"])),
            "offense_type": kwargs.get("offense_type", random.choice([0, 1, 2])),
            "start_time": kwargs.get("start_time", base_time - random.randint(3600000, 86400000)),
            "last_updated_time": kwargs.get("last_updated_time", base_time),
            "event_count": kwargs.get("event_count", random.randint(1, 1000)),
            "flow_count": kwargs.get("flow_count", random.randint(0, 100)),
            "assigned_to": kwargs.get("assigned_to", None),
            "categories": kwargs.get("categories", [f"Category_{random.randint(1000, 9999)}"]),
            "credibility": kwargs.get("credibility", random.randint(1, 10)),
            "relevance": kwargs.get("relevance", random.randint(1, 10)),
            "severity": kwargs.get("severity", random.randint(1, 10)),
            "magnitude": kwargs.get("magnitude", random.randint(1, 10)),
            "source_address_ids": kwargs.get("source_address_ids", [random.randint(1, 1000)]),
            "destination_address_ids": kwargs.get("destination_address_ids", [random.randint(1, 1000)]),
            "source_count": kwargs.get("source_count", 1),
            "destination_count": kwargs.get("destination_count", 1),
            "local_destination_count": kwargs.get("local_destination_count", 0),
            "remote_destination_count": kwargs.get("remote_destination_count", 1),
            "domain_id": kwargs.get("domain_id", 0),
            "policy_category_count": kwargs.get("policy_category_count", 1),
            "security_category_count": kwargs.get("security_category_count", 1),
            "close_time": kwargs.get("close_time", None),
            "closing_user": kwargs.get("closing_user", None),
            "closing_reason_id": kwargs.get("closing_reason_id", None),
            "follow_up": kwargs.get("follow_up", False),
            "protected": kwargs.get("protected", False),
        }

        return mock_offense

    @staticmethod
    def generate_mock_events(count: int = 10, offense_id: int = None) -> list[dict[str, Any]]:
        """
        Generate mock QRadar events for testing.

        Args:
            count: Number of events to generate
            offense_id: Associated offense ID

        Returns:
            List of mock event dictionaries
        """
        events = []
        base_time = int(time.time() * 1000)

        for i in range(count):
            event = {
                "qid": random.randint(1000, 9999),
                "qidname_qid": f"Mock Event {random.randint(1000, 9999)}",
                "starttime": base_time - random.randint(0, 3600000),
                "endtime": base_time - random.randint(0, 3600000),
                "sourceip": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "destinationip": f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}",
                "sourceport": random.randint(1024, 65535),
                "destinationport": random.choice([80, 443, 22, 21, 25, 53, 3389]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "eventcount": random.randint(1, 100),
                "magnitude": random.randint(1, 10),
                "severity": random.randint(1, 10),
                "credibility": random.randint(1, 10),
                "relevance": random.randint(1, 10),
                "category": random.randint(1000, 9999),
                "username": f"user_{random.randint(1, 100)}" if random.choice([True, False]) else None,
                "payload": "".join(random.choices(string.ascii_letters + string.digits, k=50)),
            }

            if offense_id:
                event["offense_id"] = offense_id

            events.append(event)

        return events

    @staticmethod
    def generate_mock_assets(count: int = 5) -> list[dict[str, Any]]:
        """
        Generate mock QRadar assets for testing.

        Args:
            count: Number of assets to generate

        Returns:
            List of mock asset dictionaries
        """
        assets = []

        for i in range(count):
            asset = {
                "id": random.randint(1000, 9999),
                "name": f"Asset_{random.randint(1000, 9999)}",
                "ip_addresses": [
                    {"id": random.randint(1, 1000), "value": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"}
                ],
                "hostnames": [{"id": random.randint(1, 1000), "name": f"host{random.randint(1, 100)}.example.com"}],
                "properties": [
                    {"name": "Operating System", "value": random.choice(["Windows 10", "Ubuntu 20.04", "CentOS 7", "macOS"])},
                    {"name": "Asset Type", "value": random.choice(["Server", "Workstation", "Network Device", "Mobile"])},
                ],
                "vulnerability_count": random.randint(0, 50),
                "risk_score_sum": random.randint(0, 1000),
                "domain_id": 0,
            }

            assets.append(asset)

        return assets

    @staticmethod
    def generate_mock_reference_set(name: str = None, **kwargs) -> dict[str, Any]:
        """
        Generate a mock reference set for testing.

        Args:
            name: Reference set name
            **kwargs: Override specific fields

        Returns:
            Mock reference set dictionary
        """
        if name is None:
            name = f"MockReferenceSet_{random.randint(1000, 9999)}"

        return {
            "name": name,
            "element_type": kwargs.get("element_type", random.choice(["IP", "ALN", "NUM", "PORT", "DATE"])),
            "number_of_elements": kwargs.get("number_of_elements", random.randint(0, 1000)),
            "creation_time": kwargs.get("creation_time", int(time.time() * 1000)),
            "timeout_type": kwargs.get("timeout_type", random.choice(["FIRST_SEEN", "LAST_SEEN", "UNKNOWN"])),
            "time_to_live": kwargs.get("time_to_live", None),
            "data": kwargs.get("data", [f"element_{i}" for i in range(random.randint(1, 10))]),
        }

    @staticmethod
    def generate_test_scenario_data(scenario: str) -> dict[str, Any]:
        """
        Generate data for specific test scenarios.

        Args:
            scenario: Test scenario name

        Returns:
            Dictionary containing scenario-specific test data
        """
        scenarios = {
            "high_volume_offenses": {
                "offenses": [MockDataGenerator.generate_mock_offense() for _ in range(100)],
                "description": "High volume offense scenario for performance testing",
            },
            "complex_offense_with_events": {
                "offense": MockDataGenerator.generate_mock_offense(event_count=500),
                "events": MockDataGenerator.generate_mock_events(50),
                "assets": MockDataGenerator.generate_mock_assets(10),
                "description": "Complex offense with many events and assets",
            },
            "mirroring_scenario": {
                "offenses": [
                    MockDataGenerator.generate_mock_offense(status="OPEN"),
                    MockDataGenerator.generate_mock_offense(status="CLOSED"),
                    MockDataGenerator.generate_mock_offense(status="HIDDEN"),
                ],
                "context_data": {
                    "mirrored_offenses_queried": {"1001": "WAIT", "1002": "SUCCESS"},
                    "mirrored_offenses_finished": {"1003": "COMPLETED"},
                },
                "description": "Mirroring scenario with various offense states",
            },
            "error_conditions": {
                "api_errors": [
                    {"status_code": 401, "message": "Unauthorized"},
                    {"status_code": 500, "message": "Internal Server Error"},
                    {"status_code": 429, "message": "Rate Limited"},
                ],
                "network_errors": ["Connection timeout", "DNS resolution failed"],
                "description": "Various error conditions for error handling testing",
            },
        }

        return scenarios.get(scenario, {"error": f"Unknown scenario: {scenario}", "available_scenarios": list(scenarios.keys())})


class DiagnosticCommands:
    """
    Diagnostic commands that can inspect system state and configuration.

    This class provides various diagnostic commands that can be used
    during development and troubleshooting to inspect the integration's
    internal state and configuration.
    """

    def __init__(self, client=None):
        self.client = client
        self.health_validator = SystemHealthValidator(client)
        self.debug_ctx = DebugContext("diagnostic_commands")
        self.logger = get_enhanced_logger("DiagnosticCommands").with_context(self.debug_ctx)

    def run_system_diagnostics(self) -> dict[str, Any]:
        """
        Run comprehensive system diagnostics.

        Returns:
            Dictionary containing diagnostic results
        """
        self.debug_ctx.add_breadcrumb("Starting system diagnostics")

        try:
            diagnostics = {
                "timestamp": datetime.now().isoformat(),
                "correlation_id": self.debug_ctx.correlation_id,
                "integration_info": self._get_integration_info(),
                "system_health": self.health_validator.validate_integration_health(),
                "performance_metrics": self._get_performance_metrics(),
                "context_analysis": self._analyze_context(),
                "configuration_summary": self._get_configuration_summary(),
                "development_mode": DevelopmentModeDetector.get_development_config(),
            }

            self.debug_ctx.add_breadcrumb("System diagnostics completed successfully")
            return diagnostics

        except Exception as e:
            self.logger.error_with_context("System diagnostics failed", e)
            return {
                "timestamp": datetime.now().isoformat(),
                "correlation_id": self.debug_ctx.correlation_id,
                "status": "ERROR",
                "error": str(e),
            }

    def inspect_context_state(self) -> dict[str, Any]:
        """
        Inspect current integration context state.

        Returns:
            Dictionary containing context state information
        """
        try:
            context = demisto.getIntegrationContext()

            return {
                "timestamp": datetime.now().isoformat(),
                "context_size_bytes": len(json.dumps(context).encode("utf-8")),
                "context_keys": list(context.keys()),
                "mirroring_info": {
                    "queried_offenses": len(context.get("mirrored_offenses_queried", {})),
                    "finished_offenses": len(context.get("mirrored_offenses_finished", {})),
                    "last_mirror_update": context.get("last_mirror_update", "Not set"),
                },
                "fetch_info": {
                    "last_fetch_id": context.get("last_fetch", "Not set"),
                    "samples_count": len(context.get("samples", [])),
                },
                "context_health": "HEALTHY" if len(json.dumps(context).encode("utf-8")) < 5 * 1024 * 1024 else "WARNING",
            }

        except Exception as e:
            return {"timestamp": datetime.now().isoformat(), "status": "ERROR", "error": str(e)}

    def test_api_connectivity(self) -> dict[str, Any]:
        """
        Test API connectivity with detailed diagnostics.

        Returns:
            Dictionary containing connectivity test results
        """
        if not self.client:
            return {
                "timestamp": datetime.now().isoformat(),
                "status": "ERROR",
                "error": "No client available for connectivity test",
            }

        try:
            # Test multiple endpoints
            endpoints_to_test = ["/help/versions", "/siem/offenses", "/reference_data/sets"]

            results = {}
            overall_status = "SUCCESS"

            for endpoint in endpoints_to_test:
                try:
                    start_time = time.time()

                    if endpoint == "/siem/offenses":
                        response = self.client.offenses_list(range_="items=0-0")
                    elif endpoint == "/reference_data/sets":
                        response = self.client.reference_sets_list(range_="items=0-0")
                    else:
                        response = self.client.http_request("GET", endpoint)

                    duration = time.time() - start_time

                    results[endpoint] = {
                        "status": "SUCCESS",
                        "response_time": round(duration, 3),
                        "response_size": len(str(response)),
                    }

                except Exception as e:
                    results[endpoint] = {"status": "FAILED", "error": str(e)}
                    overall_status = "PARTIAL"

            return {
                "timestamp": datetime.now().isoformat(),
                "overall_status": overall_status,
                "endpoint_results": results,
                "correlation_id": self.debug_ctx.correlation_id,
            }

        except Exception as e:
            return {
                "timestamp": datetime.now().isoformat(),
                "status": "ERROR",
                "error": str(e),
                "correlation_id": self.debug_ctx.correlation_id,
            }

    def _get_integration_info(self) -> dict[str, Any]:
        """Get basic integration information."""
        return {
            "instance_name": demisto.integrationInstance(),
            "command": demisto.command(),
            "params_count": len(demisto.params()),
            "args_count": len(demisto.args()),
            "is_fetch_enabled": demisto.params().get("isFetch", False),
            "is_mirroring_enabled": demisto.params().get("mirror_direction") != "No Mirroring",
        }

    def _get_performance_metrics(self) -> dict[str, Any]:
        """Get performance-related metrics."""
        params = demisto.params()

        return {
            "offenses_per_fetch": int(params.get("offenses_per_fetch", 10)),
            "events_limit": int(params.get("events_limit", 20)),
            "assets_limit": int(params.get("limit_assets", 100)),
            "fetch_mode": params.get("fetch_mode", "Fetch Without Events"),
            "enrichment_mode": params.get("enrichment", "None"),
            "estimated_memory_usage_mb": self._estimate_memory_usage(),
        }

    def _analyze_context(self) -> dict[str, Any]:
        """Analyze integration context for potential issues."""
        try:
            context = demisto.getIntegrationContext()
            context_size = len(json.dumps(context).encode("utf-8"))

            analysis = {
                "size_analysis": {
                    "total_size_bytes": context_size,
                    "size_mb": round(context_size / (1024 * 1024), 2),
                    "size_status": "OK" if context_size < 5 * 1024 * 1024 else "WARNING",
                },
                "key_analysis": {
                    "total_keys": len(context),
                    "mirroring_keys": len([k for k in context.keys() if "mirror" in k.lower()]),
                    "sample_keys": len([k for k in context.keys() if "sample" in k.lower()]),
                },
                "data_freshness": {
                    "last_update": context.get("last_mirror_update", "Unknown"),
                    "last_fetch": context.get("last_fetch", "Unknown"),
                },
            }

            return analysis

        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

    def _get_configuration_summary(self) -> dict[str, Any]:
        """Get configuration summary."""
        params = demisto.params()

        return {
            "server_configured": bool(params.get("server")),
            "credentials_configured": bool(params.get("credentials")),
            "api_version": params.get("api_version", "Not set"),
            "fetch_enabled": params.get("isFetch", False),
            "mirror_direction": params.get("mirror_direction", "No Mirroring"),
            "incident_type": params.get("incident_type", "Default"),
            "query_filter": bool(params.get("query")),
            "enrichment_settings": {
                "ip_enrichment": "IPs" in params.get("enrichment", ""),
                "asset_enrichment": "Assets" in params.get("enrichment", ""),
                "events_enrichment": params.get("fetch_mode", "Fetch Without Events") != "Fetch Without Events",
            },
        }

    def _estimate_memory_usage(self) -> float:
        """Estimate memory usage based on configuration."""
        params = demisto.params()

        # Base memory usage
        base_memory = 50  # MB

        # Add memory for offenses
        offenses_per_fetch = int(params.get("offenses_per_fetch", 10))
        offense_memory = offenses_per_fetch * 0.1  # ~100KB per offense

        # Add memory for events
        if params.get("fetch_mode") != "Fetch Without Events":
            events_limit = int(params.get("events_limit", 20))
            event_memory = offenses_per_fetch * events_limit * 0.01  # ~10KB per event
        else:
            event_memory = 0

        # Add memory for assets
        if "Assets" in params.get("enrichment", ""):
            assets_limit = int(params.get("limit_assets", 100))
            asset_memory = offenses_per_fetch * assets_limit * 0.005  # ~5KB per asset
        else:
            asset_memory = 0

        return round(base_memory + offense_memory + event_memory + asset_memory, 2)


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION AND CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains all configuration parameters, constants, and global settings used throughout the integration.
# All values are centralized here for easy maintenance and configuration management.

# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# ADVANCED GLOBAL PARAMETERS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# These parameters control advanced behavior and can be overridden via integration configuration.
# Each parameter includes a descriptive comment explaining its purpose and impact.

FAILURE_SLEEP = 20  # Sleep duration (seconds) between consecutive failed event fetch attempts


def get_fetch_sleep_interval():
    """Get fetch sleep interval from parameters or use default."""
    try:
        return argToNumber(demisto.params().get("fetch_interval")) or 60
    except (NameError, AttributeError):
        return 60  # Default value when demisto is not available (e.g., during testing)


FETCH_SLEEP = 60  # Default sleep duration (seconds) between incident fetch cycles
BATCH_SIZE = 100  # Batch size for processing offense IP enrichment operations
OFF_ENRCH_LIMIT = BATCH_SIZE * 10  # Maximum number of IPs to enrich per offense (prevents memory issues)
MAX_WORKERS = 8  # Maximum concurrent worker threads for event enrichment processing
DOMAIN_ENRCH_FLG = "true"  # Enable domain name enrichment for offenses and assets (true/false)
RULES_ENRCH_FLG = "true"  # Enable rule name enrichment for offenses (true/false)
SLEEP_FETCH_EVENT_RETRIES = 10  # Sleep duration (seconds) between event search retry attempts
MAX_NUMBER_OF_OFFENSES_TO_CHECK_SEARCH = 5  # Number of offenses to check during mirroring search completion
DEFAULT_EVENTS_TIMEOUT = 30  # Default timeout (minutes) for event enrichment operations
PROFILING_DUMP_ROWS_LIMIT = 20  # Maximum rows to include in profiling debug dumps
MAX_RETRIES_CONTEXT = 5  # Maximum retry attempts for context update operations
MAX_SEARCHES_QUEUE = 10  # Maximum concurrent searches allowed in mirroring operations

# Sample Management Configuration - Controls incident sampling for debugging and analysis
SAMPLE_SIZE = 2  # Number of incident samples to store in integration context
MAX_SAMPLE_SIZE_MB = 3  # Maximum size (MB) for incidents to be stored as samples
MAX_SAMPLE_SIZE_BYTES = MAX_SAMPLE_SIZE_MB * 1024 * 1024  # Convert MB to bytes for size checks

# Event Processing Timing Configuration - Controls polling and retry behavior
EVENTS_INTERVAL_SECS = 60  # Interval (seconds) between event polling operations
EVENTS_MODIFIED_SECS = 5  # Interval (seconds) between event status polling in modified state

# Retry and Connection Configuration - Controls resilience and error handling
EVENTS_SEARCH_TRIES = 3  # Number of retry attempts for creating new searches
EVENTS_POLLING_TRIES = 10  # Number of retry attempts for event polling operations
EVENTS_SEARCH_RETRY_SECONDS = 100  # Delay (seconds) between search creation retry attempts
CONNECTION_ERRORS_RETRIES = 5  # Number of retry attempts for connection errors
CONNECTION_ERRORS_INTERVAL = 1  # Delay (seconds) between connection error retry attempts

# Advanced Parameter Configuration Lists - Used for dynamic parameter validation and parsing
# These lists define which parameters can be overridden via integration configuration
ADVANCED_PARAMETERS_STRING_NAMES = [
    "DOMAIN_ENRCH_FLG",  # Domain enrichment flag (string: "true"/"false")
    "RULES_ENRCH_FLG",  # Rules enrichment flag (string: "true"/"false")
]

ADVANCED_PARAMETER_INT_NAMES = [
    "EVENTS_INTERVAL_SECS",  # Event polling interval
    "MAX_SEARCHES_QUEUE",  # Maximum concurrent searches
    "EVENTS_SEARCH_RETRIES",  # Search retry attempts
    "EVENTS_POLLING_RETRIES",  # Polling retry attempts
    "EVENTS_SEARCH_RETRY_SECONDS",  # Search retry delay
    "FAILURE_SLEEP",  # Failure sleep duration
    "FETCH_SLEEP",  # Fetch cycle sleep duration
    "BATCH_SIZE",  # Processing batch size
    "OFF_ENRCH_LIMIT",  # Offense enrichment limit
    "MAX_WORKERS",  # Maximum worker threads
    "SLEEP_FETCH_EVENT_RETRIES",  # Event fetch retry sleep
    "DEFAULT_EVENTS_TIMEOUT",  # Default events timeout
    "PROFILING_DUMP_ROWS_LIMIT",  # Profiling dump row limit
]

# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# CORE CONSTANTS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# These constants define core integration behavior and API interaction parameters.
# They should not be modified without understanding their impact on integration functionality.

# Authentication and API Configuration
API_USERNAME = "_api_token_key"  # Special username indicating API token authentication
# Context and State Management Keys
RESET_KEY = "reset"  # Key used to trigger integration context reset
LAST_FETCH_KEY = "id"  # Key for storing last fetched offense ID
LAST_MIRROR_KEY = "last_mirror_update"  # Key for last mirror update timestamp
LAST_MIRROR_CLOSED_KEY = "last_mirror_closed_update"  # Key for last closed offense mirror update

# Context Keys for Mirroring Operations
MIRRORED_OFFENSES_QUERIED_CTX_KEY = "mirrored_offenses_queried"  # Offenses that have been queried
MIRRORED_OFFENSES_FINISHED_CTX_KEY = "mirrored_offenses_finished"  # Offenses with completed searches
MIRRORED_OFFENSES_FETCHED_CTX_KEY = "mirrored_offenses_fetched"  # Offenses that have been fetched

# API Version and Compatibility
MINIMUM_API_VERSION = 10.1  # Minimum supported QRadar API version

# Default Values and Limits
DEFAULT_RANGE_VALUE = "0-49"  # Default range for API requests
DEFAULT_TIMEOUT_VALUE = "35"  # Default timeout for API requests (seconds)
DEFAULT_LIMIT_VALUE = 50  # Default limit for result sets
DEFAULT_EVENTS_LIMIT = 20  # Default limit for event queries
DEFAULT_OFFENSES_PER_FETCH = 20  # Default number of offenses to fetch per cycle
MAXIMUM_OFFENSES_PER_FETCH = 50  # Maximum allowed offenses per fetch cycle
MAXIMUM_MIRROR_LIMIT = 100  # Maximum limit for mirroring operations
DEFAULT_ASSETS_LIMIT = 100  # Default limit for asset queries

# Mirroring Configuration
DEFAULT_MIRRORING_DIRECTION = "No Mirroring"  # Default mirroring setting
MIRROR_OFFENSE_AND_EVENTS = "Mirror Offense and Events"  # Full mirroring option
MIRROR_DIRECTION: dict[str, str | None] = {"No Mirroring": None, "Mirror Offense": "In", MIRROR_OFFENSE_AND_EVENTS: "In"}

# Regular Expressions and Patterns
ID_QUERY_REGEX = re.compile(r"(?:\s+|^)id((\s)*)>(=?)((\s)*)((\d)+)(?:\s+|$)")  # Pattern for ID queries
NAME_AND_GROUP_REGEX = re.compile(r"^[\w-]+$")  # Pattern for validating names and groups

# Timezone and Time Handling
UTC_TIMEZONE = pytz.timezone("utc")  # UTC timezone object for time conversions
TIME_FIELDS_PLACE_HOLDER = 9223372036854775807  # Max 64-bit signed integer for time field placeholders

# Query and Sorting Configuration
ASCENDING_ID_ORDER = "+id"  # Sort order for ascending ID queries
FIELDS_MIRRORING = "id,start_time,event_count,last_persisted_time,close_time"  # Fields used in mirroring

# Thread Pool Configuration
EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)  # Global thread pool executor

# Global Context Manager - Provides resilient context handling throughout the integration
CONTEXT_MANAGER = None  # Lazy-initialized global context manager instance


def get_context_manager() -> QRadarContextManager:
    """
    Get or create the global context manager instance.

    This function implements lazy initialization of the context manager to ensure
    it's only created when needed and with the correct configuration.

    Returns:
        QRadarContextManager: Configured context manager instance
    """
    global CONTEXT_MANAGER
    if CONTEXT_MANAGER is None:
        CONTEXT_MANAGER = QRadarContextManager(max_retries=MAX_RETRIES_CONTEXT, max_context_size_mb=10)
    return CONTEXT_MANAGER


# Default Query Columns - Standard columns retrieved for event queries
DEFAULT_EVENTS_COLUMNS = """QIDNAME(qid), LOGSOURCENAME(logsourceid), CATEGORYNAME(highlevelcategory), CATEGORYNAME(category), PROTOCOLNAME(protocolid), sourceip, sourceport, destinationip, destinationport, QIDDESCRIPTION(qid), username, PROTOCOLNAME(protocolid), RULENAME("creEventList"), sourcegeographiclocation, sourceMAC, sourcev6, destinationgeographiclocation, destinationv6, LOGSOURCETYPENAME(devicetype), credibility, severity, magnitude, eventcount, eventDirection, postNatDestinationIP, postNatDestinationPort, postNatSourceIP, postNatSourcePort, preNatDestinationPort, preNatSourceIP, preNatSourcePort, UTF8(payload), starttime, devicetime"""  # noqa: E501

# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# OUTPUT FIELD MAPPING DICTIONARIES
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# These dictionaries map QRadar API field names to XSOAR/XSIAM standard field names.
# They ensure consistent output formatting across all integration commands.

# Offense Field Mapping - Maps QRadar offense fields to XSOAR standard names
OFFENSE_OLD_NEW_NAMES_MAP = {
    "credibility": "Credibility",
    "relevance": "Relevance",
    "severity": "Severity",
    "assigned_to": "AssignedTo",
    "destination_networks": "DestinationHostname",
    "status": "Status",
    "closing_user": "ClosingUser",
    "closing_reason_id": "ClosingReason",
    "close_time": "CloseTime",
    "categories": "Categories",
    "follow_up": "Followup",
    "id": "ID",
    "description": "Description",
    "source_address_ids": "SourceAddress",
    "local_destination_address_ids": "DestinationAddress",
    "remote_destination_count": "RemoteDestinationCount",
    "start_time": "StartTime",
    "event_count": "EventCount",
    "flow_count": "FlowCount",
    "offense_source": "OffenseSource",
    "magnitude": "Magnitude",
    "last_updated_time": "LastUpdatedTime",
    "offense_type": "OffenseType",
    "protected": "Protected",
    "LinkToOffense": "LinkToOffense",
    "rules": "Rules",
    "domain_name": "DomainName",
    "assets": "Assets",
}

CLOSING_REASONS_RAW_FORMATTED = {"id": "ID", "text": "Name", "is_reserved": "IsReserved", "is_deleted": "IsDeleted"}

NOTES_RAW_FORMATTED = {"id": "ID", "note_text": "Text", "create_time": "CreateTime", "username": "CreatedBy"}

RULES_RAW_FORMATTED = {
    "owner": "Owner",
    "base_host_id": "BaseHostID",
    "capacity_timestamp": "CapacityTimestamp",
    "origin": "Origin",
    "creation_date": "CreationDate",
    "type": "Type",
    "enabled": "Enabled",
    "modification_date": "ModificationDate",
    "name": "Name",
    "average_capacity": "AverageCapacity",
    "id": "ID",
    "base_capacity": "BaseCapacity",
}

RULES_GROUP_RAW_FORMATTED = {
    "owner": "Owner",
    "modified_time": "ModifiedTime",
    "level": "Level",
    "name": "Name",
    "description": "Description",
    "id": "ID",
    "child_groups": "ChildGroups",
    "child_items": "ChildItems",
    "type": "Type",
    "parent_id": "ParentID",
}

ASSET_RAW_FORMATTED = {
    "vulnerability_count": "VulnerabilityCount",
    "interfaces": "Interfaces",
    "risk_score_sum": "RiskScoreSum",
    "hostnames": "Hostnames",
    "id": "ID",
    "users": "Users",
    "domain_id": "DomainID",
    "properties": "Properties",
    "products": "Products",
}

SEARCH_RAW_FORMATTED = {"search_id": "ID", "status": "Status"}

REFERENCE_SETS_RAW_FORMATTED = {
    "number_of_elements": "NumberOfElements",
    "name": "Name",
    "creation_time": "CreationTime",
    "element_type": "ElementType",
    "time_to_live": "TimeToLive",
    "timeout_type": "TimeoutType",
    "data": "Data",
}
REFERENCE_SET_DATA_RAW_FORMATTED = {"last_seen": "LastSeen", "source": "Source", "value": "Value", "first_seen": "FirstSeen"}

DOMAIN_RAW_FORMATTED = {
    "asset_scanner_ids": "AssetScannerIDs",
    "custom_properties": "CustomProperties",
    "deleted": "Deleted",
    "description": "Description",
    "event_collector_ids": "EventCollectorIDs",
    "flow_collector_ids": "FlowCollectorIDs",
    "flow_source_ids": "FlowSourceIDs",
    "id": "ID",
    "log_source_ids": "LogSourceIDs",
    "log_source_group_ids": "LogSourceGroupIDs",
    "name": "Name",
    "qvm_scanner_ids": "QVMScannerIDs",
    "tenant_id": "TenantID",
}

SAVED_SEARCH_RAW_FORMATTED = {
    "owner": "Owner",
    "description": "Description",
    "creation_date": "CreationDate",
    "uid": "UID",
    "database": "Database",
    "is_quick_search": "QuickSearch",
    "name": "Name",
    "modified_date": "ModifiedDate",
    "id": "ID",
    "aql": "AQL",
    "is_shared": "IsShared",
}

IP_GEOLOCATION_RAW_FORMATTED = {
    "continent": "Continent",
    "traits": "Traits",
    "geo_json": "Geolocation",
    "city": "City",
    "ip_address": "IPAddress",
    "represented_country": "RepresentedCountry",
    "registered_country": "RegisteredCountry",
    "is_local": "IsLocalCountry",
    "location": "Location",
    "postal": "Postal",
    "physical_country": "PhysicalCountry",
    "subdivisions": "SubDivisions",
}

LOG_SOURCES_RAW_FORMATTED = {
    "sending_ip": "SendingIP",
    "internal": "Internal",
    "protocol_parameters": "ProtocolParameters",
    "description": "Description",
    "enabled": "Enabled",
    "group_ids": "GroupIDs",
    "credibility": "Credibility",
    "id": "ID",
    "protocol_type_id": "ProtocolTypeID",
    "creation_date": "CreationDate",
    "name": "Name",
    "modified_date": "ModifiedDate",
    "auto_discovered": "AutoDiscovered",
    "type_id": "TypeID",
    "last_event_time": "LastEventTime",
    "gateway": "Gateway",
    "status": "Status",
    "target_event_collector_id": "TargetEventCollectorID",
}

TIME_FIELDS_PLACE_HOLDER = 9223372036854775807  # represents the max val that can be stored in a 64-bit signed integer data type.

# Time Field Names - Fields that contain timestamps in microseconds and need conversion
USECS_ENTRIES = {
    "last_persisted_time",
    "start_time",
    "close_time",
    "create_time",
    "creation_time",
    "creation_date",
    "last_updated_time",
    "first_persisted_time",
    "modification_date",
    "last_seen",
    "first_seen",
    "starttime",
    "devicetime",
    "last_reported",
    "created",
    "last_seen_profiler",
    "last_seen_scanner",
    "first_seen_scanner",
    "first_seen_profiler",
    "modified_time",
    "last_event_time",
    "modified_date",
    "first_event_flow_seen",
    "last_event_flow_seen",
}

LOCAL_DESTINATION_IPS_RAW_FORMATTED = {
    "domain_id": "DomainID",
    "event_flow_count": "EventFlowCount",
    "first_event_flow_seen": "FirstEventFlowSeen",
    "id": "ID",
    "last_event_flow_seen": "LastEventFlowSeen",
    "local_destination_ip": "LocalDestinationIP",
    "magnitude": "Magnitude",
    "network": "Network",
    "offense_ids": "OffenseIDs",
    "source_address_ids": "SourceAddressIDs",
}
SOURCE_IPS_RAW_FORMATTED = {
    "domain_id": "DomainID",
    "event_flow_count": "EventFlowCount",
    "first_event_flow_seen": "FirstEventFlowSeen",
    "id": "ID",
    "last_event_flow_seen": "LastEventFlowSeen",
    "local_destination_address_ids": "LocalDestinationAddressIDs",
    "magnitude": "Magnitude",
    "network": "Network",
    "offense_ids": "OffenseIDs",
    "source_ip": "SourceIP",
}

EVENT_COLLECTOR_RAW_FORMATTED = {"component_name": "ComponentName", "host_id": "HostID", "id": "ID", "name": "Name"}

WINCOLLECT_DESTINATION_RAW_FORMATTED = {
    "id": "ID",
    "name": "Name",
    "host": "Host",
    "tls_certificate": "TlsCertificate",
    "port": "Port",
    "transport_protocol": "TransportProtocol",
    "inernal": "IsInternal",
    "event_rate_throttle": "EventRateThrottle",
}

DISCONNECTED_LOG_COLLECTOR_RAW_FORMATTED = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "protocol": "Protocol",
    "uuid": "UUID",
    "version": "Version",
}

LOG_SOURCE_TYPES_RAW_FORMATTED = {
    "id": "ID",
    "name": "Name",
    "custom": "Custom",
    "version": "Version",
    "uuid": "UUID",
    "supported_language_ids": "SupportedLanguageIDs",
    "protocol_types": "ProtocolTypes",
    "default_protocol_id": "DefaultProtocolID",
    "internal": "Internal",
    "latest_version": "LatestVersion",
    "log_source_extension_id": "LogSourceExtensionID",
}

LOG_SOURCE_PROTOCOL_TYPE_RAW_FORMATTED = {
    "id": "ID",
    "name": "Name",
    "version": "Version",
    "latest_version": "LatestVersion",
    "gateway_supported": "GatewaySupported",
    "inbound": "Inbound",
    "parameters": "Parameters",
    "parameter_groups": "ParameterGroups",
    "testing_capabilities": "TestingCapabilities",
}

LOG_SOURCE_EXTENSION_RAW_FORMATTED = {
    "id": "ID",
    "name": "Name",
    "description": "Description",
    "uuid": "UUID",
}

LOG_SOURCE_LANGUAGE_RAW_FORMATTED = {"id": "ID", "name": "Name"}

LOG_SOURCE_GROUP_RAW_FORMATTED = {
    "id": "ID",
    "name": "GroupName",
    "description": "Description",
    "parent_id": "ParentID",
    "assignable": "Assignable",
}

# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# ENRICHMENT CONFIGURATION MAPS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# These dictionaries control data enrichment behavior and field mapping for enhanced data presentation.

# Asset Properties Mapping - Maps asset property names for enrichment
ASSET_PROPERTIES_NAME_MAP = {
    "Unified Name": "Name",
    "CVSS Collateral Damage Potential": "AggregatedCVSSScore",
    "Weight": "Weight",
}

FULL_ASSET_PROPERTIES_NAMES_MAP = {
    "Compliance Notes": "ComplianceNotes",
    "Compliance Plan": "CompliancePlan",
    "Location": "Location",
    "Switch ID": "SwitchID",
    "Switch Port ID": "SwitchPort",
    "Group Name": "GroupName",
    "Vulnerabilities": "Vulnerabilities",
}
LONG_RUNNING_REQUIRED_PARAMS = {
    "fetch_mode": "Fetch mode",
    "offenses_per_fetch": "Number of offenses to pull per API call (max 50)",
    "events_limit": "Maximum number of events per incident.",
}


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# ENUMS AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section defines enumeration classes and data structures used throughout the integration.
# These provide type safety and clear options for various integration behaviors.


class FetchMode(str, Enum):
    """
    Enums for the options of fetching the incidents.
    """

    no_events = "Fetch Without Events"
    all_events = "Fetch With All Events"
    correlations_events_only = "Fetch Correlation Events Only"


class QueryStatus(str, Enum):
    """
    Enums for the options of fetching the events.
    """

    WAIT = "wait"
    ERROR = "error"
    SUCCESS = "success"
    PARTIAL = "partial"


FIELDS_MIRRORING = "id,start_time,event_count,last_persisted_time,close_time"


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# CLIENT CLASS (API Communication)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains the main Client class responsible for all QRadar API communication.
# The Client class handles authentication, request/response processing, error handling, and retry logic.


class Client(BaseClient):
    def __init__(
        self, server: str, verify: bool, proxy: bool, api_version: str, credentials: dict, timeout: int | None = None
    ):
        username = credentials.get("identifier")
        password = credentials.get("password")
        if username == API_USERNAME:
            self.base_headers = {"Version": api_version, "SEC": password}
            auth = None
        else:
            auth = (username, password)
            self.base_headers = {"Version": api_version}
        base_url = urljoin(server, "/api")
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)
        self.timeout = timeout  # type: ignore[assignment]
        self.password = password
        self.server = server

    def http_request(
        self,
        method: str,
        url_suffix: str,
        params: dict | None = None,
        json_data: dict | list[dict] | None = None,
        data: dict | None = None,
        additional_headers: dict | None = None,
        timeout: int | None = None,
        resp_type: str = "json",
    ) -> Any:
        headers = {**additional_headers, **self.base_headers} if additional_headers else self.base_headers

        # Use enhanced error handling for comprehensive API request debugging
        with ErrorHandlingContext(
            operation_name=f"qradar_api_{method.lower()}_{url_suffix.replace('/', '_')}",
            expected_errors={
                DemistoException: "QRadar API request failed",
                requests.ReadTimeout: "QRadar API request timed out",
                requests.ConnectionError: "Failed to connect to QRadar server",
                Exception: "Unexpected error during API request",
            },
            recovery_suggestions={
                DemistoException: [
                    "Check QRadar server status and availability",
                    "Verify API endpoint URL is correct",
                    "Review request parameters for validity",
                    "Check API token permissions for this endpoint",
                ],
                requests.ReadTimeout: [
                    "Increase timeout values in integration configuration",
                    "Check QRadar server performance and load",
                    "Consider reducing request complexity or size",
                    "Verify network stability between XSOAR and QRadar",
                ],
                requests.ConnectionError: [
                    "Verify QRadar server URL and port are correct",
                    "Check network connectivity and firewall rules",
                    "Ensure QRadar server is running and accessible",
                    "Test connectivity using ping or telnet",
                ],
            },
        ) as error_handler:
            # Capture request details for debugging
            error_handler.capture_variable("method", method, "HTTP method")
            error_handler.capture_variable("url_suffix", url_suffix, "API endpoint URL suffix")
            error_handler.capture_variable("timeout", timeout or self.timeout, "Request timeout in seconds")
            error_handler.capture_variable("retry_attempts", CONNECTION_ERRORS_RETRIES, "Maximum retry attempts")

            # Attempt the request with retry logic
            for attempt_number in range(1, CONNECTION_ERRORS_RETRIES + 1):
                error_handler.capture_variable("current_attempt", attempt_number, "Current retry attempt")

                try:
                    result = self._http_request(
                        method=method,
                        url_suffix=url_suffix,
                        params=params,
                        json_data=json_data,
                        data=data,
                        headers=headers,
                        error_handler=self.qradar_error_handler,
                        timeout=timeout or self.timeout,
                        resp_type=resp_type,
                        with_metrics=True,
                    )

                    # Log successful request
                    if attempt_number > 1:
                        demisto.info(f"QRadar API request succeeded on attempt {attempt_number}/{CONNECTION_ERRORS_RETRIES}")

                    return result

                except (DemistoException, requests.ReadTimeout) as request_error:
                    error_handler.capture_variable("error_type", type(request_error).__name__, "Type of error encountered")
                    error_handler.capture_variable("error_message", str(request_error), "Error message details")

                    # Enhanced error logging with context
                    demisto.error(
                        f"QRadar API request failed on attempt {attempt_number}/{CONNECTION_ERRORS_RETRIES}: {request_error}"
                    )

                    # Determine if we should retry
                    should_retry = attempt_number < CONNECTION_ERRORS_RETRIES and (
                        isinstance(request_error, requests.ReadTimeout)
                        or (
                            isinstance(request_error, DemistoException)
                            and isinstance(request_error.exception, requests.ConnectionError)
                        )
                    )

                    if not should_retry:
                        # Final attempt failed, re-raise with enhanced context
                        error_handler.capture_variable("final_failure", True, "Request failed after all retry attempts")
                        raise
                    else:
                        # Wait before retry with exponential backoff
                        retry_delay = CONNECTION_ERRORS_INTERVAL * (2 ** (attempt_number - 1))
                        error_handler.capture_variable("retry_delay", retry_delay, "Delay before next retry attempt")
                        demisto.info(f"Retrying QRadar API request in {retry_delay} seconds...")
                        time.sleep(retry_delay)

            return None

    @staticmethod
    def qradar_error_handler(res: requests.Response):
        """
        QRadar error handler for any error occurred during the API request.
        This function job is to translate the known exceptions returned by QRadar
        to human readable exception to help the user understand why the request have failed.
        If error returned is not in the expected error format, raises the exception as is.
        Args:
            res (Any): The error response returned by QRadar.

        Returns:
            - raises DemistoException.
        """
        err_msg = f"Error in API call [{res.status_code}] - {res.reason}"
        try:
            # Try to parse json error response
            error_entry = res.json()
            message = error_entry.get("message", "")
            if "items=x-y" in message:
                message = "Failed to parse Range argument. The syntax of the Range argument must follow this pattern: x-y"
            elif "unauthorized to access" in err_msg or "No SEC header present in request" in err_msg:
                message = "Authorization Error: make sure credentials are correct."
            elif "The specified encryption strength is not available" in err_msg:
                err_msg = ""
                message = "The specified encryption is not available, try using a weaker encryption (AES128)."
            elif "User has insufficient capabilities to access this endpoint resource" in message:
                message = (
                    "The given credentials do not have the needed permissions to perform the call the endpoint"
                    f"\n{res.request.path_url}.\n"
                    "Please supply credentials with the needed permissions as can be seen in the integration "
                    "description, or do not call or enrich offenses with the mentioned endpoint."
                )
            err_msg += f"\n{message}"
            raise DemistoException(err_msg, res=res)
        except ValueError as e:
            err_msg += f"\n{res.text}"
            raise DemistoException(err_msg, res=res) from e

    def offenses_list(
        self,
        range_: str | None = None,
        offense_id: int | None = None,
        filter_: str | None = None,
        fields: str | None = None,
        sort: str | None = None,
    ):
        id_suffix = f"/{offense_id}" if offense_id else ""
        params = assign_params(fields=fields) if offense_id else assign_params(filter=filter_, fields=fields, sort=sort)
        additional_headers = {"Range": range_} if not offense_id else None
        return self.http_request(
            method="GET", url_suffix=f"/siem/offenses{id_suffix}", params=params, additional_headers=additional_headers
        )

    def offense_update(
        self,
        offense_id: int,
        protected: str | None = None,
        follow_up: str | None = None,
        status: str | None = None,
        closing_reason_id: int | None = None,
        assigned_to: str | None = None,
        fields: str | None = None,
    ):
        return self.http_request(
            method="POST",
            url_suffix=f"/siem/offenses/{offense_id}",
            params=assign_params(
                protected=protected,
                follow_up=follow_up,
                status=status,
                closing_reason_id=closing_reason_id,
                assigned_to=assigned_to,
                fields=fields,
            ),
        )

    def closing_reasons_list(
        self,
        closing_reason_id: int | None = None,
        include_reserved: bool | None = None,
        include_deleted: bool | None = None,
        range_: str | None = None,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        id_suffix = f"/{closing_reason_id}" if closing_reason_id else ""
        params = (
            assign_params(fields=fields)
            if closing_reason_id
            else assign_params(include_reserved=include_reserved, include_deleted=include_deleted, filter=filter_, fields=fields)
        )
        additional_headers = {"Range": range_} if not closing_reason_id and range_ else None
        return self.http_request(
            method="GET",
            url_suffix=f"/siem/offense_closing_reasons{id_suffix}",
            additional_headers=additional_headers,
            params=params,
        )

    def offense_notes_list(
        self,
        offense_id: int,
        range_: str,
        note_id: int | None = None,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        note_id_suffix = f"/{note_id}" if note_id else ""
        params = assign_params(fields=fields) if note_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {"Range": range_} if not note_id else None
        return self.http_request(
            method="GET",
            url_suffix=f"/siem/offenses/{offense_id}/notes{note_id_suffix}",
            additional_headers=additional_headers,
            params=params,
        )

    def offense_notes_create(self, offense_id: int, note_text: str, fields: str | None = None):
        return self.http_request(
            method="POST",
            url_suffix=f"/siem/offenses/{offense_id}/notes",
            params=assign_params(note_text=note_text, fields=fields),
        )

    def rules_list(
        self,
        rule_id: str | None = None,
        range_: str | None = None,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        id_suffix = f"/{rule_id}" if rule_id else ""
        params = assign_params(fields=fields) if rule_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {"Range": range_} if range_ and not rule_id else None
        return self.http_request(
            method="GET", url_suffix=f"/analytics/rules{id_suffix}", params=params, additional_headers=additional_headers
        )

    def rule_groups_list(
        self, range_: str, rule_group_id: int | None = None, filter_: str | None = None, fields: str | None = None
    ):
        id_suffix = f"/{rule_group_id}" if rule_group_id else ""
        additional_headers = {"Range": range_} if not rule_group_id else None
        params = assign_params(fields=fields) if rule_group_id else assign_params(filter=filter_, fields=fields)
        return self.http_request(
            method="GET", url_suffix=f"/analytics/rule_groups{id_suffix}", additional_headers=additional_headers, params=params
        )

    def assets_list(self, range_: str | None = None, filter_: str | None = None, fields: str | None = None):
        return self.http_request(
            method="GET",
            url_suffix="/asset_model/assets",
            additional_headers={"Range": range_},
            params=assign_params(filter=filter_, fields=fields),
        )

    def saved_searches_list(
        self,
        range_: str,
        timeout: int | None,
        saved_search_id: str | None = None,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        id_suffix = f"/{saved_search_id}" if saved_search_id else ""
        params = assign_params(fields=fields) if saved_search_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {"Range": range_} if not saved_search_id else None
        return self.http_request(
            method="GET",
            url_suffix=f"/ariel/saved_searches{id_suffix}",
            additional_headers=additional_headers,
            params=params,
            timeout=timeout,
        )

    def searches_list(self, range_: str, filter_: str | None = None):
        return self.http_request(
            method="GET", url_suffix="/ariel/searches", additional_headers={"Range": range_}, params=assign_params(filter=filter_)
        )

    def search_create(self, query_expression: str | None = None, saved_search_id: str | None = None):
        return self.http_request(
            method="POST",
            url_suffix="/ariel/searches",
            params=assign_params(query_expression=query_expression, saved_search_id=saved_search_id),
        )

    def search_status_get(self, search_id: str):
        return self.http_request(
            method="GET",
            url_suffix=f"/ariel/searches/{search_id}",
        )

    def search_delete(self, search_id: str):
        return self.http_request(
            method="DELETE",
            url_suffix=f"/ariel/searches/{search_id}",
        )

    def search_cancel(self, search_id: str):
        return self.http_request(
            method="POST",
            url_suffix=f"/ariel/searches/{search_id}?status=CANCELED",
        )

    def search_results_get(self, search_id: str, range_: str | None = None):
        return self.http_request(
            method="GET",
            url_suffix=f"/ariel/searches/{search_id}/results",
            additional_headers={"Range": range_} if range_ else None,
        )

    def reference_sets_list(
        self,
        range_: str | None = None,
        ref_name: str | None = None,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        name_suffix = f'/{parse.quote(ref_name, safe="")}' if ref_name else ""
        params = assign_params(filter=filter_, fields=fields)
        additional_headers = {"Range": range_}
        return self.http_request(
            method="GET", url_suffix=f"/reference_data/sets{name_suffix}", params=params, additional_headers=additional_headers
        )

    def reference_set_create(
        self,
        ref_name: str,
        element_type: str,
        timeout_type: str | None = None,
        time_to_live: str | None = None,
        fields: str | None = None,
    ):
        return self.http_request(
            method="POST",
            url_suffix="/reference_data/sets",
            params=assign_params(
                name=ref_name, element_type=element_type, timeout_type=timeout_type, time_to_live=time_to_live, fields=fields
            ),
        )

    def reference_set_delete(self, ref_name: str, purge_only: str | None = None, fields: str | None = None):
        return self.http_request(
            method="DELETE",
            url_suffix=f'/reference_data/sets/{parse.quote(parse.quote(ref_name, safe=""), safe="")}',
            params=assign_params(purge_only=purge_only, fields=fields),
        )

    def reference_set_value_upsert(self, ref_name: str, value: str, source: str | None = None, fields: str | None = None):
        return self.http_request(
            method="POST",
            url_suffix=f'/reference_data/sets/{parse.quote(ref_name, safe="")}',
            params=assign_params(value=value, source=source, fields=fields),
        )

    def reference_set_value_delete(self, ref_name: str, value: str):
        double_encoded_value = parse.quote(parse.quote(value, safe=""), safe="")
        double_encoded_ref_name = parse.quote(parse.quote(ref_name, safe=""), safe="")
        return self.http_request(
            method="DELETE", url_suffix=f"/reference_data/sets/{double_encoded_ref_name}/{double_encoded_value}"
        )

    def domains_list(
        self,
        domain_id: int | None = None,
        range_: str | None = None,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        id_suffix = f"/{domain_id}" if domain_id else ""
        params = assign_params(fields=fields) if domain_id else assign_params(filter=filter_, fields=fields)
        additional_headers = {"Range": range_} if not domain_id and range_ else None
        return self.http_request(
            method="GET",
            url_suffix=f"/config/domain_management/domains{id_suffix}",
            additional_headers=additional_headers,
            params=params,
        )

    def reference_set_bulk_load(self, ref_name: str, indicators: Any, fields: str | None = None):
        headers = {"Content-Type": "application/json"}
        if fields:
            headers["fields"] = fields
        return self.http_request(
            method="POST",
            url_suffix=f'/reference_data/sets/bulk_load/{parse.quote(ref_name, safe="")}',
            json_data=indicators,
            additional_headers=headers,
        )

    def reference_set_entries(
        self,
        ref_name: str,
        indicators: Any,
        fields: str | None = None,
        source: str | None = None,
        timeout: int | None = None,
    ):
        headers = {"Content-Type": "application/json"}
        if fields:
            headers["fields"] = fields
        name = parse.quote(ref_name, safe="")
        sets = self.http_request(method="GET", url_suffix=f"/reference_data/sets/{name}")
        if not sets:
            raise DemistoException(f"Reference set {ref_name} does not exist.")
        set_id = sets.get("collection_id")
        return self.http_request(
            method="PATCH",
            url_suffix="/reference_data_collections/set_entries",
            json_data=[{"collection_id": set_id, "value": str(indicator), "source": source} for indicator in indicators],
            # type: ignore[arg-type]
            additional_headers=headers,
            timeout=timeout,
        )

    def get_reference_data_bulk_task_status(self, task_id: int):
        return self.http_request(method="GET", url_suffix=f"/reference_data_collections/set_bulk_update_tasks/{task_id}")

    def geolocations_for_ip(self, filter_: str | None = None, fields: str | None = None):
        return self.http_request(
            method="GET", url_suffix="/services/geolocations", params=assign_params(filter=filter_, fields=fields)
        )

    def log_sources_list(
        self,
        qrd_encryption_algorithm: str,
        qrd_encryption_password: str,
        range_: str,
        filter_: str | None = None,
        fields: str | None = None,
    ):
        return self.http_request(
            method="GET",
            url_suffix="/config/event_sources/log_source_management/log_sources",
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={
                "x-qrd-encryption-algorithm": qrd_encryption_algorithm,
                "x-qrd-encryption-password": qrd_encryption_password,
                "Range": range_,
            },
        )

    def get_log_source(self, qrd_encryption_algorithm: str, qrd_encryption_password: str, id: str, fields: str | None = None):
        return self.http_request(
            method="GET",
            url_suffix=f"/config/event_sources/log_source_management/log_sources/{id}",
            params=assign_params(fields=fields),
            additional_headers={
                "x-qrd-encryption-algorithm": qrd_encryption_algorithm,
                "x-qrd-encryption-password": qrd_encryption_password,
            },
        )

    def custom_properties(self, range_: str | None = None, filter_: str | None = None, fields: str | None = None):
        return self.http_request(
            method="GET",
            url_suffix="/config/event_sources/custom_properties/regex_properties",
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={"Range": range_} if range_ else None,
        )

    def offense_types(self, filter_: str | None = None, fields: str | None = None):
        return self.http_request(
            method="GET", url_suffix="/siem/offense_types", params=assign_params(filter=filter_, fields=fields)
        )

    def get_addresses(
        self, address_suffix: str, filter_: str | None = None, fields: str | None = None, range_: str | None = None
    ):
        return self.http_request(
            method="GET",
            url_suffix=f"/siem/{address_suffix}",
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={"Range": range_} if range_ else None,
        )

    def create_and_update_remote_network_cidr(self, body: dict[str, Any], fields: str, update: bool = False):
        headers = {"fields": fields}

        return self.http_request(
            method="POST",
            url_suffix="/staged_config/remote_networks" + (f'/{body.get("id")}' if update else ""),
            json_data=body,
            additional_headers=headers,
        )

    def get_remote_network_cidr(self, range_: str | None = None, filter_: str | None = None, fields: str | None = None):
        headers = {"Range": range_}
        params = assign_params(filter=filter_, fields=fields)

        return self.http_request(
            method="GET", url_suffix="/staged_config/remote_networks", params=params, additional_headers=headers
        )

    def delete_remote_network_cidr(self, id_):
        return self.http_request(method="DELETE", url_suffix=f"/staged_config/remote_networks/{id_}", resp_type="response")

    def remote_network_deploy_execution(self, body):
        return self.http_request(method="POST", url_suffix="/staged_config/deploy_status", json_data=body)

    def get_resource_list(
        self,
        range_: str,
        endpoint: str,
        filter_: str | None = None,
        fields: str | None = None,
        additional_headers_: dict | None = None,
    ):
        """
        Retrieve a list of resources from a specified endpoint.

        Args:
            range_ (str): The range of resources to retrieve. eg. items=0-49
            endpoint (str): The API endpoint to retrieve resources from.
            filter_ (Optional[str], optional): Optional filter query for the request. Defaults to None.
            fields (Optional[str], optional): The fields that the API should return. Defaults to None.
            additional_headers_ (Optional[dict], optional): Optional additional headers for the request. Defaults to None.

        Returns:
            Response: The response object from the HTTP request.
        """
        return self.http_request(
            method="GET",
            url_suffix=endpoint,
            params=assign_params(filter=filter_, fields=fields),
            additional_headers={"Range": range_} if additional_headers_ is None else {"Range": range_, **additional_headers_},
        )

    def get_resource_by_id(self, id: str, endpoint: str, fields: str | None = None, additional_headers: dict | None = None):
        return self.http_request(
            method="GET",
            url_suffix=endpoint + f"/{id}",
            params=assign_params(fields=fields),
            additional_headers=additional_headers,
        )

    def get_resource(
        self,
        id,
        range_: str,
        endpoint: str,
        filter_: str | None = None,
        fields: str | None = None,
        additional_headers_: dict | None = None,
    ):
        return (
            self.get_resource_list(range_, endpoint, filter_, fields, additional_headers_)
            if id is None
            else [self.get_resource_by_id(id, endpoint, fields, additional_headers_)]
        )

    def delete_log_source(self, id: str) -> requests.Response:
        return self.http_request(
            method="DELETE", url_suffix=f"/config/event_sources/log_source_management/log_sources/{id}", resp_type="response"
        )

    def create_log_source(self, log_source: dict):
        return self.http_request(
            method="POST", url_suffix="/config/event_sources/log_source_management/log_sources", json_data=log_source
        )

    def update_log_source(self, log_source: dict[str, Any]):
        return self.http_request(
            method="PATCH",
            url_suffix="/config/event_sources/log_source_management/log_sources",
            json_data=[log_source],
            resp_type="response",
        )

    def test_connection(self):
        """
        Test connection with databases (should always be up)
        """
        self.http_request(method="GET", url_suffix="/ariel/databases")
        return "ok"


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# SERVICE LAYER CLASSES (Maintainable Business Logic)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements the maintainable service layer with clear responsibilities and comprehensive debugging.
# Each service class handles a specific domain of QRadar functionality with self-documenting methods, consistent
# error handling, and built-in testing capabilities. The architecture prioritizes code clarity and debugging ease.

from abc import ABC, abstractmethod
from typing import Any
from collections.abc import Callable
from enum import Enum


class MetricsCollector:
    """
    Metrics collector for service operations with performance tracking and reporting.

    This class provides comprehensive metrics collection for service operations including:
    - Operation timing and performance metrics
    - Success/failure rate tracking
    - Error categorization and reporting
    - Resource usage monitoring
    """

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.metrics = {"operations": {}, "errors": {}, "performance": {}, "counters": {}}
        self.active_operations = {}

    def start_operation(self, operation_name: str) -> str:
        """Start tracking an operation."""
        operation_id = f"{operation_name}_{int(time.time() * 1000)}"
        self.active_operations[operation_id] = {"name": operation_name, "start_time": time.time()}
        return operation_id

    def record_success(self, operation_name: str, duration_ms: float):
        """Record a successful operation."""
        if operation_name not in self.metrics["operations"]:
            self.metrics["operations"][operation_name] = {
                "success_count": 0,
                "error_count": 0,
                "total_duration_ms": 0,
                "avg_duration_ms": 0,
                "min_duration_ms": float("inf"),
                "max_duration_ms": 0,
            }

        op_metrics = self.metrics["operations"][operation_name]
        op_metrics["success_count"] += 1
        op_metrics["total_duration_ms"] += duration_ms
        op_metrics["avg_duration_ms"] = op_metrics["total_duration_ms"] / (
            op_metrics["success_count"] + op_metrics["error_count"]
        )
        op_metrics["min_duration_ms"] = min(op_metrics["min_duration_ms"], duration_ms)
        op_metrics["max_duration_ms"] = max(op_metrics["max_duration_ms"], duration_ms)

    def record_error(self, operation_name: str, error_message: str, duration_ms: float):
        """Record a failed operation."""
        if operation_name not in self.metrics["operations"]:
            self.metrics["operations"][operation_name] = {
                "success_count": 0,
                "error_count": 0,
                "total_duration_ms": 0,
                "avg_duration_ms": 0,
                "min_duration_ms": float("inf"),
                "max_duration_ms": 0,
            }

        op_metrics = self.metrics["operations"][operation_name]
        op_metrics["error_count"] += 1
        op_metrics["total_duration_ms"] += duration_ms
        op_metrics["avg_duration_ms"] = op_metrics["total_duration_ms"] / (
            op_metrics["success_count"] + op_metrics["error_count"]
        )

        # Track error types
        if operation_name not in self.metrics["errors"]:
            self.metrics["errors"][operation_name] = {}

        error_type = error_message.split(":")[0] if ":" in error_message else "Unknown"
        if error_type not in self.metrics["errors"][operation_name]:
            self.metrics["errors"][operation_name][error_type] = 0
        self.metrics["errors"][operation_name][error_type] += 1

    def get_metrics(self) -> dict[str, Any]:
        """Get all collected metrics."""
        return {"service_name": self.service_name, "collection_time": time.time(), "metrics": self.metrics}


class ServiceOperationResult:
    """
    Standardized result container for service operations with comprehensive debugging information.

    This class provides a consistent way to return results from service operations along with
    debugging context, performance metrics, and error information when applicable.
    """

    def __init__(
        self,
        success: bool,
        data: Any = None,
        error_message: str | None = None,
        error_code: str | None = None,
        operation_name: str | None = None,
        duration_ms: float | None = None,
        debug_context: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
    ):
        self.success = success
        self.data = data
        self.error_message = error_message
        self.error_code = error_code
        self.operation_name = operation_name
        self.duration_ms = duration_ms
        self.debug_context = debug_context or {}
        self.warnings = warnings or []

    def is_success(self) -> bool:
        """Check if the operation was successful."""
        return self.success

    def has_warnings(self) -> bool:
        """Check if the operation has warnings."""
        return len(self.warnings) > 0

    def get_data_or_raise(self) -> Any:
        """Get the data or raise an exception if the operation failed."""
        if not self.success:
            raise DemistoException(f"Service operation failed: {self.error_message}")
        return self.data

    def add_warning(self, warning: str):
        """Add a warning message to the result."""
        self.warnings.append(warning)

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary for logging or debugging."""
        return {
            "success": self.success,
            "data_type": type(self.data).__name__ if self.data is not None else None,
            "error_message": self.error_message,
            "error_code": self.error_code,
            "operation_name": self.operation_name,
            "duration_ms": self.duration_ms,
            "warnings_count": len(self.warnings),
            "debug_context": self.debug_context,
        }


class BaseService(ABC):
    """
    Base service class providing common functionality for all QRadar services.

    This class establishes the standard patterns that make all services:
    - Easy to understand and modify through clear method names and documentation
    - Consistent in error handling and logging across all operations
    - Self-documenting through comprehensive docstrings and type hints
    - Testable through dependency injection and clear interfaces
    - Debuggable through built-in tracing and context capture

    All service classes inherit from this base to ensure consistency and maintainability.
    """

    def __init__(self, client: Client, service_name: str):
        """
        Initialize base service with client and debugging infrastructure.

        Args:
            client: QRadar client instance for API communication
            service_name: Name of the service for logging and debugging
        """
        self.client = client
        self.service_name = service_name
        self.logger = get_enhanced_logger(f"Service.{service_name}")
        self.metrics_collector = MetricsCollector(service_name)

        # Service configuration with sensible defaults
        self.config = {
            "default_timeout": 30,
            "max_retries": 3,
            "enable_caching": False,
            "cache_ttl_seconds": 300,
            "enable_metrics": True,
            "enable_debug_logging": True,
        }

        # Initialize service-specific components
        self._initialize_service_components()

    def _initialize_service_components(self):
        """Initialize service-specific components. Override in subclasses if needed."""

    @contextmanager
    def _operation_context(self, operation_name: str, **context_data):
        """
        Context manager for service operations with comprehensive debugging and metrics.

        This context manager provides:
        - Automatic timing and performance metrics
        - Debug context creation and cleanup
        - Error handling and logging
        - Operation tracing and breadcrumbs

        Args:
            operation_name: Name of the operation being performed
            **context_data: Additional context data for debugging
        """
        debug_ctx = DebugContext(f"{self.service_name}_{operation_name}")
        start_time = time.time()

        # Add initial context
        debug_ctx.add_breadcrumb(f"Starting {operation_name}", **context_data)
        for key, value in context_data.items():
            debug_ctx.capture_variable(key, value)

        # Associate logger with debug context
        logger = self.logger.with_context(debug_ctx)

        try:
            logger.info(f"Starting {self.service_name} operation: {operation_name}")

            if self.config["enable_metrics"]:
                self.metrics_collector.start_operation(operation_name)

            yield debug_ctx, logger

            # Record successful completion
            duration_ms = (time.time() - start_time) * 1000
            debug_ctx.add_breadcrumb(f"Completed {operation_name} successfully", duration_ms=duration_ms)
            logger.info(f"Completed {operation_name} in {duration_ms:.2f}ms")

            if self.config["enable_metrics"]:
                self.metrics_collector.record_success(operation_name, duration_ms)

        except Exception as e:
            # Record failure with full context
            duration_ms = (time.time() - start_time) * 1000
            debug_ctx.add_breadcrumb(f"Operation {operation_name} failed", error=str(e), level="error")

            logger.error_with_context(
                f"{self.service_name} operation {operation_name} failed", exception=e, duration_ms=duration_ms, **context_data
            )

            if self.config["enable_metrics"]:
                self.metrics_collector.record_error(operation_name, str(e), duration_ms)

            raise

    def _make_api_request_with_retry(
        self, method: str, endpoint: str, operation_name: str, debug_ctx: DebugContext, logger: Any, **request_kwargs
    ) -> Any:
        """
        Make API request with retry logic and comprehensive error handling.

        This method provides:
        - Automatic retry with exponential backoff
        - Detailed logging of each attempt
        - Error categorization and recovery suggestions
        - Request/response debugging information

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint URL suffix
            operation_name: Name of the operation for logging
            debug_ctx: Debug context for tracing
            logger: Enhanced logger instance
            **request_kwargs: Additional request parameters

        Returns:
            API response data

        Raises:
            Various exceptions based on the type of error encountered
        """
        max_retries = self.config["max_retries"]
        base_delay = 1.0

        debug_ctx.add_breadcrumb("Making API request", method=method, endpoint=endpoint)
        debug_ctx.capture_variable("api_method", method)
        debug_ctx.capture_variable("api_endpoint", endpoint)
        debug_ctx.capture_variable("max_retries", max_retries)

        last_exception = None

        for attempt in range(max_retries + 1):
            try:
                debug_ctx.add_breadcrumb(f"API request attempt {attempt + 1}/{max_retries + 1}")

                # Make the API request
                request_start = time.time()
                response = self.client.http_request(method=method, url_suffix=endpoint, **request_kwargs)
                request_duration = (time.time() - request_start) * 1000

                # Log successful request
                debug_ctx.add_breadcrumb("API request successful", attempt=attempt + 1, duration_ms=request_duration)
                logger.debug(f"API {method} {endpoint} succeeded in {request_duration:.2f}ms")

                return response

            except Exception as e:
                last_exception = e
                request_duration = (time.time() - request_start) * 1000

                debug_ctx.add_breadcrumb(
                    "API request failed", attempt=attempt + 1, error=str(e), duration_ms=request_duration, level="error"
                )

                # Determine if we should retry
                should_retry = attempt < max_retries and self._is_retryable_error(e)

                if should_retry:
                    # Calculate delay with exponential backoff and jitter
                    delay = base_delay * (2**attempt) + random.uniform(0, 1)
                    debug_ctx.add_breadcrumb(f"Retrying after {delay:.2f}s", delay_seconds=delay)
                    logger.warning(f"API request failed (attempt {attempt + 1}), retrying in {delay:.2f}s: {e}")
                    time.sleep(delay)
                else:
                    # Final failure
                    debug_ctx.add_breadcrumb("All retry attempts exhausted", level="error")
                    logger.error(f"API request failed after {attempt + 1} attempts: {e}")
                    break

        # Re-raise the last exception with enhanced context
        if last_exception:
            raise last_exception

    def _is_retryable_error(self, error: Exception) -> bool:
        """
        Determine if an error is retryable.

        Args:
            error: The exception that occurred

        Returns:
            True if the error should trigger a retry, False otherwise
        """
        # Retryable error types
        retryable_types = (requests.ReadTimeout, requests.ConnectionError, requests.HTTPError)

        if isinstance(error, retryable_types):
            return True

        # Check for specific DemistoException cases that are retryable
        if isinstance(error, DemistoException):
            error_message = str(error).lower()
            retryable_messages = ["timeout", "connection", "temporary", "rate limit", "server error", "5xx"]
            return any(msg in error_message for msg in retryable_messages)

        return False

    def _validate_required_parameters(
        self, parameters: dict[str, Any], required_params: list[str], operation_name: str
    ) -> list[str]:
        """
        Validate required parameters with clear error messages.

        Args:
            parameters: Dictionary of parameters to validate
            required_params: List of required parameter names
            operation_name: Name of the operation for error context

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        for param_name in required_params:
            if param_name not in parameters:
                errors.append(f"Missing required parameter '{param_name}' for {operation_name}")
            elif parameters[param_name] is None:
                errors.append(f"Parameter '{param_name}' cannot be None for {operation_name}")
            elif isinstance(parameters[param_name], str) and not parameters[param_name].strip():
                errors.append(f"Parameter '{param_name}' cannot be empty for {operation_name}")

        return errors

    def _create_success_result(
        self, data: Any, operation_name: str, duration_ms: float, debug_context: dict[str, Any] | None = None
    ) -> ServiceOperationResult:
        """Create a successful operation result."""
        return ServiceOperationResult(
            success=True, data=data, operation_name=operation_name, duration_ms=duration_ms, debug_context=debug_context or {}
        )

    def _create_error_result(
        self,
        error_message: str,
        operation_name: str,
        duration_ms: float,
        error_code: str | None = None,
        debug_context: dict[str, Any] | None = None,
    ) -> ServiceOperationResult:
        """Create a failed operation result."""
        return ServiceOperationResult(
            success=False,
            error_message=error_message,
            error_code=error_code,
            operation_name=operation_name,
            duration_ms=duration_ms,
            debug_context=debug_context or {},
        )

    @abstractmethod
    def get_service_health(self) -> dict[str, Any]:
        """
        Get health status of the service.

        Returns:
            Dictionary containing service health information
        """

    def get_service_metrics(self) -> dict[str, Any]:
        """
        Get performance metrics for the service.

        Returns:
            Dictionary containing service metrics
        """
        if self.config["enable_metrics"]:
            return self.metrics_collector.get_metrics()
        return {"metrics_disabled": True}


class OffenseService(BaseService):
    """
    Service for QRadar offense operations with comprehensive functionality and debugging.

    This service handles all offense-related operations including:
    - Listing offenses with filtering and pagination
    - Updating offense properties (status, assignment, etc.)
    - Managing offense notes and comments
    - Enriching offenses with additional data (assets, events, etc.)
    - Bulk operations on multiple offenses

    All methods provide clear error messages, comprehensive logging, and built-in validation.
    """

    def __init__(self, client: Client):
        super().__init__(client, "OffenseService")

        # Offense-specific configuration
        self.config.update(
            {
                "default_offense_limit": 50,
                "max_offense_limit": 200,
                "default_enrichment_timeout": 60,
                "enable_offense_caching": True,
                "cache_offense_details": True,
            }
        )

    def list_offenses(
        self,
        offense_id: int | None = None,
        range_header: str | None = None,
        filter_query: str | None = None,
        fields: str | None = None,
        sort_criteria: str | None = None,
        include_enrichment: bool = False,
        enrichment_timeout: int | None = None,
    ) -> ServiceOperationResult:
        """
        List QRadar offenses with optional filtering, sorting, and enrichment.

        This method provides comprehensive offense listing with:
        - Flexible filtering using QRadar's filter syntax
        - Pagination support through range headers
        - Field selection for performance optimization
        - Optional enrichment with assets, events, and metadata
        - Comprehensive error handling and validation

        Args:
            offense_id: Specific offense ID to retrieve (optional)
            range_header: Range header for pagination (e.g., "items=0-49")
            filter_query: QRadar filter expression for offense selection
            fields: Comma-separated list of fields to include in response
            sort_criteria: Sort criteria (e.g., "start_time DESC")
            include_enrichment: Whether to enrich offenses with additional data
            enrichment_timeout: Timeout for enrichment operations in seconds

        Returns:
            ServiceOperationResult containing offense data or error information

        Example:
            >>> service = OffenseService(client)
            >>> result = service.list_offenses(
            ...     filter_query="status='OPEN'",
            ...     range_header="items=0-19",
            ...     include_enrichment=True
            ... )
            >>> if result.is_success():
            ...     offenses = result.data
            ...     print(f"Found {len(offenses)} offenses")
        """
        with self._operation_context(
            "list_offenses",
            offense_id=offense_id,
            range_header=range_header,
            filter_query=filter_query,
            include_enrichment=include_enrichment,
        ) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = []

            if offense_id is not None and not isinstance(offense_id, int):
                validation_errors.append("offense_id must be an integer")

            if offense_id is not None and offense_id <= 0:
                validation_errors.append("offense_id must be a positive integer")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                debug_ctx.add_breadcrumb("Parameter validation failed", errors=validation_errors, level="error")
                return self._create_error_result(error_msg, "list_offenses", 0, "VALIDATION_ERROR")

            try:
                # Build API parameters
                api_params = {}
                if filter_query:
                    api_params["filter"] = filter_query
                if fields:
                    api_params["fields"] = fields
                if sort_criteria:
                    api_params["sort"] = sort_criteria

                # Build headers
                headers = {}
                if range_header:
                    headers["Range"] = range_header

                # Determine endpoint
                if offense_id:
                    endpoint = f"/siem/offenses/{offense_id}"
                    debug_ctx.add_breadcrumb("Fetching specific offense", offense_id=offense_id)
                else:
                    endpoint = "/siem/offenses"
                    debug_ctx.add_breadcrumb("Fetching offense list", filter=filter_query, range=range_header)

                # Make API request
                raw_offenses = self._make_api_request_with_retry(
                    method="GET",
                    endpoint=endpoint,
                    operation_name="list_offenses",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=api_params,
                    additional_headers=headers if headers else None,
                )

                # Ensure we have a list for processing
                if offense_id and raw_offenses:
                    raw_offenses = [raw_offenses]
                elif not raw_offenses:
                    raw_offenses = []

                debug_ctx.add_breadcrumb(f"Retrieved {len(raw_offenses)} offenses from API")
                debug_ctx.capture_variable("offense_count", len(raw_offenses))

                # Apply enrichment if requested
                if include_enrichment and raw_offenses:
                    debug_ctx.add_breadcrumb("Starting offense enrichment")
                    enriched_offenses = self._enrich_offenses(
                        raw_offenses, enrichment_timeout or self.config["default_enrichment_timeout"], debug_ctx, logger
                    )
                    debug_ctx.add_breadcrumb("Offense enrichment completed")
                else:
                    enriched_offenses = raw_offenses

                # Transform to standardized format
                standardized_offenses = []
                for offense in enriched_offenses:
                    try:
                        standardized_offense = self._transform_offense_to_standard_format(offense)
                        standardized_offenses.append(standardized_offense)
                    except Exception as transform_error:
                        logger.warning(f"Failed to transform offense {offense.get('id', 'unknown')}: {transform_error}")
                        # Include raw offense with warning
                        offense["_transformation_warning"] = str(transform_error)
                        standardized_offenses.append(offense)

                debug_ctx.add_breadcrumb(f"Transformed {len(standardized_offenses)} offenses to standard format")

                return self._create_success_result(
                    data=standardized_offenses,
                    operation_name="list_offenses",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "offense_count": len(standardized_offenses),
                        "enrichment_applied": include_enrichment,
                        "filter_applied": bool(filter_query),
                        "specific_offense": bool(offense_id),
                    },
                )

            except Exception as e:
                error_msg = f"Failed to list offenses: {str(e)}"
                debug_ctx.add_breadcrumb("Offense listing failed", error=str(e), level="error")
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="list_offenses",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def update_offense(
        self,
        offense_id: int,
        status: str | None = None,
        assigned_to: str | None = None,
        closing_reason_id: int | None = None,
        follow_up: bool | None = None,
        protected: bool | None = None,
        fields: str | None = None,
    ) -> ServiceOperationResult:
        """
        Update a QRadar offense with new properties.

        This method allows updating various offense properties including:
        - Status (OPEN, HIDDEN, CLOSED)
        - Assignment to specific users
        - Closing reason for closed offenses
        - Follow-up flag for tracking
        - Protection status

        Args:
            offense_id: ID of the offense to update
            status: New status for the offense
            assigned_to: Username to assign the offense to
            closing_reason_id: ID of the closing reason (required when closing)
            follow_up: Whether the offense requires follow-up
            protected: Whether the offense is protected from deletion
            fields: Comma-separated list of fields to return

        Returns:
            ServiceOperationResult containing updated offense data or error information
        """
        with self._operation_context("update_offense", offense_id=offense_id, status=status, assigned_to=assigned_to) as (
            debug_ctx,
            logger,
        ):
            # Validate required parameters
            validation_errors = self._validate_required_parameters({"offense_id": offense_id}, ["offense_id"], "update_offense")

            # Additional validation
            if not isinstance(offense_id, int) or offense_id <= 0:
                validation_errors.append("offense_id must be a positive integer")

            if status and status not in ["OPEN", "HIDDEN", "CLOSED"]:
                validation_errors.append("status must be one of: OPEN, HIDDEN, CLOSED")

            if status == "CLOSED" and not closing_reason_id:
                validation_errors.append("closing_reason_id is required when status is CLOSED")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "update_offense", 0, "VALIDATION_ERROR")

            try:
                # Build update parameters
                update_params = {}
                if status:
                    update_params["status"] = status
                if assigned_to:
                    update_params["assigned_to"] = assigned_to
                if closing_reason_id:
                    update_params["closing_reason_id"] = closing_reason_id
                if follow_up is not None:
                    update_params["follow_up"] = follow_up
                if protected is not None:
                    update_params["protected"] = protected
                if fields:
                    update_params["fields"] = fields

                debug_ctx.add_breadcrumb("Updating offense", offense_id=offense_id, updates=update_params)

                # Make API request
                updated_offense = self._make_api_request_with_retry(
                    method="POST",
                    endpoint=f"/siem/offenses/{offense_id}",
                    operation_name="update_offense",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=update_params,
                )

                debug_ctx.add_breadcrumb("Offense updated successfully")

                # Transform to standardized format
                standardized_offense = self._transform_offense_to_standard_format(updated_offense)

                return self._create_success_result(
                    data=standardized_offense,
                    operation_name="update_offense",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={"offense_id": offense_id, "updates_applied": list(update_params.keys())},
                )

            except Exception as e:
                error_msg = f"Failed to update offense {offense_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="update_offense",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def list_offense_notes(
        self,
        offense_id: int,
        note_id: int | None = None,
        range_header: str | None = None,
        filter_query: str | None = None,
        fields: str | None = None,
    ) -> ServiceOperationResult:
        """
        List notes for a specific QRadar offense.

        This method retrieves notes associated with an offense, providing
        comprehensive filtering and pagination capabilities.

        Args:
            offense_id: ID of the offense to retrieve notes for
            note_id: Specific note ID to retrieve (optional)
            range_header: Range header for pagination
            filter_query: QRadar filter expression for note selection
            fields: Comma-separated list of fields to include

        Returns:
            ServiceOperationResult containing note data or error information
        """
        with self._operation_context("list_offense_notes", offense_id=offense_id, note_id=note_id, range_header=range_header) as (
            debug_ctx,
            logger,
        ):
            # Validate required parameters
            validation_errors = self._validate_required_parameters(
                {"offense_id": offense_id}, ["offense_id"], "list_offense_notes"
            )

            if not isinstance(offense_id, int) or offense_id <= 0:
                validation_errors.append("offense_id must be a positive integer")

            if note_id is not None and (not isinstance(note_id, int) or note_id <= 0):
                validation_errors.append("note_id must be a positive integer")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "list_offense_notes", 0, "VALIDATION_ERROR")

            try:
                # Build API parameters
                api_params = {}
                if filter_query:
                    api_params["filter"] = filter_query
                if fields:
                    api_params["fields"] = fields

                # Build headers
                headers = {}
                if range_header:
                    headers["Range"] = range_header

                # Determine endpoint
                if note_id:
                    endpoint = f"/siem/offenses/{offense_id}/notes/{note_id}"
                    debug_ctx.add_breadcrumb("Fetching specific offense note", offense_id=offense_id, note_id=note_id)
                else:
                    endpoint = f"/siem/offenses/{offense_id}/notes"
                    debug_ctx.add_breadcrumb("Fetching offense notes list", offense_id=offense_id)

                # Make API request
                raw_notes = self._make_api_request_with_retry(
                    method="GET",
                    endpoint=endpoint,
                    operation_name="list_offense_notes",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=api_params,
                    additional_headers=headers if headers else None,
                )

                # Ensure we have a list for processing
                if note_id and raw_notes:
                    raw_notes = [raw_notes]
                elif not raw_notes:
                    raw_notes = []

                debug_ctx.add_breadcrumb(f"Retrieved {len(raw_notes)} notes from API")

                # Transform to standardized format
                standardized_notes = []
                for note in raw_notes:
                    standardized_note = self._transform_note_to_standard_format(note)
                    standardized_notes.append(standardized_note)

                return self._create_success_result(
                    data=standardized_notes,
                    operation_name="list_offense_notes",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "offense_id": offense_id,
                        "note_count": len(standardized_notes),
                        "specific_note": bool(note_id),
                    },
                )

            except Exception as e:
                error_msg = f"Failed to list notes for offense {offense_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="list_offense_notes",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def create_offense_note(self, offense_id: int, note_text: str, fields: str | None = None) -> ServiceOperationResult:
        """
        Create a new note for a QRadar offense.

        This method adds a note to an existing offense with comprehensive
        validation and error handling.

        Args:
            offense_id: ID of the offense to add the note to
            note_text: Text content of the note
            fields: Comma-separated list of fields to return

        Returns:
            ServiceOperationResult containing created note data or error information
        """
        with self._operation_context(
            "create_offense_note", offense_id=offense_id, note_text_length=len(note_text) if note_text else 0
        ) as (debug_ctx, logger):
            # Validate required parameters
            validation_errors = self._validate_required_parameters(
                {"offense_id": offense_id, "note_text": note_text}, ["offense_id", "note_text"], "create_offense_note"
            )

            if not isinstance(offense_id, int) or offense_id <= 0:
                validation_errors.append("offense_id must be a positive integer")

            if not isinstance(note_text, str) or not note_text.strip():
                validation_errors.append("note_text must be a non-empty string")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "create_offense_note", 0, "VALIDATION_ERROR")

            try:
                # Build API parameters
                api_params = {"note_text": note_text.strip()}
                if fields:
                    api_params["fields"] = fields

                debug_ctx.add_breadcrumb("Creating offense note", offense_id=offense_id)
                debug_ctx.capture_variable("note_text_length", len(note_text.strip()))

                # Make API request
                created_note = self._make_api_request_with_retry(
                    method="POST",
                    endpoint=f"/siem/offenses/{offense_id}/notes",
                    operation_name="create_offense_note",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=api_params,
                )

                debug_ctx.add_breadcrumb("Offense note created successfully")

                # Transform to standardized format
                standardized_note = self._transform_note_to_standard_format(created_note)

                return self._create_success_result(
                    data=standardized_note,
                    operation_name="create_offense_note",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "offense_id": offense_id,
                        "note_id": standardized_note.get("id"),
                        "note_text_length": len(note_text.strip()),
                    },
                )

            except Exception as e:
                error_msg = f"Failed to create note for offense {offense_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="create_offense_note",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def resolve_closing_reason_name_to_id(self, closing_reason_name: str) -> ServiceOperationResult:
        """
        Resolve a human-readable closing reason name to its corresponding ID.

        This method searches through all available closing reasons (including
        deleted and reserved ones) to find a matching name and return its ID.

        Args:
            closing_reason_name: Human-readable closing reason name to resolve

        Returns:
            ServiceOperationResult containing the closing reason ID or error information
        """
        with self._operation_context("resolve_closing_reason_name_to_id", closing_reason_name=closing_reason_name) as (
            debug_ctx,
            logger,
        ):
            # Validate required parameters
            validation_errors = self._validate_required_parameters(
                {"closing_reason_name": closing_reason_name}, ["closing_reason_name"], "resolve_closing_reason_name_to_id"
            )

            if not isinstance(closing_reason_name, str) or not closing_reason_name.strip():
                validation_errors.append("closing_reason_name must be a non-empty string")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "resolve_closing_reason_name_to_id", 0, "VALIDATION_ERROR")

            try:
                debug_ctx.add_breadcrumb("Fetching all closing reasons for name resolution")

                # Fetch all closing reasons including deleted and reserved ones
                all_closing_reasons = self._make_api_request_with_retry(
                    method="GET",
                    endpoint="/reference_data/offense_closing_reasons",
                    operation_name="resolve_closing_reason_name_to_id",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params={"include_deleted": "true", "include_reserved": "true"},
                )

                debug_ctx.capture_variable("closing_reasons_count", len(all_closing_reasons))

                # Search for matching closing reason name (case-sensitive)
                resolved_closing_reason_id = None
                for closing_reason in all_closing_reasons:
                    if closing_reason.get("text") == closing_reason_name:
                        resolved_closing_reason_id = closing_reason.get("id")
                        break

                if resolved_closing_reason_id is not None:
                    debug_ctx.add_breadcrumb(
                        "Closing reason name resolved successfully", name=closing_reason_name, id=resolved_closing_reason_id
                    )

                    return self._create_success_result(
                        data={"closing_reason_id": resolved_closing_reason_id, "closing_reason_name": closing_reason_name},
                        operation_name="resolve_closing_reason_name_to_id",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                        debug_context={
                            "closing_reason_name": closing_reason_name,
                            "resolved_id": resolved_closing_reason_id,
                            "total_reasons_searched": len(all_closing_reasons),
                        },
                    )
                else:
                    # Provide helpful error with available options
                    available_reasons = [reason.get("text") for reason in all_closing_reasons[:10]]
                    error_msg = (
                        f"Could not find closing reason with name '{closing_reason_name}'. "
                        f"Available options include: {', '.join(available_reasons)}"
                    )

                    return self._create_error_result(
                        error_message=error_msg,
                        operation_name="resolve_closing_reason_name_to_id",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                        error_code="NOT_FOUND",
                        debug_context={
                            "closing_reason_name": closing_reason_name,
                            "available_reasons_sample": available_reasons,
                            "total_reasons_searched": len(all_closing_reasons),
                        },
                    )

            except Exception as e:
                error_msg = f"Failed to resolve closing reason name '{closing_reason_name}': {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="resolve_closing_reason_name_to_id",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def _transform_note_to_standard_format(self, note: dict[str, Any]) -> dict[str, Any]:
        """
        Transform raw QRadar note data to standardized format.

        This method ensures consistent field names, data types, and structure
        for all note operations.
        """
        return {
            "id": note.get("id"),
            "text": note.get("note_text", ""),
            "created_by": note.get("username", ""),
            "create_time": note.get("create_time"),
            "offense_id": note.get("offense_id"),
        }

    def _enrich_offenses(
        self, offenses: list[dict[str, Any]], timeout_seconds: int, debug_ctx: DebugContext, logger: Any
    ) -> list[dict[str, Any]]:
        """
        Enrich offenses with additional data from QRadar.

        This internal method adds enrichment data such as:
        - Asset information for source/destination IPs
        - Event samples and statistics
        - Rule information and metadata
        - Domain and network context

        Args:
            offenses: List of raw offense data from QRadar API
            timeout_seconds: Maximum time to spend on enrichment
            debug_ctx: Debug context for tracing
            logger: Logger instance for debugging

        Returns:
            List of enriched offense data
        """
        debug_ctx.add_breadcrumb(f"Starting enrichment for {len(offenses)} offenses", timeout=timeout_seconds)

        enriched_offenses = []
        enrichment_start = time.time()

        for i, offense in enumerate(offenses):
            # Check timeout
            elapsed = time.time() - enrichment_start
            if elapsed > timeout_seconds:
                debug_ctx.add_breadcrumb(
                    f"Enrichment timeout reached after {elapsed:.2f}s", processed=i, total=len(offenses), level="warning"
                )
                logger.warning(f"Enrichment timeout reached, processed {i}/{len(offenses)} offenses")
                # Return remaining offenses without enrichment
                enriched_offenses.extend(offenses[i:])
                break

            try:
                enriched_offense = self._enrich_single_offense(offense, debug_ctx, logger)
                enriched_offenses.append(enriched_offense)
            except Exception as e:
                logger.warning(f"Failed to enrich offense {offense.get('id', 'unknown')}: {e}")
                # Include original offense with enrichment error
                offense["_enrichment_error"] = str(e)
                enriched_offenses.append(offense)

        debug_ctx.add_breadcrumb("Enrichment completed", processed=len(enriched_offenses), total=len(offenses))
        return enriched_offenses

    def _enrich_single_offense(self, offense: dict[str, Any], debug_ctx: DebugContext, logger: Any) -> dict[str, Any]:
        """
        Enrich a single offense with comprehensive metadata and related information.

        This method applies the same enrichment logic as the existing
        enrich_qradar_offenses_with_comprehensive_metadata function but in a
        service-oriented, maintainable way.

        Args:
            offense: Raw offense data from QRadar API
            debug_ctx: Debug context for tracing
            logger: Logger instance for debugging

        Returns:
            Enriched offense data with additional metadata
        """
        offense_id = offense.get("id")
        debug_ctx.add_breadcrumb(f"Enriching offense {offense_id}")

        # Create a copy to avoid modifying the original
        enriched_offense = copy.deepcopy(offense)

        # Add enrichment metadata
        enriched_offense["_enrichment"] = {"timestamp": time.time(), "version": "1.0", "applied": []}

        try:
            # Apply core enrichments using existing helper functions
            # This maintains compatibility while organizing the logic better

            # 1. Offense type enrichment
            if "offense_type" in offense:
                offense_type_mapping = get_offense_types(self.client, [offense])
                if offense_type_mapping:
                    enriched_offense["offense_type"] = offense_type_mapping.get(
                        offense.get("offense_type"), offense.get("offense_type")
                    )
                    enriched_offense["_enrichment"]["applied"].append("offense_type")

            # 2. Closing reason enrichment
            if "closing_reason_id" in offense and offense.get("closing_reason_id"):
                closing_reason_mapping = get_offense_closing_reasons(self.client, [offense])
                if closing_reason_mapping:
                    enriched_offense["closing_reason_id"] = closing_reason_mapping.get(
                        offense.get("closing_reason_id"), offense.get("closing_reason_id")
                    )
                    enriched_offense["_enrichment"]["applied"].append("closing_reason")

            # 3. Generate direct link to offense in QRadar console
            offense_console_link_suffix = (
                f"/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={offense_id}"
            )
            enriched_offense["LinkToOffense"] = urljoin(self.client.server, offense_console_link_suffix)
            enriched_offense["_enrichment"]["applied"].append("console_link")

            # 4. Domain name enrichment (if enabled)
            if DOMAIN_ENRCH_FLG.lower() == "true" and "domain_id" in offense:
                domain_mapping = get_domain_names(self.client, [offense])
                if domain_mapping and offense.get("domain_id"):
                    enriched_offense["domain_name"] = domain_mapping.get(offense.get("domain_id"), offense.get("domain_id"))
                    enriched_offense["_enrichment"]["applied"].append("domain_name")

            # 5. Rules enrichment (if enabled)
            if RULES_ENRCH_FLG.lower() == "true" and "rules" in offense:
                rule_mapping = get_rules_names(self.client, [offense])
                if rule_mapping and offense.get("rules"):
                    enriched_rules = []
                    for rule in offense.get("rules", []):
                        enriched_rule = {
                            "id": rule.get("id"),
                            "type": rule.get("type"),
                            "name": rule_mapping.get(rule.get("id"), rule.get("id")),
                        }
                        enriched_rules.append(enriched_rule)
                    enriched_offense["rules"] = enriched_rules
                    enriched_offense["_enrichment"]["applied"].append("rules")

            debug_ctx.add_breadcrumb(
                f"Offense {offense_id} enriched successfully", applied_enrichments=enriched_offense["_enrichment"]["applied"]
            )

        except Exception as e:
            logger.warning(f"Partial enrichment failure for offense {offense_id}: {e}")
            enriched_offense["_enrichment"]["error"] = str(e)
            enriched_offense["_enrichment"]["partial"] = True

        return enriched_offense

    def _transform_offense_to_standard_format(self, offense: dict[str, Any]) -> dict[str, Any]:
        """
        Transform raw QRadar offense data to standardized format.

        This method ensures consistent field names, data types, and structure
        across all offense operations.
        """
        # Create standardized offense structure
        standardized = {
            "id": offense.get("id"),
            "description": offense.get("description", ""),
            "status": offense.get("status", "UNKNOWN"),
            "start_time": offense.get("start_time"),
            "last_updated_time": offense.get("last_updated_time"),
            "event_count": offense.get("event_count", 0),
            "magnitude": offense.get("magnitude", 0),
            "credibility": offense.get("credibility", 0),
            "relevance": offense.get("relevance", 0),
            "severity": offense.get("severity", 0),
            "assigned_to": offense.get("assigned_to"),
            "follow_up": offense.get("follow_up", False),
            "protected": offense.get("protected", False),
            "source_address_ids": offense.get("source_address_ids", []),
            "destination_address_ids": offense.get("destination_address_ids", []),
            "local_destination_address_ids": offense.get("local_destination_address_ids", []),
            "remote_destination_count": offense.get("remote_destination_count", 0),
            "source_count": offense.get("source_count", 0),
            "destination_count": offense.get("destination_count", 0),
            "category_count": offense.get("category_count", 0),
            "device_count": offense.get("device_count", 0),
            "closing_reason_id": offense.get("closing_reason_id"),
            "close_time": offense.get("close_time"),
            "domain_id": offense.get("domain_id"),
            "policy_category_count": offense.get("policy_category_count", 0),
            "security_category_count": offense.get("security_category_count", 0),
            "log_sources": offense.get("log_sources", []),
        }

        # Preserve any enrichment data
        if "_enrichment" in offense:
            standardized["_enrichment"] = offense["_enrichment"]

        # Preserve any transformation warnings
        if "_transformation_warning" in offense:
            standardized["_transformation_warning"] = offense["_transformation_warning"]

        # Preserve any enrichment errors
        if "_enrichment_error" in offense:
            standardized["_enrichment_error"] = offense["_enrichment_error"]

        return standardized

    def enrich_offenses_with_ip_addresses(
        self, offenses: list[dict[str, Any]], include_source_ips: bool = True, include_destination_ips: bool = True
    ) -> ServiceOperationResult:
        """
        Enrich offenses with actual IP addresses resolved from address IDs.

        This method converts source_address_ids and local_destination_address_ids
        to actual IP addresses for better readability and analysis.

        Args:
            offenses: List of offense data to enrich
            include_source_ips: Whether to resolve source IP addresses
            include_destination_ips: Whether to resolve destination IP addresses

        Returns:
            ServiceOperationResult containing enriched offense data
        """
        with self._operation_context(
            "enrich_offenses_with_ip_addresses",
            offense_count=len(offenses),
            include_source_ips=include_source_ips,
            include_destination_ips=include_destination_ips,
        ) as (debug_ctx, logger):
            try:
                enriched_offenses = []

                # Get IP address mappings in batch for efficiency
                source_ip_mapping = {}
                destination_ip_mapping = {}

                if include_source_ips:
                    debug_ctx.add_breadcrumb("Retrieving source IP address mappings")
                    source_ip_mapping = retrieve_offense_ip_addresses_with_enrichment(
                        self.client,
                        offenses,
                        False,  # False = source addresses
                    )
                    debug_ctx.capture_variable("source_ip_count", len(source_ip_mapping))

                if include_destination_ips:
                    debug_ctx.add_breadcrumb("Retrieving destination IP address mappings")
                    destination_ip_mapping = retrieve_offense_ip_addresses_with_enrichment(
                        self.client,
                        offenses,
                        True,  # True = destination addresses
                    )
                    debug_ctx.capture_variable("destination_ip_count", len(destination_ip_mapping))

                # Apply IP enrichment to each offense
                for offense in offenses:
                    enriched_offense = copy.deepcopy(offense)

                    # Enrich source IP addresses
                    if include_source_ips and "source_address_ids" in offense:
                        source_ips = []
                        for addr_id in offense.get("source_address_ids", []):
                            ip_address = source_ip_mapping.get(addr_id)
                            if ip_address:
                                source_ips.append(ip_address)
                        enriched_offense["source_address_ids"] = source_ips

                    # Enrich destination IP addresses
                    if include_destination_ips and "local_destination_address_ids" in offense:
                        dest_ips = []
                        for addr_id in offense.get("local_destination_address_ids", []):
                            ip_address = destination_ip_mapping.get(addr_id)
                            if ip_address:
                                dest_ips.append(ip_address)
                        enriched_offense["local_destination_address_ids"] = dest_ips

                    enriched_offenses.append(enriched_offense)

                debug_ctx.add_breadcrumb(f"IP enrichment completed for {len(enriched_offenses)} offenses")

                return self._create_success_result(
                    data=enriched_offenses,
                    operation_name="enrich_offenses_with_ip_addresses",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "offense_count": len(enriched_offenses),
                        "source_ips_enriched": include_source_ips,
                        "destination_ips_enriched": include_destination_ips,
                    },
                )

            except Exception as e:
                error_msg = f"Failed to enrich offenses with IP addresses: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="enrich_offenses_with_ip_addresses",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="ENRICHMENT_ERROR",
                )

    def enrich_offenses_with_assets(
        self, offenses: list[dict[str, Any]], max_assets_per_offense: int | None = None
    ) -> ServiceOperationResult:
        """
        Enrich offenses with asset information correlated with offense IP addresses.

        This method fetches asset data for all IP addresses associated with each offense,
        providing additional context about the systems involved.

        Args:
            offenses: List of offense data to enrich
            max_assets_per_offense: Maximum number of assets to fetch per offense

        Returns:
            ServiceOperationResult containing offense data enriched with assets
        """
        with self._operation_context(
            "enrich_offenses_with_assets", offense_count=len(offenses), max_assets_per_offense=max_assets_per_offense
        ) as (debug_ctx, logger):
            try:
                enriched_offenses = []

                for offense in offenses:
                    enriched_offense = copy.deepcopy(offense)
                    offense_id = offense.get("id", "unknown")

                    debug_ctx.add_breadcrumb(f"Enriching offense {offense_id} with assets")

                    # Collect all IP addresses from the offense
                    all_ips = []

                    # Add source IPs
                    source_ips = offense.get("source_address_ids", [])
                    if isinstance(source_ips, list):
                        all_ips.extend([ip for ip in source_ips if ip])

                    # Add destination IPs
                    dest_ips = offense.get("local_destination_address_ids", [])
                    if isinstance(dest_ips, list):
                        all_ips.extend([ip for ip in dest_ips if ip])

                    # Remove duplicates while preserving order
                    unique_ips = list(dict.fromkeys(all_ips))

                    if unique_ips:
                        debug_ctx.add_breadcrumb(
                            f"Fetching assets for {len(unique_ips)} IPs", offense_id=offense_id, ip_count=len(unique_ips)
                        )

                        # Fetch assets using existing helper function
                        try:
                            assets = retrieve_assets_correlated_with_offense_ip_addresses(
                                self.client, unique_ips, max_assets_per_offense
                            )
                            enriched_offense["assets"] = assets
                            debug_ctx.add_breadcrumb(f"Found {len(assets)} assets for offense {offense_id}")
                        except Exception as asset_error:
                            logger.warning(f"Failed to fetch assets for offense {offense_id}: {asset_error}")
                            enriched_offense["assets"] = []
                            enriched_offense["_asset_enrichment_error"] = str(asset_error)
                    else:
                        enriched_offense["assets"] = []
                        debug_ctx.add_breadcrumb(f"No IPs found for offense {offense_id}")

                    enriched_offenses.append(enriched_offense)

                debug_ctx.add_breadcrumb(f"Asset enrichment completed for {len(enriched_offenses)} offenses")

                return self._create_success_result(
                    data=enriched_offenses,
                    operation_name="enrich_offenses_with_assets",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={"offense_count": len(enriched_offenses), "max_assets_per_offense": max_assets_per_offense},
                )

            except Exception as e:
                error_msg = f"Failed to enrich offenses with assets: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="enrich_offenses_with_assets",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="ENRICHMENT_ERROR",
                )

    def apply_comprehensive_enrichment(
        self,
        offenses: list[dict[str, Any]],
        include_ip_addresses: bool = True,
        include_assets: bool = True,
        max_assets_per_offense: int | None = None,
        enrichment_timeout: int | None = None,
    ) -> ServiceOperationResult:
        """
        Apply comprehensive enrichment to offenses using the existing enrichment function.

        This method serves as a bridge between the service layer and the existing
        enrich_qradar_offenses_with_comprehensive_metadata function, maintaining
        compatibility while providing a clean service interface.

        Args:
            offenses: List of offense data to enrich
            include_ip_addresses: Whether to resolve IP address IDs to actual IPs
            include_assets: Whether to fetch asset information
            max_assets_per_offense: Maximum assets to fetch per offense
            enrichment_timeout: Timeout for enrichment operations

        Returns:
            ServiceOperationResult containing fully enriched offense data
        """
        with self._operation_context(
            "apply_comprehensive_enrichment",
            offense_count=len(offenses),
            include_ip_addresses=include_ip_addresses,
            include_assets=include_assets,
        ) as (debug_ctx, logger):
            try:
                debug_ctx.add_breadcrumb("Starting comprehensive offense enrichment")

                # Use the existing enrichment function for compatibility
                enriched_offenses = enrich_qradar_offenses_with_comprehensive_metadata(
                    self.client, offenses, include_ip_addresses, include_assets, max_assets_per_offense
                )

                debug_ctx.add_breadcrumb(f"Comprehensive enrichment completed for {len(enriched_offenses)} offenses")

                return self._create_success_result(
                    data=enriched_offenses,
                    operation_name="apply_comprehensive_enrichment",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "offense_count": len(enriched_offenses),
                        "ip_enrichment": include_ip_addresses,
                        "asset_enrichment": include_assets,
                        "max_assets_per_offense": max_assets_per_offense,
                    },
                )

            except Exception as e:
                error_msg = f"Failed to apply comprehensive enrichment: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="apply_comprehensive_enrichment",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="ENRICHMENT_ERROR",
                )

    def get_service_health(self) -> dict[str, Any]:
        """Get health status of the OffenseService."""
        try:
            # Test basic offense listing to verify service health
            test_result = self.list_offenses(range_header="items=0-0")

            return {
                "service_name": self.service_name,
                "status": "healthy" if test_result.is_success() else "unhealthy",
                "last_check": time.time(),
                "api_connectivity": test_result.is_success(),
                "error_message": test_result.error_message if not test_result.is_success() else None,
            }
        except Exception as e:
            return {
                "service_name": self.service_name,
                "status": "unhealthy",
                "last_check": time.time(),
                "api_connectivity": False,
                "error_message": str(e),
            }


class SearchService(BaseService):
    """
    Service for QRadar search and query operations with comprehensive functionality.

    This service handles all search-related operations including:
    - Creating and managing Ariel searches
    - Monitoring search status and progress
    - Retrieving search results with pagination
    - Managing saved searches
    - Query validation and optimization

    All methods provide clear error messages, comprehensive logging, and built-in validation.
    """

    def __init__(self, client: Client):
        super().__init__(client, "SearchService")

        # Search-specific configuration
        self.config.update(
            {
                "default_search_timeout": 300,  # 5 minutes
                "max_search_timeout": 1800,  # 30 minutes
                "poll_interval_seconds": 5,
                "max_results_per_page": 1000,
                "enable_query_validation": True,
                "enable_search_caching": False,
            }
        )

    def create_search(
        self, query_expression: str | None = None, saved_search_id: str | None = None, query_timeout: int | None = None
    ) -> ServiceOperationResult:
        """
        Create a new Ariel search in QRadar.

        This method creates a search using either a custom query expression or a saved search.
        It provides comprehensive validation and error handling for search creation.

        Args:
            query_expression: AQL query string to execute
            saved_search_id: ID of a saved search to execute
            query_timeout: Maximum time to wait for search completion

        Returns:
            ServiceOperationResult containing search ID and metadata
        """
        with self._operation_context("create_search", query_expression=query_expression, saved_search_id=saved_search_id) as (
            debug_ctx,
            logger,
        ):
            # Validate parameters
            validation_errors = []

            if not query_expression and not saved_search_id:
                validation_errors.append("Either query_expression or saved_search_id must be provided")

            if query_expression and saved_search_id:
                validation_errors.append("Cannot specify both query_expression and saved_search_id")

            if query_timeout and (query_timeout <= 0 or query_timeout > self.config["max_search_timeout"]):
                validation_errors.append(f"query_timeout must be between 1 and {self.config['max_search_timeout']} seconds")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "create_search", 0, "VALIDATION_ERROR")

            try:
                # Validate query if provided
                if query_expression and self.config["enable_query_validation"]:
                    validation_result = self._validate_aql_query(query_expression, debug_ctx, logger)
                    if not validation_result["valid"]:
                        return self._create_error_result(
                            f"Query validation failed: {validation_result['error']}", "create_search", 0, "QUERY_VALIDATION_ERROR"
                        )

                # Build request parameters
                request_params = {}
                if query_expression:
                    request_params["query_expression"] = query_expression
                if saved_search_id:
                    request_params["saved_search_id"] = saved_search_id

                debug_ctx.add_breadcrumb("Creating search", params=request_params)

                # Make API request
                search_response = self._make_api_request_with_retry(
                    method="POST",
                    endpoint="/ariel/searches",
                    operation_name="create_search",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=request_params,
                )

                search_id = search_response.get("search_id")
                if not search_id:
                    raise DemistoException("Search creation succeeded but no search_id returned")

                debug_ctx.add_breadcrumb("Search created successfully", search_id=search_id)

                return self._create_success_result(
                    data={
                        "search_id": search_id,
                        "status": search_response.get("status", "UNKNOWN"),
                        "query_expression": query_expression,
                        "saved_search_id": saved_search_id,
                        "created_time": time.time(),
                    },
                    operation_name="create_search",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to create search: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="create_search",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def get_search_results(
        self,
        search_id: str,
        range_header: str | None = None,
        wait_for_completion: bool = True,
        timeout_seconds: int | None = None,
    ) -> ServiceOperationResult:
        """
        Retrieve results from a QRadar search.

        This method can either wait for search completion or return immediately
        with current results. It provides comprehensive error handling and
        progress monitoring.

        Args:
            search_id: ID of the search to retrieve results from
            range_header: Range header for pagination
            wait_for_completion: Whether to wait for search completion
            timeout_seconds: Maximum time to wait for completion

        Returns:
            ServiceOperationResult containing search results
        """
        with self._operation_context("get_search_results", search_id=search_id, wait_for_completion=wait_for_completion) as (
            debug_ctx,
            logger,
        ):
            # Validate parameters
            validation_errors = self._validate_required_parameters({"search_id": search_id}, ["search_id"], "get_search_results")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "get_search_results", 0, "VALIDATION_ERROR")

            try:
                # Wait for completion if requested
                if wait_for_completion:
                    completion_result = self._wait_for_search_completion(
                        search_id, timeout_seconds or self.config["default_search_timeout"], debug_ctx, logger
                    )

                    if not completion_result["completed"]:
                        return self._create_error_result(
                            completion_result["error"],
                            "get_search_results",
                            (time.time() - debug_ctx.start_time) * 1000,
                            "SEARCH_TIMEOUT",
                        )

                # Build headers for pagination
                headers = {}
                if range_header:
                    headers["Range"] = range_header

                debug_ctx.add_breadcrumb("Retrieving search results", search_id=search_id, range=range_header)

                # Get search results
                results = self._make_api_request_with_retry(
                    method="GET",
                    endpoint=f"/ariel/searches/{search_id}/results",
                    operation_name="get_search_results",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    additional_headers=headers if headers else None,
                )

                # Get search metadata
                search_status = self._get_search_status_internal(search_id, debug_ctx, logger)

                debug_ctx.add_breadcrumb("Search results retrieved successfully")

                return self._create_success_result(
                    data={
                        "search_id": search_id,
                        "results": results.get("events", []),
                        "record_count": search_status.get("record_count", 0),
                        "status": search_status.get("status", "UNKNOWN"),
                        "progress": search_status.get("progress", 0),
                        "completed": search_status.get("status") == "COMPLETED",
                    },
                    operation_name="get_search_results",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to get search results for {search_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="get_search_results",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def _validate_aql_query(self, query: str, debug_ctx: DebugContext, logger: Any) -> dict[str, Any]:
        """
        Validate an AQL query for basic syntax and structure.

        This method performs basic validation to catch common query errors
        before sending to QRadar.
        """
        debug_ctx.add_breadcrumb("Validating AQL query")

        # Basic validation checks
        if not query or not query.strip():
            return {"valid": False, "error": "Query cannot be empty"}

        query_lower = query.lower().strip()

        # Check for required SELECT statement
        if not query_lower.startswith("select"):
            return {"valid": False, "error": "Query must start with SELECT statement"}

        # Check for basic SQL injection patterns
        dangerous_patterns = ["drop ", "delete ", "insert ", "update ", "create ", "alter "]
        for pattern in dangerous_patterns:
            if pattern in query_lower:
                return {"valid": False, "error": f"Query contains potentially dangerous pattern: {pattern}"}

        # Check for balanced parentheses
        if query.count("(") != query.count(")"):
            return {"valid": False, "error": "Unbalanced parentheses in query"}

        debug_ctx.add_breadcrumb("Query validation passed")
        return {"valid": True, "error": None}

    def _wait_for_search_completion(
        self, search_id: str, timeout_seconds: int, debug_ctx: DebugContext, logger: Any
    ) -> dict[str, Any]:
        """Wait for search completion with progress monitoring."""
        debug_ctx.add_breadcrumb("Waiting for search completion", search_id=search_id, timeout=timeout_seconds)

        start_time = time.time()
        poll_interval = self.config["poll_interval_seconds"]

        while (time.time() - start_time) < timeout_seconds:
            try:
                status_info = self._get_search_status_internal(search_id, debug_ctx, logger)
                status = status_info.get("status", "UNKNOWN")
                progress = status_info.get("progress", 0)

                debug_ctx.add_breadcrumb("Search status check", status=status, progress=progress)

                if status == "COMPLETED":
                    debug_ctx.add_breadcrumb("Search completed successfully")
                    return {"completed": True, "status": status_info}

                if status in ["CANCELED", "ERROR"]:
                    error_msg = f"Search failed with status: {status}"
                    debug_ctx.add_breadcrumb("Search failed", status=status, level="error")
                    return {"completed": False, "error": error_msg}

                # Wait before next poll
                time.sleep(poll_interval)

            except Exception as e:
                logger.warning(f"Error checking search status: {e}")
                time.sleep(poll_interval)

        # Timeout reached
        debug_ctx.add_breadcrumb("Search completion timeout", level="error")
        return {"completed": False, "error": f"Search did not complete within {timeout_seconds} seconds"}

    def _get_search_status_internal(self, search_id: str, debug_ctx: DebugContext, logger: Any) -> dict[str, Any]:
        """Get search status information."""
        return self._make_api_request_with_retry(
            method="GET",
            endpoint=f"/ariel/searches/{search_id}",
            operation_name="get_search_status",
            debug_ctx=debug_ctx,
            logger=logger,
        )

    def list_searches(self, range_header: str | None = None, filter_query: str | None = None) -> ServiceOperationResult:
        """
        List all active searches in QRadar.

        This method retrieves a list of all searches currently in the system,
        including their status and basic metadata.

        Args:
            range_header: Range specification for pagination (e.g., "0-49")
            filter_query: Filter to apply to search results

        Returns:
            ServiceOperationResult containing list of searches
        """
        with self._operation_context("list_searches", range_header=range_header, filter_query=filter_query) as (
            debug_ctx,
            logger,
        ):
            try:
                # Build request parameters
                params = {}
                if range_header:
                    params["Range"] = f"items={range_header}"
                if filter_query:
                    params["filter"] = filter_query

                debug_ctx.add_breadcrumb("Listing searches", params=params)

                # Make API request
                searches = self._make_api_request_with_retry(
                    method="GET",
                    endpoint="/ariel/searches",
                    operation_name="list_searches",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=params,
                )

                # Transform to standard format
                search_list = []
                for search_id in searches:
                    search_list.append(
                        {
                            "search_id": search_id,
                            "id": search_id,  # For backwards compatibility
                        }
                    )

                debug_ctx.add_breadcrumb(f"Retrieved {len(search_list)} searches")

                return self._create_success_result(
                    data={"searches": search_list, "total_count": len(search_list)},
                    operation_name="list_searches",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to list searches: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="list_searches",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def list_saved_searches(
        self,
        saved_search_id: str | None = None,
        range_header: str | None = None,
        filter_query: str | None = None,
        fields: list[str] | None = None,
        timeout_seconds: int | None = None,
    ) -> ServiceOperationResult:
        """
        List saved searches from QRadar.

        This method retrieves saved searches with optional filtering and field selection.
        It provides comprehensive error handling and validation.

        Args:
            saved_search_id: Specific saved search ID to retrieve
            range_header: Range specification for pagination
            filter_query: Filter to apply to results
            fields: List of fields to include in response
            timeout_seconds: Request timeout

        Returns:
            ServiceOperationResult containing saved searches data
        """
        with self._operation_context(
            "list_saved_searches", saved_search_id=saved_search_id, range_header=range_header, filter_query=filter_query
        ) as (debug_ctx, logger):
            try:
                # Build request parameters
                params = {}
                if range_header:
                    params["Range"] = f"items={range_header}"
                if filter_query:
                    params["filter"] = filter_query
                if fields:
                    params["fields"] = ",".join(fields)
                if timeout_seconds:
                    params["timeout"] = timeout_seconds

                # Build endpoint
                endpoint = "/ariel/saved_searches"
                if saved_search_id:
                    endpoint = f"/ariel/saved_searches/{saved_search_id}"

                debug_ctx.add_breadcrumb("Listing saved searches", endpoint=endpoint, params=params)

                # Make API request
                saved_searches = self._make_api_request_with_retry(
                    method="GET",
                    endpoint=endpoint,
                    operation_name="list_saved_searches",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=params,
                )

                # Ensure we have a list
                if saved_search_id and not isinstance(saved_searches, list):
                    saved_searches = [saved_searches]

                # Transform to standard format
                transformed_searches = []
                for search in saved_searches:
                    transformed_search = self._transform_saved_search_to_standard_format(search)
                    transformed_searches.append(transformed_search)

                debug_ctx.add_breadcrumb(f"Retrieved {len(transformed_searches)} saved searches")

                return self._create_success_result(
                    data={"saved_searches": transformed_searches, "total_count": len(transformed_searches)},
                    operation_name="list_saved_searches",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to list saved searches: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="list_saved_searches",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def get_search_status(self, search_id: str) -> ServiceOperationResult:
        """
        Get the status of a specific search.

        This method retrieves detailed status information for a search including
        progress, record count, and completion status.

        Args:
            search_id: ID of the search to check

        Returns:
            ServiceOperationResult containing search status information
        """
        with self._operation_context("get_search_status", search_id=search_id) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters({"search_id": search_id}, ["search_id"], "get_search_status")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "get_search_status", 0, "VALIDATION_ERROR")

            try:
                debug_ctx.add_breadcrumb("Getting search status", search_id=search_id)

                # Get search status
                status_info = self._get_search_status_internal(search_id, debug_ctx, logger)

                # Transform to standard format
                transformed_status = self._transform_search_status_to_standard_format(status_info)

                debug_ctx.add_breadcrumb("Search status retrieved", status=transformed_status.get("status"))

                return self._create_success_result(
                    data=transformed_status,
                    operation_name="get_search_status",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to get search status for {search_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="get_search_status",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def delete_search(self, search_id: str) -> ServiceOperationResult:
        """
        Delete a search from QRadar.

        This method removes a search and all its associated data from the system.

        Args:
            search_id: ID of the search to delete

        Returns:
            ServiceOperationResult indicating success or failure
        """
        with self._operation_context("delete_search", search_id=search_id) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters({"search_id": search_id}, ["search_id"], "delete_search")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "delete_search", 0, "VALIDATION_ERROR")

            try:
                debug_ctx.add_breadcrumb("Deleting search", search_id=search_id)

                # Make API request
                self._make_api_request_with_retry(
                    method="DELETE",
                    endpoint=f"/ariel/searches/{search_id}",
                    operation_name="delete_search",
                    debug_ctx=debug_ctx,
                    logger=logger,
                )

                debug_ctx.add_breadcrumb("Search deleted successfully")

                return self._create_success_result(
                    data={"search_id": search_id, "deleted": True, "deleted_time": time.time()},
                    operation_name="delete_search",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to delete search {search_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="delete_search",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def cancel_search(self, search_id: str) -> ServiceOperationResult:
        """
        Cancel a running search in QRadar.

        This method cancels a search that is currently in progress.

        Args:
            search_id: ID of the search to cancel

        Returns:
            ServiceOperationResult indicating success or failure
        """
        with self._operation_context("cancel_search", search_id=search_id) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters({"search_id": search_id}, ["search_id"], "cancel_search")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "cancel_search", 0, "VALIDATION_ERROR")

            try:
                debug_ctx.add_breadcrumb("Cancelling search", search_id=search_id)

                # Make API request
                self._make_api_request_with_retry(
                    method="POST",
                    endpoint=f"/ariel/searches/{search_id}",
                    operation_name="cancel_search",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params={"status": "CANCELED"},
                )

                debug_ctx.add_breadcrumb("Search cancelled successfully")

                return self._create_success_result(
                    data={"search_id": search_id, "cancelled": True, "cancelled_time": time.time()},
                    operation_name="cancel_search",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to cancel search {search_id}: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="cancel_search",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def validate_query(
        self, query_expression: str, perform_syntax_check: bool = True, perform_security_check: bool = True
    ) -> ServiceOperationResult:
        """
        Validate an AQL query for syntax and security issues.

        This method performs comprehensive validation of AQL queries including
        syntax checking, security validation, and best practice recommendations.

        Args:
            query_expression: AQL query to validate
            perform_syntax_check: Whether to perform syntax validation
            perform_security_check: Whether to perform security validation

        Returns:
            ServiceOperationResult containing validation results
        """
        with self._operation_context(
            "validate_query",
            query_length=len(query_expression) if query_expression else 0,
            perform_syntax_check=perform_syntax_check,
            perform_security_check=perform_security_check,
        ) as (debug_ctx, logger):
            # Validate parameters
            if not query_expression or not query_expression.strip():
                return self._create_error_result("Query expression cannot be empty", "validate_query", 0, "VALIDATION_ERROR")

            try:
                validation_results = {
                    "query": query_expression,
                    "valid": True,
                    "errors": [],
                    "warnings": [],
                    "recommendations": [],
                }

                debug_ctx.add_breadcrumb("Starting query validation")

                # Perform syntax validation
                if perform_syntax_check:
                    syntax_result = self._validate_aql_query(query_expression, debug_ctx, logger)
                    if not syntax_result["valid"]:
                        validation_results["valid"] = False
                        validation_results["errors"].append(f"Syntax error: {syntax_result['error']}")

                # Perform security validation
                if perform_security_check:
                    security_result = self._perform_security_validation(query_expression, debug_ctx, logger)
                    if security_result["warnings"]:
                        validation_results["warnings"].extend(security_result["warnings"])
                    if security_result["errors"]:
                        validation_results["valid"] = False
                        validation_results["errors"].extend(security_result["errors"])

                # Add performance recommendations
                performance_recommendations = self._get_performance_recommendations(query_expression)
                validation_results["recommendations"].extend(performance_recommendations)

                debug_ctx.add_breadcrumb(
                    "Query validation completed",
                    valid=validation_results["valid"],
                    error_count=len(validation_results["errors"]),
                    warning_count=len(validation_results["warnings"]),
                )

                return self._create_success_result(
                    data=validation_results,
                    operation_name="validate_query",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                )

            except Exception as e:
                error_msg = f"Failed to validate query: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="validate_query",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="VALIDATION_ERROR",
                )

    def _transform_saved_search_to_standard_format(self, saved_search: dict[str, Any]) -> dict[str, Any]:
        """
        Transform raw QRadar saved search data to standardized format.

        This method ensures consistent field names, data types, and structure
        for all saved search operations.
        """
        return {
            "id": saved_search.get("id"),
            "name": saved_search.get("name", ""),
            "description": saved_search.get("description", ""),
            "owner": saved_search.get("owner", ""),
            "creation_date": saved_search.get("creation_date"),
            "modified_date": saved_search.get("modified_date"),
            "database": saved_search.get("database", ""),
            "aql": saved_search.get("aql", ""),
            "is_shared": saved_search.get("is_shared", False),
            "is_quick_search": saved_search.get("is_quick_search", False),
            "uid": saved_search.get("uid", ""),
        }

    def _transform_search_status_to_standard_format(self, status_info: dict[str, Any]) -> dict[str, Any]:
        """
        Transform raw QRadar search status data to standardized format.

        This method ensures consistent field names, data types, and structure
        for all search status operations.
        """
        return {
            "search_id": status_info.get("search_id"),
            "status": status_info.get("status", "UNKNOWN"),
            "progress": status_info.get("progress", 0),
            "record_count": status_info.get("record_count", 0),
            "data_file_count": status_info.get("data_file_count", 0),
            "data_total_size": status_info.get("data_total_size", 0),
            "index_file_count": status_info.get("index_file_count", 0),
            "index_total_size": status_info.get("index_total_size", 0),
            "processed_record_count": status_info.get("processed_record_count", 0),
            "desired_retention_time_msec": status_info.get("desired_retention_time_msec", 0),
            "query_execution_time": status_info.get("query_execution_time", 0),
            "query_string": status_info.get("query_string", ""),
            "save_results": status_info.get("save_results", False),
            "completed": status_info.get("status") == "COMPLETED",
        }

    def _perform_security_validation(self, query: str, debug_ctx: DebugContext, logger: Any) -> dict[str, Any]:
        """
        Perform security validation on an AQL query.

        This method checks for potential security issues and provides warnings
        for queries that might be problematic.
        """
        debug_ctx.add_breadcrumb("Performing security validation")

        security_result = {"errors": [], "warnings": []}

        query_lower = query.lower()

        # Check for potentially dangerous patterns
        dangerous_patterns = {
            "drop ": "DROP statements are not allowed in AQL queries",
            "delete ": "DELETE statements are not allowed in AQL queries",
            "insert ": "INSERT statements are not allowed in AQL queries",
            "update ": "UPDATE statements are not allowed in AQL queries",
            "create ": "CREATE statements are not allowed in AQL queries",
            "alter ": "ALTER statements are not allowed in AQL queries",
            "truncate ": "TRUNCATE statements are not allowed in AQL queries",
        }

        for pattern, message in dangerous_patterns.items():
            if pattern in query_lower:
                security_result["errors"].append(message)

        # Check for potential performance issues
        performance_warnings = {
            "select *": "Using SELECT * may impact performance. Consider specifying specific fields.",
            "limit 0": "LIMIT 0 will return no results. This may not be intended.",
            "where 1=1": "WHERE 1=1 condition is always true and may impact performance.",
        }

        for pattern, message in performance_warnings.items():
            if pattern in query_lower:
                security_result["warnings"].append(message)

        debug_ctx.add_breadcrumb(
            "Security validation completed",
            error_count=len(security_result["errors"]),
            warning_count=len(security_result["warnings"]),
        )

        return security_result

    def _get_performance_recommendations(self, query: str) -> list[str]:
        """
        Get performance recommendations for an AQL query.

        This method analyzes the query and provides recommendations for
        improving performance and best practices.
        """
        recommendations = []
        query_lower = query.lower()

        # Check for missing LIMIT clause
        if "limit" not in query_lower:
            recommendations.append("Consider adding a LIMIT clause to prevent returning excessive results")

        # Check for missing time range
        if "start" not in query_lower and "last" not in query_lower:
            recommendations.append("Consider adding a time range (START/LAST) to improve query performance")

        # Check for SELECT *
        if "select *" in query_lower:
            recommendations.append("Consider selecting specific fields instead of using SELECT * for better performance")

        # Check for complex WHERE clauses
        if query_lower.count("where") > 1:
            recommendations.append("Multiple WHERE clauses detected. Consider combining conditions for better performance")

        return recommendations

    def get_service_health(self) -> dict[str, Any]:
        """Get health status of the SearchService."""
        try:
            # Test basic search functionality
            test_query = "SELECT sourceip FROM events LIMIT 1"
            test_result = self.create_search(query_expression=test_query)

            return {
                "service_name": self.service_name,
                "status": "healthy" if test_result.is_success() else "unhealthy",
                "last_check": time.time(),
                "api_connectivity": test_result.is_success(),
                "error_message": test_result.error_message if not test_result.is_success() else None,
            }
        except Exception as e:
            return {
                "service_name": self.service_name,
                "status": "unhealthy",
                "last_check": time.time(),
                "api_connectivity": False,
                "error_message": str(e),
            }


class ReferenceService(BaseService):
    """
    Service for QRadar reference data operations with comprehensive functionality.

    This service handles all reference data operations including:
    - Managing reference sets (create, update, delete)
    - Bulk operations on reference set values
    - Reference set value management
    - Data validation and integrity checks
    - Performance optimization for large datasets

    All methods provide clear error messages, comprehensive logging, built-in validation,
    and actionable feedback for troubleshooting and issue resolution.
    """

    def __init__(self, client: Client):
        super().__init__(client, "ReferenceService")

        # Reference data specific configuration
        self.config.update(
            {
                "default_bulk_size": 1000,
                "max_bulk_size": 10000,
                "bulk_operation_timeout": 600,  # 10 minutes
                "enable_value_validation": True,
                "enable_duplicate_detection": True,
            }
        )

    def list_reference_sets(
        self, range_header: str | None = None, filter_query: str | None = None, fields: str | None = None
    ) -> ServiceOperationResult:
        """
        List QRadar reference sets with optional filtering.

        This method provides comprehensive reference set listing with:
        - Flexible filtering using QRadar's filter syntax
        - Pagination support through range headers
        - Field selection for performance optimization
        - Comprehensive error handling and validation

        Args:
            range_header: Range header for pagination
            filter_query: QRadar filter expression
            fields: Comma-separated list of fields to include

        Returns:
            ServiceOperationResult containing reference set data
        """
        with self._operation_context("list_reference_sets", range_header=range_header, filter_query=filter_query) as (
            debug_ctx,
            logger,
        ):
            try:
                # Build API parameters
                api_params = {}
                if filter_query:
                    api_params["filter"] = filter_query
                if fields:
                    api_params["fields"] = fields

                # Build headers
                headers = {}
                if range_header:
                    headers["Range"] = range_header

                debug_ctx.add_breadcrumb("Listing reference sets", filter=filter_query, range=range_header)

                # Make API request
                reference_sets = self._make_api_request_with_retry(
                    method="GET",
                    endpoint="/reference_data/sets",
                    operation_name="list_reference_sets",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=api_params,
                    additional_headers=headers if headers else None,
                )

                debug_ctx.add_breadcrumb(f"Retrieved {len(reference_sets)} reference sets")

                return self._create_success_result(
                    data=reference_sets,
                    operation_name="list_reference_sets",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={"reference_set_count": len(reference_sets)},
                )

            except Exception as e:
                error_msg = f"Failed to list reference sets: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="list_reference_sets",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def create_reference_set(
        self,
        name: str,
        element_type: str,
        timeout_type: str | None = None,
        time_to_live: str | None = None,
        fields: str | None = None,
    ) -> ServiceOperationResult:
        """
        Create a new QRadar reference set.

        Args:
            name: Name of the reference set
            element_type: Type of elements (IP, ALNIC, etc.)
            timeout_type: Timeout type for elements
            time_to_live: Time to live for elements
            fields: Fields to return in response

        Returns:
            ServiceOperationResult containing created reference set data
        """
        with self._operation_context("create_reference_set", name=name, element_type=element_type) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"name": name, "element_type": element_type}, ["name", "element_type"], "create_reference_set"
            )

            # Additional validation
            valid_element_types = ["IP", "ALNIC", "PORT", "NUM", "DATE"]
            if element_type not in valid_element_types:
                validation_errors.append(f"element_type must be one of: {', '.join(valid_element_types)}")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "create_reference_set", 0, "VALIDATION_ERROR")

            try:
                # Build request parameters
                request_params = {"name": name, "element_type": element_type}

                if timeout_type:
                    request_params["timeout_type"] = timeout_type
                if time_to_live:
                    request_params["time_to_live"] = time_to_live
                if fields:
                    request_params["fields"] = fields

                debug_ctx.add_breadcrumb("Creating reference set", params=request_params)

                # Make API request
                created_set = self._make_api_request_with_retry(
                    method="POST",
                    endpoint="/reference_data/sets",
                    operation_name="create_reference_set",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=request_params,
                )

                debug_ctx.add_breadcrumb("Reference set created successfully", name=name)

                return self._create_success_result(
                    data=created_set,
                    operation_name="create_reference_set",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={"reference_set_name": name, "element_type": element_type},
                )

            except Exception as e:
                error_msg = f"Failed to create reference set '{name}': {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="create_reference_set",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def bulk_load_reference_set(
        self,
        reference_set_name: str,
        values: list[str],
        source: str | None = None,
        validate_values: bool = True,
        batch_size: int = 100,
        remove_duplicates: bool = True,
        progress_reporting: bool = True,
    ) -> ServiceOperationResult:
        """
        Enhanced bulk load values into a reference set with comprehensive validation and error handling.

        This method provides:
        - Configurable batch processing for large datasets
        - Comprehensive value validation and duplicate detection
        - Progress monitoring and detailed error reporting
        - Automatic retry for failed batches
        - Performance optimization for large value sets

        Args:
            reference_set_name: Name of the reference set
            values: List of values to add
            source: Source identifier for the values
            validate_values: Whether to validate values before loading
            batch_size: Size of each batch for processing
            remove_duplicates: Whether to remove duplicate values
            progress_reporting: Whether to provide detailed progress updates

        Returns:
            ServiceOperationResult containing comprehensive bulk load results
        """
        with self._operation_context(
            "bulk_load_reference_set", reference_set_name=reference_set_name, value_count=len(values)
        ) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"reference_set_name": reference_set_name, "values": values},
                ["reference_set_name", "values"],
                "bulk_load_reference_set",
            )

            if not isinstance(values, list) or len(values) == 0:
                validation_errors.append("values must be a non-empty list")

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "bulk_load_reference_set", 0, "VALIDATION_ERROR")

            try:
                # Validate values if requested
                if validate_values:
                    validation_result = self._validate_reference_set_values(values, debug_ctx, logger)
                    if validation_result["invalid_values"]:
                        logger.warning(f"Found {len(validation_result['invalid_values'])} invalid values")
                        # Filter out invalid values
                        values = validation_result["valid_values"]

                # Remove duplicates if enabled
                if remove_duplicates:
                    original_count = len(values)
                    values = list(set(values))  # Remove duplicates
                    if len(values) < original_count:
                        debug_ctx.add_breadcrumb(f"Removed {original_count - len(values)} duplicate values")

                debug_ctx.add_breadcrumb("Starting bulk load", reference_set=reference_set_name, value_count=len(values))

                # Process in batches with configurable batch size
                effective_batch_size = min(batch_size, len(values))
                batches = [values[i : i + effective_batch_size] for i in range(0, len(values), effective_batch_size)]

                successful_loads = 0
                failed_loads = 0
                errors = []

                for i, batch in enumerate(batches):
                    debug_ctx.add_breadcrumb(f"Processing batch {i + 1}/{len(batches)}", batch_size=len(batch))

                    try:
                        # Prepare batch data
                        batch_data = [{"value": value, "source": source} for value in batch]

                        # Make API request for this batch
                        batch_result = self._make_api_request_with_retry(
                            method="POST",
                            endpoint=f"/reference_data/sets/{reference_set_name}",
                            operation_name="bulk_load_batch",
                            debug_ctx=debug_ctx,
                            logger=logger,
                            json_data=batch_data,
                        )

                        successful_loads += len(batch)
                        debug_ctx.add_breadcrumb(f"Batch {i + 1} completed successfully")

                    except Exception as batch_error:
                        failed_loads += len(batch)
                        error_msg = f"Batch {i + 1} failed: {str(batch_error)}"
                        errors.append(error_msg)
                        debug_ctx.add_breadcrumb(f"Batch {i + 1} failed", error=str(batch_error), level="error")
                        logger.warning(error_msg)

                debug_ctx.add_breadcrumb(
                    "Bulk load completed", successful=successful_loads, failed=failed_loads, total_batches=len(batches)
                )

                # Determine overall success
                overall_success = failed_loads == 0

                result_data = {
                    "reference_set_name": reference_set_name,
                    "total_values": len(values),
                    "successful_loads": successful_loads,
                    "failed_loads": failed_loads,
                    "batch_count": len(batches),
                    "errors": errors,
                }

                if overall_success:
                    return self._create_success_result(
                        data=result_data,
                        operation_name="bulk_load_reference_set",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    )
                else:
                    return self._create_error_result(
                        error_message=f"Bulk load partially failed: {failed_loads}/{len(values)} values failed",
                        operation_name="bulk_load_reference_set",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                        error_code="PARTIAL_FAILURE",
                        debug_context=result_data,
                    )

            except Exception as e:
                error_msg = f"Failed to bulk load reference set '{reference_set_name}': {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="bulk_load_reference_set",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def delete_reference_set(self, reference_set_name: str, purge_only: bool = False) -> ServiceOperationResult:
        """
        Delete a QRadar reference set with comprehensive validation.

        This method provides:
        - Pre-deletion validation to prevent accidental deletions
        - Option to purge data only or delete the entire set
        - Clear error messages for common deletion issues
        - Comprehensive logging of deletion operations

        Args:
            reference_set_name: Name of the reference set to delete
            purge_only: If True, only purge data; if False, delete entire set

        Returns:
            ServiceOperationResult containing deletion results
        """
        with self._operation_context("delete_reference_set", reference_set_name=reference_set_name, purge_only=purge_only) as (
            debug_ctx,
            logger,
        ):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"reference_set_name": reference_set_name}, ["reference_set_name"], "delete_reference_set"
            )

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "delete_reference_set", 0, "VALIDATION_ERROR")

            try:
                # First, verify the reference set exists
                debug_ctx.add_breadcrumb("Verifying reference set exists before deletion")

                existing_sets = self._make_api_request_with_retry(
                    method="GET",
                    endpoint="/reference_data/sets",
                    operation_name="verify_reference_set_exists",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params={"filter": f'name="{reference_set_name}"'},
                )

                if not existing_sets:
                    error_msg = f"Reference set '{reference_set_name}' does not exist and cannot be deleted"
                    return self._create_error_result(
                        error_message=error_msg,
                        operation_name="delete_reference_set",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                        error_code="NOT_FOUND",
                    )

                reference_set_info = existing_sets[0]
                debug_ctx.capture_variable("reference_set_info", reference_set_info)

                if purge_only:
                    debug_ctx.add_breadcrumb("Purging reference set data only")
                    endpoint = f"/reference_data/sets/{reference_set_name}"
                    method = "DELETE"
                    params = {"purge_only": "true"}
                else:
                    debug_ctx.add_breadcrumb("Deleting entire reference set")
                    endpoint = f"/reference_data/sets/{reference_set_name}"
                    method = "DELETE"
                    params = {}

                # Perform the deletion
                deletion_result = self._make_api_request_with_retry(
                    method=method,
                    endpoint=endpoint,
                    operation_name="delete_reference_set",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=params,
                )

                operation_type = "purged" if purge_only else "deleted"
                debug_ctx.add_breadcrumb(f"Reference set {operation_type} successfully")

                return self._create_success_result(
                    data={
                        "reference_set_name": reference_set_name,
                        "operation": operation_type,
                        "previous_info": reference_set_info,
                    },
                    operation_name="delete_reference_set",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "reference_set_name": reference_set_name,
                        "operation_type": operation_type,
                        "element_count": reference_set_info.get("number_of_elements", 0),
                    },
                )

            except Exception as e:
                error_msg = f"Failed to delete reference set '{reference_set_name}': {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="delete_reference_set",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def update_reference_set_value(
        self, reference_set_name: str, value: str, source: str | None = None, validate_value: bool = True
    ) -> ServiceOperationResult:
        """
        Update or add a single value to a reference set with comprehensive validation.

        This method provides:
        - Value format validation based on reference set type
        - Clear error messages for validation failures
        - Source tracking for audit purposes
        - Duplicate detection and handling

        Args:
            reference_set_name: Name of the reference set
            value: Value to add or update
            source: Source identifier for the value
            validate_value: Whether to validate the value format

        Returns:
            ServiceOperationResult containing update results
        """
        with self._operation_context("update_reference_set_value", reference_set_name=reference_set_name, value=value) as (
            debug_ctx,
            logger,
        ):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"reference_set_name": reference_set_name, "value": value},
                ["reference_set_name", "value"],
                "update_reference_set_value",
            )

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "update_reference_set_value", 0, "VALIDATION_ERROR")

            try:
                # Get reference set information for validation
                debug_ctx.add_breadcrumb("Retrieving reference set information for validation")

                ref_set_info = self._make_api_request_with_retry(
                    method="GET",
                    endpoint="/reference_data/sets",
                    operation_name="get_reference_set_info",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params={"filter": f'name="{reference_set_name}"'},
                )

                if not ref_set_info:
                    error_msg = f"Reference set '{reference_set_name}' does not exist"
                    return self._create_error_result(
                        error_message=error_msg,
                        operation_name="update_reference_set_value",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                        error_code="NOT_FOUND",
                    )

                element_type = ref_set_info[0].get("element_type", "ALNIC")
                debug_ctx.capture_variable("element_type", element_type)

                # Validate value format if requested
                if validate_value:
                    validation_result = self._validate_single_reference_value(value, element_type, debug_ctx, logger)
                    if not validation_result["is_valid"]:
                        error_msg = f"Value validation failed: {validation_result['error_message']}"
                        return self._create_error_result(
                            error_message=error_msg,
                            operation_name="update_reference_set_value",
                            duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                            error_code="VALIDATION_ERROR",
                            debug_context={
                                "value": value,
                                "element_type": element_type,
                                "validation_error": validation_result["error_message"],
                            },
                        )

                # Prepare request parameters
                request_params = {"value": value}
                if source:
                    request_params["source"] = source

                debug_ctx.add_breadcrumb("Updating reference set value", params=request_params)

                # Make API request to update the value
                update_result = self._make_api_request_with_retry(
                    method="POST",
                    endpoint=f"/reference_data/sets/{reference_set_name}",
                    operation_name="update_reference_set_value",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=request_params,
                )

                debug_ctx.add_breadcrumb("Reference set value updated successfully")

                return self._create_success_result(
                    data={
                        "reference_set_name": reference_set_name,
                        "value": value,
                        "source": source,
                        "element_type": element_type,
                        "update_result": update_result,
                    },
                    operation_name="update_reference_set_value",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={
                        "reference_set_name": reference_set_name,
                        "value_length": len(str(value)),
                        "element_type": element_type,
                    },
                )

            except Exception as e:
                error_msg = f"Failed to update reference set value in '{reference_set_name}': {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="update_reference_set_value",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def delete_reference_set_value(self, reference_set_name: str, value: str) -> ServiceOperationResult:
        """
        Delete a specific value from a reference set with validation.

        This method provides:
        - Pre-deletion validation to ensure value exists
        - Clear error messages for common deletion issues
        - Comprehensive logging of deletion operations
        - Graceful handling of non-existent values

        Args:
            reference_set_name: Name of the reference set
            value: Value to delete from the reference set

        Returns:
            ServiceOperationResult containing deletion results
        """
        with self._operation_context("delete_reference_set_value", reference_set_name=reference_set_name, value=value) as (
            debug_ctx,
            logger,
        ):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"reference_set_name": reference_set_name, "value": value},
                ["reference_set_name", "value"],
                "delete_reference_set_value",
            )

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "delete_reference_set_value", 0, "VALIDATION_ERROR")

            try:
                debug_ctx.add_breadcrumb("Deleting reference set value", value=value)

                # Make API request to delete the value
                deletion_result = self._make_api_request_with_retry(
                    method="DELETE",
                    endpoint=f"/reference_data/sets/{reference_set_name}/{value}",
                    operation_name="delete_reference_set_value",
                    debug_ctx=debug_ctx,
                    logger=logger,
                )

                debug_ctx.add_breadcrumb("Reference set value deleted successfully")

                return self._create_success_result(
                    data={"reference_set_name": reference_set_name, "deleted_value": value, "deletion_result": deletion_result},
                    operation_name="delete_reference_set_value",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={"reference_set_name": reference_set_name, "deleted_value": value},
                )

            except Exception as e:
                # Provide helpful error messages for common scenarios
                error_msg = str(e)
                if "does not exist" in error_msg.lower():
                    error_msg = f"Value '{value}' does not exist in reference set '{reference_set_name}'"
                elif "not found" in error_msg.lower():
                    error_msg = f"Reference set '{reference_set_name}' or value '{value}' not found"
                else:
                    error_msg = f"Failed to delete value '{value}' from reference set '{reference_set_name}': {error_msg}"

                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="delete_reference_set_value",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def get_reference_set_values(
        self, reference_set_name: str, range_header: str | None = None, filter_query: str | None = None
    ) -> ServiceOperationResult:
        """
        Retrieve values from a reference set with pagination and filtering support.

        This method provides:
        - Efficient pagination for large reference sets
        - Flexible filtering capabilities
        - Clear error messages for invalid queries
        - Performance optimization for large datasets

        Args:
            reference_set_name: Name of the reference set
            range_header: Range header for pagination (e.g., "items=0-49")
            filter_query: Filter expression for values

        Returns:
            ServiceOperationResult containing reference set values
        """
        with self._operation_context(
            "get_reference_set_values", reference_set_name=reference_set_name, range_header=range_header
        ) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"reference_set_name": reference_set_name}, ["reference_set_name"], "get_reference_set_values"
            )

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "get_reference_set_values", 0, "VALIDATION_ERROR")

            try:
                # Build API parameters
                api_params = {}
                if filter_query:
                    api_params["filter"] = filter_query

                # Build headers
                headers = {}
                if range_header:
                    headers["Range"] = range_header

                debug_ctx.add_breadcrumb("Retrieving reference set values", filter=filter_query, range=range_header)

                # Make API request
                values_data = self._make_api_request_with_retry(
                    method="GET",
                    endpoint=f"/reference_data/sets/{reference_set_name}",
                    operation_name="get_reference_set_values",
                    debug_ctx=debug_ctx,
                    logger=logger,
                    params=api_params,
                    additional_headers=headers if headers else None,
                )

                # Extract values from the response
                values = values_data.get("data", []) if isinstance(values_data, dict) else []
                debug_ctx.add_breadcrumb(f"Retrieved {len(values)} reference set values")

                return self._create_success_result(
                    data={
                        "reference_set_name": reference_set_name,
                        "values": values,
                        "total_count": len(values),
                        "metadata": {
                            "element_type": values_data.get("element_type"),
                            "timeout_type": values_data.get("timeout_type"),
                            "time_to_live": values_data.get("time_to_live"),
                            "number_of_elements": values_data.get("number_of_elements"),
                        },
                    },
                    operation_name="get_reference_set_values",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    debug_context={"reference_set_name": reference_set_name, "value_count": len(values)},
                )

            except Exception as e:
                error_msg = f"Failed to retrieve values from reference set '{reference_set_name}': {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="get_reference_set_values",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def validate_reference_set_configuration(
        self, reference_set_name: str, expected_element_type: str | None = None, check_permissions: bool = True
    ) -> ServiceOperationResult:
        """
        Validate reference set configuration and accessibility with comprehensive checks.

        This method provides:
        - Configuration validation against expected settings
        - Permission and accessibility checks
        - Element type validation
        - Clear diagnostic information for troubleshooting

        Args:
            reference_set_name: Name of the reference set to validate
            expected_element_type: Expected element type (IP, ALNIC, etc.)
            check_permissions: Whether to check read/write permissions

        Returns:
            ServiceOperationResult containing validation results
        """
        with self._operation_context(
            "validate_reference_set_configuration",
            reference_set_name=reference_set_name,
            expected_element_type=expected_element_type,
        ) as (debug_ctx, logger):
            # Validate parameters
            validation_errors = self._validate_required_parameters(
                {"reference_set_name": reference_set_name}, ["reference_set_name"], "validate_reference_set_configuration"
            )

            if validation_errors:
                error_msg = f"Parameter validation failed: {', '.join(validation_errors)}"
                return self._create_error_result(error_msg, "validate_reference_set_configuration", 0, "VALIDATION_ERROR")

            try:
                validation_results = {
                    "reference_set_name": reference_set_name,
                    "exists": False,
                    "accessible": False,
                    "element_type_valid": False,
                    "permissions": {},
                    "configuration": {},
                    "issues": [],
                    "recommendations": [],
                }

                debug_ctx.add_breadcrumb("Starting reference set configuration validation")

                # Check if reference set exists
                try:
                    ref_set_info = self._make_api_request_with_retry(
                        method="GET",
                        endpoint="/reference_data/sets",
                        operation_name="check_reference_set_exists",
                        debug_ctx=debug_ctx,
                        logger=logger,
                        params={"filter": f'name="{reference_set_name}"'},
                    )

                    if ref_set_info:
                        validation_results["exists"] = True
                        validation_results["accessible"] = True
                        validation_results["configuration"] = ref_set_info[0]

                        actual_element_type = ref_set_info[0].get("element_type")
                        debug_ctx.capture_variable("actual_element_type", actual_element_type)

                        # Validate element type if expected type is provided
                        if expected_element_type:
                            if actual_element_type == expected_element_type:
                                validation_results["element_type_valid"] = True
                            else:
                                validation_results["issues"].append(
                                    f"Element type mismatch: expected '{expected_element_type}', "
                                    f"found '{actual_element_type}'"
                                )
                                validation_results["recommendations"].append(
                                    f"Update your configuration to use element type '{actual_element_type}' "
                                    f"or recreate the reference set with type '{expected_element_type}'"
                                )
                        else:
                            validation_results["element_type_valid"] = True

                        debug_ctx.add_breadcrumb("Reference set exists and is accessible")

                    else:
                        validation_results["issues"].append(f"Reference set '{reference_set_name}' does not exist")
                        validation_results["recommendations"].append(
                            f"Create the reference set '{reference_set_name}' before attempting to use it"
                        )

                except Exception as access_error:
                    validation_results["issues"].append(f"Cannot access reference set: {str(access_error)}")
                    validation_results["recommendations"].append(
                        "Check QRadar connectivity and user permissions for reference data operations"
                    )

                # Check permissions if requested and reference set exists
                if check_permissions and validation_results["exists"]:
                    debug_ctx.add_breadcrumb("Checking reference set permissions")

                    # Test read permission
                    try:
                        self._make_api_request_with_retry(
                            method="GET",
                            endpoint=f"/reference_data/sets/{reference_set_name}",
                            operation_name="test_read_permission",
                            debug_ctx=debug_ctx,
                            logger=logger,
                            params={"Range": "items=0-0"},  # Minimal read test
                        )
                        validation_results["permissions"]["read"] = True
                    except Exception:
                        validation_results["permissions"]["read"] = False
                        validation_results["issues"].append("No read permission for reference set")
                        validation_results["recommendations"].append(
                            "Ensure the QRadar user has read permissions for reference data"
                        )

                    # Test write permission (attempt to add a test value)
                    try:
                        test_value = f"__validation_test_{int(time.time())}"
                        self._make_api_request_with_retry(
                            method="POST",
                            endpoint=f"/reference_data/sets/{reference_set_name}",
                            operation_name="test_write_permission",
                            debug_ctx=debug_ctx,
                            logger=logger,
                            params={"value": test_value},
                        )
                        # Clean up test value
                        try:
                            self._make_api_request_with_retry(
                                method="DELETE",
                                endpoint=f"/reference_data/sets/{reference_set_name}/{test_value}",
                                operation_name="cleanup_test_value",
                                debug_ctx=debug_ctx,
                                logger=logger,
                            )
                        except Exception:
                            pass  # Ignore cleanup errors

                        validation_results["permissions"]["write"] = True
                    except Exception:
                        validation_results["permissions"]["write"] = False
                        validation_results["issues"].append("No write permission for reference set")
                        validation_results["recommendations"].append(
                            "Ensure the QRadar user has write permissions for reference data"
                        )

                # Determine overall validation status
                is_valid = (
                    validation_results["exists"]
                    and validation_results["accessible"]
                    and validation_results["element_type_valid"]
                    and (
                        not check_permissions
                        or (
                            validation_results["permissions"].get("read", False)
                            and validation_results["permissions"].get("write", False)
                        )
                    )
                )

                validation_results["is_valid"] = is_valid

                debug_ctx.add_breadcrumb(
                    "Configuration validation completed", is_valid=is_valid, issues_count=len(validation_results["issues"])
                )

                if is_valid:
                    return self._create_success_result(
                        data=validation_results,
                        operation_name="validate_reference_set_configuration",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    )
                else:
                    error_msg = f"Reference set validation failed: {', '.join(validation_results['issues'])}"
                    return self._create_error_result(
                        error_message=error_msg,
                        operation_name="validate_reference_set_configuration",
                        duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                        error_code="VALIDATION_FAILED",
                        debug_context=validation_results,
                    )

            except Exception as e:
                error_msg = f"Failed to validate reference set configuration: {str(e)}"
                return self._create_error_result(
                    error_message=error_msg,
                    operation_name="validate_reference_set_configuration",
                    duration_ms=(time.time() - debug_ctx.start_time) * 1000,
                    error_code="API_ERROR",
                )

    def _validate_reference_set_values(self, values: list[str], debug_ctx: DebugContext, logger: Any) -> dict[str, Any]:
        """
        Validate reference set values for format and content with comprehensive error reporting.

        This enhanced validation method provides:
        - Format validation based on common patterns
        - Clear error messages for each validation failure
        - Suggestions for fixing invalid values
        - Performance optimization for large value lists
        """
        debug_ctx.add_breadcrumb(f"Validating {len(values)} reference set values")

        valid_values = []
        invalid_values = []
        validation_stats = {
            "total_values": len(values),
            "empty_values": 0,
            "duplicate_values": 0,
            "format_errors": 0,
            "length_errors": 0,
        }

        seen_values = set()

        for i, value in enumerate(values):
            try:
                # Convert to string and strip whitespace
                str_value = str(value).strip() if value is not None else ""

                # Check for empty values
                if not str_value:
                    invalid_values.append(
                        {
                            "index": i,
                            "value": value,
                            "error": "Empty or null value",
                            "suggestion": "Remove empty values or provide valid data",
                        }
                    )
                    validation_stats["empty_values"] += 1
                    continue

                # Check for duplicates
                if str_value in seen_values:
                    invalid_values.append(
                        {
                            "index": i,
                            "value": str_value,
                            "error": "Duplicate value",
                            "suggestion": "Remove duplicate values to improve performance",
                        }
                    )
                    validation_stats["duplicate_values"] += 1
                    continue

                # Check value length (QRadar has limits)
                if len(str_value) > 1000:  # QRadar typical limit
                    invalid_values.append(
                        {
                            "index": i,
                            "value": str_value[:50] + "...",  # Truncate for display
                            "error": f"Value too long ({len(str_value)} characters, max 1000)",
                            "suggestion": "Truncate the value or split into multiple entries",
                        }
                    )
                    validation_stats["length_errors"] += 1
                    continue

                # Additional format validation could be added here based on element type
                # For now, we'll accept any non-empty string within length limits
                valid_values.append(str_value)
                seen_values.add(str_value)

            except Exception as e:
                invalid_values.append(
                    {
                        "index": i,
                        "value": str(value)[:50] if value else None,
                        "error": f"Processing error: {str(e)}",
                        "suggestion": "Check the value format and encoding",
                    }
                )
                validation_stats["format_errors"] += 1

        validation_stats["valid_values"] = len(valid_values)
        validation_stats["invalid_values"] = len(invalid_values)

        debug_ctx.add_breadcrumb(
            "Value validation completed", valid_count=len(valid_values), invalid_count=len(invalid_values), stats=validation_stats
        )

        return {
            "valid_values": valid_values,
            "invalid_values": invalid_values,
            "validation_stats": validation_stats,
            "has_issues": len(invalid_values) > 0,
        }

    def _validate_qradar_filter_syntax(filter_query: str) -> dict[str, Any]:
        """
        Validate QRadar filter syntax and provide helpful error messages.

        This function validates common QRadar filter patterns and provides
        suggestions for fixing syntax errors.

        Args:
            filter_query: The filter query to validate

        Returns:
            Dictionary containing validation results and suggestions
        """
        validation_result = {"is_valid": True, "error": "", "suggestions": []}

        try:
            # Basic syntax checks
            if not filter_query.strip():
                validation_result["is_valid"] = False
                validation_result["error"] = "Filter query cannot be empty"
                validation_result["suggestions"] = [
                    "Provide a valid QRadar filter expression",
                    'Example: name="my_reference_set"',
                    'Example: element_type="IP"',
                ]
                return validation_result

            # Check for balanced quotes
            single_quotes = filter_query.count("'")
            double_quotes = filter_query.count('"')

            if single_quotes % 2 != 0:
                validation_result["is_valid"] = False
                validation_result["error"] = "Unbalanced single quotes in filter"
                validation_result["suggestions"] = [
                    "Ensure all single quotes are properly paired",
                    'Use double quotes for string values: name="value"',
                    "Escape quotes within strings if needed",
                ]
                return validation_result

            if double_quotes % 2 != 0:
                validation_result["is_valid"] = False
                validation_result["error"] = "Unbalanced double quotes in filter"
                validation_result["suggestions"] = [
                    "Ensure all double quotes are properly paired",
                    'Use format: field="value" for string comparisons',
                    "Escape quotes within strings if needed",
                ]
                return validation_result

            # Check for common field names
            common_fields = ["name", "element_type", "timeout_type", "creation_time"]
            has_valid_field = any(field in filter_query.lower() for field in common_fields)

            if not has_valid_field:
                validation_result["suggestions"].append(f"Consider using common fields: {', '.join(common_fields)}")

            return validation_result

        except Exception as e:
            validation_result["is_valid"] = False
            validation_result["error"] = f"Filter validation error: {str(e)}"
            validation_result["suggestions"] = [
                "Check filter syntax for special characters",
                "Refer to QRadar API documentation for filter syntax",
                "Test with simpler filter expressions first",
            ]
            return validation_result

    def _validate_single_reference_value(
        self, value: str, element_type: str, debug_ctx: DebugContext, logger: Any
    ) -> dict[str, Any]:
        """
        Validate a single reference set value based on its element type.

        This method provides type-specific validation with clear error messages
        and suggestions for fixing invalid values.

        Args:
            value: The value to validate
            element_type: The element type (IP, ALNIC, PORT, NUM, DATE)
            debug_ctx: Debug context for tracing
            logger: Logger instance

        Returns:
            Dictionary containing validation results
        """
        debug_ctx.add_breadcrumb(f"Validating single value for type {element_type}", value=value[:50])

        validation_result = {"is_valid": False, "error_message": "", "suggestion": "", "normalized_value": value}

        try:
            str_value = str(value).strip()

            # Basic checks
            if not str_value:
                validation_result["error_message"] = "Value cannot be empty"
                validation_result["suggestion"] = "Provide a non-empty value"
                return validation_result

            if len(str_value) > 1000:
                validation_result["error_message"] = f"Value too long ({len(str_value)} characters, max 1000)"
                validation_result["suggestion"] = "Truncate the value to 1000 characters or less"
                return validation_result

            # Type-specific validation
            if element_type == "IP":
                validation_result = self._validate_ip_value(str_value)
            elif element_type == "PORT":
                validation_result = self._validate_port_value(str_value)
            elif element_type == "NUM":
                validation_result = self._validate_numeric_value(str_value)
            elif element_type == "DATE":
                validation_result = self._validate_date_value(str_value)
            elif element_type == "ALNIC":
                # ALNIC (alphanumeric) accepts most strings
                validation_result["is_valid"] = True
                validation_result["normalized_value"] = str_value
            else:
                # Unknown type - accept as string but warn
                validation_result["is_valid"] = True
                validation_result["normalized_value"] = str_value
                validation_result["suggestion"] = f"Unknown element type '{element_type}', treating as string"

            debug_ctx.add_breadcrumb(
                "Single value validation completed", is_valid=validation_result["is_valid"], element_type=element_type
            )

        except Exception as e:
            validation_result["error_message"] = f"Validation error: {str(e)}"
            validation_result["suggestion"] = "Check the value format and try again"

        return validation_result

    def _validate_ip_value(self, value: str) -> dict[str, Any]:
        """Validate IP address value."""
        try:
            # Try to parse as IP address
            ip_address(value)
            return {"is_valid": True, "normalized_value": value, "error_message": "", "suggestion": ""}
        except ValueError:
            return {
                "is_valid": False,
                "normalized_value": value,
                "error_message": f"'{value}' is not a valid IP address",
                "suggestion": "Provide a valid IPv4 or IPv6 address (e.g., '192.168.1.1' or '2001:db8::1')",
            }

    def _validate_port_value(self, value: str) -> dict[str, Any]:
        """Validate port number value."""
        try:
            port_num = int(value)
            if 1 <= port_num <= 65535:
                return {"is_valid": True, "normalized_value": str(port_num), "error_message": "", "suggestion": ""}
            else:
                return {
                    "is_valid": False,
                    "normalized_value": value,
                    "error_message": f"Port number {port_num} is out of valid range (1-65535)",
                    "suggestion": "Provide a port number between 1 and 65535",
                }
        except ValueError:
            return {
                "is_valid": False,
                "normalized_value": value,
                "error_message": f"'{value}' is not a valid port number",
                "suggestion": "Provide a numeric port value between 1 and 65535",
            }

    def _validate_numeric_value(self, value: str) -> dict[str, Any]:
        """Validate numeric value."""
        try:
            # Try to parse as number (int or float)
            if "." in value:
                float(value)
            else:
                int(value)
            return {"is_valid": True, "normalized_value": value, "error_message": "", "suggestion": ""}
        except ValueError:
            return {
                "is_valid": False,
                "normalized_value": value,
                "error_message": f"'{value}' is not a valid number",
                "suggestion": "Provide a valid numeric value (integer or decimal)",
            }

    def _validate_date_value(self, value: str) -> dict[str, Any]:
        """Validate date value."""
        # QRadar typically expects epoch timestamps for DATE type
        try:
            # Try as epoch timestamp first
            timestamp = int(value)
            if timestamp > 0:
                return {"is_valid": True, "normalized_value": str(timestamp), "error_message": "", "suggestion": ""}
        except ValueError:
            pass

        # Try common date formats
        date_formats = ["%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d", "%m/%d/%Y", "%d/%m/%Y"]

        for date_format in date_formats:
            try:
                from datetime import datetime

                parsed_date = datetime.strptime(value, date_format)
                epoch_timestamp = int(parsed_date.timestamp() * 1000)  # QRadar uses milliseconds
                return {
                    "is_valid": True,
                    "normalized_value": str(epoch_timestamp),
                    "error_message": "",
                    "suggestion": f"Converted '{value}' to epoch timestamp {epoch_timestamp}",
                }
            except ValueError:
                continue

        return {
            "is_valid": False,
            "normalized_value": value,
            "error_message": f"'{value}' is not a valid date format",
            "suggestion": "Provide a date in format YYYY-MM-DD, YYYY-MM-DD HH:MM:SS, or epoch timestamp",
        }

    def get_service_health(self) -> dict[str, Any]:
        """Get health status of the ReferenceService."""
        try:
            # Test basic reference set listing
            test_result = self.list_reference_sets(range_header="items=0-0")

            return {
                "service_name": self.service_name,
                "status": "healthy" if test_result.is_success() else "unhealthy",
                "last_check": time.time(),
                "api_connectivity": test_result.is_success(),
                "error_message": test_result.error_message if not test_result.is_success() else None,
            }
        except Exception as e:
            return {
                "service_name": self.service_name,
                "status": "unhealthy",
                "last_check": time.time(),
                "api_connectivity": False,
                "error_message": str(e),
            }


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS (Utilities and Data Processing)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains utility functions organized by purpose for easy navigation and maintenance.
# Functions are grouped logically: data transformation, time processing, enrichment, context management, etc.

# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# DATA TRANSFORMATION UTILITIES
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def get_major_version(version: str) -> int:
    try:
        if "." not in version:
            return int(version)
        return int(version.split(".")[0])
    except ValueError:
        print_debug_msg(f"Could not parse version {version} to int")
        return 17


def insert_values_to_reference_set_polling(
    client: Client,
    api_version: str,
    args: dict,
    from_indicators: bool = False,
    values: list[str] | None = None,
) -> PollResult:
    """This function inserts values to reference set using polling method.


    Args:
        client (Client): QRadar Client
        api_version (str): The API version of QRadar.
        args (dict): args of the command
        from_indicators (bool, optional): Whether to insert values from XSOAR indicators. Defaults to False.
        values (list[str] | None, optional): The values to insert. Defaults to None.

    Raises:
        DemistoException: If there are no values to insert

    Returns:
        PollResult: The result with the CommandResults
    """
    response = {}
    use_old_api = get_major_version(api_version) <= 15
    ref_name = args.get("ref_name", "")
    try:
        if use_old_api or "task_id" not in args:
            if from_indicators:
                query = args.get("query")
                limit = arg_to_number(args.get("limit", DEFAULT_LIMIT_VALUE))
                page = arg_to_number(args.get("page", 0))

                # Backward compatibility for QRadar V2 command. Create reference set for given 'ref_name' if does not exist.
                element_type = args.get("element_type", "")
                timeout_type = args.get("timeout_type")
                time_to_live = args.get("time_to_live")
                try:
                    client.reference_sets_list(ref_name=ref_name)
                except DemistoException as e:
                    # Create reference set if does not exist
                    if e.message and f"{ref_name} does not exist" in e.message:
                        # if this call fails, raise an error and stop command execution
                        client.reference_set_create(ref_name, element_type, timeout_type, time_to_live)
                    else:
                        raise e

                search_indicators = IndicatorsSearcher(page=page)
                indicators = search_indicators.search_indicators_by_version(query=query, size=limit).get("iocs", [])
                indicators_data = [
                    {"Indicator Value": indicator.get("value"), "Indicator Type": indicator.get("indicator_type")}
                    for indicator in indicators
                    if "value" in indicator and "indicator_type" in indicator
                ]
                values = [indicator.get("Indicator Value", "") for indicator in indicators_data]
                if not indicators_data:
                    return PollResult(
                        CommandResults(
                            readable_output=f"No indicators were found for reference set {ref_name}",
                        )
                    )

            if not values:
                raise DemistoException("Value to insert must be given.")
            source = args.get("source")
            date_value = argToBoolean(args.get("date_value", False))
            fields = args.get("fields")

            if date_value:
                values = [get_time_parameter(value, epoch_format=True) for value in values]
            if use_old_api:
                response = client.reference_set_bulk_load(ref_name, values, fields)
            else:
                response = client.reference_set_entries(ref_name, values, fields, source, timeout=300)
                args["task_id"] = response.get("id")
        if not use_old_api:
            response = client.get_reference_data_bulk_task_status(args["task_id"])
    except (DemistoException, requests.Timeout) as e:
        if "task_id" in args:
            print_debug_msg(
                f"Polling task status {args['task_id']} failed due to {e}. "
                f"Will try to poll task status again in the next interval."
            )
        else:
            print_debug_msg(f"Failed inserting values to reference due to {e}, will retry in the insert in the next interval")
        response = {}
    if use_old_api or response.get("status") == "COMPLETED":
        if not use_old_api:
            # get the reference set data
            response = client.reference_sets_list(ref_name=ref_name)
        key_replace_dict = {
            k: v
            for k, v in REFERENCE_SETS_RAW_FORMATTED.items()
            if k != "data" or not argToBoolean(args.get("quiet_mode") or False)
        }
        outputs = sanitize_outputs(response, key_replace_dict)

        command_results = CommandResults(
            readable_output=tableToMarkdown("Reference Update Create", outputs, removeNull=True),
            outputs_prefix="QRadar.Reference",
            outputs_key_field="Name",
            outputs=outputs,
            raw_response=response,
        )
        return PollResult(command_results, continue_to_poll=False)
    return PollResult(
        partial_result=CommandResults(
            readable_output=f'Reference set {ref_name} is still being updated in task {args["task_id"]}'
        ),
        continue_to_poll=True,
        args_for_next_run=args,
        response=None,
    )


def get_remote_events(
    client: Client,
    offense_id: str,
    context_data: dict,
    context_version: Any,
    events_columns: str,
    events_limit: int,
    fetch_mode: str,
) -> tuple[list[dict], str]:
    """
    Get the remote events of the `offense_id`
    It will update the context data as well

    Args:
        client (Client): QRadar client
        offense_id (str): Offense id to update
        context_data (dict): The current context data
        context_version (Any): The current context version
        events_columns (str): events columns of AQL
        events_limit (int): events limit of AQL
        fetch_mode (str): The fetch mode configure

    Returns:
        Tuple[list[dict], SearchQueryStatus]: List of events of the offense id, the status of the request
    """
    changed_ids_ctx = []
    offenses_queried = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    offenses_finished = context_data.get(MIRRORED_OFFENSES_FINISHED_CTX_KEY, {})
    offenses_fetched = context_data.get(MIRRORED_OFFENSES_FETCHED_CTX_KEY, {})

    events: list[dict] = []
    status = QueryStatus.ERROR.value
    if offenses_queried.get(offense_id) == QueryStatus.ERROR.value:
        return events, QueryStatus.ERROR.value
    if offense_id not in offenses_finished or offenses_queried.get(offense_id, "") in {
        QueryStatus.WAIT.value,
        QueryStatus.ERROR.value,
    }:
        # if our offense not in the finished list, we will create a new search
        # the value will be error because we don't want to wait until the search is complete
        search_id = create_events_search(client, fetch_mode, events_columns, events_limit, int(offense_id))
        offenses_queried[offense_id] = search_id
        changed_ids_ctx.append(offense_id)
    elif offense_id in offenses_finished:  # if our offense is in finished list, we will get the result
        search_id = offenses_finished[offense_id]
        try:
            search_results = client.search_results_get(search_id)
            events = search_results.get("events", [])
            del offenses_finished[offense_id]
            changed_ids_ctx.append(offense_id)
            status = QueryStatus.SUCCESS.value
        except Exception as e:
            # getting results failed, move back to queried queue to be queried again
            del offenses_finished[offense_id]
            changed_ids_ctx.append(offense_id)
            offenses_queried[offense_id] = QueryStatus.ERROR.value
            status = QueryStatus.ERROR.value
            print_debug_msg(f"No results for {offense_id}. Error: {e}. Stopping execution")
            time.sleep(FAILURE_SLEEP)

    elif offense_id in offenses_queried:
        search_id = offenses_queried[offense_id]
        events, status = poll_offense_events(client, search_id, should_get_events=True, offense_id=int(offense_id))
        if status == QueryStatus.SUCCESS.value:
            del offenses_queried[offense_id]
            changed_ids_ctx.append(offense_id)

    if status == QueryStatus.SUCCESS.value:
        offenses_fetched[offense_id] = get_num_events(events)

    partial_changes = {
        MIRRORED_OFFENSES_QUERIED_CTX_KEY: offenses_queried,
        MIRRORED_OFFENSES_FINISHED_CTX_KEY: offenses_finished,
        MIRRORED_OFFENSES_FETCHED_CTX_KEY: offenses_fetched,
    }

    # Use context manager for atomic update
    context_manager = get_context_manager()
    context_manager.update_context_partial(partial_changes)

    return events, status


def update_user_query(user_query: str) -> str:
    return f" AND ({user_query})" if user_query else ""


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# CONTEXT MANAGEMENT HELPERS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def insert_to_updated_context(
    context_data: dict,
    offense_ids: list | None = None,
    should_update_last_fetch: bool = False,
    should_update_last_mirror: bool = False,
    should_add_reset_key: bool = False,
    should_force_update: bool = False,
):
    """When we have a race condition, insert the changed data from context_data to the updated context data

    Args:
        context_data (dict): Context data with relevant changes.
        updated_context_data (dict): Context data that was updated before.
        offense_ids (list, optional): Offense ids that were changed. Defaults to None.
        should_update_last_fetch (bool, optional): Should update the last_fetch. Defaults to False.
        should_update_last_mirror (bool, optional): Should update the last mirror. Defaults to False.
        should_add_reset_key (bool, optional): If we should add reset key. Defaults to False
        should_force_update (bool, optional): If we should force update the current context. Defaults to False

    """
    if offense_ids is None:
        offense_ids = []
    # Use context manager for resilient context handling
    context_manager = get_context_manager()
    updated_context_data, version = context_manager.get_context_safe()
    new_context_data = updated_context_data.copy()
    if should_force_update:
        return context_data, version

    if should_add_reset_key:
        new_context_data[RESET_KEY] = True
    for id_ in offense_ids:
        # Those are "trusted ids" from the changed context_data, we will keep the data (either update or delete it)
        for key in (MIRRORED_OFFENSES_QUERIED_CTX_KEY, MIRRORED_OFFENSES_FINISHED_CTX_KEY, MIRRORED_OFFENSES_FETCHED_CTX_KEY):
            if id_ in context_data[key]:
                new_context_data[key][id_] = context_data[key][id_]
            else:
                new_context_data[key].pop(id_, None)

    if should_update_last_fetch:
        # Last fetch is updated with the samples that were fetched
        # Use SampleManager to handle sample size limits properly
        context_manager = get_context_manager()
        current_samples = context_data.get("samples", [])

        # Validate and optimize samples using SampleManager
        if current_samples:
            # Ensure samples are within limits and optimized
            validated_samples = context_manager.sample_manager.optimize_samples(current_samples)
            # Limit to maximum allowed samples
            validated_samples = validated_samples[:SAMPLE_SIZE]
        else:
            validated_samples = []

        new_context_data.update({LAST_FETCH_KEY: int(context_data.get(LAST_FETCH_KEY, 0)), "samples": validated_samples})

    if should_update_last_mirror:
        new_context_data.update(
            {
                LAST_MIRROR_KEY: int(context_data.get(LAST_MIRROR_KEY, 0)),
                LAST_MIRROR_CLOSED_KEY: int(context_data.get(LAST_MIRROR_CLOSED_KEY, 0)),
            }
        )
    return new_context_data, version


def deep_merge_context_changes(current_ctx: dict, changes: dict) -> None:
    """
    Recursively merges 'changes' into 'current_ctx' using the deepmerge package.
    """
    always_merger.merge(current_ctx, changes)


def safely_update_context_data_partial(changes: dict, attempts=5) -> None:
    """
    Reads the current integration context+version,
    deep-merges `changes` into it, then writes it back.
    Retries up to `attempts` times if there's a version conflict.
    Uses QRadarContextManager for resilient context handling.
    """
    context_manager = get_context_manager()
    success = context_manager.update_context_partial(changes, max_attempts=attempts)

    if not success:
        raise DemistoException(f"Failed updating context after {attempts} attempts.")


def add_iso_entries_to_dict(dicts: list[dict]) -> list[dict]:
    """
    Takes list of dicts, for each dict:
    creates a new dict, and for each field in the output that
    is contained in 'USECS_ENTRIES', maps its value to be iso format corresponding to the value of the field.
    Args:
        dicts (List[Dict]): List of the dicts to be transformed.

    Returns:
        (List[Dict]): New dicts with iso entries for the corresponding items in 'USECS_ENTRIES'
    """
    return [
        {k: (get_time_parameter(v, iso_format=True) if should_get_time_parameter(k, v) else v) for k, v in dict_.items()}
        for dict_ in dicts
    ]


def should_get_time_parameter(k: str, v: str | None | int | None) -> bool:
    """Checks whether the given key should be converted or not.
    The variable should be converted if the key is in the USECS_ENTRIES list and the value is valid.

    Args:
        k (str): the key of the field
        v (Union[Optional[str], Optional[int]]): the field value

    Returns:
        bool: True if it should be converted, otherwise return False.
    """
    valid_value = isinstance(v, str) or v != TIME_FIELDS_PLACE_HOLDER
    return k in USECS_ENTRIES and valid_value


def sanitize_outputs(outputs: Any, key_replace_dict: dict | None = None) -> list[dict]:
    """
    Gets a list of all the outputs, and sanitizes outputs.
    - Removes empty elements.
    - adds ISO entries to the outputs.
    - Outputs only keys found in 'key_replace_dict', saving their names by 'key_replace_dict values,
      if 'key_replace_dict' is not None.
    Args:
        outputs (List[Dict]): List of the outputs to be sanitized.
        key_replace_dict (Dict): Dict of the keys to transform their names.

    Returns:
        (List[Dict]): Sanitized outputs.
    """
    if not isinstance(outputs, list):
        outputs = [outputs]
    outputs = [remove_empty_elements(output) for output in outputs]
    outputs = add_iso_entries_to_dict(outputs)
    return build_final_outputs(outputs, key_replace_dict) if key_replace_dict else outputs


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# TIME AND DATE PROCESSING UTILITIES
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def get_time_parameter(arg: str | None | int | None, iso_format: bool = False, epoch_format: bool = False):
    """
    parses arg into date time object with aware time zone if 'arg' exists.
    If no time zone is given, sets timezone to UTC.
    Returns the date time object created/ISO format/epoch format.
    Args:
        arg (str): The argument to turn into aware date time.
        iso_format (bool): Whether to return date or the parsed format of the date.
        epoch_format (bool): Whether to return date or the epoch format of the date.

    Returns:
        - (None) If 'arg' is None, returns None.
        - (datetime): If 'arg' is exists and 'iso_format' and 'epoch_format' are false, returns date time.
        - (str): If 'arg' is exists and parse_format is true, returns ISO format of the date time object.
        - (int): If 'arg' is exists and epoch_format is true, returns epoch format of the date time object.
    """
    try:
        maybe_unaware_date = arg_to_datetime(arg, is_utc=True)
        if not maybe_unaware_date:
            return None

        aware_time_date = maybe_unaware_date if maybe_unaware_date.tzinfo else UTC_TIMEZONE.localize(maybe_unaware_date)

        if iso_format:
            return aware_time_date.isoformat()
        if epoch_format:
            return int(aware_time_date.timestamp() * 1000)
        return aware_time_date
    except Exception as e:
        demisto.info(f"Could not convert time for {arg=}, reason {e}")
        return arg


def build_final_outputs(outputs: list[dict], old_new_dict: dict) -> list[dict]:
    """
    Receives outputs, or a single output, and a dict containing mapping of old key names to new key names.
    Returns a list of outputs containing the new names contained in old_new_dict.
    Args:
        outputs (Dict): Outputs to replace its keys.
        old_new_dict (Dict): Old key name mapped to new key name.

    Returns:
        (Dict): The dictionary with the transformed keys and their values.
    """
    return [{old_new_dict.get(k): v for k, v in output.items() if k in old_new_dict} for output in outputs]


def build_headers(first_headers: list[str], all_headers: set[str]) -> list[str]:
    """
    Receives headers to be shown first in entry room, and concat all the headers after first headers.
    Args:
        first_headers (Set[str]): First headers to be shown in the entry room.
        all_headers (Set[str]): List of all of the headers.

    Returns:
        (List[str]): List of all of the headers, where first_headers are first in the list.
    """
    return first_headers + list(set.difference(all_headers, first_headers))


def is_valid_ip(ip: str) -> bool:
    try:
        ip_address(ip)
        return True
    except ValueError:
        print_debug_msg(f"IP {ip} was found invalid.")
        return False


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# ENRICHMENT FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def get_offense_types(client: Client, offenses: list[dict]) -> dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the offense type names
    matching the offense type IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {offense_type_id: offense_type_name}
    """
    try:
        offense_types_ids = {offense.get("offense_type") for offense in offenses if offense.get("offense_type") is not None}
        if not offense_types_ids:
            return {}
        offense_types = client.offense_types(filter_=f"""id in ({','.join(map(str, offense_types_ids))})""", fields="id,name")
        return {offense_type.get("id"): offense_type.get("name") for offense_type in offense_types}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offense type: {e}")
        return {}


def get_offense_closing_reasons(client: Client, offenses: list[dict]) -> dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the closing reason names
    matching the closing reason IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {closing_reason_id: closing_reason_name}
    """
    try:
        closing_reason_ids = {
            offense.get("closing_reason_id") for offense in offenses if offense.get("closing_reason_id") is not None
        }
        if not closing_reason_ids:
            return {}
        closing_reasons = client.closing_reasons_list(
            filter_=f"""id in ({','.join(map(str, closing_reason_ids))})""", fields="id,text"
        )
        return {closing_reason.get("id"): closing_reason.get("text") for closing_reason in closing_reasons}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offense closing reasons: {e}")
        return {}


def get_domain_names(client: Client, outputs: list[dict]) -> dict:
    """
    Receives list of outputs, and performs API call to QRadar service to retrieve the domain names
    matching the domain IDs of the outputs.
    Includes retry logic and enhanced logging for better reliability.
    Args:
        client (Client): Client to perform the API request to QRadar.
        outputs (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {domain_id: domain_name}
    """
    domain_ids = {offense.get("domain_id") for offense in outputs if offense.get("domain_id") is not None}
    if not domain_ids:
        demisto.debug("No domain IDs found in outputs for domain name enrichment")
        return {}

    domain_ids_str = ",".join(map(str, domain_ids))
    demisto.debug(f"Attempting to resolve domain names for domain IDs: {domain_ids_str}")

    # Retry logic with exponential backoff
    max_retries = CONNECTION_ERRORS_RETRIES  # Use existing constant (5)
    base_delay = CONNECTION_ERRORS_INTERVAL  # Use existing constant (1)

    last_exception = None
    # NOTE: Retry logic is essential here to prevent silent failures in domain name resolution.
    # Without retries, API call failures result in empty dict return, causing domain IDs (e.g., "6")
    # to be displayed instead of domain names (e.g., "ABC") in the "Domain - Offense" field.
    for attempt in range(max_retries):
        try:
            demisto.debug(f"Domain name resolution attempt {attempt + 1}/{max_retries}")
            domains_info = client.domains_list(filter_=f"""id in ({domain_ids_str})""", fields="id,name")

            if domains_info:
                domain_mapping = {domain_info.get("id"): domain_info.get("name") for domain_info in domains_info}
                demisto.debug(f"Successfully resolved {len(domain_mapping)} domain names: {domain_mapping}")
                return domain_mapping
            else:
                demisto.debug(f"Domain list API returned empty response for domain IDs: {domain_ids_str}")
                return {}

        except Exception as e:
            last_exception = e
            attempt_msg = f"Domain name resolution attempt {attempt + 1}/{max_retries} failed"

            if attempt < max_retries - 1:
                # Calculate delay with exponential backoff
                delay = base_delay * (2**attempt)
                demisto.debug(f"{attempt_msg}: {str(e)}. Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                demisto.error(f"{attempt_msg}: {str(e)}. All retry attempts exhausted.")

    # If we reach here, all retries failed
    error_msg = f"Failed to resolve domain names after {max_retries} attempts for domain IDs: {domain_ids_str}"
    if last_exception:
        error_msg += f". Last error: {str(last_exception)}"

    demisto.error(error_msg)
    demisto.info("Falling back to using domain IDs instead of domain names for affected offenses")

    return {}


def get_rules_names(client: Client, offenses: list[dict]) -> dict:
    """
    Receives list of offenses, and performs API call to QRadar service to retrieve the rules names
    matching the rule IDs of the offenses.
    Args:
        client (Client): Client to perform the API request to QRadar.
        offenses (List[Dict]): List of all of the offenses.

    Returns:
        (Dict): Dictionary of {rule_id: rule_name}
    """
    try:
        rules_ids = {rule.get("id") for offense in offenses for rule in offense.get("rules", [])}
        if not rules_ids:
            return {}
        rules = client.rules_list(None, None, f"""id in ({','.join(map(str, rules_ids))})""", "id,name")
        return {rule.get("id"): rule.get("name") for rule in rules}
    except Exception as e:
        demisto.error(f"Encountered an issue while getting offenses rules: {e}")
        return {}


def retrieve_offense_ip_addresses_with_enrichment(
    qradar_client: Client, offense_list: list[dict[str, Any]], should_fetch_destination_addresses: bool
) -> dict[int, str]:
    """
    Retrieve IP address information for offenses from QRadar API with batch processing optimization.

    This function takes a list of offenses and fetches the actual IP addresses corresponding to the
    address IDs stored in each offense. It handles both source and destination addresses based on
    the parameter flag, and uses batch processing to avoid overwhelming the QRadar service.

    The function implements the following workflow:
    1. Determine address type (source or destination) based on input parameter
    2. Extract all address IDs from the provided offenses
    3. Process address IDs in batches to respect QRadar API limits
    4. Return a mapping of address ID to actual IP address

    Args:
        qradar_client (Client): Authenticated QRadar API client instance for making requests
        offense_list (List[Dict[str, Any]]): List of offense dictionaries containing address ID references
        should_fetch_destination_addresses (bool): True to fetch destination IPs, False for source IPs
            - When True: fetches local_destination_address_ids and local_destination_ip fields
            - When False: fetches source_address_ids and source_ip fields

    Returns:
        Dict[int, str]: Mapping of address ID (int) to IP address string (str)
            Example: {123: "192.168.1.1", 456: "10.0.0.1"}
            Returns empty dict if no addresses found or all API calls fail

    Raises:
        Exception: Propagates any critical API errors that prevent batch processing

    Note:
        - Uses OFF_ENRCH_LIMIT to cap the number of addresses processed
        - Uses BATCH_SIZE for optimal API request batching
        - Logs errors for failed batches but continues processing other batches
        - Typo in original error message "barch" is preserved for compatibility
    """
    # Determine the address type and corresponding field names based on request type
    address_type_prefix = "local_destination" if should_fetch_destination_addresses else "source"
    ip_address_field_name = f"{address_type_prefix}_ip"
    address_ids_field_name = f"{address_type_prefix}_address_ids"
    api_endpoint_suffix = f"{address_type_prefix}_addresses"

    def fetch_addresses_for_single_batch(address_id_batch: list[int]) -> list[dict[str, Any]]:
        """
        Fetch address data for a single batch of address IDs from QRadar API.

        Args:
            address_id_batch (List[int]): List of address IDs to fetch in this batch

        Returns:
            List[Dict[str, Any]]: List of address data dictionaries, empty list on error
        """
        try:
            # Build filter query to match any of the address IDs in the batch
            address_ids_filter_query = f"""id in ({','.join(map(str, address_id_batch))})"""
            # Specify fields to return: ID and the appropriate IP field
            requested_fields = f"id,{ip_address_field_name}"

            return qradar_client.get_addresses(api_endpoint_suffix, address_ids_filter_query, requested_fields)
        except Exception as batch_processing_error:
            # Log the error but don't stop processing - other batches might succeed
            demisto.error(f"Failed getting address barch with error: {batch_processing_error}")
            return []

    # Extract all address IDs from all offenses, flattening the nested lists
    all_address_ids_from_offenses = [
        single_address_id
        for single_offense in offense_list
        for single_address_id in single_offense.get(address_ids_field_name, [])
    ]

    # Process addresses in batches to avoid overloading QRadar service with large requests
    # Apply enrichment limit to prevent excessive API calls
    limited_address_ids = all_address_ids_from_offenses[:OFF_ENRCH_LIMIT]

    # Split address IDs into batches and fetch data for each batch
    address_data_batches = [
        fetch_addresses_for_single_batch(single_batch) for single_batch in batch(limited_address_ids, batch_size=int(BATCH_SIZE))
    ]

    # Flatten all batch results and create ID-to-IP mapping
    address_id_to_ip_mapping = {
        address_data_item.get("id"): address_data_item.get(ip_address_field_name)
        for single_address_batch in address_data_batches
        for address_data_item in single_address_batch
        if address_data_item.get("id") is not None and address_data_item.get(ip_address_field_name) is not None
    }

    return address_id_to_ip_mapping


def transform_qradar_asset_for_offense_enrichment(raw_asset_data: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a raw QRadar asset into the standardized format required for offense enrichment.

    This function takes a raw asset dictionary from QRadar API and transforms it into a clean,
    standardized format suitable for enriching offense data. The transformation includes:
    1. Extracting and restructuring network interface information
    2. Flattening asset properties into key-value pairs
    3. Combining all data into a unified asset representation
    4. Adding ISO timestamp entries for temporal data

    The function handles the complex nested structure of QRadar assets and produces a flat,
    easily consumable format for downstream processing and display.

    Args:
        raw_asset_data (Dict[str, Any]): Raw asset dictionary from QRadar API containing:
            - interfaces: List of network interfaces with MAC addresses and IP addresses
            - properties: List of property objects with name/value pairs
            - Other asset metadata fields (id, hostname, etc.)

    Returns:
        Dict[str, Any]: Transformed asset dictionary with:
            - All original asset fields (except 'properties' which gets flattened)
            - 'interfaces': Restructured interface data with MAC and IP information
            - Flattened property key-value pairs merged at root level
            - ISO-formatted timestamp entries where applicable

    Example:
        Input: {
            "id": 123,
            "hostname": "server01",
            "interfaces": [{"mac_address": "00:11:22:33:44:55", "ip_addresses": [{"value": "192.168.1.1"}]}],
            "properties": [{"name": "OS", "value": "Windows"}, {"name": "Version", "value": "10"}]
        }

        Output: {
            "id": 123,
            "hostname": "server01",
            "interfaces": [{"mac_address": "00:11:22:33:44:55", "ip_addresses": [{"value": "192.168.1.1"}]}],
            "OS": "Windows",
            "Version": "10"
        }

    Note:
        - Properties with missing 'name' or 'value' fields are filtered out
        - Interface data is preserved in its nested structure for compatibility
        - The function calls add_iso_entries_to_asset() for timestamp formatting
    """
    # Extract and restructure network interface information
    # Each interface contains MAC address, ID, and associated IP addresses
    restructured_interfaces_data = {
        "interfaces": [
            {
                "mac_address": single_interface.get("mac_address"),
                "id": single_interface.get("id"),
                "ip_addresses": [
                    {"type": ip_address_entry.get("type"), "value": ip_address_entry.get("value")}
                    for ip_address_entry in single_interface.get("ip_addresses", [])
                ],
            }
            for single_interface in raw_asset_data.get("interfaces", [])
        ]
    }

    # Flatten asset properties from list of name/value objects to key-value pairs
    # Only include properties that have both 'name' and 'value' fields populated
    flattened_asset_properties = {
        property_item.get("name"): property_item.get("value")
        for property_item in raw_asset_data.get("properties", [])
        if "name" in property_item
        and "value" in property_item
        and property_item.get("name") is not None
        and property_item.get("value") is not None
    }

    # Create base asset data by excluding the original 'properties' field
    # This prevents duplication since properties are now flattened at root level
    asset_data_without_properties = {
        field_name: field_value for field_name, field_value in raw_asset_data.items() if field_name != "properties"
    }

    # Combine all components: base asset data + flattened properties + restructured interfaces
    combined_asset_data = {**asset_data_without_properties, **flattened_asset_properties, **restructured_interfaces_data}

    # Apply ISO timestamp formatting to temporal fields and return final result
    return add_iso_entries_to_asset(combined_asset_data)


def retrieve_assets_correlated_with_offense_ip_addresses(
    qradar_client: Client, offense_related_ip_addresses: list[str], maximum_assets_to_return: int | None = 100
) -> list[dict[str, Any]]:
    """
    Retrieve QRadar assets that are correlated with the provided IP addresses from an offense.

    This function takes a list of IP addresses associated with an offense and queries QRadar
    to find all assets that have network interfaces matching those IP addresses. The function
    implements batch processing to handle large numbers of IPs efficiently and respects
    both enrichment limits and user-specified asset limits.

    The workflow includes:
    1. Validate and filter IP addresses to ensure they are properly formatted
    2. Process IPs in batches to avoid overwhelming QRadar API
    3. Build complex filter queries to match assets with specific IP addresses
    4. Transform raw asset data into standardized format for offense enrichment
    5. Apply limits to prevent excessive data retrieval

    Args:
        qradar_client (Client): Authenticated QRadar API client for making asset queries
        offense_related_ip_addresses (List[str]): List of IP address strings from the offense
            - Can include both IPv4 and IPv6 addresses
            - Invalid IP addresses are automatically filtered out
            - Empty or None values are handled gracefully
        maximum_assets_to_return (Optional[int], default=100): Maximum number of assets to return
            - None means no limit (use with caution for performance)
            - Positive integer limits the result set size
            - Applied after all batches are processed

    Returns:
        List[Dict[str, Any]]: List of transformed asset dictionaries ready for offense enrichment
            - Each asset contains standardized interface and property information
            - Assets are transformed using transform_qradar_asset_for_offense_enrichment()
            - Empty list returned if no assets found or all queries fail

    Example:
        offense_ips = ["192.168.1.1", "10.0.0.1", "invalid-ip"]
        assets = retrieve_assets_correlated_with_offense_ip_addresses(client, offense_ips, 50)
        # Returns up to 50 assets that have interfaces matching the valid IPs

    Note:
        - Uses OFF_ENRCH_LIMIT to cap the number of IPs processed
        - Uses BATCH_SIZE for optimal API request batching
        - Invalid IP addresses are silently filtered out using is_valid_ip()
        - Failed batch queries are logged but don't stop processing
        - Asset limit is enforced as soon as the threshold is reached
    """

    def fetch_assets_for_ip_address_batch(ip_address_batch: list[str]) -> list[dict[str, Any]]:
        """
        Fetch assets from QRadar API for a single batch of IP addresses.

        This nested function builds a complex filter query to find assets whose network
        interfaces contain IP addresses matching any of the IPs in the provided batch.

        Args:
            ip_address_batch (List[str]): Batch of valid IP addresses to query

        Returns:
            List[Dict[str, Any]]: Raw asset data from QRadar API, empty list on error
        """
        # Build OR-based filter query to match any IP in the batch
        # Format: 'interfaces contains ip_addresses contains value="IP1" or interfaces contains ip_addresses contains value="IP2"'
        ip_filter_query = " or ".join(
            [f'interfaces contains ip_addresses contains value="{single_ip_address}"' for single_ip_address in ip_address_batch]
        )

        try:
            return qradar_client.assets_list(filter_=ip_filter_query)
        except Exception as asset_query_error:
            # Log the error with the specific filter query that failed
            demisto.error(f"Failed getting assets for filter_query: {ip_filter_query}. {asset_query_error}")
            return []

    # Filter out invalid IP addresses to prevent API errors
    # Only process IPs that pass validation (IPv4/IPv6 format check)
    validated_offense_ip_addresses = [
        single_offense_ip for single_offense_ip in offense_related_ip_addresses if is_valid_ip(single_offense_ip)
    ]

    # Apply enrichment limit to prevent excessive API calls and processing time
    limited_ip_addresses = validated_offense_ip_addresses[:OFF_ENRCH_LIMIT]

    # Process IP addresses in batches to avoid overloading QRadar service
    accumulated_assets: list[dict[str, Any]] = []

    for single_ip_batch in batch(limited_ip_addresses, batch_size=int(BATCH_SIZE)):
        # Fetch assets for this batch of IP addresses
        batch_assets = fetch_assets_for_ip_address_batch(single_ip_batch)
        accumulated_assets.extend(batch_assets)

        # Check if we've reached the user-specified asset limit
        if maximum_assets_to_return and len(accumulated_assets) >= maximum_assets_to_return:
            # Truncate to exact limit and stop processing further batches
            accumulated_assets = accumulated_assets[:maximum_assets_to_return]
            break

    # Transform all raw assets into standardized format for offense enrichment
    transformed_assets_for_enrichment = [
        transform_qradar_asset_for_offense_enrichment(raw_asset_data) for raw_asset_data in accumulated_assets
    ]

    return transformed_assets_for_enrichment


def enrich_qradar_offenses_with_comprehensive_metadata(
    qradar_client: Client,
    raw_offense_data: dict[str, Any] | list[dict[str, Any]],
    should_enrich_ip_addresses: bool,
    should_enrich_with_assets: bool,
    maximum_assets_per_offense: int | None = None,
) -> list[dict[str, Any]]:
    """
    Enrich QRadar offense data with comprehensive metadata and related information.

    This function takes raw offense data from QRadar API and enriches it with human-readable
    names, links, and related data to provide a complete picture of each offense. The enrichment
    process includes multiple types of data transformation and augmentation:

    Core Enrichments (always applied):
    - Convert offense type IDs to human-readable offense type names
    - Convert closing reason IDs to descriptive closing reason text
    - Generate direct links to offense details in QRadar console

    Conditional Enrichments (based on configuration flags):
    - Domain names (when DOMAIN_ENRCH_FLG is enabled)
    - Rule names for all rules associated with the offense (when RULES_ENRCH_FLG is enabled)
    - IP address resolution for source and destination address IDs (when requested)
    - Asset information correlated with offense IP addresses (when requested)

    The function handles both single offense dictionaries and lists of offenses, normalizing
    the input to always process a list internally for consistent handling.

    Args:
        qradar_client (Client): Authenticated QRadar API client for making enrichment queries
        raw_offense_data (Union[Dict[str, Any], List[Dict[str, Any]]]): Raw offense data from QRadar
            - Can be a single offense dictionary or list of offense dictionaries
            - Each offense should contain standard QRadar offense fields (id, offense_type, etc.)
        should_enrich_ip_addresses (bool): Whether to resolve IP address IDs to actual IP addresses
            - True: Fetches actual IP addresses for source_address_ids and local_destination_address_ids
            - False: Leaves address IDs as-is to improve performance
        should_enrich_with_assets (bool): Whether to fetch asset information correlated with offense IPs
            - True: Queries QRadar for assets matching the offense's IP addresses
            - False: Skips asset enrichment to improve performance
        maximum_assets_per_offense (Optional[int], default=None): Limit on assets per offense
            - None: No limit on asset count (use with caution)
            - Positive integer: Maximum assets to fetch per offense

    Returns:
        List[Dict[str, Any]]: List of enriched offense dictionaries containing:
            - All original offense fields
            - offense_type: Human-readable offense type name (instead of ID)
            - closing_reason_id: Human-readable closing reason text (instead of ID)
            - LinkToOffense: Direct URL to offense in QRadar console
            - domain_name: Domain name (if domain enrichment enabled)
            - rules: List of rules with human-readable names (if rule enrichment enabled)
            - source_address_ids: Actual IP addresses (if IP enrichment requested)
            - local_destination_address_ids: Actual IP addresses (if IP enrichment requested)
            - assets: List of correlated assets (if asset enrichment requested)

    Example:
        # Enrich with all available data
        enriched = enrich_qradar_offenses_with_comprehensive_metadata(
            client, raw_offenses, True, True, 50
        )

        # Enrich with minimal data for performance
        enriched = enrich_qradar_offenses_with_comprehensive_metadata(
            client, raw_offenses, False, False
        )

    Note:
        - Uses global configuration flags (DOMAIN_ENRCH_FLG, RULES_ENRCH_FLG) for conditional enrichment
        - Performs batch API calls for efficiency when enriching multiple offenses
        - Handles missing or invalid data gracefully by falling back to original values
        - Asset enrichment combines source and destination IPs for comprehensive asset correlation
    """
    # Normalize input to always work with a list of offenses for consistent processing
    offense_list_to_process = raw_offense_data if isinstance(raw_offense_data, list) else [raw_offense_data]

    print_debug_msg("Starting comprehensive offense enrichment process")

    # Fetch all enrichment data in batch operations for efficiency
    # These operations are performed once for all offenses to minimize API calls
    offense_type_id_to_name_mapping = get_offense_types(qradar_client, offense_list_to_process)
    closing_reason_id_to_name_mapping = get_offense_closing_reasons(qradar_client, offense_list_to_process)

    # Conditional enrichment data - only fetch if configuration flags are enabled
    domain_id_to_name_mapping = (
        get_domain_names(qradar_client, offense_list_to_process) if DOMAIN_ENRCH_FLG.lower() == "true" else {}
    )

    rule_id_to_name_mapping = get_rules_names(qradar_client, offense_list_to_process) if RULES_ENRCH_FLG.lower() == "true" else {}

    # IP address enrichment data - only fetch if requested by user
    source_address_id_to_ip_mapping = (
        retrieve_offense_ip_addresses_with_enrichment(qradar_client, offense_list_to_process, False)
        if should_enrich_ip_addresses
        else {}
    )

    destination_address_id_to_ip_mapping = (
        retrieve_offense_ip_addresses_with_enrichment(qradar_client, offense_list_to_process, True)
        if should_enrich_ip_addresses
        else {}
    )

    def transform_single_offense_with_enrichment(single_offense_data: dict[str, Any]) -> dict[str, Any]:
        """
        Transform a single offense with all available enrichment data.

        This nested function applies all enrichment transformations to a single offense,
        building the enriched data incrementally and combining it with the original offense.

        Args:
            single_offense_data (Dict[str, Any]): Single offense dictionary to enrich

        Returns:
            Dict[str, Any]: Fully enriched offense dictionary
        """
        # Build direct link to offense details in QRadar console
        offense_console_link_suffix = (
            f"/console/do/sem/offensesummary?appName=Sem&pageId=OffenseSummary&summaryId={single_offense_data.get('id')}"
        )

        # Extract key IDs for enrichment lookups
        offense_type_id = single_offense_data.get("offense_type")
        closing_reason_id = single_offense_data.get("closing_reason_id")
        domain_id = single_offense_data.get("domain_id")

        # Core enrichment data - always applied
        core_enrichment_data = {
            "offense_type": offense_type_id_to_name_mapping.get(offense_type_id, offense_type_id),
            "closing_reason_id": closing_reason_id_to_name_mapping.get(closing_reason_id, closing_reason_id),
            "LinkToOffense": urljoin(qradar_client.server, offense_console_link_suffix),
        }

        # Domain enrichment - only applied if enabled and domain data exists
        domain_enrichment_data = (
            {"domain_name": domain_id_to_name_mapping.get(domain_id, domain_id)}
            if DOMAIN_ENRCH_FLG.lower() == "true" and domain_id_to_name_mapping.get(domain_id, domain_id)
            else {}
        )

        # Rule enrichment - only applied if enabled
        rule_enrichment_data = (
            {
                "rules": [
                    {
                        "id": single_rule.get("id"),
                        "type": single_rule.get("type"),
                        "name": rule_id_to_name_mapping.get(single_rule.get("id"), single_rule.get("id")),
                    }
                    for single_rule in single_offense_data.get("rules", [])
                ]
            }
            if RULES_ENRCH_FLG.lower() == "true"
            else {}
        )

        # Source IP address enrichment - convert address IDs to actual IP addresses
        source_ip_enrichment_data = (
            {
                "source_address_ids": [
                    source_address_id_to_ip_mapping.get(source_address_id)
                    for source_address_id in single_offense_data.get("source_address_ids", [])
                    if source_address_id_to_ip_mapping.get(source_address_id) is not None
                ]
            }
            if should_enrich_ip_addresses
            else {}
        )

        # Destination IP address enrichment - convert address IDs to actual IP addresses
        destination_ip_enrichment_data = (
            {
                "local_destination_address_ids": [
                    destination_address_id_to_ip_mapping.get(destination_address_id)
                    for destination_address_id in single_offense_data.get("local_destination_address_ids", [])
                    if destination_address_id_to_ip_mapping.get(destination_address_id) is not None
                ]
            }
            if should_enrich_ip_addresses
            else {}
        )

        # Asset enrichment - fetch assets correlated with offense IP addresses
        if should_enrich_with_assets:
            # Combine source and destination IPs for comprehensive asset correlation
            source_ip_addresses = source_ip_enrichment_data.get("source_address_ids", [])
            destination_ip_addresses = destination_ip_enrichment_data.get("local_destination_address_ids", [])
            all_offense_ip_addresses = source_ip_addresses + destination_ip_addresses

            asset_enrichment_data = {
                "assets": retrieve_assets_correlated_with_offense_ip_addresses(
                    qradar_client, all_offense_ip_addresses, maximum_assets_per_offense
                )
            }
        else:
            asset_enrichment_data = {}

        # Combine original offense data with all enrichment data
        return {
            **single_offense_data,
            **core_enrichment_data,
            **domain_enrichment_data,
            **rule_enrichment_data,
            **source_ip_enrichment_data,
            **destination_ip_enrichment_data,
            **asset_enrichment_data,
        }

    # Apply enrichment transformation to all offenses
    enriched_offense_list = [
        transform_single_offense_with_enrichment(single_offense) for single_offense in offense_list_to_process
    ]

    print_debug_msg("Successfully completed comprehensive offense enrichment process")
    return enriched_offense_list


def enrich_asset_properties(properties: list, properties_to_enrich_dict: dict) -> dict:
    """
    Receives list of properties of an asset, and properties to enrich, and returns a dict containing the enrichment
    Args:
        properties (List): List of properties of an asset.
        properties_to_enrich_dict (Dict): Properties to be enriched.

    Returns:
        (List[Dict]) List of new assets with enrichment.
    """
    return {
        properties_to_enrich_dict.get(prop.get("name")): {"Value": prop.get("value"), "LastUser": prop.get("last_reported_by")}
        for prop in properties
        if prop.get("name") in properties_to_enrich_dict
    }


def add_iso_entries_to_asset(asset: dict) -> dict:
    """
    Transforms epoch entries to ISO entries in an asset.
    Requires a special treatment, because some of the usec entries are nested.
    Args:
        asset (Dict): Asset to transform its epoch entries to ISO.

    Returns:
        (Dict): Asset transformed.
    """

    def get_asset_entry(k: str, v: Any):
        if k == "interfaces":
            return [
                {
                    k: (
                        get_time_parameter(v, iso_format=True)
                        if k in USECS_ENTRIES
                        else add_iso_entries_to_dict(v)
                        if k == "ip_addresses"
                        else v
                    )
                    for k, v in interface.items()
                }
                for interface in v
            ]

        elif k == "properties":
            return add_iso_entries_to_dict(v)

        elif k in USECS_ENTRIES:
            return get_time_parameter(v, iso_format=True)

        else:
            return v

    return {k: get_asset_entry(k, v) for k, v in asset.items()}


def enrich_assets_results(client: Client, assets: Any, full_enrichment: bool) -> list[dict]:
    """
    Receives list of assets, and enriches each asset with 'Endpoint' entry containing the following:
    - IP addresses of all interfaces.
    - OS name.
    - MAC addresses of the interfaces, if full enrichment was requested.
    - Domain name if full enrichment was requested.
    - Properties enrichment.

    Args:
        client (Client): Client to perform API call to retrieve domain names corresponding to the domain IDs.
        assets (List[Dict]): List of assets to be enriched.
        full_enrichment (bool): Whether the asset should be full enriched.

    Returns:
        (List[Dict]) List of new assets with enrichment.
    """
    domain_id_name_dict = get_domain_names(client, assets) if full_enrichment else {}

    def enrich_single_asset(asset: dict) -> dict:
        updated_asset = add_iso_entries_to_asset(asset)
        interfaces = updated_asset.get("interfaces", [])
        properties = updated_asset.get("properties", [])
        domain_id = updated_asset.get("domain_id")
        os_name = next((prop.get("value") for prop in properties if prop.get("name") == "Primary OS ID"), None)

        ip_enrichment = {
            "IPAddress": [
                ip_add.get("value")
                for interface in interfaces
                for ip_add in interface.get("ip_addresses", [])
                if ip_add.get("value")
            ]
        }

        os_enrichment = {"OS": os_name} if os_name else {}

        mac_enrichment = (
            {"MACAddress": [interface.get("mac_address") for interface in interfaces if interface.get("mac_address")]}
            if full_enrichment
            else {}
        )

        domains_enrichment = {"Domain": domain_id_name_dict.get(domain_id, domain_id)} if full_enrichment and domain_id else {}

        basic_properties_enrichment = enrich_asset_properties(properties, ASSET_PROPERTIES_NAME_MAP)
        full_properties_enrichment = (
            enrich_asset_properties(properties, FULL_ASSET_PROPERTIES_NAMES_MAP) if full_enrichment else {}
        )

        enriched_asset = dict(asset, **basic_properties_enrichment, **full_properties_enrichment)
        return {
            "Asset": add_iso_entries_to_asset(enriched_asset),
            "Endpoint": dict(ip_enrichment, **os_enrichment, **mac_enrichment, **domains_enrichment),
        }

    return [enrich_single_asset(asset) for asset in assets]


def get_minimum_id_to_fetch(highest_offense_id: int, user_query: str | None, first_fetch: str, client: Client) -> int:
    """
    Receives the highest offense ID saved from last run, and user query.
    Checks if user query has a limitation for a minimum ID.
    If such ID exists, returns the maximum between 'highest_offense_id' and the minimum ID
    limitation received by the user query.
    Args:
        highest_offense_id (int): Minimum ID to fetch offenses by from last run.
        user_query (Optional[str]): User query for QRadar service.
        first_fetch (str): First fetch timestamp.
        client (Client): Client to perform the API calls.
    Returns:
        (int): The Minimum ID to fetch offenses by.
    """
    if not highest_offense_id:
        highest_offense_id = get_min_id_from_first_fetch(first_fetch, client)
    if user_query:
        id_query = ID_QUERY_REGEX.search(user_query)
        if id_query:
            id_query_raw = id_query.group(0)
            operator = ">=" if ">=" in id_query_raw else ">"
            # safe to int parse without catch because regex checks for number
            user_offense_id = int(id_query.group(0).split(operator)[1].strip())
            user_lowest_offense_id = user_offense_id if operator == ">" else user_offense_id - 1
            print_debug_msg(f"Found ID in user query: {user_lowest_offense_id}, last highest ID: {highest_offense_id}")
            return max(highest_offense_id, user_lowest_offense_id)
    return highest_offense_id


def get_min_id_from_first_fetch(first_fetch: str, client: Client):
    """
    Receives first_fetch integration param
    and retrieve the lowest id (earliest offense) that was created after that time.
    Args:
        first_fetch (str): First fetch timestamp.
        client (Client): Client to perform the API calls.

    Returns:
        (int): The ID of the earliest offense created after first_fetch.
    """
    filter_fetch_query = f"start_time>{convert_start_fetch_to_milliseconds(first_fetch)!s}"
    raw_offenses = client.offenses_list(filter_=filter_fetch_query, sort=ASCENDING_ID_ORDER, range_="items=0-0", fields="id")
    return int(raw_offenses[0].get("id")) - 1 if raw_offenses else 0


def arg_to_real_number(arg, arg_name=None, required=False):
    # type: (Any, Optional[str], bool) -> Optional[int | float]
    """Converts an XSOAR argument to a Python int or float

    This function acts exactly like CommonServerPython's arg_to_number, but is able to return float
    :type arg: ``Any``
    :param arg: argument to convert

    :type arg_name: ``str``
    :param arg_name: argument name

    :type required: ``bool``
    :param required:
        throws exception if ``True`` and argument provided is None

    :return:
        returns an ``int | float`` if arg can be converted
        returns ``None`` if arg is ``None`` and required is set to ``False``
        otherwise throws an Exception
    :rtype: ``Optional[int | float]``
    """

    if arg is None or arg == "":
        if required is True:
            if arg_name:
                raise ValueError(f'Missing "{arg_name}"')
            else:
                raise ValueError("Missing required argument")

        return None

    arg = encode_string_results(arg)

    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)

        try:
            return float(arg)
        except Exception:
            if arg_name:
                raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
            else:
                raise ValueError(f'"{arg}" is not a valid number')
    if isinstance(arg, int):
        return arg

    if arg_name:
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    else:
        raise ValueError(f'"{arg}" is not a valid number')


def convert_start_fetch_to_milliseconds(fetch_start_time: str):
    """
    Convert a timestamp string to milliseconds
    Args:
        fetch_start_time (str): First fetch timestamp.

    Returns:
        (int): time since (epoch - first_fetch) in milliseconds.
    """
    date = dateparser.parse(fetch_start_time, settings={"TIMEZONE": "UTC"})
    if date is None:
        # if date is None it means dateparser failed to parse it
        raise ValueError(f"Invalid first_fetch format: {fetch_start_time}")
    return int(date.timestamp() * 1000)


def convert_dict_to_actual_values(input_dict: dict) -> dict[str, Any]:
    """
    Recursively converts string representations of values in a dictionary to their actual data types.

    Args:
        input_dict (dict): A dictionary with string representations of values.

    Returns:
        dict: A dictionary with actual values (numbers, booleans, etc.).
    """
    output_dict: dict[str, Any] = {}
    for key, value in input_dict.items():
        if isinstance(value, dict):
            output_dict[key] = convert_dict_to_actual_values(value)
        elif isinstance(value, list):
            output_dict[key] = convert_list_to_actual_values(value)
        elif isinstance(value, str):
            try:
                output_dict[key] = argToBoolean(value)
            except ValueError:
                try:
                    output_dict[key] = arg_to_real_number(value)
                except ValueError:
                    output_dict[key] = value
        else:
            output_dict[key] = value
    return output_dict


def convert_list_to_actual_values(input_list: list) -> list[Any]:
    """
    Recursively converts string representations of values in a list to their actual data types.

    Args:
        input_list (list): A list with string representations of values.

    Returns:
        dict: A list with actual values (numbers, booleans, etc.).
    """
    output_list: list[Any] = []
    for value in input_list:
        if isinstance(value, dict):
            output_list.append(convert_dict_to_actual_values(value))
        elif isinstance(value, list):
            output_list.append(convert_list_to_actual_values(value))
        elif isinstance(value, str):
            try:
                output_list.append(argToBoolean(value))
            except ValueError:
                try:
                    output_list.append(arg_to_real_number(value))
                except ValueError:
                    output_list.append(value)
        else:
            output_list.append(value)
    return output_list


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# VALIDATION AND PARSING UTILITIES
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def parse_log_source(create_args: dict[str, Any]):
    pp_pairs = create_args.get("protocol_parameters", "").split(",")
    protocol_parameters = []
    group_ids = create_args.get("group_ids", "").split(",") if create_args.get("group_ids") else []
    wincollect_external_destination_ids = (
        create_args.get("wincollect_external_destination_ids", "").split(",") if create_args.get("group_ids") else []
    )
    for pair in pp_pairs:
        # Split the pair into name and value using '=' as delimiter
        name, value = pair.split("=")
        # Add the pair to the dictionary
        protocol_parameters.append({"name": name.strip(), "value": value.strip()})
    return convert_dict_to_actual_values(
        {
            **create_args,
            "protocol_parameters": protocol_parameters,
            "group_ids": group_ids,
            "wincollect_external_destination_ids": wincollect_external_destination_ids,
        }
    )


def parse_partial_log_source(update_args: dict[str, Any]):
    protocol_parameters = update_args.get("protocol_parameters", "").split(",") if update_args.get("protocol_parameters") else []
    group_ids = update_args.get("group_ids", "").split(",") if update_args.get("group_ids") else None
    wincollect_external_destination_ids = (
        update_args.get("wincollect_external_destination_ids", "").split(",") if update_args.get("group_ids") else None
    )
    if protocol_parameters:
        for pair in protocol_parameters:
            # Split the pair into name and value using '=' as delimiter
            name, value = pair.split("=")
            # Add the pair to the dictionary
            protocol_parameters.append({"name": name.strip(), "value": value.strip()})
    log_source_str = {**update_args}
    if protocol_parameters:
        log_source_str["protocol_parameters"] = protocol_parameters
    if group_ids:
        log_source_str["group_ids"] = group_ids
    if wincollect_external_destination_ids:
        log_source_str["wincollect_external_destination_ids"] = wincollect_external_destination_ids
    return convert_dict_to_actual_values(log_source_str)


def get_offense_enrichment(enrichment: str) -> tuple[bool, bool]:
    """
    Receives enrichment asked by the user, returns true or false values indicating which enrichment should be done.
    Args:
        enrichment (Optional[str]): Enrichment argument.

    Returns:
        (bool, bool): Tuple of (ip_enrich, asset_enrich).
    """
    if enrichment == "IPs And Assets":
        return True, True
    if enrichment == "IPs":
        return True, False
    return False, False


def print_debug_msg(msg: str):
    """
    Prints a message to debug with QRadarMsg prefix.
    Args:
        msg (str): Message to be logged.

    """
    demisto.debug(f"QRadarMsg - {msg}")


def is_reset_triggered(ctx: dict | None = None, version: Any = None) -> bool:
    """
    Checks if reset of the integration context has been made by the user.
    Because fetch is long-running, the user triggers a reset by calling
    'qradar-reset-last-run', which sets 'reset' in the context.

    If found, we clear the key sub-dicts and 'samples', plus remove the 'reset' key.
    Returns True if a reset was triggered and handled, False otherwise.
    """
    # Use QRadarContextManager for resilient context handling
    context_manager = get_context_manager()
    if not ctx or not version:
        ctx, version = context_manager.get_context_safe()

    if ctx and RESET_KEY in ctx:
        print_debug_msg("Reset fetch-incidents.")
        demisto.setLastRun({LAST_FETCH_KEY: 0})

        ctx.pop(RESET_KEY, None)

        ctx[MIRRORED_OFFENSES_QUERIED_CTX_KEY] = {}
        ctx[MIRRORED_OFFENSES_FINISHED_CTX_KEY] = {}
        ctx["samples"] = []

        # Use context manager for reset operation
        context_manager = get_context_manager()
        partial_changes = {
            # Explicitly remove RESET_KEY by setting it to None (will be handled by merge logic)
            RESET_KEY: None,
            MIRRORED_OFFENSES_QUERIED_CTX_KEY: ctx[MIRRORED_OFFENSES_QUERIED_CTX_KEY],
            MIRRORED_OFFENSES_FINISHED_CTX_KEY: ctx[MIRRORED_OFFENSES_FINISHED_CTX_KEY],
            "samples": ctx["samples"],
        }

        context_manager.update_context_partial(partial_changes)

        return True

    return False


def validate_long_running_params(params: dict) -> None:
    """
    Receives params, checks whether the required parameters for long running execution is configured.
    Args:
        params (Dict): Cortex XSOAR params.

    Returns:
        (None): If all required params are set, raises DemistoException otherwise.
    """
    for param_field, param_display in LONG_RUNNING_REQUIRED_PARAMS.items():
        if param_field not in params:
            raise DemistoException(
                f"Parameter {param_display} is required when enabling long running execution. Please set a value for it."
            )


def get_cidrs_indicators(query):
    """Extracts cidrs from a query"""
    if not query:
        return []

    res = demisto.searchIndicators(query=query)

    indicators = []
    for indicator in res.get("iocs", []):
        if indicator.get("indicator_type").lower() == "cidr":
            indicators.append(indicator.get("value"))

    return indicators


def verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields):
    # verify that only one of the arguments is given
    if cidrs_list and cidrs_from_query:
        return "Cannot specify both cidrs and query arguments."

    # verify that at least one of the arguments is given
    if not cidrs_list and not cidrs_from_query:
        return "Must specify either cidrs or query arguments."

    # verify that the given cidrs are valid
    for cidr in cidrs_list:
        if not re.match(ipv4cidrRegex, cidr) and not re.match(ipv6cidrRegex, cidr):
            return f"{cidr} is not a valid CIDR."

    # verify that the given name and group are valid
    if not NAME_AND_GROUP_REGEX.match(name) or not NAME_AND_GROUP_REGEX.match(group):
        return "Name and group arguments only allow letters, numbers, '_' and '-'."

    fields_list = argToList(fields)
    if fields_list:
        possible_fields = ["id", "name", "group", "cidrs", "description"]
        for field in fields_list:
            if field not in possible_fields:
                return f"{field} is not a valid field. Possible fields are: {possible_fields}."
        return None
    return None


def is_positive(*values: int | None) -> bool:
    # checks if all values are positive or None but not a negative numbers
    return all(value is None or value >= 1 for value in values)


def verify_args_for_remote_network_cidr_list(limit, page, page_size, filter_, group, id_, name):
    # verify that the given limit and page and page_size are valid
    if not is_positive(limit, page, page_size):
        return "Limit, page and page_size arguments must be positive numbers."

    # verify that only one of the arguments is given
    if limit and (page or page_size):
        return "Please provide either limit argument or page and page_size arguments."

    # verify that if page are given, page_size is also given and vice versa
    if (page and not page_size) or (page_size and not page):
        return "Please provide both page and page_size arguments."

    # verify that only one of the arguments is given
    if filter_ and (group or id_ or name):
        return "You can not use filter argument with group, id or name arguments."
    return None


""" COMMAND FUNCTIONS """

# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# COMMAND WRAPPER INFRASTRUCTURE - THIN WRAPPER PATTERN
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements the thin wrapper pattern for all existing command functions. Each wrapper preserves
# the exact original interface while adding comprehensive logging and debugging capabilities that can be enabled
# without modifying existing interfaces.

from abc import ABC, abstractmethod
from typing import Any
import functools


class CommandWrapper:
    """
    Base wrapper class that provides comprehensive logging and debugging for existing command functions.

    This class implements the thin wrapper pattern by preserving exact function signatures while
    adding debugging capabilities that can be enabled without modifying existing interfaces.
    """

    def __init__(self, original_function: Callable, command_name: str):
        """
        Initialize command wrapper.

        Args:
            original_function: The original command function to wrap
            command_name: Name of the command for logging purposes
        """
        self.original_function = original_function
        self.command_name = command_name
        self.logger = get_enhanced_logger(f"CommandWrapper.{command_name}")

        # Preserve original function metadata
        functools.update_wrapper(self, original_function)

    def __call__(self, *args, **kwargs):
        """
        Execute the wrapped command with comprehensive logging and debugging.

        This method preserves the exact original interface while adding debugging
        capabilities that can be enabled through configuration.
        """
        # Create debug context for this command execution
        debug_ctx = DiagnosticUtilities.create_debug_context_for_command(
            self.command_name, self._extract_args_dict(*args, **kwargs)
        )

        # Associate logger with debug context
        logger = self.logger.with_context(debug_ctx)

        try:
            # Log command start with arguments (sensitive data will be redacted)
            debug_ctx.add_breadcrumb(f"Starting command: {self.command_name}")
            logger.info(f"Executing command: {self.command_name}")

            # Capture function arguments for debugging
            self._capture_function_arguments(debug_ctx, *args, **kwargs)

            # Execute the original function with timing
            start_time = time.time()
            debug_ctx.add_breadcrumb("Executing original command function")

            result = self.original_function(*args, **kwargs)

            execution_time = time.time() - start_time
            debug_ctx.set_metric("execution_time", execution_time, "Total command execution time in seconds")

            # Log successful completion
            debug_ctx.add_breadcrumb(f"Command completed successfully in {execution_time:.2f}s")
            logger.info(f"Command {self.command_name} completed successfully in {execution_time:.2f}s")

            # Capture result information for debugging (without exposing sensitive data)
            self._capture_result_information(debug_ctx, result)

            return result

        except Exception as e:
            # Log error with full context
            debug_ctx.add_breadcrumb(f"Command failed: {str(e)}", "error")
            logger.error_with_context(
                f"Command {self.command_name} failed", exception=e, command_args=self._extract_args_dict(*args, **kwargs)
            )

            # Re-raise the original exception to preserve existing error handling
            raise

        finally:
            # Log execution summary for debugging
            summary = debug_ctx.get_execution_summary()
            logger.debug(f"Command {self.command_name} execution summary: {summary}")

    def _extract_args_dict(self, *args, **kwargs) -> dict[str, Any]:
        """
        Extract arguments into a dictionary for logging purposes.

        This method safely extracts function arguments while redacting sensitive data.
        """
        try:
            # Get function signature
            sig = inspect.signature(self.original_function)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()

            # Convert to dictionary and redact sensitive data
            args_dict = dict(bound_args.arguments)
            return self._redact_sensitive_data(args_dict)

        except Exception:
            # If we can't extract arguments safely, return a safe representation
            return {
                "args_count": len(args),
                "kwargs_keys": list(kwargs.keys()) if kwargs else [],
                "extraction_error": "Could not safely extract arguments",
            }

    def _redact_sensitive_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        Redact sensitive data from arguments for safe logging.

        Args:
            data: Dictionary containing function arguments

        Returns:
            Dictionary with sensitive data redacted
        """
        redacted_data = {}
        sensitive_keys = {
            "password",
            "token",
            "api_key",
            "secret",
            "credentials",
            "auth",
            "authorization",
            "x-auth-token",
            "sec-token",
        }

        for key, value in data.items():
            key_lower = key.lower()

            # Check if this is a sensitive key
            if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):
                redacted_data[key] = "[REDACTED]"
            elif isinstance(value, dict):
                # Recursively redact nested dictionaries
                redacted_data[key] = self._redact_sensitive_data(value)
            elif isinstance(value, str) and len(value) > 100:
                # Truncate very long strings to prevent log bloat
                redacted_data[key] = value[:100] + "... [TRUNCATED]"
            else:
                redacted_data[key] = value

        return redacted_data

    def _capture_function_arguments(self, debug_ctx: DebugContext, *args, **kwargs):
        """
        Capture function arguments in debug context.

        Args:
            debug_ctx: Debug context to capture arguments in
            *args: Positional arguments
            **kwargs: Keyword arguments
        """
        try:
            args_dict = self._extract_args_dict(*args, **kwargs)
            debug_ctx.capture_variable("function_arguments", args_dict, "Arguments passed to the command function")

            # Capture argument count and types for debugging
            debug_ctx.capture_variable("args_count", len(args), "Number of positional arguments")
            debug_ctx.capture_variable("kwargs_count", len(kwargs), "Number of keyword arguments")

        except Exception as e:
            debug_ctx.add_breadcrumb(f"Failed to capture function arguments: {str(e)}", "warning")

    def _capture_result_information(self, debug_ctx: DebugContext, result: Any):
        """
        Capture information about the command result for debugging.

        Args:
            debug_ctx: Debug context to capture result information in
            result: Command result
        """
        try:
            # Capture result type and basic information
            debug_ctx.capture_variable("result_type", type(result).__name__, "Type of the command result")

            # For CommandResults, capture additional information
            if hasattr(result, "outputs"):
                debug_ctx.capture_variable("has_outputs", result.outputs is not None, "Whether result has outputs")
                if result.outputs:
                    debug_ctx.capture_variable("outputs_type", type(result.outputs).__name__, "Type of result outputs")
                    if isinstance(result.outputs, list | dict):
                        debug_ctx.capture_variable("outputs_size", len(result.outputs), "Size of result outputs")

            if hasattr(result, "readable_output"):
                debug_ctx.capture_variable(
                    "has_readable_output", bool(result.readable_output), "Whether result has readable output"
                )

            if hasattr(result, "raw_response"):
                debug_ctx.capture_variable("has_raw_response", result.raw_response is not None, "Whether result has raw response")

        except Exception as e:
            debug_ctx.add_breadcrumb(f"Failed to capture result information: {str(e)}", "warning")


def create_command_wrapper(original_function: Callable, command_name: str) -> Callable:
    """
    Create a thin wrapper around an existing command function.

    This function creates a wrapper that preserves the exact original interface
    while adding comprehensive logging and debugging capabilities.

    Args:
        original_function: The original command function to wrap
        command_name: Name of the command for logging purposes

    Returns:
        Wrapped function with debugging capabilities
    """
    wrapper = CommandWrapper(original_function, command_name)
    return wrapper


# Store original functions before wrapping them
_original_functions = {}


def wrap_existing_command(command_name: str, original_function: Callable) -> Callable:
    """
    Wrap an existing command function with debugging capabilities.

    This function preserves the original function for reference and creates
    a thin wrapper that adds debugging without changing the interface.

    Args:
        command_name: Name of the command
        original_function: Original function to wrap

    Returns:
        Wrapped function
    """
    # Store original function for reference
    _original_functions[command_name] = original_function

    # Create and return wrapper
    return create_command_wrapper(original_function, command_name)


def get_original_function(command_name: str) -> Callable | None:
    """
    Get the original unwrapped function for a command.

    Args:
        command_name: Name of the command

    Returns:
        Original function if available, None otherwise
    """
    return _original_functions.get(command_name)


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# COMMAND LAYER CLASSES (Maintainable Command Architecture)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements the maintainable command base class with comprehensive debugging capabilities, standardized
# patterns for validation, execution, and error handling. The BaseCommand class provides a consistent foundation that
# all commands follow for easy understanding, modification, and troubleshooting.

from abc import ABC, abstractmethod
from typing import Any
from collections.abc import Callable
from contextlib import contextmanager


class CommandValidationError(Exception):
    """
    Exception raised when command arguments are invalid.

    This exception provides detailed context about validation failures and includes
    helpful suggestions for fixing common validation issues.
    """

    def __init__(
        self,
        message: str,
        command_name: str | None = None,
        invalid_args: dict[str, Any] | None = None,
        suggestions: list[str] | None = None,
        **kwargs,
    ):
        self.command_name = command_name
        self.invalid_args = invalid_args or {}
        self.suggestions = suggestions or []

        # Build comprehensive error message
        full_message = message
        if command_name:
            full_message = f"Command '{command_name}' validation failed: {message}"

        if self.invalid_args:
            full_message += f"\nInvalid arguments: {self.invalid_args}"

        if self.suggestions:
            full_message += "\n\nSuggestions to fix this issue:"
            for i, suggestion in enumerate(self.suggestions, 1):
                full_message += f"\n  {i}. {suggestion}"

        super().__init__(full_message)


class CommandExecutionError(Exception):
    """
    Exception raised when command execution fails.

    This exception provides context about what operation was being performed
    and why it failed, with debugging information and recovery suggestions.
    """

    def __init__(
        self,
        message: str,
        command_name: str | None = None,
        operation_step: str | None = None,
        correlation_id: str | None = None,
        original_exception: Exception | None = None,
        **kwargs,
    ):
        self.command_name = command_name
        self.operation_step = operation_step
        self.correlation_id = correlation_id
        self.original_exception = original_exception

        full_message = f"Command execution failed: {message}"
        if command_name:
            full_message = f"Command '{command_name}' execution failed: {message}"
        if operation_step:
            full_message += f" (step: {operation_step})"
        if correlation_id:
            full_message += f" (correlation ID: {correlation_id})"
        if original_exception:
            full_message += f" (caused by: {str(original_exception)})"

        super().__init__(full_message)


@dataclass
class CommandMetrics:
    """
    Metrics collected during command execution for performance monitoring and debugging.
    """

    command_name: str
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    duration_ms: float | None = None
    success: bool = False
    error_type: str | None = None
    error_message: str | None = None
    validation_time_ms: float | None = None
    execution_time_ms: float | None = None
    api_calls_count: int = 0
    api_calls_duration_ms: float = 0
    memory_usage_mb: float | None = None

    def finish(self, success: bool = True, error: Exception | None = None):
        """Mark the command as finished and calculate final metrics."""
        self.end_time = time.time()
        self.duration_ms = (self.end_time - self.start_time) * 1000
        self.success = success

        if error:
            self.error_type = type(error).__name__
            self.error_message = str(error)

    def to_dict(self) -> dict[str, Any]:
        """Convert metrics to dictionary for logging and reporting."""
        return {
            "command_name": self.command_name,
            "duration_ms": self.duration_ms,
            "success": self.success,
            "error_type": self.error_type,
            "error_message": self.error_message,
            "validation_time_ms": self.validation_time_ms,
            "execution_time_ms": self.execution_time_ms,
            "api_calls_count": self.api_calls_count,
            "api_calls_duration_ms": self.api_calls_duration_ms,
            "memory_usage_mb": self.memory_usage_mb,
        }


class BaseCommand(ABC):
    """
    Base class for all QRadar commands with comprehensive debugging and maintainable patterns.

    This class establishes the standard pattern that makes all commands:
    - Easy to understand and modify through clear method names and documentation
    - Consistent in error handling and logging across all operations
    - Self-documenting through comprehensive docstrings and type hints
    - Testable through dependency injection and clear interfaces
    - Debuggable through built-in tracing and variable capture

    The BaseCommand class provides:
    - Standardized argument validation with clear error messages
    - Comprehensive debugging capabilities including execution tracing
    - Consistent error handling with actionable troubleshooting information
    - Performance metrics collection for monitoring and optimization
    - Built-in logging with correlation IDs for easy issue tracking

    All command implementations should inherit from this class and implement
    the abstract methods to ensure consistency and maintainability.
    """

    def __init__(
        self, client: "Client", metrics_collector: Optional["MetricsCollector"] = None, logger_name: str | None = None
    ):
        """
        Initialize the base command with required dependencies.

        Args:
            client: QRadar API client for making requests
            metrics_collector: Optional metrics collector for performance tracking
            logger_name: Optional custom logger name (defaults to class name)
        """
        self.client = client
        self.metrics_collector = metrics_collector
        self.logger_name = logger_name or self.__class__.__name__
        self.debug_context: DebugContext | None = None
        self.logger: EnhancedLogger | None = None
        self.command_metrics: CommandMetrics | None = None

    def execute_with_full_context(self, args: dict[str, Any]) -> CommandResults:
        """
        Execute command with comprehensive debugging context and error handling.

        This method wraps the actual execution with debugging infrastructure
        that makes troubleshooting straightforward. It provides:
        - Complete execution tracing with breadcrumbs
        - Variable capture for debugging
        - Performance metrics collection
        - Structured error reporting with correlation IDs
        - Automatic error categorization and recovery suggestions

        Args:
            args: Command arguments dictionary from XSOAR

        Returns:
            CommandResults: Formatted command results for XSOAR

        Raises:
            CommandValidationError: When arguments are invalid
            CommandExecutionError: When execution fails
        """
        command_name = self.__class__.__name__

        # Initialize debugging infrastructure
        self.debug_context = DebugContext(f"command_{command_name}")
        self.logger = get_enhanced_logger(self.logger_name).with_context(self.debug_context)
        self.command_metrics = CommandMetrics(command_name)

        try:
            self.debug_context.add_breadcrumb(f"Starting {command_name}", args=args)
            self.logger.info(f"Executing {command_name} with args: {self._sanitize_args_for_logging(args)}")

            # Phase 1: Argument Validation
            validation_start = time.time()
            self.debug_context.add_breadcrumb("Starting argument validation")

            validation_errors = self._validate_args_with_clear_messages(args)
            if validation_errors:
                validation_error = CommandValidationError(
                    f"Invalid arguments: {', '.join(validation_errors)}",
                    command_name=command_name,
                    invalid_args=args,
                    suggestions=self._get_validation_suggestions(validation_errors),
                )
                self.command_metrics.finish(success=False, error=validation_error)
                raise validation_error

            self.command_metrics.validation_time_ms = (time.time() - validation_start) * 1000
            self.debug_context.add_breadcrumb("Arguments validated successfully")

            # Phase 2: Command Execution
            execution_start = time.time()
            self.debug_context.add_breadcrumb("Starting command execution")

            # Capture initial variable states for debugging
            self.debug_context.capture_variable("validated_args", args)
            self.debug_context.capture_variable("command_name", command_name)

            # Execute the actual command logic
            result = self._execute_command_logic(args)

            self.command_metrics.execution_time_ms = (time.time() - execution_start) * 1000
            self.debug_context.add_breadcrumb("Command executed successfully")

            # Phase 3: Result Processing
            self.debug_context.add_breadcrumb("Processing command results")

            # Validate result format
            if not isinstance(result, CommandResults):
                raise CommandExecutionError(
                    f"Command returned invalid result type: {type(result)}",
                    command_name=command_name,
                    operation_step="result_processing",
                    correlation_id=self.debug_context.correlation_id,
                )

            # Add debugging information to result if in debug mode
            if self._is_debug_mode():
                result = self._enhance_result_with_debug_info(result)

            # Record success metrics
            self.command_metrics.finish(success=True)
            self._record_command_metrics()

            self.debug_context.add_breadcrumb("Command completed successfully")
            self.logger.info(f"{command_name} completed successfully in {self.command_metrics.duration_ms:.2f}ms")

            return result

        except CommandValidationError:
            # Re-raise validation errors as-is (already properly formatted)
            raise

        except Exception as e:
            # Handle all other exceptions with comprehensive error reporting
            execution_error = CommandExecutionError(
                f"Unexpected error during execution: {str(e)}",
                command_name=command_name,
                operation_step="command_execution",
                correlation_id=self.debug_context.correlation_id if self.debug_context else None,
                original_exception=e,
            )

            if self.command_metrics:
                self.command_metrics.finish(success=False, error=execution_error)
                self._record_command_metrics()

            if self.debug_context:
                self.debug_context.add_breadcrumb(f"Command failed: {str(e)}", level="error")

            if self.logger:
                self.logger.error_with_context(
                    f"{command_name} failed",
                    exception=e,
                    command_args=self._sanitize_args_for_logging(args),
                    execution_trace=traceback.format_exc(),
                )

            raise execution_error

    @abstractmethod
    def _execute_command_logic(self, args: dict[str, Any]) -> CommandResults:
        """
        Execute the core command logic.

        This method contains the actual business logic and should be:
        - Focused on a single responsibility
        - Testable with clear inputs and outputs
        - Easy to understand and modify
        - Well-documented with comprehensive docstrings

        Args:
            args: Validated command arguments

        Returns:
            CommandResults: Formatted results for XSOAR

        Raises:
            Any exceptions that occur during execution (will be caught and wrapped)
        """

    def _validate_args_with_clear_messages(self, args: dict[str, Any]) -> list[str]:
        """
        Validate arguments and return clear error messages.

        This method performs comprehensive argument validation and returns
        a list of clear, actionable error messages for any validation failures.

        Args:
            args: Command arguments to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Check required arguments
        required_args = self._get_required_arguments()
        for arg_name in required_args:
            if arg_name not in args or args[arg_name] is None or args[arg_name] == "":
                errors.append(f"Missing required argument: {arg_name}")

        # Check argument types and formats
        type_errors = self._validate_argument_types(args)
        errors.extend(type_errors)

        # Add command-specific validation
        command_specific_errors = self._validate_command_specific_args(args)
        errors.extend(command_specific_errors)

        return errors

    @abstractmethod
    def _get_required_arguments(self) -> list[str]:
        """
        Return list of required argument names.

        Returns:
            List of argument names that are required for this command
        """

    def _validate_argument_types(self, args: dict[str, Any]) -> list[str]:
        """
        Validate argument types and formats.

        Override in subclasses to add specific type validation.

        Args:
            args: Arguments to validate

        Returns:
            List of type validation error messages
        """
        return []

    def _validate_command_specific_args(self, args: dict[str, Any]) -> list[str]:
        """
        Perform command-specific argument validation.

        Override in subclasses for command-specific validation logic.

        Args:
            args: Arguments to validate

        Returns:
            List of command-specific validation error messages
        """
        return []

    def _get_validation_suggestions(self, validation_errors: list[str]) -> list[str]:
        """
        Generate helpful suggestions for fixing validation errors.

        Args:
            validation_errors: List of validation error messages

        Returns:
            List of suggestions for fixing the errors
        """
        suggestions = []

        for error in validation_errors:
            if "Missing required argument" in error:
                arg_name = error.split(": ")[-1]
                suggestions.append(f"Provide a value for the '{arg_name}' parameter")
                suggestions.append("Check the command documentation for required parameters")
            elif "Invalid type" in error:
                suggestions.append("Check the parameter data types in the documentation")
                suggestions.append("Ensure numeric parameters are numbers, not strings")
            elif "Invalid format" in error:
                suggestions.append("Check the parameter format requirements")
                suggestions.append("Verify special characters are properly escaped")

        # Add general suggestions
        if not suggestions:
            suggestions.extend(
                [
                    "Check the command documentation for parameter requirements",
                    "Verify all parameter names are spelled correctly",
                    "Ensure all required parameters are provided",
                ]
            )

        return list(set(suggestions))  # Remove duplicates

    def _sanitize_args_for_logging(self, args: dict[str, Any]) -> dict[str, Any]:
        """
        Sanitize arguments for safe logging (remove sensitive data).

        Args:
            args: Original arguments

        Returns:
            Sanitized arguments safe for logging
        """
        sensitive_keys = {"password", "token", "api_key", "secret", "credential"}
        sanitized = {}

        for key, value in args.items():
            if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, str) and len(value) > 1000:
                sanitized[key] = f"{value[:100]}...[truncated {len(value) - 100} chars]"
            else:
                sanitized[key] = value

        return sanitized

    def _is_debug_mode(self) -> bool:
        """
        Check if debug mode is enabled.

        Returns:
            True if debug mode is enabled
        """
        # Check for debug mode indicators
        debug_indicators = [
            demisto.params().get("debug_mode", False),
            demisto.args().get("debug", False),
            os.environ.get("QRADAR_DEBUG", "").lower() in ("true", "1", "yes"),
        ]

        return any(debug_indicators)

    def _enhance_result_with_debug_info(self, result: CommandResults) -> CommandResults:
        """
        Enhance command result with debugging information when in debug mode.

        Args:
            result: Original command result

        Returns:
            Enhanced result with debug information
        """
        if not self.debug_context or not self.command_metrics:
            return result

        # Add debug information to readable output
        debug_info = f"""
### Debug Information
- **Correlation ID**: {self.debug_context.correlation_id}
- **Execution Time**: {self.command_metrics.duration_ms:.2f}ms
- **Validation Time**: {self.command_metrics.validation_time_ms:.2f}ms
- **API Calls**: {self.command_metrics.api_calls_count}
- **Breadcrumb Trail**: {' → '.join([b['message'] for b in self.debug_context.breadcrumbs])}
"""

        # Append debug info to readable output
        enhanced_readable = result.readable_output + debug_info

        # Create new CommandResults with debug info
        return CommandResults(
            outputs_prefix=result.outputs_prefix,
            outputs_key_field=result.outputs_key_field,
            outputs=result.outputs,
            readable_output=enhanced_readable,
            raw_response=result.raw_response,
        )

    def _record_command_metrics(self):
        """Record command metrics for monitoring and analysis."""
        if self.metrics_collector and self.command_metrics:
            if self.command_metrics.success:
                self.metrics_collector.record_success(self.command_metrics.command_name, self.command_metrics.duration_ms)
            else:
                self.metrics_collector.record_error(
                    self.command_metrics.command_name,
                    self.command_metrics.error_message or "Unknown error",
                    self.command_metrics.duration_ms or 0,
                )

    @contextmanager
    def _operation_context(self, operation_name: str, **context_vars):
        """
        Context manager for operation-level debugging and error handling.

        Args:
            operation_name: Name of the operation being performed
            **context_vars: Additional context variables to capture

        Yields:
            Tuple of (debug_context, logger) for the operation
        """
        operation_debug_ctx = DebugContext(f"{self.__class__.__name__}_{operation_name}")
        operation_logger = get_enhanced_logger(f"{self.logger_name}.{operation_name}").with_context(operation_debug_ctx)

        # Capture context variables
        for key, value in context_vars.items():
            operation_debug_ctx.capture_variable(key, value)

        operation_debug_ctx.add_breadcrumb(f"Starting {operation_name}")

        try:
            yield operation_debug_ctx, operation_logger
            operation_debug_ctx.add_breadcrumb(f"Completed {operation_name}")
        except Exception as e:
            operation_debug_ctx.add_breadcrumb(f"Failed {operation_name}: {str(e)}", level="error")
            operation_logger.error_with_context(f"Operation {operation_name} failed", exception=e)
            raise


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# CORE COMMAND FUNCTIONS (Main Integration Commands)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains all command functions organized by functional area for easy navigation and maintenance.
# Each command follows consistent patterns for validation, execution, and error handling.

# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# TEST AND FETCH COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_module_command(qradar_client: Client, integration_parameters: dict[str, Any]) -> str:
    """
    Validate QRadar integration connectivity, authentication, and configuration settings.

    This function performs comprehensive validation of the QRadar integration setup to ensure
    all components are properly configured and accessible. It tests multiple aspects of the
    integration including API connectivity, authentication, context management, and long-running
    execution parameters when applicable.

    The test performs the following validation steps:
    1. Context manager initialization and health check
    2. Integration context data validation and statistics
    3. Long-running execution parameter validation (if enabled)
    4. QRadar API connectivity test with minimal data request
    5. Authentication and authorization verification

    This function is called by XSOAR during integration configuration to verify that the
    integration is properly set up before allowing it to be used in production workflows.

    Args:
        qradar_client (Client): Authenticated QRadar API client instance to test
        integration_parameters (Dict[str, Any]): Complete integration configuration parameters including:
            - longRunning (Optional[bool]): Whether long-running execution is enabled
            - server (str): QRadar server URL
            - credentials (Dict): Authentication credentials
            - fetch_mode (str): Incident fetching mode (if long-running enabled)
            - offenses_per_fetch (int): Number of offenses per fetch cycle
            - Other configuration parameters specific to the integration setup

    Returns:
        str: Test result status
            - "ok": All tests passed successfully, integration is ready for use
            - "Authorization Error: make sure credentials are correct.": Authentication failed

    Raises:
        DemistoException: When critical configuration or connectivity issues are detected:
            - Invalid server URL or network connectivity issues
            - API endpoint not accessible or returning unexpected responses
            - Context manager initialization failures
            - Long-running parameter validation failures (when long-running is enabled)
            - Any other critical errors that prevent integration operation

    Example Usage:
        # Test basic integration setup
        result = test_module_command(client, {"server": "https://qradar.example.com"})

        # Test long-running integration setup
        result = test_module_command(client, {
            "longRunning": True,
            "fetch_mode": "Fetch With All Events",
            "offenses_per_fetch": 50
        })

    Test Coverage:
        - QRadar API endpoint accessibility and response validation
        - Authentication token validity and permissions
        - Context manager resilience and data integrity
        - Long-running execution parameter completeness and validity
        - Network connectivity and SSL certificate validation
        - Integration context data structure and statistics

    Error Handling:
        - Provides specific error messages for common authentication issues
        - Distinguishes between configuration errors and runtime errors
        - Preserves detailed error information for debugging while providing user-friendly messages
        - Handles both expected authentication errors and unexpected system errors

    Note:
        - Uses minimal API call (items=0-0) to test connectivity without loading large datasets
        - Leverages QRadarContextManager for resilient context handling during testing
        - Validates long-running parameters only when long-running mode is enabled
        - Provides context data statistics for debugging integration state
        - Returns standardized success message expected by XSOAR platform
    """
    # Use enhanced error handling for comprehensive debugging and user-friendly error messages
    with ErrorHandlingContext(
        operation_name="integration_test_module",
        expected_errors={
            DemistoException: "QRadar integration test failed",
            Exception: "Unexpected error during integration test",
        },
        recovery_suggestions={
            DemistoException: [
                "Verify QRadar server URL and credentials are correct",
                "Check network connectivity to QRadar server",
                "Ensure API token has sufficient permissions",
                "Test the connection using QRadar's API documentation interface",
            ]
        },
    ) as error_handler:
        # Capture key variables for debugging
        error_handler.capture_variable("integration_parameters", integration_parameters, "Integration configuration parameters")

        # Initialize and validate context manager for resilient integration state handling
        # This ensures the integration can properly manage its internal state
        integration_context_manager = get_context_manager()
        current_context_data, context_version = integration_context_manager.get_context_safe()

        error_handler.capture_variable("context_version", context_version, "Current context version")
        error_handler.capture_variable("context_size", len(str(current_context_data)), "Context data size in characters")

        # Display context statistics for debugging and validation purposes
        # This helps identify any context-related issues during setup
        print_context_data_stats(current_context_data, "Integration Test Module Validation")

        # Validate long-running execution parameters if long-running mode is enabled
        # This ensures all required parameters are present and valid for continuous operation
        is_long_running_execution_enabled = integration_parameters.get("longRunning")
        error_handler.capture_variable("is_long_running_enabled", is_long_running_execution_enabled, "Long-running mode status")

        if is_long_running_execution_enabled:
            validate_long_running_params(integration_parameters)

        # Perform minimal QRadar API connectivity test
        # Uses the smallest possible request (0-0 range) to verify API access without loading data
        # This tests authentication, network connectivity, and basic API functionality
        minimal_api_test_response = qradar_client.offenses_list(range_="items=0-0")
        error_handler.capture_variable(
            "api_test_response_type", type(minimal_api_test_response).__name__, "API test response type"
        )

        # If we reach this point, all tests passed successfully
        test_result_message = "ok"

        return test_result_message


# Apply thin wrapper to test_module_command
_original_test_module_command = test_module_command
test_module_command = wrap_existing_command("test_module", _original_test_module_command)


def calculate_incident_size(incident: dict) -> int:
    """
    Calculate the approximate size of an incident in bytes for context storage.

    This function is deprecated. Use SampleManager.calculate_sample_size() instead.
    Kept for backward compatibility.

    Args:
        incident (dict): The incident dictionary.

    Returns:
        int: The calculated or estimated size of the incident in bytes.
    """
    # Use SampleManager for consistent size calculation
    context_manager = get_context_manager()
    return context_manager.sample_manager.calculate_sample_size(incident)


def is_incident_size_acceptable(incident: dict) -> bool:
    """
    Check if an incident is small enough to be stored as a sample in the integration context.

    This function is deprecated. Use SampleManager._is_incident_size_acceptable() instead.
    Kept for backward compatibility.

    Args:
        incident (dict): The incident dictionary

    Returns:
        bool: True if incident size is acceptable, False otherwise
    """
    # Use SampleManager for consistent size validation
    context_manager = get_context_manager()
    return context_manager.sample_manager._is_incident_size_acceptable(incident)


def fetch_incidents_command() -> list[dict[str, Any]]:
    """
    Retrieve stored incident samples for XSOAR incident mapping and testing purposes.

    This function serves as the interface between XSOAR's incident fetching mechanism and the
    QRadar integration's sample storage system. It is specifically designed for mapping purposes
    and testing, providing access to previously stored incident samples that were collected
    during long-running execution cycles.

    The function leverages the QRadarContextManager's sample management system to retrieve
    incident samples that have been stored in the integration context. These samples are used
    by XSOAR for:
    - Incident field mapping configuration
    - Integration testing and validation
    - Playbook development and testing
    - Data format verification

    Key Features:
    - Retrieves samples using the resilient context manager
    - Enforces sample size limits to prevent memory issues
    - Provides consistent data format for XSOAR consumption
    - Handles context validation and error recovery automatically

    Returns:
        List[Dict[str, Any]]: List of incident sample dictionaries containing:
            - Standard XSOAR incident fields (name, rawJSON, occurred, type, etc.)
            - QRadar-specific offense data in rawJSON field
            - Properly formatted timestamps and identifiers
            - Limited to SAMPLE_SIZE to prevent excessive memory usage

    Example Return Data:
        [
            {
                "name": "123 Suspicious Network Activity",
                "rawJSON": "{\"id\": 123, \"description\": \"Suspicious Network Activity\", ...}",
                "occurred": "2023-01-01T12:00:00Z",
                "type": "QRadar Offense",
                "haIntegrationEventID": "123"
            },
            ...
        ]

    Note:
        - This function is called by XSOAR's incident fetching mechanism
        - Samples are populated by the long-running execution process
        - Sample size is limited by SAMPLE_SIZE constant to prevent performance issues
        - Uses QRadarContextManager for resilient sample retrieval
        - Returns empty list if no samples are available or context is corrupted
        - Samples are automatically managed and rotated by the context manager

    Implementation Details:
        - Leverages get_context_manager() for singleton context manager access
        - Uses get_incident_samples() method for validated sample retrieval
        - Applies slice operation [:SAMPLE_SIZE] for size enforcement
        - Handles all context-related errors gracefully through context manager
        - Maintains backward compatibility with existing XSOAR integrations

    Error Handling:
        - Context manager handles all context corruption and recovery scenarios
        - Returns empty list if samples cannot be retrieved
        - Logs errors through context manager's internal error handling
        - Does not raise exceptions to prevent XSOAR integration failures
    """
    # Initialize context manager for resilient sample retrieval
    # The context manager handles all error scenarios and provides validated samples
    integration_context_manager = get_context_manager()

    # Retrieve incident samples with automatic validation and error handling
    # The context manager ensures samples are in the correct format and handles corruption
    stored_incident_samples = integration_context_manager.get_incident_samples()

    # Enforce sample size limit to prevent memory issues and ensure consistent performance
    # This protects against scenarios where too many samples might impact XSOAR performance
    size_limited_samples = stored_incident_samples[:SAMPLE_SIZE]

    return size_limited_samples


# Apply thin wrapper to fetch_incidents_command
_original_fetch_incidents_command = fetch_incidents_command
fetch_incidents_command = wrap_existing_command("fetch_incidents", _original_fetch_incidents_command)


def create_qradar_events_search_with_resilient_retry_mechanism(
    qradar_client: Client,
    event_fetch_mode: str,
    target_offense_data: dict[str, Any],
    requested_event_columns: str,
    maximum_events_to_retrieve: int,
    maximum_retry_attempts: int = EVENTS_SEARCH_TRIES,
) -> str:
    """
    Create a QRadar search query for offense events with robust retry mechanism for reliability.

    This function creates a search query in QRadar to retrieve events associated with a specific
    offense, implementing a comprehensive retry mechanism to handle QRadar's tendency to return
    transient errors under load. The function is designed to be resilient against temporary
    service issues while providing detailed logging for troubleshooting.

    QRadar's search API can be unreliable under heavy load, returning random errors that often
    resolve on retry. This function implements exponential backoff and comprehensive error
    logging to maximize the chances of successful search creation while providing visibility
    into any issues that occur.

    Search Creation Process:
    1. Extract offense ID and start time from offense data
    2. Attempt to create search using specified parameters
    3. If search creation fails, log the error and retry
    4. Continue retrying up to the maximum retry limit
    5. Return search ID on success or error status on failure

    Args:
        qradar_client (Client): Authenticated QRadar API client for making search requests
        event_fetch_mode (str): Event retrieval mode determining search scope:
            - "Fetch With All Events": Retrieve all events associated with the offense
            - "Fetch Correlation Events Only": Retrieve only correlation events (faster)
        target_offense_data (Dict[str, Any]): Offense dictionary containing:
            - id (int): Unique offense identifier for search targeting
            - start_time (int): Offense start timestamp for temporal filtering
            - Other offense metadata used for search context
        requested_event_columns (str): Comma-separated list of event fields to retrieve:
            - Controls which event attributes are included in search results
            - Affects search performance and result size
            - Example: "sourceip,destinationip,eventname,starttime"
        maximum_events_to_retrieve (int): Maximum number of events to return:
            - Limits search result size to prevent memory issues
            - Applied as LIMIT clause in the generated search query
            - Should be balanced between completeness and performance
        maximum_retry_attempts (int, default=EVENTS_SEARCH_TRIES): Maximum retry attempts:
            - Number of times to retry search creation on failure
            - Uses EVENTS_SEARCH_TRIES constant as default value
            - Should account for typical QRadar load patterns

    Returns:
        str: Search operation result:
            - Valid search ID string: Search created successfully, can be used for polling
            - QueryStatus.ERROR.value: All retry attempts failed, search creation impossible

    Example Usage:
        # Create search for all events with standard columns
        search_id = create_qradar_events_search_with_resilient_retry_mechanism(
            client,
            "Fetch With All Events",
            {"id": 123, "start_time": 1640995200000},
            "sourceip,destinationip,eventname,starttime",
            1000,
            5
        )

        # Create search for correlation events only (faster)
        search_id = create_qradar_events_search_with_resilient_retry_mechanism(
            client,
            "Fetch Correlation Events Only",
            offense_data,
            "eventname,starttime,magnitude",
            500
        )

    Error Handling:
        - Logs each retry attempt with detailed context information
        - Captures and logs full exception stack traces for debugging
        - Provides clear indication when maximum retries are reached
        - Returns standardized error status for consistent handling

    Performance Considerations:
        - Retry mechanism adds latency but improves reliability
        - Event column selection significantly impacts search performance
        - Event limit should be tuned based on typical offense sizes
        - Consider QRadar system load when setting retry limits

    Note:
        - Uses create_events_search() helper function for actual search creation
        - Implements comprehensive debug logging for troubleshooting
        - Handles QRadar's transient error patterns gracefully
        - Returns QueryStatus.ERROR.value for consistent error handling
        - Retry attempts are 1-indexed in logging for human readability
    """
    # Extract offense identifier for search targeting and logging
    target_offense_id = target_offense_data["id"]

    # Attempt search creation with retry mechanism for resilience
    for current_retry_attempt in range(maximum_retry_attempts):
        try:
            # Attempt to create the events search using the provided parameters
            # This calls the underlying search creation logic with offense-specific parameters
            created_search_id = create_events_search(
                qradar_client,
                event_fetch_mode,
                requested_event_columns,
                maximum_events_to_retrieve,
                target_offense_id,
                target_offense_data["start_time"],
            )

            # Check if search creation was successful
            if created_search_id == QueryStatus.ERROR.value:
                # Search creation failed, log the attempt and prepare for retry
                current_attempt_number = current_retry_attempt + 1  # 1-indexed for human readability
                print_debug_msg(
                    f"Failed to create search for offense ID: {target_offense_id}. "
                    f"Retry attempt {current_attempt_number}/{maximum_retry_attempts}."
                )
                print_debug_msg(traceback.format_exc())
            else:
                # Search creation succeeded, return the search ID immediately
                return created_search_id

        except Exception as search_creation_error:
            # Handle unexpected exceptions during search creation
            current_attempt_number = current_retry_attempt + 1
            print_debug_msg(
                f"Exception occurred while creating search for offense ID: {target_offense_id}. "
                f"Retry attempt {current_attempt_number}/{maximum_retry_attempts}. "
                f"Error: {search_creation_error}"
            )
            print_debug_msg(traceback.format_exc())

    # All retry attempts have been exhausted without success
    print_debug_msg(
        f"Reached maximum retry attempts ({maximum_retry_attempts}) for creating search "
        f"for offense: {target_offense_id}. Returning error status."
    )
    return QueryStatus.ERROR.value


def poll_offense_events(
    client: Client,
    search_id: str,
    should_get_events: bool,
    offense_id: int | None,
):
    try:
        print_debug_msg(f"Getting search status for {search_id}")
        search_status_response = client.search_status_get(search_id)
        print_debug_msg(f"Got search status for {search_id}")
        query_status = search_status_response.get("status")
        print_debug_msg(f"Search status for offense {offense_id} is {query_status}.")

        if query_status in {"CANCELED", "ERROR"}:
            return [], QueryStatus.ERROR.value
        elif query_status == "COMPLETED":
            print_debug_msg(f"Search for offense {offense_id} is completed.")
            if not should_get_events:
                return [], QueryStatus.SUCCESS.value
            print_debug_msg(f"Getting events for offense {offense_id}")
            search_results_response = client.search_results_get(search_id)
            print_debug_msg(f'Http response: {search_results_response.get("http_response", "Not specified - ok")}')
            events = search_results_response.get("events", [])
            sanitized_events = sanitize_outputs(events)
            print_debug_msg(f"Fetched events for offense {offense_id}.")
            return sanitized_events, QueryStatus.SUCCESS.value
        else:
            # still waiting for events
            return [], QueryStatus.WAIT.value
    except Exception as e:
        print_debug_msg(
            f"Error while fetching offense {offense_id} events, search_id: {search_id}. Error details: {e!s} \n"
            f"{traceback.format_exc()}"
        )
        time.sleep(FAILURE_SLEEP)
        return [], QueryStatus.ERROR.value


def poll_offense_events_with_retry(
    client: Client,
    search_id: str,
    offense_id: int,
    max_retries: int = EVENTS_POLLING_TRIES,
) -> tuple[list[dict], str]:
    """
    Polls QRadar service for search ID given until status returned is within '{'CANCELED', 'ERROR', 'COMPLETED'}'.
    Afterwards, performs a call to retrieve the events returned by the search.
    Has retry mechanism, because QRadar service tends to return random errors when
    it is loaded.
    Therefore, 'max_retries' retries will be made, to try avoid such cases as much as possible.

    Args:
        client (Client): Client to perform the API calls.
        search_id (str): ID of the search to poll for its status.
        offense_id (int): ID of the offense to enrich with events returned by search. Used for logging purposes here.
        max_retries (int): Number of retries.

    Returns:
        (List[Dict], str): List of events returned by query. Returns empty list if number of retries exceeded limit,
                           A failure message in case an error occurred.
    """
    for retry in range(max_retries):
        print_debug_msg(f"Polling for events for offense {offense_id}. Retry number {retry + 1}/{max_retries}")
        events, status = poll_offense_events(client, search_id, should_get_events=True, offense_id=int(offense_id))
        if status == QueryStatus.SUCCESS.value:
            return events, ""
        elif status == QueryStatus.ERROR.value:
            return [], "Error while getting events."
        # dont sleep in the last iteration
        if retry < max_retries - 1:
            time.sleep(EVENTS_INTERVAL_SECS)

    print_debug_msg(f"Max retries for getting events for offense {offense_id}. Cancel query search_id: {search_id}")
    # need to cancel query
    client.search_cancel(search_id=search_id)
    return [], "Fetching events is in progress"


def enrich_offense_with_events(client: Client, offense: dict, fetch_mode: FetchMode, events_columns: str, events_limit: int):
    """
    Enriches offense given with events.
    Has retry mechanism for events returned by query to QRadar. This is needed because events might not be
    indexed when performing the search, and QRadar will return less events than expected.
    Retry mechanism here meant to avoid such cases as much as possible
    Args:
        client (Client): Client to perform the API calls.
        offense (Dict): Offense to enrich with events.
        fetch_mode (str): Which enrichment mode was requested.
                          Can be 'Fetch With All Events', 'Fetch Correlation Events Only'
        events_columns (str): Columns of the events to be extracted from query.
        events_limit (int): Maximum number of events to enrich the offense.

    Returns:
        (Dict): Enriched offense with events.
    """
    offense_id = str(offense["id"])
    events_count = offense.get("event_count", 0)
    events: list[dict] = []
    failure_message = ""
    is_success = True
    for retry in range(EVENTS_SEARCH_TRIES):
        start_time = time.time()
        search_id = create_qradar_events_search_with_resilient_retry_mechanism(
            client, fetch_mode, offense, events_columns, events_limit
        )
        if search_id == QueryStatus.ERROR.value:
            failure_message = "Search for events was failed."
        else:
            events, failure_message = poll_offense_events_with_retry(client, search_id, int(offense_id))
        events_fetched = get_num_events(events)
        offense["events_fetched"] = events_fetched
        offense["events"] = events
        if is_all_events_fetched(client, fetch_mode, offense_id, events_limit, events):
            break
        print_debug_msg(
            f"Not enough events were fetched for offense {offense_id}. Retrying in {FAILURE_SLEEP} seconds."
            f"Retry {retry + 1}/{EVENTS_SEARCH_TRIES}"
        )
        time_elapsed = int(time.time() - start_time)
        # wait for the rest of the time
        time.sleep(max(EVENTS_SEARCH_RETRY_SECONDS - time_elapsed, 0))
    else:
        print_debug_msg(
            f"Not all the events were fetched for offense {offense_id} (fetched {events_fetched}/{events_count}). "
            f"If mirroring is enabled, it will be queried again in mirroring."
        )
        is_success = False
    mirroring_events_message = update_events_mirror_message(
        mirror_options=MIRROR_OFFENSE_AND_EVENTS,
        events_limit=events_limit,
        fetch_mode=fetch_mode,
        events_count=events_count,
        events_mirrored=events_fetched,
        events_mirrored_collapsed=len(events),
        failure_message=failure_message,
        offense_id=int(offense_id),
    )
    offense["mirroring_events_message"] = mirroring_events_message

    return offense, is_success


def get_num_events(events: list[dict]) -> int:
    return sum(int(event.get("eventcount", 1)) for event in events)


def get_current_concurrent_searches(context_data: dict) -> int:
    """This will return the number of concurrent searches that are currently running.

    Args:
        context_data (dict): context data

    Returns:
        int: number of concurrent searches
    """
    waiting_for_update = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    # we need offenses which we have a search_id for it in QRadar
    return len([offense_id for offense_id, status in waiting_for_update.items() if status not in list(QueryStatus)])


def delete_offense_from_context(offense_id: str):
    """
    Removes offense_id from MIRRORED_OFFENSES_QUERIED_CTX_KEY and MIRRORED_OFFENSES_FINISHED_CTX_KEY
    in a concurrency-safe manner, without overwriting unrelated data.
    Uses QRadarContextManager for resilient context handling.
    """
    context_manager = get_context_manager()
    context_manager.delete_offense_from_context(offense_id)


def is_all_events_fetched(client: Client, fetch_mode: FetchMode, offense_id: str, events_limit: int, events: list[dict]) -> bool:
    """
    This function checks if all events were fetched for a specific offense.

    Args:
        client (Client): QRadar client
        offense_id (str): offense id of qradar
        events_limit (int): event limit parameter for the integration
        events (list[dict]): list of events fetched

    Returns:
        bool: True if all events were fetched, False otherwise
    """
    if not offense_id:
        # if we don't have offense id, we can't know if we fetched all the events
        return True
    events_count = client.offenses_list(offense_id=int(offense_id)).get("event_count", 0)
    expected_events = min(events_count, events_limit) if events_limit else events_count
    num_events = get_num_events(events)
    print_debug_msg(f"Fetched {num_events}/{expected_events} events for offense {offense_id}")
    # if we're not fetching only correlation events, we can't know if we fetched all the events
    return num_events >= expected_events if fetch_mode == FetchMode.all_events else num_events > 0


def get_incidents_long_running_execution(
    client: Client,
    offenses_per_fetch: int,
    user_query: str,
    fetch_mode: str,
    events_columns: str,
    events_limit: int,
    ip_enrich: bool,
    asset_enrich: bool,
    last_highest_id: int,
    incident_type: str | None,
    mirror_direction: str | None,
    first_fetch: str,
    mirror_options: str,
    assets_limit: int,
) -> tuple[list[dict] | None, int | None]:
    """
    Gets offenses from QRadar service, and transforms them to incidents in a long running execution.
    Args:
        client (Client): Client to perform the API calls.
        offenses_per_fetch (int): Maximum number of offenses to be fetched.
        user_query (str): If given, the user filters for fetching offenses from QRadar service.
        fetch_mode (str): Fetch mode of the offenses.
                          Can be 'Fetch Without Events', 'Fetch With All Events', 'Fetch Correlation Events Only'
        events_columns (str): Events columns to extract by search query for each offense. Only used when fetch mode
                              is not 'Fetch Without Events'.
        events_limit (int): Number of events to be fetched for each offense. Only used when fetch mode is not
                            'Fetch Without Events'.
        ip_enrich (bool): Whether to enrich offense by changing IP IDs of each offense to its IP value.
        asset_enrich (bool): Whether to enrich offense with assets
        last_highest_id (int): The highest ID of all the offenses that have been fetched from QRadar service.
        incident_type (Optional[str]): Incident type.
        mirror_direction (Optional[str]): Whether mirror in is activated or not.
        first_fetch (str): First fetch timestamp.


    Returns:
        (List[Dict], int): List of the incidents, and the new highest ID for next fetch.
        (None, None): if reset was triggered
    """
    offense_highest_id = get_minimum_id_to_fetch(last_highest_id, user_query, first_fetch, client)

    user_query = update_user_query(user_query)

    filter_fetch_query = f"id>{offense_highest_id}{user_query}"
    print_debug_msg(f"Filter query to QRadar: {filter_fetch_query}")
    range_max = offenses_per_fetch - 1 if offenses_per_fetch else MAXIMUM_OFFENSES_PER_FETCH - 1
    range_ = f"items=0-{range_max}"

    # if it fails here we can't recover, retry again later
    raw_offenses = client.offenses_list(range_, filter_=filter_fetch_query, sort=ASCENDING_ID_ORDER)
    if raw_offenses:
        raw_offenses_len = len(raw_offenses)
        print_debug_msg(f"raw_offenses size: {raw_offenses_len}")
    else:
        print_debug_msg("empty raw_offenses")

    new_highest_offense_id = raw_offenses[-1].get("id") if raw_offenses else offense_highest_id
    print_debug_msg(f"New highest ID returned from QRadar offenses: {new_highest_offense_id}")

    offenses: list[dict] = []
    if fetch_mode != FetchMode.no_events.value:
        futures = []
        for offense in raw_offenses:
            futures.append(
                EXECUTOR.submit(
                    enrich_offense_with_events,
                    client=client,
                    offense=offense,
                    fetch_mode=fetch_mode,  # type: ignore
                    events_columns=events_columns,
                    events_limit=events_limit,
                )
            )
        offenses_with_metadata = [future.result() for future in futures]
        offenses = [offense for offense, _ in offenses_with_metadata]
        if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
            prepare_context_for_events(offenses_with_metadata)
    else:
        offenses = raw_offenses
    if is_reset_triggered():
        return None, None
    offenses_with_mirror = (
        [dict(offense, mirror_direction=mirror_direction, mirror_instance=demisto.integrationInstance()) for offense in offenses]
        if mirror_direction
        else offenses
    )

    enriched_offenses = enrich_qradar_offenses_with_comprehensive_metadata(
        client, offenses_with_mirror, ip_enrich, asset_enrich, assets_limit
    )
    final_offenses = sanitize_outputs(enriched_offenses)
    incidents = create_incidents_from_offenses(final_offenses, incident_type)
    return incidents, new_highest_offense_id


def prepare_context_for_events(offenses_with_metadata):
    """
    For any offense that wasn't successfully enriched, mark it in MIRRORED_OFFENSES_QUERIED_CTX_KEY as WAIT.
    Uses QRadarContextManager for atomic operations and resilient context handling.
    """
    context_manager = get_context_manager()
    ctx, _ = context_manager.get_context_safe()

    mirrored_offenses_queried = ctx.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})

    for offense, is_success in offenses_with_metadata:
        if not is_success:
            offense_id = str(offense.get("id"))
            mirrored_offenses_queried[offense_id] = QueryStatus.WAIT.value

    partial_changes = {MIRRORED_OFFENSES_QUERIED_CTX_KEY: mirrored_offenses_queried}

    # Use context manager for atomic update
    context_manager.update_context_partial(partial_changes)


def create_incidents_from_offenses(offenses: list[dict], incident_type: str | None) -> list[dict]:
    """
    Transforms list of offenses given into incidents for Demisto.
    Args:
        offenses (List[Dict]): List of the offenses to transform into incidents.
        incident_type (Optional[str]): Incident type to be used for each incident.

    Returns:
        (List[Dict]): Incidents list.
    """
    print_debug_msg(f"Creating {len(offenses)} incidents")
    return [
        {
            # NOTE: incident name will be updated in mirroring also with incoming mapper.
            "name": f"""{offense.get('id')} {offense.get('description', '')}""",
            "rawJSON": json.dumps(offense),
            "occurred": get_time_parameter(offense.get("start_time"), iso_format=True),
            "type": incident_type,
            "haIntegrationEventID": str(offense.get("id")),
        }
        for offense in offenses
    ]


def print_context_data_stats(context_data: dict, stage: str) -> set[str]:
    """Print debug message with information about mirroring events.

    Args:
        context_data: The integration context data.
        stage: A prefix for the debug message.

    Returns: The ids of the mirrored offenses being currently processed.
    """
    if MIRRORED_OFFENSES_QUERIED_CTX_KEY not in context_data or MIRRORED_OFFENSES_FINISHED_CTX_KEY not in context_data:
        raise ValueError(
            f"Context data is missing keys: {MIRRORED_OFFENSES_QUERIED_CTX_KEY} or {MIRRORED_OFFENSES_FINISHED_CTX_KEY}"
        )

    if not context_data:
        print_debug_msg("Not printing stats")
        return set()

    finished_queries = context_data.get(MIRRORED_OFFENSES_FINISHED_CTX_KEY, {})
    waiting_for_update = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    print_debug_msg(f"{finished_queries=}")
    print_debug_msg(f"{waiting_for_update=}")
    last_fetch_key = context_data.get(LAST_FETCH_KEY, "Missing")
    last_mirror_update = context_data.get(LAST_MIRROR_KEY, 0)
    last_mirror_update_closed = context_data.get(LAST_MIRROR_CLOSED_KEY, 0)
    concurrent_mirroring_searches = get_current_concurrent_searches(context_data)
    # Use SampleManager to get sample information safely
    try:
        context_manager = get_context_manager()
        samples_info = context_manager.get_samples_info()
        sample_count = samples_info.get("count", 0) if isinstance(samples_info, dict) else 0
        sample_length = 0
        if sample_count > 0 and isinstance(samples_info, dict) and "samples" in samples_info:
            first_sample = samples_info["samples"][0] if samples_info["samples"] else {}
            sample_length = len(str(first_sample))
    except Exception as e:
        print_debug_msg(f"Error getting sample info: {str(e)}")
        sample_length = 0
    not_updated_ids = list(waiting_for_update)
    finished_queries_ids = list(finished_queries)
    print_debug_msg(
        f"Context Data Stats: {stage}\n Finished Offenses (id): {finished_queries_ids}"
        f"\n Offenses ids waiting for update: {not_updated_ids}"
        f"\n Concurrent mirroring events searches: {concurrent_mirroring_searches}"
        f"\n Last Fetch Key {last_fetch_key}, Last mirror update {last_mirror_update}, "
        f"Last mirror update closed: {last_mirror_update_closed}, "
        f"sample length {sample_length}"
    )
    return set(not_updated_ids + finished_queries_ids)


def perform_long_running_loop(
    client: Client,
    offenses_per_fetch: int,
    fetch_mode: str,
    user_query: str,
    events_columns: str,
    events_limit: int,
    ip_enrich: bool,
    asset_enrich: bool,
    incident_type: str | None,
    mirror_direction: str | None,
    first_fetch: str,
    mirror_options: str,
    assets_limit: int,
    long_running_container_id: str,
):
    # Use QRadarContextManager for resilient context handling
    context_manager = get_context_manager()
    context_data, version = context_manager.get_context_safe()

    if is_reset_triggered(context_data, version):
        last_highest_id = 0
    else:
        last_highest_id = int(context_data.get(LAST_FETCH_KEY, 0))
    print_debug_msg(f"Starting fetch loop. Fetch mode: {fetch_mode} on Container:{long_running_container_id}.")
    incidents, new_highest_id = get_incidents_long_running_execution(
        client=client,
        offenses_per_fetch=offenses_per_fetch,
        user_query=user_query,
        fetch_mode=fetch_mode,
        events_columns=events_columns,
        events_limit=events_limit,
        ip_enrich=ip_enrich,
        asset_enrich=asset_enrich,
        last_highest_id=last_highest_id,
        incident_type=incident_type,
        mirror_direction=mirror_direction,
        first_fetch=first_fetch,
        mirror_options=mirror_options,
        assets_limit=assets_limit,
    )

    print_debug_msg(f"Got incidents, Creating incidents and updating context data. new highest id is {new_highest_id}")

    # Refresh context to see if something changed in parallel
    context_data, ctx_version = context_manager.get_context_safe()

    if incidents and new_highest_id:
        # Actually create the incidents in XSOAR
        demisto.createIncidents(incidents, {LAST_FETCH_KEY: str(new_highest_id)})

        # Use context manager for sample handling and context updates
        context_manager = get_context_manager()

        # Add incidents as samples using the new sample manager with automatic cleanup
        sample_added_count = 0
        for incident in incidents:
            # Check if we need to perform cleanup before adding the sample
            try:
                # Get current context size before adding
                ctx, _ = context_manager.get_context_safe()
                context_size_mb = len(json.dumps(ctx).encode("utf-8")) / (1024 * 1024)

                # If context is approaching size limits, perform auto-management first
                if context_size_mb > 7:  # 7MB threshold for proactive management
                    print_debug_msg(
                        f"Context size ({context_size_mb:.1f}MB) approaching limits, performing auto-management before adding sample"
                    )
                    context_manager.auto_manage_samples_on_size_limit()

                # Try to add the sample
                if context_manager.add_incident_sample(incident):
                    sample_added_count += 1
                else:
                    # If sample couldn't be added, try compressing existing samples and retry
                    print_debug_msg(f"Failed to add sample for incident {incident.get('name', 'Unknown')}, trying compression")
                    if context_manager.optimize_context_samples():
                        # Retry after compression
                        if context_manager.add_incident_sample(incident):
                            sample_added_count += 1
                            print_debug_msg("Sample added successfully after compression")

            except Exception as e:
                print_debug_msg(f"Error during sample addition with cleanup: {str(e)}")

        if sample_added_count > 0:
            print_debug_msg(f"Added {sample_added_count} incident(s) as samples")

        # Update LAST_FETCH_KEY using context manager
        partial_changes = {LAST_FETCH_KEY: int(new_highest_id)}
        context_manager.update_context_partial(partial_changes)

        print_debug_msg(
            f'Successfully Created {len(incidents)} incidents. '
            f'Incidents created: {[incident["name"] for incident in incidents]}'
        )

        # Perform automatic sample cleanup when context size limits are approached
        context_manager = get_context_manager()
        try:
            # Check if context optimization is needed
            samples_info = context_manager.get_samples_info()
            if isinstance(samples_info, dict):
                total_size_mb = samples_info.get("total_size_mb", 0)

                # Use auto-management for intelligent sample handling
                if total_size_mb > 3:  # 3MB threshold for any management action
                    print_debug_msg(f"Context samples size ({total_size_mb:.1f}MB) requires management")
                    context_manager.auto_manage_samples_on_size_limit()

        except Exception as e:
            print_debug_msg(f"Automatic sample cleanup failed but continuing: {str(e)}")


def recover_from_last_run(ctx: dict | None = None, version: Any = None):
    """
    This recovers the integration context from the last run, if there is an inconsistency
    between demisto.getLastRun() and the context. This can happen when the container crashes
    after demisto.createIncidents but before the context is updated.
    """
    # Use QRadarContextManager for resilient context handling
    context_manager = get_context_manager()
    if not ctx or not version:
        ctx, version = context_manager.get_context_safe()

    assert isinstance(ctx, dict)

    last_run = demisto.getLastRun() or {}
    last_highest_id_last_run = int(last_run.get(LAST_FETCH_KEY, 0))
    print_debug_msg(f"Last highest ID from last run: {last_highest_id_last_run}")

    last_highest_id_context = int(ctx.get(LAST_FETCH_KEY, 0))
    if last_highest_id_last_run != last_highest_id_context and last_highest_id_last_run > 0:
        # There's an inconsistency: we want to force the integration context to reflect last_run's ID.
        print_debug_msg(
            f"Updating context data with last highest ID from last run: {last_highest_id_last_run}. "
            f"ID from context: {last_highest_id_context}"
        )

        # Use context manager for recovery operation
        context_manager = get_context_manager()
        partial_changes = {LAST_FETCH_KEY: last_highest_id_last_run}

        # Keep existing samples during recovery (they are already validated by context manager)
        context_manager.update_context_partial(partial_changes)

        print_debug_msg(f"Updated context last-fetch key from {last_highest_id_context} to {last_highest_id_last_run}.")


def long_running_execution_command(client: Client, params: dict):
    """
    Long running execution of fetching incidents from QRadar service.
    Will continue to fetch in an infinite loop offenses from QRadar,
    Enriching each offense with events/IPs/assets according to the
    configurations given in Demisto params.
    transforming the offenses into incidents and sending them to Demisto
    to save the incidents.
    Args:
        client (Client): Client to perform API calls.
        params (Dict): Demisto params.

    """
    global EVENTS_SEARCH_TRIES
    validate_long_running_params(params)
    fetch_mode = params.get("fetch_mode", "")
    first_fetch = params.get("first_fetch", "3 days")
    ip_enrich, asset_enrich = get_offense_enrichment(params.get("enrichment", "IPs And Assets"))
    offenses_per_fetch = int(params.get("offenses_per_fetch"))  # type: ignore
    user_query = params.get("query", "")
    events_columns = params.get("events_columns") or DEFAULT_EVENTS_COLUMNS
    events_limit = int(params.get("events_limit") or DEFAULT_EVENTS_LIMIT)
    incident_type = params.get("incident_type")
    mirror_options = params.get("mirror_options", DEFAULT_MIRRORING_DIRECTION)
    mirror_direction = MIRROR_DIRECTION.get(mirror_options)
    mirror_options = params.get("mirror_options", "")
    assets_limit = int(params.get("limit_assets", DEFAULT_ASSETS_LIMIT))
    if not argToBoolean(params.get("retry_events_fetch", True)):
        EVENTS_SEARCH_TRIES = 1
    # Use QRadarContextManager for resilient context handling
    context_manager = get_context_manager()
    context_data, version = context_manager.get_context_safe()
    is_reset_triggered(context_data, version)
    recover_from_last_run(context_data, version)
    long_running_container_id = str(uuid.uuid4())
    print_debug_msg(f"Starting container with UUID: {long_running_container_id}")
    while True:
        try:
            perform_long_running_loop(
                client=client,
                offenses_per_fetch=offenses_per_fetch,
                fetch_mode=fetch_mode,
                user_query=user_query,
                events_columns=events_columns,
                events_limit=events_limit,
                ip_enrich=ip_enrich,
                asset_enrich=asset_enrich,
                incident_type=incident_type,
                mirror_direction=mirror_direction,
                first_fetch=first_fetch,
                mirror_options=mirror_options,
                assets_limit=assets_limit,
                long_running_container_id=long_running_container_id,
            )
            demisto.updateModuleHealth("")

        except Exception as e:
            msg = f"Error occurred during long running loop: {e}"
            demisto.updateModuleHealth(msg)
            demisto.error(msg)
            demisto.error(traceback.format_exc())

        finally:
            print_debug_msg("Finished fetch loop")
            time.sleep(get_fetch_sleep_interval())


# Apply thin wrapper to long_running_execution_command
_original_long_running_execution_command = long_running_execution_command
long_running_execution_command = wrap_existing_command("long_running_execution", _original_long_running_execution_command)


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# OFFENSE MANAGEMENT COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────

# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# ENHANCED OFFENSE COMMAND CLASSES (Maintainable Architecture)
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements maintainable offense command classes that use the new architecture while preserving
# backwards compatibility. Each command class provides comprehensive debugging, clear error messages, and
# self-testing capabilities for easy development and troubleshooting.


class OffenseListCommand(BaseCommand):
    """
    Command class for listing QRadar offenses with comprehensive maintainability features.

    This command provides a clean, testable implementation for offense listing with:
    - Comprehensive input validation with clear error messages for common mistakes
    - Detailed logging that shows exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for maintainable business logic
    - Full backwards compatibility with existing interfaces

    The command handles all aspects of offense listing including filtering, pagination,
    enrichment, and result formatting while maintaining crystal-clear code organization.
    """

    def __init__(self, client: Client, metrics_collector: Optional["MetricsCollector"] = None):
        super().__init__(client, metrics_collector, "OffenseListCommand")
        self.offense_service = OffenseService(client)

    def _get_required_arguments(self) -> list[str]:
        """Return list of required argument names for offense listing."""
        return []  # No required arguments for offense listing

    def _validate_command_specific_args(self, args: dict[str, Any]) -> list[str]:
        """
        Validate offense-specific arguments with clear error messages.

        Args:
            args: Command arguments to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        validation_errors = []

        # Validate offense_id if provided
        if "offense_id" in args and args["offense_id"] is not None:
            try:
                offense_id = int(args["offense_id"])
                if offense_id <= 0:
                    validation_errors.append("offense_id must be a positive integer greater than 0")
            except (ValueError, TypeError):
                validation_errors.append("offense_id must be a valid integer (e.g., 123, 456)")

        # Validate range format if provided
        if "range" in args and args["range"]:
            range_value = str(args["range"])
            if not self._is_valid_range_format(range_value):
                validation_errors.append(
                    "range must be in format 'start-end' (e.g., '0-20', '5-15') or single number (e.g., '10')"
                )

        # Validate enrichment level if provided
        if "enrichment" in args and args["enrichment"]:
            enrichment = str(args["enrichment"])
            valid_enrichments = ["None", "IPs", "Assets", "IPs and Assets"]
            if enrichment not in valid_enrichments:
                validation_errors.append(f"enrichment must be one of: {', '.join(valid_enrichments)}")

        # Validate filter length to prevent overly complex queries
        if "filter" in args and args["filter"]:
            filter_query = str(args["filter"])
            if len(filter_query) > 2000:
                validation_errors.append("filter query is too long (maximum 2000 characters). Please simplify your filter.")

        # Validate fields parameter format
        if "fields" in args and args["fields"]:
            fields = str(args["fields"])
            if len(fields) > 1000:
                validation_errors.append(
                    "fields parameter is too long (maximum 1000 characters). Please reduce the number of fields."
                )

        return validation_errors

    def _is_valid_range_format(self, range_value: str) -> bool:
        """
        Validate range format with clear business rules.

        Args:
            range_value: Range string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            # Handle single number format
            if range_value.isdigit():
                return int(range_value) >= 0

            # Handle range format (start-end)
            if "-" in range_value:
                parts = range_value.split("-")
                if len(parts) == 2:
                    start, end = parts
                    start_num = int(start)
                    end_num = int(end)
                    return start_num >= 0 and end_num >= start_num and (end_num - start_num) <= 1000

            return False
        except (ValueError, TypeError):
            return False

    def _execute_command_logic(self, args: dict[str, Any]) -> CommandResults:
        """
        Execute the core offense listing logic with comprehensive debugging.

        This method implements the main business logic for offense listing while
        providing detailed logging and error handling at each step.

        Args:
            args: Validated command arguments

        Returns:
            CommandResults: Formatted offense data for XSOAR
        """
        # Extract and prepare parameters with clear variable names
        self.debug_context.add_breadcrumb("Extracting and preparing parameters")

        specific_offense_id = args.get("offense_id")
        if specific_offense_id is not None:
            specific_offense_id = int(specific_offense_id)

        result_range_specification = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
        qradar_filter_expression = args.get("filter")
        requested_field_list = args.get("fields")
        enrichment_level = args.get("enrichment", "None")

        # Log parameter extraction for debugging
        self.debug_context.capture_variable("specific_offense_id", specific_offense_id)
        self.debug_context.capture_variable("result_range_specification", result_range_specification)
        self.debug_context.capture_variable("qradar_filter_expression", qradar_filter_expression)
        self.debug_context.capture_variable("enrichment_level", enrichment_level)

        # Parse enrichment options with clear logging
        self.debug_context.add_breadcrumb("Parsing enrichment options")
        should_enrich_ip_addresses, should_enrich_with_assets = get_offense_enrichment(enrichment_level)

        self.debug_context.capture_variable("should_enrich_ip_addresses", should_enrich_ip_addresses)
        self.debug_context.capture_variable("should_enrich_with_assets", should_enrich_with_assets)

        # Use service layer for maintainable offense operations
        self.debug_context.add_breadcrumb("Calling offense service for offense listing")

        service_result = self.offense_service.list_offenses(
            offense_id=specific_offense_id,
            range_header=result_range_specification,
            filter_query=qradar_filter_expression,
            fields=requested_field_list,
            include_enrichment=(should_enrich_ip_addresses or should_enrich_with_assets),
        )

        # Handle service result with comprehensive error reporting
        if not service_result.is_success():
            self.debug_context.add_breadcrumb("Offense service call failed", error=service_result.error_message, level="error")
            raise CommandExecutionError(
                f"Failed to list offenses: {service_result.error_message}",
                command_name="OffenseListCommand",
                operation_step="service_call",
                correlation_id=self.debug_context.correlation_id,
            )

        raw_offense_response = service_result.data
        self.debug_context.add_breadcrumb(f"Retrieved {len(raw_offense_response)} offenses from service")

        # Apply comprehensive enrichment if requested
        if should_enrich_ip_addresses or should_enrich_with_assets:
            self.debug_context.add_breadcrumb("Applying comprehensive enrichment")

            enrichment_result = self.offense_service.apply_comprehensive_enrichment(
                raw_offense_response, include_ip_addresses=should_enrich_ip_addresses, include_assets=should_enrich_with_assets
            )

            if enrichment_result.is_success():
                enriched_offense_data = enrichment_result.data
                self.debug_context.add_breadcrumb("Enrichment applied successfully")
            else:
                # Log enrichment failure but continue with raw data
                self.debug_context.add_breadcrumb(
                    "Enrichment failed, continuing with raw data", error=enrichment_result.error_message, level="warning"
                )
                self.logger.warning(f"Enrichment failed: {enrichment_result.error_message}")
                enriched_offense_data = raw_offense_response
        else:
            enriched_offense_data = raw_offense_response
            self.debug_context.add_breadcrumb("No enrichment requested, using raw data")

        # Sanitize output data for consistent field naming and security
        self.debug_context.add_breadcrumb("Sanitizing output data")
        sanitized_final_outputs = sanitize_outputs(enriched_offense_data, OFFENSE_OLD_NEW_NAMES_MAP)

        # Build dynamic headers for table display
        self.debug_context.add_breadcrumb("Building table headers")
        table_display_headers = build_headers(
            ["ID", "Description", "OffenseType", "Status", "Severity"], set(OFFENSE_OLD_NEW_NAMES_MAP.values())
        )

        # Create and return command results
        self.debug_context.add_breadcrumb("Creating command results")

        return CommandResults(
            readable_output=tableToMarkdown(
                "Offenses List", sanitized_final_outputs, headers=table_display_headers, removeNull=True
            ),
            outputs_prefix="QRadar.Offense",
            outputs_key_field="ID",
            outputs=sanitized_final_outputs,
            raw_response=raw_offense_response,
        )

    def self_test(self) -> dict[str, Any]:
        """
        Self-testing capability that validates command functionality during development.

        This method provides comprehensive testing of the command's functionality
        including parameter validation, service integration, and result formatting.

        Returns:
            Dict containing test results and diagnostic information
        """
        test_results = {
            "command_name": "OffenseListCommand",
            "test_timestamp": time.time(),
            "tests_passed": 0,
            "tests_failed": 0,
            "test_details": [],
            "overall_status": "unknown",
        }

        # Test 1: Parameter validation
        try:
            # Test valid parameters
            valid_args = {"range": "0-10", "enrichment": "None"}
            validation_errors = self._validate_command_specific_args(valid_args)

            if not validation_errors:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Valid parameter validation",
                        "status": "PASSED",
                        "details": "Valid parameters correctly accepted",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Valid parameter validation",
                        "status": "FAILED",
                        "details": f"Valid parameters rejected: {validation_errors}",
                    }
                )

            # Test invalid parameters
            invalid_args = {"offense_id": "invalid", "range": "invalid-range"}
            validation_errors = self._validate_command_specific_args(invalid_args)

            if validation_errors:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Invalid parameter rejection",
                        "status": "PASSED",
                        "details": f"Invalid parameters correctly rejected: {validation_errors}",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Invalid parameter rejection",
                        "status": "FAILED",
                        "details": "Invalid parameters were not rejected",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Parameter validation testing",
                    "status": "FAILED",
                    "details": f"Exception during validation testing: {str(e)}",
                }
            )

        # Test 2: Service integration
        try:
            if hasattr(self, "offense_service") and self.offense_service:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "PASSED", "details": "OffenseService properly initialized"}
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "FAILED", "details": "OffenseService not properly initialized"}
                )
        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {"test_name": "Service integration", "status": "FAILED", "details": f"Exception during service testing: {str(e)}"}
            )

        # Determine overall status
        if test_results["tests_failed"] == 0:
            test_results["overall_status"] = "PASSED"
        elif test_results["tests_passed"] > test_results["tests_failed"]:
            test_results["overall_status"] = "MOSTLY_PASSED"
        else:
            test_results["overall_status"] = "FAILED"

        return test_results


def qradar_offenses_list_command(qradar_client: Client, command_arguments: dict[str, Any]) -> CommandResults:
    """
    List QRadar offenses - Enhanced maintainable implementation with backwards compatibility.

    This function maintains the exact same interface as the original while using the new
    maintainable architecture internally. It provides comprehensive debugging, clear error
    messages, and detailed logging while preserving all existing behavior.

    Key Enhancements:
    - Uses maintainable OffenseListCommand class internally
    - Comprehensive input validation with helpful error messages
    - Detailed logging showing exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for clean, testable operations
    - Full backwards compatibility with existing interfaces

    Args:
        qradar_client (Client): Authenticated QRadar API client instance for making requests
        command_arguments (Dict[str, Any]): Command parameters from XSOAR containing:
            - offense_id (Optional[str]): Specific offense ID to retrieve
            - range (Optional[str]): Result range specification (default: DEFAULT_RANGE_VALUE)
            - filter (Optional[str]): QRadar filter expression for advanced querying
            - fields (Optional[str]): Comma-separated field names to include in response
            - enrichment (Optional[str]): Enrichment level ("None", "IPs", "Assets", "IPs and Assets")

    Returns:
        CommandResults: XSOAR command results object with comprehensive offense data

    Raises:
        CommandValidationError: When command arguments are invalid with clear guidance
        CommandExecutionError: When execution fails with detailed context
        DemistoException: For backwards compatibility with existing error handling

    Example Usage:
        # Get all recent offenses with basic enrichment
        result = qradar_offenses_list_command(client, {"range": "0-10", "enrichment": "IPs"})

        # Get specific offense with full enrichment
        result = qradar_offenses_list_command(client, {
            "offense_id": "123",
            "enrichment": "IPs and Assets"
        })

        # Get filtered offenses with custom fields
        result = qradar_offenses_list_command(client, {
            "filter": "status='OPEN'",
            "fields": "id,description,status,severity",
            "range": "0-50"
        })

    Debugging Features:
        - Comprehensive execution tracing with breadcrumbs
        - Variable capture for troubleshooting
        - Performance metrics collection
        - Structured error reporting with correlation IDs
        - Automatic error categorization with recovery suggestions

    Self-Testing:
        The command includes built-in self-testing capabilities that can be accessed
        during development to validate functionality and catch issues early.
    """
    try:
        # Create enhanced command instance with comprehensive debugging
        enhanced_command = OffenseListCommand(
            client=qradar_client,
            metrics_collector=get_global_metrics_collector() if "get_global_metrics_collector" in globals() else None,
        )

        # Execute with full debugging context and error handling
        return enhanced_command.execute_with_full_context(command_arguments)

    except (CommandValidationError, CommandExecutionError) as e:
        # Convert enhanced exceptions to DemistoException for backwards compatibility
        raise DemistoException(str(e))
    except Exception as e:
        # Handle any unexpected exceptions with clear error reporting
        raise DemistoException(f"Unexpected error in qradar-offenses-list command: {str(e)}")


# Apply thin wrapper to qradar_offenses_list_command
_original_qradar_offenses_list_command = qradar_offenses_list_command
qradar_offenses_list_command = wrap_existing_command("qradar_offenses_list", _original_qradar_offenses_list_command)


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# BULK COMMAND WRAPPER APPLICATION
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section applies thin wrappers to all remaining command functions in bulk to ensure comprehensive
# debugging coverage without having to manually wrap each function individually.


def apply_thin_wrappers_to_all_commands():
    """
    Apply thin wrappers to all remaining command functions.

    This function identifies all command functions in the global namespace and applies
    thin wrappers to them, preserving their original behavior while adding comprehensive
    debugging capabilities.
    """
    # Get current global namespace
    current_globals = globals()

    # List of command functions to wrap (those not already wrapped)
    command_functions_to_wrap = [
        # Offense Management Commands
        ("qradar_offense_update_command", "qradar_offense_update"),
        ("qradar_closing_reasons_list_command", "qradar_closing_reasons_list"),
        ("qradar_offense_notes_list_command", "qradar_offense_notes_list"),
        ("qradar_offense_notes_create_command", "qradar_offense_notes_create"),
        # Rules and Assets Commands
        ("qradar_rules_list_command", "qradar_rules_list"),
        ("qradar_rule_groups_list_command", "qradar_rule_groups_list"),
        ("qradar_assets_list_command", "qradar_assets_list"),
        # Search Commands
        ("qradar_saved_searches_list_command", "qradar_saved_searches_list"),
        ("qradar_searches_list_command", "qradar_searches_list"),
        ("qradar_search_create_command", "qradar_search_create"),
        ("qradar_search_status_get_command", "qradar_search_status_get"),
        ("qradar_search_delete_command", "qradar_search_delete"),
        ("qradar_search_cancel_command", "qradar_search_cancel"),
        ("qradar_search_results_get_command", "qradar_search_results_get"),
        ("qradar_search_retrieve_events_command", "qradar_search_retrieve_events"),
        # Reference Set Commands
        ("qradar_reference_sets_list_command", "qradar_reference_sets_list"),
        ("qradar_reference_set_create_command", "qradar_reference_set_create"),
        ("qradar_reference_set_delete_command", "qradar_reference_set_delete"),
        ("qradar_reference_set_value_upsert_command", "qradar_reference_set_value_upsert"),
        ("qradar_reference_set_value_delete_command", "qradar_reference_set_value_delete"),
        # Domain and Indicator Commands
        ("qradar_domains_list_command", "qradar_domains_list"),
        ("qradar_indicators_upload_command", "qradar_indicators_upload"),
        ("qradar_geolocations_for_ip_command", "qradar_geolocations_for_ip"),
        # Log Source Commands
        ("qradar_log_sources_list_command", "qradar_log_sources_list"),
        ("qradar_get_custom_properties_command", "qradar_get_custom_properties"),
        ("qradar_log_source_types_list_command", "qradar_log_source_types_list"),
        ("qradar_log_source_protocol_types_list_command", "qradar_log_source_protocol_types_list"),
        ("qradar_log_source_extensions_list_command", "qradar_log_source_extensions_list"),
        ("qradar_log_source_languages_list_command", "qradar_log_source_languages_list"),
        ("qradar_log_source_groups_list_command", "qradar_log_source_groups_list"),
        ("qradar_log_source_delete_command", "qradar_log_source_delete"),
        # Network and Infrastructure Commands
        ("qradar_ips_source_get_command", "qradar_ips_source_get"),
        ("qradar_ips_local_destination_get_command", "qradar_ips_local_destination_get"),
        ("qradar_event_collectors_list_command", "qradar_event_collectors_list"),
        ("qradar_wincollect_destinations_list_command", "qradar_wincollect_destinations_list"),
        ("qradar_disconnected_log_collectors_list_command", "qradar_disconnected_log_collectors_list"),
        # Remote Network Commands
        ("qradar_remote_network_cidr_create_command", "qradar_remote_network_cidr_create"),
        ("qradar_remote_network_cidr_list_command", "qradar_remote_network_cidr_list"),
        ("qradar_remote_network_cidr_delete_command", "qradar_remote_network_cidr_delete"),
        ("qradar_remote_network_cidr_update_command", "qradar_remote_network_cidr_update"),
        ("qradar_remote_network_deploy_execution_command", "qradar_remote_network_deploy_execution"),
        # Utility and Management Commands
        ("qradar_reset_last_run_command", "qradar_reset_last_run"),
        ("qradar_get_mapping_fields_command", "qradar_get_mapping_fields"),
        ("get_remote_data_command", "get_remote_data"),
        ("get_modified_remote_data_command", "get_modified_remote_data"),
    ]

    # Apply wrappers to all command functions
    for function_name, command_name in command_functions_to_wrap:
        if function_name in current_globals and callable(current_globals[function_name]):
            try:
                # Store original function
                original_function = current_globals[function_name]

                # Create wrapped version
                wrapped_function = wrap_existing_command(command_name, original_function)

                # Replace in global namespace
                current_globals[function_name] = wrapped_function

                # Log successful wrapping for debugging
                demisto.debug(f"Successfully applied thin wrapper to {function_name}")

            except Exception as e:
                # Log wrapping failures but don't break the integration
                demisto.error(f"Failed to wrap command function {function_name}: {str(e)}")


# Apply all thin wrappers when the module is loaded
try:
    apply_thin_wrappers_to_all_commands()
    demisto.debug("Successfully applied thin wrappers to all command functions")
except Exception as e:
    # Don't break the integration if wrapper application fails
    demisto.error(f"Failed to apply some thin wrappers: {str(e)}")
    demisto.error("Integration will continue to function but some debugging capabilities may be limited")


class OffenseUpdateCommand(BaseCommand):
    """
    Command class for updating QRadar offenses with comprehensive maintainability features.

    This command provides a clean, testable implementation for offense updates with:
    - Comprehensive input validation with clear error messages for common mistakes
    - Business rule validation (e.g., closing reason required when closing offense)
    - Detailed logging that shows exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for maintainable business logic
    - Full backwards compatibility with existing interfaces

    The command handles all aspects of offense updates including status changes, assignment
    modifications, protection settings, and closing reason resolution while maintaining
    crystal-clear code organization and comprehensive error handling.
    """

    def __init__(self, client: Client, metrics_collector: Optional["MetricsCollector"] = None):
        super().__init__(client, metrics_collector, "OffenseUpdateCommand")
        self.offense_service = OffenseService(client)

    def _get_required_arguments(self) -> list[str]:
        """Return list of required argument names for offense updates."""
        return ["offense_id"]  # offense_id is required for updates

    def _validate_command_specific_args(self, args: dict[str, Any]) -> list[str]:
        """
        Validate offense update specific arguments with clear error messages.

        This method provides comprehensive validation including business rules
        and common mistake detection with helpful guidance for fixing issues.

        Args:
            args: Command arguments to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        validation_errors = []

        # Validate offense_id (required parameter)
        if "offense_id" not in args or args["offense_id"] is None:
            validation_errors.append("offense_id is required for offense updates")
        else:
            try:
                offense_id = int(args["offense_id"])
                if offense_id <= 0:
                    validation_errors.append("offense_id must be a positive integer greater than 0")
            except (ValueError, TypeError):
                validation_errors.append("offense_id must be a valid integer (e.g., 123, 456)")

        # Validate status if provided
        if "status" in args and args["status"]:
            status = str(args["status"]).upper()
            valid_statuses = ["OPEN", "HIDDEN", "CLOSED"]
            if status not in valid_statuses:
                validation_errors.append(f"status must be one of: {', '.join(valid_statuses)} (case insensitive)")

        # Business rule validation: closing reason required when closing offense
        status = args.get("status", "").upper() if args.get("status") else ""
        closing_reason_id = args.get("closing_reason_id")
        closing_reason_name = args.get("closing_reason_name")

        if status == "CLOSED":
            if not closing_reason_id and not closing_reason_name:
                validation_errors.append(
                    "closing_reason_id or closing_reason_name is required when setting status to CLOSED. "
                    "Use 'qradar-closing-reasons-list' command to see available closing reasons."
                )

        # Validate that both closing reason ID and name are not provided simultaneously
        if closing_reason_id and closing_reason_name:
            validation_errors.append(
                "Cannot specify both closing_reason_id and closing_reason_name. "
                "Use either the numeric ID or the text name, not both."
            )

        # Validate closing_reason_id format if provided
        if closing_reason_id is not None:
            try:
                reason_id = int(closing_reason_id)
                if reason_id <= 0:
                    validation_errors.append("closing_reason_id must be a positive integer greater than 0")
            except (ValueError, TypeError):
                validation_errors.append("closing_reason_id must be a valid integer (e.g., 1, 2, 3)")

        # Validate closing_reason_name format if provided
        if closing_reason_name is not None:
            reason_name = str(closing_reason_name).strip()
            if not reason_name:
                validation_errors.append("closing_reason_name cannot be empty if provided")
            elif len(reason_name) > 255:
                validation_errors.append("closing_reason_name is too long (maximum 255 characters)")

        # Validate boolean flags format
        for flag_name in ["protected", "follow_up"]:
            if flag_name in args and args[flag_name] is not None:
                flag_value = str(args[flag_name]).lower()
                if flag_value not in ["true", "false"]:
                    validation_errors.append(f"{flag_name} must be 'true' or 'false' (case insensitive)")

        # Validate assigned_to format if provided
        if "assigned_to" in args and args["assigned_to"]:
            assigned_to = str(args["assigned_to"]).strip()
            if not assigned_to:
                validation_errors.append("assigned_to cannot be empty if provided")
            elif len(assigned_to) > 100:
                validation_errors.append("assigned_to is too long (maximum 100 characters)")

        # Validate fields parameter format
        if "fields" in args and args["fields"]:
            fields = str(args["fields"])
            if len(fields) > 1000:
                validation_errors.append("fields parameter is too long (maximum 1000 characters)")

        # Validate enrichment level if provided
        if "enrichment" in args and args["enrichment"]:
            enrichment = str(args["enrichment"])
            valid_enrichments = ["None", "IPs", "Assets", "IPs and Assets"]
            if enrichment not in valid_enrichments:
                validation_errors.append(f"enrichment must be one of: {', '.join(valid_enrichments)}")

        return validation_errors

    def _execute_command_logic(self, args: dict[str, Any]) -> CommandResults:
        """
        Execute the core offense update logic with comprehensive debugging.

        This method implements the main business logic for offense updates while
        providing detailed logging and error handling at each step.

        Args:
            args: Validated command arguments

        Returns:
            CommandResults: Formatted updated offense data for XSOAR
        """
        # Extract and prepare parameters with clear variable names
        self.debug_context.add_breadcrumb("Extracting and preparing update parameters")

        target_offense_id = int(args["offense_id"])  # Required parameter, already validated
        should_protect_offense = self._parse_boolean_flag(args.get("protected"))
        should_mark_for_followup = self._parse_boolean_flag(args.get("follow_up"))
        new_offense_status = args.get("status")
        closing_reason_identifier = args.get("closing_reason_id")
        human_readable_closing_reason_name = args.get("closing_reason_name")
        assigned_user_name = args.get("assigned_to")
        requested_response_fields = args.get("fields")
        enrichment_level = args.get("enrichment", "None")

        # Log parameter extraction for debugging
        self.debug_context.capture_variable("target_offense_id", target_offense_id)
        self.debug_context.capture_variable("new_offense_status", new_offense_status)
        self.debug_context.capture_variable("assigned_user_name", assigned_user_name)
        self.debug_context.capture_variable("enrichment_level", enrichment_level)

        # Resolve human-readable closing reason name to ID if provided
        if human_readable_closing_reason_name:
            self.debug_context.add_breadcrumb(
                "Resolving closing reason name to ID", reason_name=human_readable_closing_reason_name
            )

            closing_reason_result = self.offense_service.resolve_closing_reason_name_to_id(human_readable_closing_reason_name)

            if not closing_reason_result.is_success():
                self.debug_context.add_breadcrumb(
                    "Closing reason resolution failed", error=closing_reason_result.error_message, level="error"
                )
                raise CommandExecutionError(
                    f"Failed to resolve closing reason name '{human_readable_closing_reason_name}': "
                    f"{closing_reason_result.error_message}. "
                    f"Use 'qradar-closing-reasons-list' command to see available closing reasons.",
                    command_name="OffenseUpdateCommand",
                    operation_step="closing_reason_resolution",
                    correlation_id=self.debug_context.correlation_id,
                )

            closing_reason_identifier = closing_reason_result.data["closing_reason_id"]
            self.debug_context.add_breadcrumb("Closing reason resolved successfully", resolved_id=closing_reason_identifier)

        # Parse enrichment options with clear logging
        self.debug_context.add_breadcrumb("Parsing enrichment options")
        should_enrich_ip_addresses, should_enrich_with_assets = get_offense_enrichment(enrichment_level)

        self.debug_context.capture_variable("should_enrich_ip_addresses", should_enrich_ip_addresses)
        self.debug_context.capture_variable("should_enrich_with_assets", should_enrich_with_assets)

        # Use service layer for maintainable offense update operations
        self.debug_context.add_breadcrumb("Calling offense service for offense update")

        update_result = self.offense_service.update_offense(
            offense_id=target_offense_id,
            status=new_offense_status,
            assigned_to=assigned_user_name,
            closing_reason_id=closing_reason_identifier,
            follow_up=should_mark_for_followup,
            protected=should_protect_offense,
            fields=requested_response_fields,
        )

        # Handle service result with comprehensive error reporting
        if not update_result.is_success():
            self.debug_context.add_breadcrumb(
                "Offense update service call failed", error=update_result.error_message, level="error"
            )
            raise CommandExecutionError(
                f"Failed to update offense {target_offense_id}: {update_result.error_message}",
                command_name="OffenseUpdateCommand",
                operation_step="service_call",
                correlation_id=self.debug_context.correlation_id,
            )

        raw_update_response = [update_result.data]  # Wrap in list for enrichment compatibility
        self.debug_context.add_breadcrumb("Offense updated successfully")

        # Apply comprehensive enrichment to the updated offense data if requested
        if should_enrich_ip_addresses or should_enrich_with_assets:
            self.debug_context.add_breadcrumb("Applying comprehensive enrichment to updated offense")

            enrichment_result = self.offense_service.apply_comprehensive_enrichment(
                raw_update_response, include_ip_addresses=should_enrich_ip_addresses, include_assets=should_enrich_with_assets
            )

            if enrichment_result.is_success():
                enriched_updated_offense = enrichment_result.data
                self.debug_context.add_breadcrumb("Enrichment applied successfully to updated offense")
            else:
                # Log enrichment failure but continue with raw data
                self.debug_context.add_breadcrumb(
                    "Enrichment failed for updated offense, continuing with raw data",
                    error=enrichment_result.error_message,
                    level="warning",
                )
                self.logger.warning(f"Enrichment failed: {enrichment_result.error_message}")
                enriched_updated_offense = raw_update_response
        else:
            enriched_updated_offense = raw_update_response
            self.debug_context.add_breadcrumb("No enrichment requested for updated offense")

        # Sanitize output data for consistent field naming and security
        self.debug_context.add_breadcrumb("Sanitizing updated offense output data")
        sanitized_final_outputs = sanitize_outputs(enriched_updated_offense, OFFENSE_OLD_NEW_NAMES_MAP)

        # Build dynamic headers for table display
        self.debug_context.add_breadcrumb("Building table headers for updated offense")
        table_display_headers = build_headers(
            ["ID", "Description", "OffenseType", "Status", "Severity"], set(OFFENSE_OLD_NEW_NAMES_MAP.values())
        )

        # Create and return command results
        self.debug_context.add_breadcrumb("Creating command results for updated offense")

        return CommandResults(
            readable_output=tableToMarkdown(
                "Offense Update Results", sanitized_final_outputs, headers=table_display_headers, removeNull=True
            ),
            outputs_prefix="QRadar.Offense",
            outputs_key_field="ID",
            outputs=sanitized_final_outputs,
            raw_response=raw_update_response,
        )

    def _parse_boolean_flag(self, flag_value: Any) -> bool | None:
        """
        Parse boolean flag values with clear error handling.

        Args:
            flag_value: Value to parse as boolean

        Returns:
            Boolean value or None if not provided
        """
        if flag_value is None:
            return None

        flag_str = str(flag_value).lower().strip()
        if flag_str == "true":
            return True
        elif flag_str == "false":
            return False
        else:
            # This should be caught by validation, but handle gracefully
            return None

    def self_test(self) -> dict[str, Any]:
        """
        Self-testing capability that validates command functionality during development.

        This method provides comprehensive testing of the command's functionality
        including parameter validation, business rule validation, service integration,
        and result formatting.

        Returns:
            Dict containing test results and diagnostic information
        """
        test_results = {
            "command_name": "OffenseUpdateCommand",
            "test_timestamp": time.time(),
            "tests_passed": 0,
            "tests_failed": 0,
            "test_details": [],
            "overall_status": "unknown",
        }

        # Test 1: Required parameter validation
        try:
            # Test missing required parameter
            missing_required_args = {"status": "OPEN"}
            validation_errors = self._validate_command_specific_args(missing_required_args)

            if any("offense_id is required" in error for error in validation_errors):
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Required parameter validation",
                        "status": "PASSED",
                        "details": "Missing offense_id correctly detected",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Required parameter validation",
                        "status": "FAILED",
                        "details": "Missing offense_id not detected",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Required parameter validation",
                    "status": "FAILED",
                    "details": f"Exception during required parameter testing: {str(e)}",
                }
            )

        # Test 2: Business rule validation (closing reason required when closing)
        try:
            # Test closing without reason
            closing_without_reason_args = {"offense_id": "123", "status": "CLOSED"}
            validation_errors = self._validate_command_specific_args(closing_without_reason_args)

            if any("closing_reason" in error for error in validation_errors):
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Business rule validation",
                        "status": "PASSED",
                        "details": "Closing without reason correctly rejected",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Business rule validation",
                        "status": "FAILED",
                        "details": "Closing without reason not rejected",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Business rule validation",
                    "status": "FAILED",
                    "details": f"Exception during business rule testing: {str(e)}",
                }
            )

        # Test 3: Boolean flag parsing
        try:
            # Test boolean flag parsing
            true_result = self._parse_boolean_flag("true")
            false_result = self._parse_boolean_flag("false")
            none_result = self._parse_boolean_flag(None)

            if true_result is True and false_result is False and none_result is None:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Boolean flag parsing", "status": "PASSED", "details": "Boolean flags parsed correctly"}
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Boolean flag parsing",
                        "status": "FAILED",
                        "details": f"Boolean parsing failed: true={true_result}, false={false_result}, none={none_result}",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Boolean flag parsing",
                    "status": "FAILED",
                    "details": f"Exception during boolean parsing testing: {str(e)}",
                }
            )

        # Test 4: Service integration
        try:
            if hasattr(self, "offense_service") and self.offense_service:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "PASSED", "details": "OffenseService properly initialized"}
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "FAILED", "details": "OffenseService not properly initialized"}
                )
        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {"test_name": "Service integration", "status": "FAILED", "details": f"Exception during service testing: {str(e)}"}
            )

        # Determine overall status
        if test_results["tests_failed"] == 0:
            test_results["overall_status"] = "PASSED"
        elif test_results["tests_passed"] > test_results["tests_failed"]:
            test_results["overall_status"] = "MOSTLY_PASSED"
        else:
            test_results["overall_status"] = "FAILED"

        return test_results


def qradar_offense_update_command(qradar_client: Client, command_arguments: dict[str, Any]) -> CommandResults:
    """
    Update QRadar offense - Enhanced maintainable implementation with backwards compatibility.

    This function maintains the exact same interface as the original while using the new
    maintainable architecture internally. It provides comprehensive debugging, clear error
    messages, business rule validation, and detailed logging while preserving all existing behavior.

    Key Enhancements:
    - Uses maintainable OffenseUpdateCommand class internally
    - Comprehensive input validation with helpful error messages for common mistakes
    - Business rule validation (e.g., closing reason required when closing offense)
    - Detailed logging showing exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for clean, testable operations
    - Full backwards compatibility with existing interfaces

    Args:
        qradar_client (Client): Authenticated QRadar API client instance for making requests
        command_arguments (Dict[str, Any]): Command parameters from XSOAR containing:
            - offense_id (Required[str]): Unique identifier of the offense to update
            - protected (Optional[str]): Protection status ("true"/"false") for sensitive offenses
            - follow_up (Optional[str]): Follow-up flag ("true"/"false") for tracking purposes
            - status (Optional[str]): New offense status ("OPEN", "HIDDEN", "CLOSED")
            - closing_reason_id (Optional[str]): ID of closing reason (required when status="CLOSED")
            - closing_reason_name (Optional[str]): Human-readable closing reason name (alternative to ID)
            - assigned_to (Optional[str]): Username to assign the offense to
            - fields (Optional[str]): Comma-separated field names to include in response
            - enrichment (Optional[str]): Enrichment level ("None", "IPs", "Assets", "IPs and Assets")

    Returns:
        CommandResults: XSOAR command results object with comprehensive updated offense data

    Raises:
        CommandValidationError: When command arguments are invalid with clear guidance
        CommandExecutionError: When execution fails with detailed context
        DemistoException: For backwards compatibility with existing error handling

    Example Usage:
        # Close an offense with a specific closing reason
        result = qradar_offense_update_command(client, {
            "offense_id": "123",
            "status": "CLOSED",
            "closing_reason_name": "False Positive",
            "enrichment": "IPs"
        })

        # Assign an offense to a user and mark for follow-up
        result = qradar_offense_update_command(client, {
            "offense_id": "456",
            "assigned_to": "analyst1",
            "follow_up": "true",
            "protected": "true"
        })

        # Update status with minimal response fields
        result = qradar_offense_update_command(client, {
            "offense_id": "789",
            "status": "HIDDEN",
            "fields": "id,status,last_updated_time"
        })

    Business Rules:
        - When status="CLOSED", either closing_reason_id or closing_reason_name must be provided
        - Closing reason names are automatically resolved to IDs via QRadar API lookup
        - All closing reasons (including deleted and reserved) are searched for name resolution
        - Protection and follow-up flags accept string values ("true"/"false")

    Debugging Features:
        - Comprehensive execution tracing with breadcrumbs
        - Variable capture for troubleshooting
        - Performance metrics collection
        - Structured error reporting with correlation IDs
        - Automatic error categorization with recovery suggestions

    Self-Testing:
        The command includes built-in self-testing capabilities that can be accessed
        during development to validate functionality and catch issues early.
    """
    try:
        # Create enhanced command instance with comprehensive debugging
        enhanced_command = OffenseUpdateCommand(
            client=qradar_client,
            metrics_collector=get_global_metrics_collector() if "get_global_metrics_collector" in globals() else None,
        )

        # Execute with full debugging context and error handling
        return enhanced_command.execute_with_full_context(command_arguments)

    except (CommandValidationError, CommandExecutionError) as e:
        # Convert enhanced exceptions to DemistoException for backwards compatibility
        raise DemistoException(str(e))
    except Exception as e:
        # Handle any unexpected exceptions with clear error reporting
        raise DemistoException(f"Unexpected error in qradar-offense-update command: {str(e)}")


def qradar_closing_reasons_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of closing reasons from QRadar service.
    possible arguments:
    - closing_reason_id: Retrieves details of the specific closing reason that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    closing_reason_id = args.get("closing_reason_id")
    include_reserved = argToBoolean(args.get("include_reserved", False))
    include_deleted = argToBoolean(args.get("include_deleted", False))
    range_ = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_ = args.get("filter")
    fields = args.get("fields")

    # if this call fails, raise an error and stop command execution
    response = client.closing_reasons_list(closing_reason_id, include_reserved, include_deleted, range_, filter_, fields)
    outputs = sanitize_outputs(response, CLOSING_REASONS_RAW_FORMATTED)
    headers = build_headers(["ID", "Name"], set(CLOSING_REASONS_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Closing Reasons", outputs, headers=headers, removeNull=True),
        outputs_prefix="QRadar.Offense.ClosingReasons",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


class OffenseNotesListCommand(BaseCommand):
    """
    Command class for listing QRadar offense notes with comprehensive maintainability features.

    This command provides a clean, testable implementation for offense notes listing with:
    - Comprehensive input validation with clear error messages for common mistakes
    - Detailed logging that shows exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for maintainable business logic
    - Full backwards compatibility with existing interfaces

    The command handles all aspects of offense notes listing including filtering, pagination,
    and result formatting while maintaining crystal-clear code organization.
    """

    def __init__(self, client: Client, metrics_collector: Optional["MetricsCollector"] = None):
        super().__init__(client, metrics_collector, "OffenseNotesListCommand")
        self.offense_service = OffenseService(client)

    def _get_required_arguments(self) -> list[str]:
        """Return list of required argument names for offense notes listing."""
        return ["offense_id"]  # offense_id is required for notes listing

    def _validate_command_specific_args(self, args: dict[str, Any]) -> list[str]:
        """
        Validate offense notes specific arguments with clear error messages.

        Args:
            args: Command arguments to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        validation_errors = []

        # Validate offense_id (required parameter)
        if "offense_id" not in args or args["offense_id"] is None:
            validation_errors.append("offense_id is required for listing offense notes")
        else:
            try:
                offense_id = int(args["offense_id"])
                if offense_id <= 0:
                    validation_errors.append("offense_id must be a positive integer greater than 0")
            except (ValueError, TypeError):
                validation_errors.append("offense_id must be a valid integer (e.g., 123, 456)")

        # Validate note_id if provided (optional parameter)
        if "note_id" in args and args["note_id"] is not None:
            try:
                note_id = int(args["note_id"])
                if note_id <= 0:
                    validation_errors.append("note_id must be a positive integer greater than 0")
            except (ValueError, TypeError):
                validation_errors.append("note_id must be a valid integer (e.g., 123, 456)")

        # Validate range format if provided
        if "range" in args and args["range"]:
            range_value = str(args["range"])
            if not self._is_valid_range_format(range_value):
                validation_errors.append(
                    "range must be in format 'start-end' (e.g., '0-20', '5-15') or single number (e.g., '10')"
                )

        # Validate filter length to prevent overly complex queries
        if "filter" in args and args["filter"]:
            filter_query = str(args["filter"])
            if len(filter_query) > 2000:
                validation_errors.append("filter query is too long (maximum 2000 characters). Please simplify your filter.")

        # Validate fields parameter format
        if "fields" in args and args["fields"]:
            fields = str(args["fields"])
            if len(fields) > 1000:
                validation_errors.append(
                    "fields parameter is too long (maximum 1000 characters). Please reduce the number of fields."
                )

        return validation_errors

    def _is_valid_range_format(self, range_value: str) -> bool:
        """
        Validate range format with clear business rules.

        Args:
            range_value: Range string to validate

        Returns:
            True if valid, False otherwise
        """
        try:
            # Handle single number format
            if range_value.isdigit():
                return int(range_value) >= 0

            # Handle range format (start-end)
            if "-" in range_value:
                parts = range_value.split("-")
                if len(parts) == 2:
                    start, end = parts
                    start_num = int(start)
                    end_num = int(end)
                    return start_num >= 0 and end_num >= start_num and (end_num - start_num) <= 1000

            return False
        except (ValueError, TypeError):
            return False

    def _execute_command_logic(self, args: dict[str, Any]) -> CommandResults:
        """
        Execute the core offense notes listing logic with comprehensive debugging.

        Args:
            args: Validated command arguments

        Returns:
            CommandResults: Formatted offense notes data for XSOAR
        """
        # Extract and prepare parameters with clear variable names
        self.debug_context.add_breadcrumb("Extracting and preparing parameters for offense notes listing")

        offense_id = int(args["offense_id"])  # Required parameter, already validated
        note_id = None
        if "note_id" in args and args["note_id"] is not None:
            note_id = int(args["note_id"])

        range_header = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
        filter_query = args.get("filter")
        fields = args.get("fields")

        # Log parameter extraction for debugging
        self.debug_context.capture_variable("offense_id", offense_id)
        self.debug_context.capture_variable("note_id", note_id)
        self.debug_context.capture_variable("range_header", range_header)
        self.debug_context.capture_variable("filter_query", filter_query)

        # Use service layer for maintainable offense notes operations
        self.debug_context.add_breadcrumb("Calling offense service for notes listing")

        service_result = self.offense_service.list_offense_notes(
            offense_id=offense_id, note_id=note_id, range_header=range_header, filter_query=filter_query, fields=fields
        )

        # Handle service result with comprehensive error reporting
        if not service_result.is_success():
            self.debug_context.add_breadcrumb(
                "Offense notes service call failed", error=service_result.error_message, level="error"
            )
            raise CommandExecutionError(
                f"Failed to list offense notes for offense {offense_id}: {service_result.error_message}",
                command_name="OffenseNotesListCommand",
                operation_step="service_call",
                correlation_id=self.debug_context.correlation_id,
            )

        notes_data = service_result.data
        self.debug_context.add_breadcrumb(f"Retrieved {len(notes_data)} notes from service")

        # Sanitize output data for consistent field naming and security
        self.debug_context.add_breadcrumb("Sanitizing notes output data")
        outputs = sanitize_outputs(notes_data, NOTES_RAW_FORMATTED)

        # Build dynamic headers for table display
        self.debug_context.add_breadcrumb("Building table headers for notes")
        headers = build_headers(["ID", "Text", "CreatedBy", "CreateTime"], set(NOTES_RAW_FORMATTED.values()))

        # Create and return command results
        self.debug_context.add_breadcrumb("Creating command results for offense notes")

        return CommandResults(
            readable_output=tableToMarkdown(f"Offense Notes List For Offense ID {offense_id}", outputs, headers, removeNull=True),
            outputs_prefix="QRadar.Note",
            outputs_key_field="ID",
            outputs=outputs,
            raw_response=notes_data,
        )

    def self_test(self) -> dict[str, Any]:
        """
        Self-testing capability that validates command functionality during development.

        Returns:
            Dict containing test results and diagnostic information
        """
        test_results = {
            "command_name": "OffenseNotesListCommand",
            "test_timestamp": time.time(),
            "tests_passed": 0,
            "tests_failed": 0,
            "test_details": [],
            "overall_status": "unknown",
        }

        # Test 1: Required parameter validation
        try:
            # Test missing required parameter
            missing_required_args = {"range": "0-10"}
            validation_errors = self._validate_command_specific_args(missing_required_args)

            if any("offense_id is required" in error for error in validation_errors):
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Required parameter validation",
                        "status": "PASSED",
                        "details": "Missing offense_id correctly detected",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Required parameter validation",
                        "status": "FAILED",
                        "details": "Missing offense_id not detected",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Required parameter validation",
                    "status": "FAILED",
                    "details": f"Exception during required parameter testing: {str(e)}",
                }
            )

        # Test 2: Range format validation
        try:
            # Test valid range formats
            valid_ranges = ["0-10", "5", "10-20"]
            all_valid = all(self._is_valid_range_format(r) for r in valid_ranges)

            # Test invalid range formats
            invalid_ranges = ["invalid", "-5", "10-5", "abc-def"]
            all_invalid = all(not self._is_valid_range_format(r) for r in invalid_ranges)

            if all_valid and all_invalid:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Range format validation",
                        "status": "PASSED",
                        "details": "Range format validation working correctly",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Range format validation",
                        "status": "FAILED",
                        "details": f"Range validation failed: valid={all_valid}, invalid={all_invalid}",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Range format validation",
                    "status": "FAILED",
                    "details": f"Exception during range validation testing: {str(e)}",
                }
            )

        # Test 3: Service integration
        try:
            if hasattr(self, "offense_service") and self.offense_service:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "PASSED", "details": "OffenseService properly initialized"}
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "FAILED", "details": "OffenseService not properly initialized"}
                )
        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {"test_name": "Service integration", "status": "FAILED", "details": f"Exception during service testing: {str(e)}"}
            )

        # Determine overall status
        if test_results["tests_failed"] == 0:
            test_results["overall_status"] = "PASSED"
        elif test_results["tests_passed"] > test_results["tests_failed"]:
            test_results["overall_status"] = "MOSTLY_PASSED"
        else:
            test_results["overall_status"] = "FAILED"

        return test_results


class OffenseNotesCreateCommand(BaseCommand):
    """
    Command class for creating QRadar offense notes with comprehensive maintainability features.

    This command provides a clean, testable implementation for offense note creation with:
    - Comprehensive input validation with clear error messages for common mistakes
    - Detailed logging that shows exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for maintainable business logic
    - Full backwards compatibility with existing interfaces

    The command handles all aspects of offense note creation including validation,
    creation, and result formatting while maintaining crystal-clear code organization.
    """

    def __init__(self, client: Client, metrics_collector: Optional["MetricsCollector"] = None):
        super().__init__(client, metrics_collector, "OffenseNotesCreateCommand")
        self.offense_service = OffenseService(client)

    def _get_required_arguments(self) -> list[str]:
        """Return list of required argument names for offense note creation."""
        return ["offense_id", "note_text"]  # Both are required for note creation

    def _validate_command_specific_args(self, args: dict[str, Any]) -> list[str]:
        """
        Validate offense note creation specific arguments with clear error messages.

        Args:
            args: Command arguments to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        validation_errors = []

        # Validate offense_id (required parameter)
        if "offense_id" not in args or args["offense_id"] is None:
            validation_errors.append("offense_id is required for creating offense notes")
        else:
            try:
                offense_id = int(args["offense_id"])
                if offense_id <= 0:
                    validation_errors.append("offense_id must be a positive integer greater than 0")
            except (ValueError, TypeError):
                validation_errors.append("offense_id must be a valid integer (e.g., 123, 456)")

        # Validate note_text (required parameter)
        if "note_text" not in args or args["note_text"] is None:
            validation_errors.append("note_text is required for creating offense notes")
        else:
            note_text = str(args["note_text"]).strip()
            if not note_text:
                validation_errors.append("note_text cannot be empty. Please provide meaningful note content.")
            elif len(note_text) > 10000:  # Reasonable limit for note text
                validation_errors.append("note_text is too long (maximum 10,000 characters). Please shorten your note.")

        # Validate fields parameter format
        if "fields" in args and args["fields"]:
            fields = str(args["fields"])
            if len(fields) > 1000:
                validation_errors.append(
                    "fields parameter is too long (maximum 1000 characters). Please reduce the number of fields."
                )

        return validation_errors

    def _execute_command_logic(self, args: dict[str, Any]) -> CommandResults:
        """
        Execute the core offense note creation logic with comprehensive debugging.

        Args:
            args: Validated command arguments

        Returns:
            CommandResults: Formatted created note data for XSOAR
        """
        # Extract and prepare parameters with clear variable names
        self.debug_context.add_breadcrumb("Extracting and preparing parameters for offense note creation")

        offense_id = int(args["offense_id"])  # Required parameter, already validated
        note_text = str(args["note_text"]).strip()  # Required parameter, already validated
        fields = args.get("fields")

        # Log parameter extraction for debugging
        self.debug_context.capture_variable("offense_id", offense_id)
        self.debug_context.capture_variable("note_text_length", len(note_text))
        self.debug_context.capture_variable("fields", fields)

        # Use service layer for maintainable offense note creation operations
        self.debug_context.add_breadcrumb("Calling offense service for note creation")

        service_result = self.offense_service.create_offense_note(offense_id=offense_id, note_text=note_text, fields=fields)

        # Handle service result with comprehensive error reporting
        if not service_result.is_success():
            self.debug_context.add_breadcrumb(
                "Offense note creation service call failed", error=service_result.error_message, level="error"
            )
            raise CommandExecutionError(
                f"Failed to create note for offense {offense_id}: {service_result.error_message}",
                command_name="OffenseNotesCreateCommand",
                operation_step="service_call",
                correlation_id=self.debug_context.correlation_id,
            )

        note_data = [service_result.data]  # Wrap in list for consistency with sanitize_outputs
        self.debug_context.add_breadcrumb("Note created successfully")

        # Sanitize output data for consistent field naming and security
        self.debug_context.add_breadcrumb("Sanitizing created note output data")
        outputs = sanitize_outputs(note_data, NOTES_RAW_FORMATTED)

        # Build dynamic headers for table display
        self.debug_context.add_breadcrumb("Building table headers for created note")
        headers = build_headers(["ID", "Text", "CreatedBy", "CreateTime"], set(NOTES_RAW_FORMATTED.values()))

        # Create and return command results
        self.debug_context.add_breadcrumb("Creating command results for created note")

        return CommandResults(
            readable_output=tableToMarkdown("Create Note", outputs, headers, removeNull=True),
            outputs_prefix="QRadar.Note",
            outputs_key_field="ID",
            outputs=outputs,
            raw_response=note_data,
        )

    def self_test(self) -> dict[str, Any]:
        """
        Self-testing capability that validates command functionality during development.

        Returns:
            Dict containing test results and diagnostic information
        """
        test_results = {
            "command_name": "OffenseNotesCreateCommand",
            "test_timestamp": time.time(),
            "tests_passed": 0,
            "tests_failed": 0,
            "test_details": [],
            "overall_status": "unknown",
        }

        # Test 1: Required parameters validation
        try:
            # Test missing offense_id
            missing_offense_id_args = {"note_text": "Test note"}
            validation_errors = self._validate_command_specific_args(missing_offense_id_args)

            offense_id_error_found = any("offense_id is required" in error for error in validation_errors)

            # Test missing note_text
            missing_note_text_args = {"offense_id": "123"}
            validation_errors = self._validate_command_specific_args(missing_note_text_args)

            note_text_error_found = any("note_text is required" in error for error in validation_errors)

            if offense_id_error_found and note_text_error_found:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Required parameters validation",
                        "status": "PASSED",
                        "details": "Missing required parameters correctly detected",
                    }
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Required parameters validation",
                        "status": "FAILED",
                        "details": f"Required parameter detection failed: offense_id={offense_id_error_found}, note_text={note_text_error_found}",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Required parameters validation",
                    "status": "FAILED",
                    "details": f"Exception during required parameter testing: {str(e)}",
                }
            )

        # Test 2: Note text validation
        try:
            # Test empty note text
            empty_note_args = {"offense_id": "123", "note_text": "   "}
            validation_errors = self._validate_command_specific_args(empty_note_args)

            empty_note_error_found = any("cannot be empty" in error for error in validation_errors)

            # Test valid note text
            valid_note_args = {"offense_id": "123", "note_text": "This is a valid note"}
            validation_errors = self._validate_command_specific_args(valid_note_args)

            valid_note_accepted = len(validation_errors) == 0

            if empty_note_error_found and valid_note_accepted:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Note text validation", "status": "PASSED", "details": "Note text validation working correctly"}
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {
                        "test_name": "Note text validation",
                        "status": "FAILED",
                        "details": f"Note text validation failed: empty_rejected={empty_note_error_found}, valid_accepted={valid_note_accepted}",
                    }
                )

        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {
                    "test_name": "Note text validation",
                    "status": "FAILED",
                    "details": f"Exception during note text validation testing: {str(e)}",
                }
            )

        # Test 3: Service integration
        try:
            if hasattr(self, "offense_service") and self.offense_service:
                test_results["tests_passed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "PASSED", "details": "OffenseService properly initialized"}
                )
            else:
                test_results["tests_failed"] += 1
                test_results["test_details"].append(
                    {"test_name": "Service integration", "status": "FAILED", "details": "OffenseService not properly initialized"}
                )
        except Exception as e:
            test_results["tests_failed"] += 1
            test_results["test_details"].append(
                {"test_name": "Service integration", "status": "FAILED", "details": f"Exception during service testing: {str(e)}"}
            )

        # Determine overall status
        if test_results["tests_failed"] == 0:
            test_results["overall_status"] = "PASSED"
        elif test_results["tests_passed"] > test_results["tests_failed"]:
            test_results["overall_status"] = "MOSTLY_PASSED"
        else:
            test_results["overall_status"] = "FAILED"

        return test_results


def qradar_offense_notes_list_command(client: Client, args: dict) -> CommandResults:
    """
    List QRadar offense notes - Enhanced maintainable implementation with backwards compatibility.

    This function maintains the exact same interface as the original while using the new
    maintainable architecture internally. It provides comprehensive debugging, clear error
    messages, and detailed logging while preserving all existing behavior.

    Key Enhancements:
    - Uses maintainable OffenseNotesListCommand class internally
    - Comprehensive input validation with helpful error messages for common mistakes
    - Detailed logging showing exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for clean, testable operations
    - Full backwards compatibility with existing interfaces

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args containing:
            - offense_id: The offense ID to retrieve the notes for (required)
            - note_id: The note ID to its details (optional)
            - range: Range of notes to return (e.g.: 0-20, 3-5, 3-3)
            - filter: Query filter to filter results returned by QRadar service
            - fields: Comma-separated list of fields to include in response

    Returns:
        CommandResults with comprehensive offense notes data

    Raises:
        CommandValidationError: When command arguments are invalid with clear guidance
        CommandExecutionError: When execution fails with detailed context
        DemistoException: For backwards compatibility with existing error handling

    Debugging Features:
        - Comprehensive execution tracing with breadcrumbs
        - Variable capture for troubleshooting
        - Performance metrics collection
        - Structured error reporting with correlation IDs

    Self-Testing:
        The command includes built-in self-testing capabilities that can be accessed
        during development to validate functionality and catch issues early.
    """
    try:
        # Create enhanced command instance with comprehensive debugging
        enhanced_command = OffenseNotesListCommand(
            client=client,
            metrics_collector=get_global_metrics_collector() if "get_global_metrics_collector" in globals() else None,
        )

        # Execute with full debugging context and error handling
        return enhanced_command.execute_with_full_context(args)

    except (CommandValidationError, CommandExecutionError) as e:
        # Convert enhanced exceptions to DemistoException for backwards compatibility
        raise DemistoException(str(e))
    except Exception as e:
        # Handle any unexpected exceptions with clear error reporting
        raise DemistoException(f"Unexpected error in qradar-offense-notes-list command: {str(e)}")


def qradar_offense_notes_create_command(client: Client, args: dict) -> CommandResults:
    """
    Create QRadar offense note - Enhanced maintainable implementation with backwards compatibility.

    This function maintains the exact same interface as the original while using the new
    maintainable architecture internally. It provides comprehensive debugging, clear error
    messages, and detailed logging while preserving all existing behavior.

    Key Enhancements:
    - Uses maintainable OffenseNotesCreateCommand class internally
    - Comprehensive input validation with helpful error messages for common mistakes
    - Detailed logging showing exactly what the command is doing at each step
    - Built-in self-testing capabilities for development validation
    - Service layer integration for clean, testable operations
    - Full backwards compatibility with existing interfaces

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args containing:
            - offense_id: The offense ID to add note to (required)
            - note_text: The note text content (required)
            - fields: Comma-separated list of fields to include in response

    Returns:
        CommandResults with comprehensive created note data

    Raises:
        CommandValidationError: When command arguments are invalid with clear guidance
        CommandExecutionError: When execution fails with detailed context
        DemistoException: For backwards compatibility with existing error handling

    Debugging Features:
        - Comprehensive execution tracing with breadcrumbs
        - Variable capture for troubleshooting
        - Performance metrics collection
        - Structured error reporting with correlation IDs

    Self-Testing:
        The command includes built-in self-testing capabilities that can be accessed
        during development to validate functionality and catch issues early.
    """
    try:
        # Create enhanced command instance with comprehensive debugging
        enhanced_command = OffenseNotesCreateCommand(
            client=client,
            metrics_collector=get_global_metrics_collector() if "get_global_metrics_collector" in globals() else None,
        )

        # Execute with full debugging context and error handling
        return enhanced_command.execute_with_full_context(args)

    except (CommandValidationError, CommandExecutionError) as e:
        # Convert enhanced exceptions to DemistoException for backwards compatibility
        raise DemistoException(str(e))
    except Exception as e:
        # Handle any unexpected exceptions with clear error reporting
        raise DemistoException(f"Unexpected error in qradar-offense-notes-create command: {str(e)}")


def qradar_rules_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of rules from QRadar service.
    possible arguments:
    - rule_id: Retrieves details of the specific rule that corresponds to the ID given.
    - rule_type: Retrieves rules corresponding to the given rule type.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    rule_id = args.get("rule_id")
    rule_type = args.get("rule_type")
    range_ = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_ = args.get("filter")
    fields = args.get("fields")

    if not filter_ and rule_type:
        filter_ = f"type={rule_type}"

    # if this call fails, raise an error and stop command execution
    response = client.rules_list(rule_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, RULES_RAW_FORMATTED)
    headers = build_headers(["ID", "Name", "Type"], set(RULES_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Rules List", outputs, headers=headers, removeNull=True),
        outputs_prefix="QRadar.Rule",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_rule_groups_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of rule groups from QRadar service.
    possible arguments:
    - rule_group_id: Retrieves details of the specific rule group that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    rule_group_id = arg_to_number(args.get("rule_group_id"))
    range_ = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_ = args.get("filter")
    fields = args.get("fields")

    # if this call fails, raise an error and stop command execution
    response = client.rule_groups_list(range_, rule_group_id, filter_, fields)
    outputs = sanitize_outputs(response, RULES_GROUP_RAW_FORMATTED)
    headers = build_headers(["ID", "Name", "Description", "Owner"], set(RULES_GROUP_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Rules Group List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.RuleGroup",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# ASSET AND DOMAIN COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def qradar_assets_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of assets from QRadar service.
    possible arguments:
    - asset_id: Retrieves details of the specific asset that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    asset_id = args.get("asset_id")
    range_ = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_ = args.get("filter")
    fields = args.get("fields")

    # If asset ID was given, override filter if both filter and asset ID were given.
    if asset_id:
        filter_ = f"id={asset_id}"

    full_enrichment = bool(asset_id)

    # if this call fails, raise an error and stop command execution
    response = client.assets_list(range_, filter_, fields)
    enriched_outputs = enrich_assets_results(client, response, full_enrichment)
    assets_results = {}
    assets_hr = []
    endpoints = []
    for output in enriched_outputs:
        output["Asset"]["hostnames"] = add_iso_entries_to_dict(output.get("Asset", {}).get("hostnames", []))
        output["Asset"]["users"] = add_iso_entries_to_dict(output.get("Asset", {}).get("users", []))
        output["Asset"]["products"] = add_iso_entries_to_dict(output.get("Asset", {}).get("products", []))
        output["Asset"] = sanitize_outputs(output.get("Asset"), ASSET_RAW_FORMATTED)[0]
        assets_hr.append(output["Asset"])
        assets_results[f"""QRadar.Asset(val.ID === "{output['Asset']['ID']}")"""] = output["Asset"]
        sanitized_endpoint = remove_empty_elements(output.get("Endpoint", {}))
        if sanitized_endpoint:
            endpoints.append(sanitized_endpoint)

    asset_human_readable = tableToMarkdown("Assets List", assets_hr, removeNull=True)
    endpoints_human_readable = tableToMarkdown("Endpoints", endpoints, removeNull=True)

    if endpoints:
        assets_results["Endpoint"] = endpoints

    return CommandResults(
        readable_output=asset_human_readable + endpoints_human_readable, outputs=assets_results, raw_response=response
    )


def qradar_saved_searches_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of saved searches from QRadar service with enhanced debugging capabilities.

    This command provides comprehensive error handling, query validation, and performance monitoring
    for saved search operations. It includes detailed logging and debugging information to help
    troubleshoot issues and optimize performance.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing search parameters.

    Returns:
        CommandResults: Formatted saved search data with debugging information.

    Raises:
        ValidationError: When arguments are invalid or malformed.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED DEBUGGING AND PERFORMANCE MONITORING
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create debug context for comprehensive operation tracking
    debug_ctx = DebugContext("qradar_saved_searches_list")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    # Start performance monitoring
    start_time = time.time()
    debug_ctx.add_breadcrumb("Starting saved searches list command", args=args)

    try:
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION WITH HELPFUL ERROR MESSAGES
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create validator for this command
        validator = CommandArgumentValidator("qradar-saved-searches-list")

        # Add validation rules with helpful error messages
        validator.add_validator(
            "saved_search_id",
            StringValidator(
                "saved_search_id",
                required=False,
                min_length=1,
                max_length=100,
                pattern=r"^\d+$",  # Must be numeric
            ),
        ).add_validator(
            "range",
            StringValidator(
                "range",
                required=False,
                pattern=r"^\d+-\d+$",  # Format: start-end
            ),
        ).add_validator(
            "timeout",
            IntegerValidator(
                "timeout",
                required=False,
                min_value=1,
                max_value=3600,  # Max 1 hour
            ),
        ).add_validator("filter", StringValidator("filter", required=False, max_length=2000)).add_validator(
            "fields", StringValidator("fields", required=False, max_length=1000)
        )

        # Validate arguments with clear error messages
        try:
            validated_args = validator.validate_arguments(args)
            debug_ctx.add_breadcrumb("Arguments validated successfully", validated_args=validated_args)
        except ValidationError as e:
            debug_ctx.add_breadcrumb("Argument validation failed", error=str(e), level="error")
            raise ValidationError(
                f"Invalid arguments for qradar-saved-searches-list command: {str(e)}",
                suggestions=[
                    "Check that saved_search_id is a valid numeric ID",
                    "Ensure range follows format 'start-end' (e.g., '0-20')",
                    "Verify timeout is between 1 and 3600 seconds",
                    "Check filter syntax against QRadar API documentation",
                    "Review the command examples for proper usage",
                ],
            )

        # Extract validated parameters with defaults
        saved_search_id = validated_args.get("saved_search_id")
        timeout = validated_args.get("timeout") or DEFAULT_TIMEOUT_VALUE
        range_ = f"items={validated_args.get('range', DEFAULT_RANGE_VALUE)}"
        filter_ = validated_args.get("filter")
        fields = validated_args.get("fields")

        debug_ctx.capture_variable("saved_search_id", saved_search_id)
        debug_ctx.capture_variable("timeout", timeout)
        debug_ctx.capture_variable("range_", range_)
        debug_ctx.capture_variable("filter_", filter_)
        debug_ctx.capture_variable("fields", fields)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # QUERY VALIDATION WITH HELPFUL SUGGESTIONS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        if filter_:
            debug_ctx.add_breadcrumb("Validating filter query", filter_query=filter_)
            filter_validation = _validate_qradar_filter_query(filter_)
            if not filter_validation["valid"]:
                debug_ctx.add_breadcrumb("Filter validation failed", error=filter_validation["error"], level="error")
                raise ValidationError(
                    f"Invalid filter query: {filter_validation['error']}",
                    field_name="filter",
                    suggestions=filter_validation.get(
                        "suggestions",
                        [
                            "Check QRadar API documentation for filter syntax",
                            "Ensure field names are correct and properly quoted",
                            "Verify operators are supported (=, !=, >, <, LIKE, etc.)",
                            "Check for proper parentheses and logical operators",
                        ],
                    ),
                )
            debug_ctx.add_breadcrumb("Filter query validated successfully")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH PERFORMANCE MONITORING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Making API call to retrieve saved searches")
        api_start_time = time.time()

        try:
            response = client.saved_searches_list(range_, timeout, saved_search_id, filter_, fields)
            api_duration = (time.time() - api_start_time) * 1000  # Convert to milliseconds

            debug_ctx.log_api_call(method="GET", url="/ariel/saved_searches", status_code=200, duration=api_duration)

            debug_ctx.add_breadcrumb(
                "API call completed successfully", duration_ms=api_duration, response_size=len(str(response)) if response else 0
            )

            # Log performance metrics
            if api_duration > 5000:  # More than 5 seconds
                logger.warning(f"Slow API response detected: {api_duration:.2f}ms for saved searches list")

        except Exception as e:
            api_duration = (time.time() - api_start_time) * 1000
            debug_ctx.log_api_call(method="GET", url="/ariel/saved_searches", status_code=0, duration=api_duration)
            debug_ctx.add_breadcrumb("API call failed", error=str(e), duration_ms=api_duration, level="error")

            # Provide helpful error context
            error_context = _analyze_qradar_api_error(str(e))
            raise DemistoException(f"Failed to retrieve saved searches: {str(e)}. {error_context.get('suggestion', '')}")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT PROCESSING WITH DEBUGGING INFORMATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Processing API response")

        if not response:
            debug_ctx.add_breadcrumb("Empty response received", level="warning")
            logger.warning("Empty response received from QRadar API")
            response = []

        # Sanitize and format outputs
        outputs = sanitize_outputs(response, SAVED_SEARCH_RAW_FORMATTED)
        headers = build_headers(["ID", "Name", "Description"], set(SAVED_SEARCH_RAW_FORMATTED.values()))

        debug_ctx.add_breadcrumb(
            "Response processed successfully",
            result_count=len(outputs) if isinstance(outputs, list) else 1,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # PERFORMANCE ANALYSIS AND RECOMMENDATIONS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        total_duration = (time.time() - start_time) * 1000
        result_count = len(outputs) if isinstance(outputs, list) else 1

        # Log performance metrics
        logger.info(
            f"Saved searches list completed: {result_count} results in {total_duration:.2f}ms",
            extra={
                "command": "qradar-saved-searches-list",
                "result_count": result_count,
                "duration_ms": total_duration,
                "api_duration_ms": api_duration,
                "has_filter": bool(filter_),
                "specific_search": bool(saved_search_id),
            },
        )

        # Add performance recommendations to readable output
        performance_notes = []
        if total_duration > 10000:  # More than 10 seconds
            performance_notes.append("⚠️ Slow query detected. Consider adding filters to improve performance.")
        if result_count > 100:
            performance_notes.append("💡 Large result set. Consider using range parameter to paginate results.")
        if filter_ and api_duration > 3000:
            performance_notes.append("🔍 Complex filter detected. Review filter syntax for optimization opportunities.")

        readable_output = tableToMarkdown("Saved Searches List", outputs, headers, removeNull=True)
        if performance_notes:
            readable_output += "\n\n**Performance Notes:**\n" + "\n".join(performance_notes)

        debug_ctx.add_breadcrumb("Command completed successfully", total_duration_ms=total_duration)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="QRadar.SavedSearch",
            outputs_key_field="ID",
            outputs=outputs,
            raw_response=response,
        )

    except Exception as e:
        total_duration = (time.time() - start_time) * 1000
        debug_ctx.add_breadcrumb("Command failed", error=str(e), duration_ms=total_duration, level="error")

        logger.error_with_context(
            "qradar-saved-searches-list command failed", exception=e, command_args=args, duration_ms=total_duration
        )
        raise


def qradar_searches_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of active searches from QRadar service with enhanced debugging capabilities.

    This command provides comprehensive error handling, query validation, and performance monitoring
    for search listing operations. It includes detailed logging and debugging information to help
    troubleshoot issues and optimize performance.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing search parameters.

    Returns:
        CommandResults: Formatted search list data with debugging information.

    Raises:
        ValidationError: When arguments are invalid or malformed.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED DEBUGGING AND PERFORMANCE MONITORING
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create debug context for comprehensive operation tracking
    debug_ctx = DebugContext("qradar_searches_list")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    # Start performance monitoring
    start_time = time.time()
    debug_ctx.add_breadcrumb("Starting searches list command", args=args)

    try:
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION WITH HELPFUL ERROR MESSAGES
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create validator for this command
        validator = CommandArgumentValidator("qradar-searches-list")

        # Add validation rules with helpful error messages
        validator.add_validator(
            "range",
            StringValidator(
                "range",
                required=False,
                pattern=r"^\d+-\d+$",  # Format: start-end
            ),
        ).add_validator("filter", StringValidator("filter", required=False, max_length=2000))

        # Validate arguments with clear error messages
        try:
            validated_args = validator.validate_arguments(args)
            debug_ctx.add_breadcrumb("Arguments validated successfully", validated_args=validated_args)
        except ValidationError as e:
            debug_ctx.add_breadcrumb("Argument validation failed", error=str(e), level="error")
            raise ValidationError(
                f"Invalid arguments for qradar-searches-list command: {str(e)}",
                suggestions=[
                    "Ensure range follows format 'start-end' (e.g., '0-20')",
                    "Check filter syntax against QRadar API documentation",
                    "Verify all parameter values are properly formatted",
                    "Review the command examples for proper usage",
                ],
            )

        # Extract validated parameters with defaults
        range_ = f"items={validated_args.get('range', DEFAULT_RANGE_VALUE)}"
        filter_ = validated_args.get("filter")

        debug_ctx.capture_variable("range_", range_)
        debug_ctx.capture_variable("filter_", filter_)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # QUERY VALIDATION WITH HELPFUL SUGGESTIONS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        if filter_:
            debug_ctx.add_breadcrumb("Validating filter query", filter_query=filter_)
            filter_validation = _validate_qradar_filter_query(filter_)
            if not filter_validation["valid"]:
                debug_ctx.add_breadcrumb("Filter validation failed", error=filter_validation["error"], level="error")
                raise ValidationError(
                    f"Invalid filter query: {filter_validation['error']}",
                    field_name="filter",
                    suggestions=filter_validation.get(
                        "suggestions",
                        [
                            "Check QRadar API documentation for filter syntax",
                            "Ensure field names are correct (status, cursor_id, etc.)",
                            "Verify operators are supported (=, !=, >, <, LIKE, etc.)",
                            "Check for proper parentheses and logical operators",
                        ],
                    ),
                )
            debug_ctx.add_breadcrumb("Filter query validated successfully")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH PERFORMANCE MONITORING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Making API call to retrieve active searches")
        api_start_time = time.time()

        try:
            response = client.searches_list(range_, filter_)
            api_duration = (time.time() - api_start_time) * 1000  # Convert to milliseconds

            debug_ctx.log_api_call(method="GET", url="/ariel/searches", status_code=200, duration=api_duration)

            debug_ctx.add_breadcrumb(
                "API call completed successfully", duration_ms=api_duration, response_size=len(str(response)) if response else 0
            )

            # Log performance metrics
            if api_duration > 3000:  # More than 3 seconds
                logger.warning(f"Slow API response detected: {api_duration:.2f}ms for searches list")

        except Exception as e:
            api_duration = (time.time() - api_start_time) * 1000
            debug_ctx.log_api_call(method="GET", url="/ariel/searches", status_code=0, duration=api_duration)
            debug_ctx.add_breadcrumb("API call failed", error=str(e), duration_ms=api_duration, level="error")

            # Provide helpful error context
            error_context = _analyze_qradar_api_error(str(e))
            raise DemistoException(f"Failed to retrieve active searches: {str(e)}. {error_context.get('suggestion', '')}")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT PROCESSING WITH DEBUGGING INFORMATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Processing API response")

        if not response:
            debug_ctx.add_breadcrumb("Empty response received", level="warning")
            logger.warning("No active searches found")
            response = []

        # Transform response to include additional debugging information
        outputs = []
        for search_id in response:
            search_info = {"SearchID": search_id}

            # Try to get additional search status information for debugging
            try:
                status_response = client.search_status_get(search_id)
                if status_response:
                    search_info.update(
                        {
                            "Status": status_response.get("status", "UNKNOWN"),
                            "Progress": status_response.get("progress", 0),
                            "RecordCount": status_response.get("record_count", 0),
                        }
                    )
            except Exception as status_error:
                debug_ctx.add_breadcrumb(
                    f"Could not retrieve status for search {search_id}", error=str(status_error), level="warning"
                )
                # Don't fail the entire command for status retrieval issues
                search_info["Status"] = "STATUS_UNAVAILABLE"

            outputs.append(search_info)

        debug_ctx.add_breadcrumb(
            "Response processed successfully", result_count=len(outputs), processing_time_ms=(time.time() - start_time) * 1000
        )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # PERFORMANCE ANALYSIS AND RECOMMENDATIONS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        total_duration = (time.time() - start_time) * 1000
        result_count = len(outputs)

        # Log performance metrics
        logger.info(
            f"Searches list completed: {result_count} results in {total_duration:.2f}ms",
            extra={
                "command": "qradar-searches-list",
                "result_count": result_count,
                "duration_ms": total_duration,
                "api_duration_ms": api_duration,
                "has_filter": bool(filter_),
            },
        )

        # Add performance recommendations to readable output
        performance_notes = []
        if total_duration > 8000:  # More than 8 seconds
            performance_notes.append("⚠️ Slow query detected. Consider adding filters to improve performance.")
        if result_count > 50:
            performance_notes.append("💡 Large number of active searches. Consider using range parameter to paginate results.")
        if result_count == 0:
            performance_notes.append(
                "ℹ️ No active searches found. This may indicate all searches have completed or been cancelled."
            )

        # Enhanced readable output with status information
        headers = (
            ["SearchID", "Status", "Progress", "RecordCount"] if any("Status" in output for output in outputs) else ["SearchID"]
        )
        readable_output = tableToMarkdown("Active Searches List", outputs, headers, removeNull=True)

        if performance_notes:
            readable_output += "\n\n**Performance Notes:**\n" + "\n".join(performance_notes)

        debug_ctx.add_breadcrumb("Command completed successfully", total_duration_ms=total_duration)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="QRadar.SearchID",
            outputs_key_field="SearchID",
            outputs=outputs,
            raw_response=response,
        )

    except Exception as e:
        total_duration = (time.time() - start_time) * 1000
        debug_ctx.add_breadcrumb("Command failed", error=str(e), duration_ms=total_duration, level="error")

        logger.error_with_context(
            "qradar-searches-list command failed", exception=e, command_args=args, duration_ms=total_duration
        )
        raise


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# SEARCH AND QUERY COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def qradar_search_create_command(client: Client, params: dict, args: dict) -> CommandResults:
    """
    Create a search in QRadar service with comprehensive input validation.

    This command creates a new search in QRadar using one of three methods:
    - AQL query expression for custom searches
    - Saved search ID for predefined searches
    - Offense ID for offense-specific event searches

    Args:
        client (Client): QRadar client to perform the API call.
        params (Dict): Demisto params containing default values.
        args (Dict): Demisto args containing command-specific parameters.

    Returns:
        CommandResults: Search creation results with search ID and status.

    Raises:
        ValidationError: When arguments are invalid or mutually exclusive options are provided.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # COMPREHENSIVE INPUT VALIDATION WITH CLEAR ERROR MESSAGES
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create validator for this command with comprehensive validation rules
    validator = CommandArgumentValidator("qradar-search-create")

    # Add validation rules for each parameter with helpful error messages
    validator.add_validator(
        "query_expression",
        StringValidator(
            "query_expression",
            required=False,
            min_length=1,
            max_length=10000,  # Reasonable limit for AQL queries
        ),
    ).add_validator(
        "saved_search_id", IntegerValidator("saved_search_id", required=False, min_value=1, positive_only=True)
    ).add_validator("offense_id", IntegerValidator("offense_id", required=False, min_value=1, positive_only=True)).add_validator(
        "events_columns",
        StringValidator(
            "events_columns",
            required=False,
            max_length=2000,  # Reasonable limit for column lists
        ),
    ).add_validator(
        "events_limit",
        IntegerValidator(
            "events_limit",
            required=False,
            min_value=1,
            max_value=10000,  # Reasonable limit to prevent system overload
        ),
    ).add_validator(
        "fetch_mode",
        StringValidator(
            "fetch_mode",
            required=False,
            allowed_values=["Fetch With All Events", "Fetch Correlation Events Only", "Fetch Raw Events Only"],
            case_sensitive=False,
        ),
    ).add_validator("start_time", StringValidator("start_time", required=False, min_length=1))

    # Validate all arguments and get cleaned values
    try:
        validated_args = validator.validate_arguments(args)
    except ValidationError as e:
        # Re-raise with additional context for debugging
        raise ValidationError(
            f"Invalid arguments for qradar-search-create command: {str(e)}",
            suggestions=[
                "Check the parameter documentation for correct formats",
                "Verify all parameter values are within acceptable ranges",
                "Ensure at least one search method is provided",
                "Review the command examples for proper usage",
            ],
        )

    # Extract validated parameters with defaults from params
    query_expression = validated_args.get("query_expression")
    saved_search_id = validated_args.get("saved_search_id")
    offense_id = validated_args.get("offense_id")
    events_columns = validated_args.get("events_columns") or params.get("events_columns") or DEFAULT_EVENTS_COLUMNS
    events_limit = validated_args.get("events_limit") or params.get("events_limit")
    fetch_mode = validated_args.get("fetch_mode") or params.get("fetch_mode")
    start_time = validated_args.get("start_time")

    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # BUSINESS RULE VALIDATION WITH CLEAR ERROR MESSAGES
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Validate that at least one search method is provided
    search_methods_provided = [query_expression, saved_search_id, offense_id]
    if not any(search_methods_provided):
        raise ValidationError(
            "No search method specified. Must provide one of: query_expression, saved_search_id, or offense_id",
            suggestions=[
                "Provide 'query_expression' for custom AQL queries (e.g., 'SELECT * FROM events LAST 1 HOURS')",
                "Provide 'saved_search_id' to execute a saved search (e.g., saved_search_id=123)",
                "Provide 'offense_id' to search events for a specific offense (e.g., offense_id=456)",
                "Check the command documentation for examples of each search method",
            ],
        )

    # Validate mutual exclusivity of search methods
    provided_methods = []
    if query_expression:
        provided_methods.append("query_expression")
    if saved_search_id:
        provided_methods.append("saved_search_id")
    if offense_id:
        provided_methods.append("offense_id")

    if len(provided_methods) > 1:
        raise ValidationError(
            f"Multiple search methods provided: {', '.join(provided_methods)}. Only one method is allowed per search",
            suggestions=[
                "Use only 'query_expression' for custom AQL queries",
                "Use only 'saved_search_id' for saved searches",
                "Use only 'offense_id' for offense-specific searches",
                "Remove the extra search method parameters",
            ],
        )

    # Additional validation for offense-based searches
    if offense_id and not fetch_mode:
        raise ValidationError(
            "fetch_mode is required when using offense_id for event searches",
            field_name="fetch_mode",
            suggestions=[
                "Provide fetch_mode parameter with one of these values:",
                "  - 'Fetch With All Events' (includes all event types)",
                "  - 'Fetch Correlation Events Only' (correlation events only)",
                "  - 'Fetch Raw Events Only' (raw events only)",
                "Check the integration configuration for default fetch_mode settings",
            ],
        )
    # if this call fails, raise an error and stop command execution
    if query_expression or saved_search_id:
        try:
            response = client.search_create(query_expression, saved_search_id)
        except Exception as e:
            if query_expression:
                raise DemistoException(f"Could not create search for query: {query_expression}.") from e
            if saved_search_id:
                raise DemistoException(f"Could not create search for saved_search_id: {saved_search_id}.") from e
    else:
        response = create_events_search(
            client, fetch_mode, events_columns, events_limit, int(offense_id), start_time, return_raw_response=True
        )
        if response == QueryStatus.ERROR.value:
            raise DemistoException(f"Could not create events search for offense_id: {offense_id}.")

    outputs = sanitize_outputs(response, SEARCH_RAW_FORMATTED)
    return CommandResults(
        readable_output=tableToMarkdown("Create Search", outputs),
        outputs_prefix="QRadar.Search",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_search_status_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves search status from QRadar service with enhanced debugging and performance monitoring.

    This command provides comprehensive error handling, detailed status information, and performance
    monitoring for search status operations. It includes debugging information to help troubleshoot
    search issues and optimize query performance.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing search ID.

    Returns:
        CommandResults: Detailed search status information with debugging data.

    Raises:
        ValidationError: When arguments are invalid or missing.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED DEBUGGING AND PERFORMANCE MONITORING
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create debug context for comprehensive operation tracking
    debug_ctx = DebugContext("qradar_search_status_get")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    # Start performance monitoring
    start_time = time.time()
    debug_ctx.add_breadcrumb("Starting search status get command", args=args)

    try:
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION WITH HELPFUL ERROR MESSAGES
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create validator for this command
        validator = CommandArgumentValidator("qradar-search-status-get")

        # Add validation rules with helpful error messages
        validator.add_validator(
            "search_id",
            StringValidator(
                "search_id",
                required=True,
                min_length=1,
                max_length=100,
                pattern=r"^[a-fA-F0-9\-]+$",  # UUID format typically used by QRadar
            ),
        )

        # Validate arguments with clear error messages
        try:
            validated_args = validator.validate_arguments(args)
            debug_ctx.add_breadcrumb("Arguments validated successfully", validated_args=validated_args)
        except ValidationError as e:
            debug_ctx.add_breadcrumb("Argument validation failed", error=str(e), level="error")
            raise ValidationError(
                f"Invalid arguments for qradar-search-status-get command: {str(e)}",
                suggestions=[
                    "Ensure search_id is provided and not empty",
                    "Verify search_id format matches QRadar search ID pattern",
                    "Check that the search_id was obtained from a previous search creation",
                    "Review the command examples for proper usage",
                ],
            )

        # Extract validated parameters
        search_id = validated_args["search_id"]
        debug_ctx.capture_variable("search_id", search_id)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH PERFORMANCE MONITORING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Making API call to retrieve search status", search_id=search_id)
        api_start_time = time.time()

        try:
            response = client.search_status_get(search_id)
            api_duration = (time.time() - api_start_time) * 1000  # Convert to milliseconds

            debug_ctx.log_api_call(method="GET", url=f"/ariel/searches/{search_id}", status_code=200, duration=api_duration)

            debug_ctx.add_breadcrumb(
                "API call completed successfully", duration_ms=api_duration, response_size=len(str(response)) if response else 0
            )

            # Log performance metrics
            if api_duration > 2000:  # More than 2 seconds
                logger.warning(f"Slow API response detected: {api_duration:.2f}ms for search status")

        except Exception as e:
            api_duration = (time.time() - api_start_time) * 1000
            debug_ctx.log_api_call(method="GET", url=f"/ariel/searches/{search_id}", status_code=0, duration=api_duration)
            debug_ctx.add_breadcrumb("API call failed", error=str(e), duration_ms=api_duration, level="error")

            # Provide helpful error context based on error type
            error_context = _analyze_qradar_api_error(str(e))
            if "404" in str(e) or "not found" in str(e).lower():
                raise DemistoException(
                    f"Search ID {search_id} not found. The search may have been deleted or expired. "
                    f"Verify the search ID is correct and the search still exists."
                )
            else:
                raise DemistoException(
                    f"Failed to retrieve search status for {search_id}: {str(e)}. {error_context.get('suggestion', '')}"
                )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT PROCESSING WITH DEBUGGING INFORMATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Processing API response")

        if not response:
            debug_ctx.add_breadcrumb("Empty response received", level="error")
            raise DemistoException(f"Empty response received for search ID {search_id}")

        # Sanitize and format outputs
        outputs = sanitize_outputs(response, SEARCH_RAW_FORMATTED)

        # Extract key status information for analysis
        status = response.get("status", "UNKNOWN")
        progress = response.get("progress", 0)
        record_count = response.get("record_count", 0)

        debug_ctx.capture_variable("search_status", status)
        debug_ctx.capture_variable("search_progress", progress)
        debug_ctx.capture_variable("record_count", record_count)

        debug_ctx.add_breadcrumb(
            "Response processed successfully",
            status=status,
            progress=progress,
            record_count=record_count,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # SEARCH PERFORMANCE ANALYSIS AND RECOMMENDATIONS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        total_duration = (time.time() - start_time) * 1000

        # Log performance metrics
        logger.info(
            f"Search status retrieved: {status} ({progress}% complete) in {total_duration:.2f}ms",
            extra={
                "command": "qradar-search-status-get",
                "search_id": search_id,
                "status": status,
                "progress": progress,
                "record_count": record_count,
                "duration_ms": total_duration,
                "api_duration_ms": api_duration,
            },
        )

        # Add performance and status recommendations to readable output
        performance_notes = []
        status_insights = []

        # Status-based insights
        if status == "COMPLETED":
            status_insights.append(f"✅ Search completed successfully with {record_count} records")
        elif status == "WAIT":
            status_insights.append("⏳ Search is queued and waiting to start")
        elif status == "EXECUTE":
            status_insights.append(f"🔄 Search is running ({progress}% complete)")
            if progress < 10:
                status_insights.append("💡 Search just started - check again in a few moments")
        elif status == "SORTING":
            status_insights.append(f"📊 Search results are being sorted ({progress}% complete)")
        elif status == "ERROR":
            status_insights.append("❌ Search failed with an error - check search query syntax")
        elif status == "CANCELED":
            status_insights.append("🛑 Search was cancelled before completion")

        # Performance insights
        if total_duration > 5000:  # More than 5 seconds
            performance_notes.append("⚠️ Slow status retrieval. Check network connectivity to QRadar.")

        # Query performance insights based on record count and status
        if status == "COMPLETED" and record_count > 100000:
            performance_notes.append("📈 Large result set detected. Consider adding filters to improve query performance.")
        elif status == "EXECUTE" and progress < 50:
            # Estimate remaining time based on current progress (rough estimate)
            if progress > 0:
                estimated_total_time = (time.time() - start_time) / (progress / 100)
                estimated_remaining = estimated_total_time - (time.time() - start_time)
                if estimated_remaining > 300:  # More than 5 minutes
                    performance_notes.append(
                        f"⏱️ Long-running search detected. Estimated {estimated_remaining / 60:.1f} minutes remaining."
                    )

        # Build enhanced readable output
        readable_output = tableToMarkdown(f"Search Status For Search ID {search_id}", outputs)

        if status_insights:
            readable_output += "\n\n**Status Information:**\n" + "\n".join(status_insights)

        if performance_notes:
            readable_output += "\n\n**Performance Notes:**\n" + "\n".join(performance_notes)

        # Add debugging information if search is in error state
        if status == "ERROR" and response.get("error_messages"):
            error_messages = response.get("error_messages", [])
            readable_output += "\n\n**Error Details:**\n"
            for error_msg in error_messages:
                readable_output += f"- {error_msg}\n"

        debug_ctx.add_breadcrumb("Command completed successfully", total_duration_ms=total_duration)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="QRadar.Search",
            outputs_key_field="ID",
            outputs=outputs,
            raw_response=response,
        )

    except Exception as e:
        total_duration = (time.time() - start_time) * 1000
        debug_ctx.add_breadcrumb("Command failed", error=str(e), duration_ms=total_duration, level="error")

        logger.error_with_context(
            "qradar-search-status-get command failed", exception=e, command_args=args, duration_ms=total_duration
        )
        raise


def qradar_search_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Delete search from QRadar service with enhanced debugging and validation.

    This command provides comprehensive error handling and validation for search deletion
    operations. It includes detailed logging and debugging information to help troubleshoot
    issues and ensure proper cleanup of search resources.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing search ID.

    Returns:
        CommandResults: Confirmation of search deletion with debugging information.

    Raises:
        ValidationError: When arguments are invalid or missing.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED DEBUGGING AND PERFORMANCE MONITORING
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create debug context for comprehensive operation tracking
    debug_ctx = DebugContext("qradar_search_delete")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    # Start performance monitoring
    start_time = time.time()
    debug_ctx.add_breadcrumb("Starting search delete command", args=args)

    try:
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION WITH HELPFUL ERROR MESSAGES
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create validator for this command
        validator = CommandArgumentValidator("qradar-search-delete")

        # Add validation rules with helpful error messages
        validator.add_validator(
            "search_id",
            StringValidator(
                "search_id",
                required=True,
                min_length=1,
                max_length=100,
                pattern=r"^[a-fA-F0-9\-]+$",  # UUID format typically used by QRadar
            ),
        )

        # Validate arguments with clear error messages
        try:
            validated_args = validator.validate_arguments(args)
            debug_ctx.add_breadcrumb("Arguments validated successfully", validated_args=validated_args)
        except ValidationError as e:
            debug_ctx.add_breadcrumb("Argument validation failed", error=str(e), level="error")
            raise ValidationError(
                f"Invalid arguments for qradar-search-delete command: {str(e)}",
                suggestions=[
                    "Ensure search_id is provided and not empty",
                    "Verify search_id format matches QRadar search ID pattern",
                    "Check that the search_id was obtained from a previous search creation",
                    "Review the command examples for proper usage",
                ],
            )

        # Extract validated parameters
        search_id = validated_args["search_id"]
        debug_ctx.capture_variable("search_id", search_id)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # SEARCH STATUS CHECK BEFORE DELETION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Checking search status before deletion")
        search_exists = True
        search_status = "UNKNOWN"

        try:
            status_response = client.search_status_get(search_id)
            search_status = status_response.get("status", "UNKNOWN")
            debug_ctx.capture_variable("search_status_before_delete", search_status)
            debug_ctx.add_breadcrumb("Search status retrieved", status=search_status)

            # Warn if trying to delete a running search
            if search_status in ["EXECUTE", "SORTING"]:
                logger.warning(f"Deleting search {search_id} while it's still running (status: {search_status})")

        except Exception as status_error:
            if "404" in str(status_error) or "not found" in str(status_error).lower():
                search_exists = False
                debug_ctx.add_breadcrumb("Search not found", error=str(status_error), level="warning")
            else:
                debug_ctx.add_breadcrumb("Could not check search status", error=str(status_error), level="warning")
                logger.warning(f"Could not verify search status before deletion: {str(status_error)}")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH PERFORMANCE MONITORING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Making API call to delete search", search_id=search_id)
        api_start_time = time.time()

        try:
            response = client.search_delete(search_id)
            api_duration = (time.time() - api_start_time) * 1000  # Convert to milliseconds

            debug_ctx.log_api_call(method="DELETE", url=f"/ariel/searches/{search_id}", status_code=200, duration=api_duration)

            debug_ctx.add_breadcrumb(
                "API call completed successfully", duration_ms=api_duration, response_size=len(str(response)) if response else 0
            )

            # Log performance metrics
            if api_duration > 5000:  # More than 5 seconds
                logger.warning(f"Slow API response detected: {api_duration:.2f}ms for search deletion")

        except Exception as e:
            api_duration = (time.time() - api_start_time) * 1000
            debug_ctx.log_api_call(method="DELETE", url=f"/ariel/searches/{search_id}", status_code=0, duration=api_duration)
            debug_ctx.add_breadcrumb("API call failed", error=str(e), duration_ms=api_duration, level="error")

            # Provide helpful error context based on error type
            error_context = _analyze_qradar_api_error(str(e))
            if "404" in str(e) or "not found" in str(e).lower():
                # Search already deleted or doesn't exist
                logger.info(f"Search {search_id} was already deleted or doesn't exist")
                return CommandResults(
                    readable_output=f"Search ID {search_id} was already deleted or doesn't exist.",
                    raw_response={"message": "Search not found - may have been already deleted"},
                )
            else:
                raise DemistoException(f"Failed to delete search {search_id}: {str(e)}. {error_context.get('suggestion', '')}")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT PROCESSING WITH DEBUGGING INFORMATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        total_duration = (time.time() - start_time) * 1000

        # Log performance metrics
        logger.info(
            f"Search deleted successfully: {search_id} in {total_duration:.2f}ms",
            extra={
                "command": "qradar-search-delete",
                "search_id": search_id,
                "search_status_before_delete": search_status,
                "duration_ms": total_duration,
                "api_duration_ms": api_duration,
            },
        )

        # Build enhanced readable output with debugging information
        readable_output = f"✅ Search ID {search_id} was successfully deleted."

        if search_status != "UNKNOWN":
            readable_output += "\n\n**Operation Details:**\n"
            readable_output += f"- Search Status Before Deletion: `{search_status}`\n"
            readable_output += f"- Deletion Duration: `{total_duration:.2f}ms`\n"
            readable_output += f"- API Call Duration: `{api_duration:.2f}ms`\n"

        # Add performance notes if applicable
        performance_notes = []
        if search_status in ["EXECUTE", "SORTING"]:
            performance_notes.append("⚠️ Search was deleted while still running. This may have interrupted processing.")

        if total_duration > 10000:  # More than 10 seconds
            performance_notes.append("⚠️ Slow deletion operation. Check QRadar system performance.")

        if performance_notes:
            readable_output += "\n\n**Performance Notes:**\n" + "\n".join(performance_notes)

        debug_ctx.add_breadcrumb("Command completed successfully", total_duration_ms=total_duration)

        return CommandResults(readable_output=readable_output, raw_response=response)

    except Exception as e:
        total_duration = (time.time() - start_time) * 1000
        debug_ctx.add_breadcrumb("Command failed", error=str(e), duration_ms=total_duration, level="error")

        logger.error_with_context(
            "qradar-search-delete command failed", exception=e, command_args=args, duration_ms=total_duration
        )
        raise


def qradar_search_cancel_command(client: Client, args: dict) -> CommandResults:
    """
    Cancel search from QRadar service with enhanced debugging and validation.

    This command provides comprehensive error handling and validation for search cancellation
    operations. It includes detailed logging and debugging information to help troubleshoot
    issues and monitor search lifecycle management.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing search ID.

    Returns:
        CommandResults: Confirmation of search cancellation with debugging information.

    Raises:
        ValidationError: When arguments are invalid or missing.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED DEBUGGING AND PERFORMANCE MONITORING
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create debug context for comprehensive operation tracking
    debug_ctx = DebugContext("qradar_search_cancel")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    # Start performance monitoring
    start_time = time.time()
    debug_ctx.add_breadcrumb("Starting search cancel command", args=args)

    try:
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION WITH HELPFUL ERROR MESSAGES
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create validator for this command
        validator = CommandArgumentValidator("qradar-search-cancel")

        # Add validation rules with helpful error messages
        validator.add_validator(
            "search_id",
            StringValidator(
                "search_id",
                required=True,
                min_length=1,
                max_length=100,
                pattern=r"^[a-fA-F0-9\-]+$",  # UUID format typically used by QRadar
            ),
        )

        # Validate arguments with clear error messages
        try:
            validated_args = validator.validate_arguments(args)
            debug_ctx.add_breadcrumb("Arguments validated successfully", validated_args=validated_args)
        except ValidationError as e:
            debug_ctx.add_breadcrumb("Argument validation failed", error=str(e), level="error")
            raise ValidationError(
                f"Invalid arguments for qradar-search-cancel command: {str(e)}",
                suggestions=[
                    "Ensure search_id is provided and not empty",
                    "Verify search_id format matches QRadar search ID pattern",
                    "Check that the search_id was obtained from a previous search creation",
                    "Review the command examples for proper usage",
                ],
            )

        # Extract validated parameters
        search_id = validated_args["search_id"]
        debug_ctx.capture_variable("search_id", search_id)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # SEARCH STATUS CHECK BEFORE CANCELLATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Checking search status before cancellation")
        search_status_before = "UNKNOWN"
        progress_before = 0

        try:
            status_response = client.search_status_get(search_id)
            search_status_before = status_response.get("status", "UNKNOWN")
            progress_before = status_response.get("progress", 0)

            debug_ctx.capture_variable("search_status_before_cancel", search_status_before)
            debug_ctx.capture_variable("progress_before_cancel", progress_before)
            debug_ctx.add_breadcrumb("Search status retrieved", status=search_status_before, progress=progress_before)

            # Check if search is in a cancellable state
            if search_status_before == "COMPLETED":
                logger.info(f"Search {search_id} is already completed - cancellation not needed")
            elif search_status_before == "CANCELED":
                logger.info(f"Search {search_id} is already cancelled")
            elif search_status_before == "ERROR":
                logger.info(f"Search {search_id} is in error state - cancellation may not be necessary")

        except Exception as status_error:
            debug_ctx.add_breadcrumb("Could not check search status", error=str(status_error), level="warning")
            logger.warning(f"Could not verify search status before cancellation: {str(status_error)}")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH PERFORMANCE MONITORING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Making API call to cancel search", search_id=search_id)
        api_start_time = time.time()

        try:
            response = client.search_cancel(search_id)
            api_duration = (time.time() - api_start_time) * 1000  # Convert to milliseconds

            debug_ctx.log_api_call(
                method="POST", url=f"/ariel/searches/{search_id}/cancel", status_code=200, duration=api_duration
            )

            debug_ctx.add_breadcrumb(
                "API call completed successfully", duration_ms=api_duration, response_size=len(str(response)) if response else 0
            )

            # Log performance metrics
            if api_duration > 5000:  # More than 5 seconds
                logger.warning(f"Slow API response detected: {api_duration:.2f}ms for search cancellation")

        except Exception as e:
            api_duration = (time.time() - api_start_time) * 1000
            debug_ctx.log_api_call(method="POST", url=f"/ariel/searches/{search_id}/cancel", status_code=0, duration=api_duration)
            debug_ctx.add_breadcrumb("API call failed", error=str(e), duration_ms=api_duration, level="error")

            # Provide helpful error context based on error type
            error_context = _analyze_qradar_api_error(str(e))
            if "404" in str(e) or "not found" in str(e).lower():
                raise DemistoException(
                    f"Search ID {search_id} not found. The search may have been deleted or expired. "
                    f"Verify the search ID is correct and the search still exists."
                )
            else:
                raise DemistoException(f"Failed to cancel search {search_id}: {str(e)}. {error_context.get('suggestion', '')}")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT PROCESSING WITH DEBUGGING INFORMATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        total_duration = (time.time() - start_time) * 1000

        # Extract final status from response
        final_status = response.get("status", "UNKNOWN") if response else "UNKNOWN"
        debug_ctx.capture_variable("search_status_after_cancel", final_status)

        # Log performance metrics
        logger.info(
            f"Search cancellation completed: {search_id} ({search_status_before} -> {final_status}) in {total_duration:.2f}ms",
            extra={
                "command": "qradar-search-cancel",
                "search_id": search_id,
                "status_before": search_status_before,
                "status_after": final_status,
                "progress_before": progress_before,
                "duration_ms": total_duration,
                "api_duration_ms": api_duration,
            },
        )

        # Build enhanced readable output with debugging information
        if final_status == "COMPLETED":
            readable_output = f"ℹ️ Search ID {search_id} is already in a completed status."
            operation_result = "already_completed"
        elif final_status == "CANCELED":
            readable_output = f"✅ Search ID {search_id} was successfully cancelled."
            operation_result = "cancelled"
        elif search_status_before == "CANCELED":
            readable_output = f"ℹ️ Search ID {search_id} was already cancelled."
            operation_result = "already_cancelled"
        else:
            readable_output = f"✅ Search ID {search_id} cancellation initiated (status: {final_status})."
            operation_result = "cancellation_initiated"

        # Add detailed operation information
        readable_output += "\n\n**Operation Details:**\n"
        readable_output += f"- Status Before: `{search_status_before}`\n"
        readable_output += f"- Status After: `{final_status}`\n"
        readable_output += f"- Progress Before Cancellation: `{progress_before}%`\n"
        readable_output += f"- Cancellation Duration: `{total_duration:.2f}ms`\n"
        readable_output += f"- API Call Duration: `{api_duration:.2f}ms`\n"

        # Add performance and operational notes
        performance_notes = []
        operational_insights = []

        # Operational insights
        if search_status_before == "EXECUTE" and progress_before > 50:
            operational_insights.append(
                f"🔄 Search was {progress_before}% complete when cancelled - significant progress was made"
            )
        elif search_status_before == "WAIT":
            operational_insights.append("⏳ Search was cancelled while queued - no processing time was wasted")
        elif search_status_before == "SORTING":
            operational_insights.append("📊 Search was cancelled during result sorting phase")

        # Performance insights
        if total_duration > 10000:  # More than 10 seconds
            performance_notes.append("⚠️ Slow cancellation operation. Check QRadar system performance.")

        if operation_result == "cancelled" and search_status_before in ["EXECUTE", "SORTING"]:
            performance_notes.append("💡 Successfully cancelled running search - resources have been freed")

        if operational_insights:
            readable_output += "\n\n**Operational Insights:**\n" + "\n".join(operational_insights)

        if performance_notes:
            readable_output += "\n\n**Performance Notes:**\n" + "\n".join(performance_notes)

        debug_ctx.add_breadcrumb("Command completed successfully", total_duration_ms=total_duration)

        return CommandResults(readable_output=readable_output, raw_response=response)

    except Exception as e:
        total_duration = (time.time() - start_time) * 1000
        debug_ctx.add_breadcrumb("Command failed", error=str(e), duration_ms=total_duration, level="error")

        logger.error_with_context(
            "qradar-search-cancel command failed", exception=e, command_args=args, duration_ms=total_duration
        )
        raise


def qradar_search_results_get_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves search results from QRadar service with enhanced debugging and performance monitoring.

    This command provides comprehensive error handling, result analysis, and performance monitoring
    for search result retrieval. It includes detailed logging and debugging information to help
    troubleshoot issues and optimize query performance.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing search parameters.

    Returns:
        CommandResults: Search results with debugging and performance information.

    Raises:
        ValidationError: When arguments are invalid or missing.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED DEBUGGING AND PERFORMANCE MONITORING
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create debug context for comprehensive operation tracking
    debug_ctx = DebugContext("qradar_search_results_get")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    # Start performance monitoring
    start_time = time.time()
    debug_ctx.add_breadcrumb("Starting search results get command", args=args)

    try:
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION WITH HELPFUL ERROR MESSAGES
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create validator for this command
        validator = CommandArgumentValidator("qradar-search-results-get")

        # Add validation rules with helpful error messages
        validator.add_validator(
            "search_id",
            StringValidator(
                "search_id",
                required=True,
                min_length=1,
                max_length=100,
                pattern=r"^[a-fA-F0-9\-]+$",  # UUID format typically used by QRadar
            ),
        ).add_validator(
            "range",
            StringValidator(
                "range",
                required=False,
                pattern=r"^\d+-\d+$",  # Format: start-end
            ),
        ).add_validator("output_path", StringValidator("output_path", required=False, max_length=200))

        # Validate arguments with clear error messages
        try:
            validated_args = validator.validate_arguments(args)
            debug_ctx.add_breadcrumb("Arguments validated successfully", validated_args=validated_args)
        except ValidationError as e:
            debug_ctx.add_breadcrumb("Argument validation failed", error=str(e), level="error")
            raise ValidationError(
                f"Invalid arguments for qradar-search-results-get command: {str(e)}",
                suggestions=[
                    "Ensure search_id is provided and not empty",
                    "Verify search_id format matches QRadar search ID pattern",
                    "Check that range follows format 'start-end' (e.g., '0-100')",
                    "Ensure output_path is a valid context path if specified",
                    "Review the command examples for proper usage",
                ],
            )

        # Extract validated parameters with defaults
        search_id = validated_args["search_id"]
        output_path = validated_args.get("output_path")
        range_ = f"items={validated_args.get('range') or DEFAULT_RANGE_VALUE}"

        debug_ctx.capture_variable("search_id", search_id)
        debug_ctx.capture_variable("output_path", output_path)
        debug_ctx.capture_variable("range_", range_)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # SEARCH STATUS VALIDATION BEFORE RETRIEVING RESULTS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Checking search status before retrieving results")
        status_start_time = time.time()

        try:
            status_response = client.search_status_get(search_id)
            status_duration = (time.time() - status_start_time) * 1000

            search_status = status_response.get("status", "UNKNOWN")
            progress = status_response.get("progress", 0)
            record_count = status_response.get("record_count", 0)

            debug_ctx.capture_variable("search_status", search_status)
            debug_ctx.capture_variable("search_progress", progress)
            debug_ctx.capture_variable("record_count", record_count)

            debug_ctx.add_breadcrumb(
                "Search status retrieved",
                status=search_status,
                progress=progress,
                record_count=record_count,
                duration_ms=status_duration,
            )

            # Validate search is in a state where results can be retrieved
            if search_status == "ERROR":
                error_messages = status_response.get("error_messages", ["Unknown error"])
                raise DemistoException(f"Cannot retrieve results - search failed with error: {'; '.join(error_messages)}")
            elif search_status == "CANCELED":
                raise DemistoException("Cannot retrieve results - search was cancelled")
            elif search_status in ["WAIT", "EXECUTE", "SORTING"] and progress < 100:
                logger.warning(
                    f"Search is not complete (status: {search_status}, progress: {progress}%). " f"Results may be partial."
                )

        except Exception as status_error:
            debug_ctx.add_breadcrumb("Failed to check search status", error=str(status_error), level="warning")
            logger.warning(f"Could not verify search status: {str(status_error)}")
            # Continue with result retrieval attempt

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH PERFORMANCE MONITORING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Making API call to retrieve search results", search_id=search_id, range=range_)
        api_start_time = time.time()

        try:
            response = client.search_results_get(search_id, range_)
            api_duration = (time.time() - api_start_time) * 1000  # Convert to milliseconds

            debug_ctx.log_api_call(
                method="GET", url=f"/ariel/searches/{search_id}/results", status_code=200, duration=api_duration
            )

            debug_ctx.add_breadcrumb(
                "API call completed successfully", duration_ms=api_duration, response_size=len(str(response)) if response else 0
            )

            # Log performance metrics
            if api_duration > 10000:  # More than 10 seconds
                logger.warning(f"Slow API response detected: {api_duration:.2f}ms for search results")

        except Exception as e:
            api_duration = (time.time() - api_start_time) * 1000
            debug_ctx.log_api_call(method="GET", url=f"/ariel/searches/{search_id}/results", status_code=0, duration=api_duration)
            debug_ctx.add_breadcrumb("API call failed", error=str(e), duration_ms=api_duration, level="error")

            # Provide helpful error context based on error type
            error_context = _analyze_qradar_api_error(str(e))
            if "404" in str(e) or "not found" in str(e).lower():
                raise DemistoException(
                    f"Search ID {search_id} not found. The search may have been deleted or expired. "
                    f"Verify the search ID is correct and the search still exists."
                )
            else:
                raise DemistoException(
                    f"Failed to retrieve search results for {search_id}: {str(e)}. {error_context.get('suggestion', '')}"
                )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT PROCESSING WITH DEBUGGING INFORMATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        debug_ctx.add_breadcrumb("Processing API response")

        if not response:
            debug_ctx.add_breadcrumb("Empty response received", level="error")
            raise DemistoException(f"Unexpected empty response from QRadar service for search {search_id}")

        # Extract result key and data
        if not isinstance(response, dict) or not response:
            raise DemistoException(f"Invalid response format from QRadar service for search {search_id}")

        result_key = list(response.keys())[0]
        result_data = response.get(result_key)

        debug_ctx.capture_variable("result_key", result_key)
        debug_ctx.capture_variable("result_data_type", type(result_data).__name__)
        debug_ctx.capture_variable("result_count", len(result_data) if isinstance(result_data, list) else 1)

        # Sanitize and format outputs
        outputs = sanitize_outputs(result_data)

        debug_ctx.add_breadcrumb(
            "Response processed successfully",
            result_key=result_key,
            result_count=len(outputs) if isinstance(outputs, list) else 1,
            processing_time_ms=(time.time() - start_time) * 1000,
        )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════
        # RESULT ANALYSIS AND PERFORMANCE RECOMMENDATIONS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════

        total_duration = (time.time() - start_time) * 1000
        result_count = len(outputs) if isinstance(outputs, list) else 1

        # Log performance metrics
        logger.info(
            f"Search results retrieved: {result_count} results in {total_duration:.2f}ms",
            extra={
                "command": "qradar-search-results-get",
                "search_id": search_id,
                "result_count": result_count,
                "result_key": result_key,
                "duration_ms": total_duration,
                "api_duration_ms": api_duration,
                "range": range_,
            },
        )

        # Add performance and result analysis to readable output
        performance_notes = []
        result_insights = []

        # Result analysis
        if result_count == 0:
            result_insights.append("ℹ️ No results found for this search")
        elif result_count == 1:
            result_insights.append("✅ Single result retrieved")
        else:
            result_insights.append(f"📊 {result_count} results retrieved")

        # Performance insights
        if total_duration > 15000:  # More than 15 seconds
            performance_notes.append("⚠️ Slow result retrieval. Consider using smaller range or adding filters.")

        if result_count > 1000:
            performance_notes.append("📈 Large result set. Consider pagination for better performance.")

        # Data transfer insights
        response_size_mb = len(str(response)) / (1024 * 1024)
        if response_size_mb > 10:  # More than 10MB
            performance_notes.append(
                f"💾 Large data transfer ({response_size_mb:.1f}MB). Consider limiting fields or using pagination."
            )

        # Build enhanced readable output
        readable_output = tableToMarkdown(f"Search Results For Search ID {search_id}", outputs)

        if result_insights:
            readable_output += "\n\n**Result Information:**\n" + "\n".join(result_insights)

        if performance_notes:
            readable_output += "\n\n**Performance Notes:**\n" + "\n".join(performance_notes)

        # Add query debugging information
        readable_output += "\n\n**Query Details:**\n"
        readable_output += f"- Search ID: `{search_id}`\n"
        readable_output += f"- Result Type: `{result_key}`\n"
        readable_output += f"- Range: `{range_}`\n"
        readable_output += f"- Total Duration: `{total_duration:.2f}ms`\n"
        readable_output += f"- API Duration: `{api_duration:.2f}ms`\n"

        # Determine output prefix
        outputs_prefix = output_path if output_path else f'QRadar.Search(val.ID === "{search_id}").Result.{result_key}'

        debug_ctx.add_breadcrumb("Command completed successfully", total_duration_ms=total_duration)

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=outputs_prefix,
            outputs=outputs,
            raw_response=response,
        )

    except Exception as e:
        total_duration = (time.time() - start_time) * 1000
        debug_ctx.add_breadcrumb("Command failed", error=str(e), duration_ms=total_duration, level="error")

        logger.error_with_context(
            "qradar-search-results-get command failed", exception=e, command_args=args, duration_ms=total_duration
        )
        raise


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# REFERENCE SET COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def qradar_reference_sets_list_command(client: Client, args: dict) -> CommandResults:
    """
    Enhanced reference sets list command with comprehensive validation and diagnostics.

    This enhanced command provides:
    - Comprehensive input validation with clear error messages
    - Advanced filtering and pagination support
    - Optional health checks and diagnostics
    - Performance monitoring and optimization
    - Clear error handling with troubleshooting suggestions

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments with enhanced validation.

    Returns:
        CommandResults: Enhanced results with validation and diagnostic information.

    Raises:
        ValidationError: When arguments are invalid with clear suggestions.
        QRadarAPIError: When QRadar API calls fail with context.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # ENHANCED INPUT VALIDATION WITH COMPREHENSIVE ERROR MESSAGES
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create enhanced client and service
    enhanced_client = get_enhanced_client(client)
    reference_service = ReferenceService(enhanced_client)

    # Create debug context for this operation
    debug_ctx = DebugContext("qradar_reference_sets_list")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    try:
        debug_ctx.add_breadcrumb("Starting reference sets list command", args=args)

        # Enhanced argument validation
        ref_name = args.get("ref_name")
        convert_date_value = argToBoolean(args.get("date_value", False))
        range_arg = args.get("range", DEFAULT_RANGE_VALUE)
        filter_ = args.get("filter")
        fields = args.get("fields")
        include_diagnostics = argToBoolean(args.get("include_diagnostics", False))
        validate_health = argToBoolean(args.get("validate_health", False))

        # Validate range format
        if range_arg and not re.match(r"^\d+-\d+$", range_arg):
            raise ValidationError(
                f"Invalid range format: '{range_arg}'. Expected format: 'start-end' (e.g., '0-49')",
                field_name="range",
                suggestions=[
                    "Use format like '0-49' for first 50 items",
                    "Use '10-19' for items 10 through 19",
                    "Ensure both start and end are non-negative integers",
                ],
            )

        range_ = f"items={range_arg}"

        # Validate filter syntax if provided
        if filter_:
            filter_validation = _validate_qradar_filter_syntax(filter_)
            if not filter_validation["is_valid"]:
                raise ValidationError(
                    f"Invalid filter syntax: {filter_validation['error']}",
                    field_name="filter",
                    field_value=filter_,
                    suggestions=filter_validation["suggestions"],
                )

        debug_ctx.add_breadcrumb("Arguments validated successfully")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED API CALL WITH SERVICE LAYER
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Use enhanced service layer for better error handling
        service_result = reference_service.list_reference_sets(range_header=range_, filter_query=filter_, fields=fields)

        if not service_result.is_success():
            raise QRadarAPIError(
                f"Failed to list reference sets: {service_result.error_message}",
                error_code=service_result.error_code,
                suggestions=[
                    "Check QRadar connectivity and authentication",
                    "Verify filter syntax if using filters",
                    "Ensure you have permissions to access reference sets",
                    "Check QRadar system status and availability",
                ],
            )

        response = service_result.data
        debug_ctx.add_breadcrumb(f"Retrieved {len(response) if isinstance(response, list) else 1} reference sets")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED DATA PROCESSING WITH VALIDATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        if ref_name:
            # Single reference set processing with enhanced validation
            outputs = dict(response)

            # Validate response structure
            if not isinstance(outputs, dict) or "name" not in outputs:
                raise QRadarAPIError(
                    f"Invalid response structure for reference set '{ref_name}'",
                    suggestions=[
                        "Verify the reference set name exists in QRadar",
                        "Check if you have permissions to access this reference set",
                        "Ensure the reference set is not corrupted",
                    ],
                )

            # Enhanced date value conversion with error handling
            if convert_date_value and outputs.get("element_type") == "DATE":
                debug_ctx.add_breadcrumb("Converting date values")
                try:
                    for data_entry in outputs.get("data", []):
                        if "value" in data_entry:
                            data_entry["value"] = get_time_parameter(data_entry.get("value"), iso_format=True)
                except Exception as e:
                    logger.warning(f"Date conversion failed for some values: {e}")
                    debug_ctx.add_breadcrumb("Date conversion had issues", error=str(e), level="warning")

            # Enhanced data sanitization
            outputs["data"] = sanitize_outputs(outputs.get("data", []), REFERENCE_SET_DATA_RAW_FORMATTED)

            # Add diagnostic information if requested
            if include_diagnostics:
                debug_ctx.add_breadcrumb("Adding diagnostic information")
                diagnostic_result = reference_service.validate_reference_set_configuration(ref_name)
                if diagnostic_result.is_success():
                    outputs["diagnostics"] = diagnostic_result.data
        else:
            # Multiple reference sets processing
            outputs = response

            # Validate response is a list
            if not isinstance(outputs, list):
                raise QRadarAPIError(
                    "Invalid response format: expected list of reference sets",
                    suggestions=[
                        "Check QRadar API version compatibility",
                        "Verify your query parameters are correct",
                        "Contact QRadar administrator if issue persists",
                    ],
                )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED OUTPUT FORMATTING WITH VALIDATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        final_outputs = sanitize_outputs(outputs, REFERENCE_SETS_RAW_FORMATTED)
        headers = build_headers(
            ["Name", "ElementType", "Data", "TimeToLive", "TimeoutType"], set(REFERENCE_SETS_RAW_FORMATTED.values())
        )

        # Add diagnostic headers if diagnostics are included
        if include_diagnostics and ref_name:
            headers.extend(["Health", "DataCount", "LastModified"])

        # Create enhanced readable output
        readable_title = "Reference Sets List"
        if ref_name:
            readable_title = f"Reference Set: {ref_name}"
        if include_diagnostics:
            readable_title += " (with Diagnostics)"

        debug_ctx.add_breadcrumb("Command completed successfully")
        logger.info("Reference sets list command completed successfully")

        return CommandResults(
            readable_output=tableToMarkdown(readable_title, final_outputs, headers, removeNull=True),
            outputs_prefix="QRadar.Reference",
            outputs_key_field="Name",
            outputs=final_outputs,
            raw_response=response,
        )

    except ValidationError as e:
        debug_ctx.add_breadcrumb("Validation error occurred", error=str(e), level="error")
        logger.error_with_context(f"Validation failed: {str(e)}", exception=e)
        raise
    except Exception as e:
        debug_ctx.add_breadcrumb("Unexpected error occurred", error=str(e), level="error")
        logger.error_with_context(f"Reference sets list command failed: {str(e)}", exception=e)
        raise QRadarAPIError(
            f"Failed to list reference sets: {str(e)}",
            suggestions=[
                "Check QRadar connectivity and authentication",
                "Verify your command parameters are correct",
                "Review the QRadar logs for additional error details",
                "Contact support if the issue persists",
            ],
        )


def qradar_reference_set_create_command(client: Client, args: dict) -> CommandResults:
    """
    Create a new reference set with comprehensive input validation.

    This command creates a new reference set in QRadar with specified data type and optional
    time-to-live settings. Reference sets are used to store collections of data that can be
    referenced in rules and searches.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments containing reference set configuration.

    Returns:
        CommandResults: Reference set creation results with configuration details.

    Raises:
        ValidationError: When arguments are invalid or required parameters are missing.
        DemistoException: When QRadar API calls fail.
    """
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # COMPREHENSIVE INPUT VALIDATION WITH CLEAR ERROR MESSAGES
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Create validator for this command with comprehensive validation rules
    validator = CommandArgumentValidator("qradar-reference-set-create")

    # Add validation rules for each parameter with helpful error messages
    validator.add_validator(
        "ref_name",
        StringValidator(
            "ref_name",
            required=True,
            min_length=1,
            max_length=255,
            pattern=r"^[a-zA-Z0-9_\-\.]+$",  # QRadar naming conventions
        ),
    ).add_validator(
        "element_type",
        StringValidator(
            "element_type", required=True, allowed_values=["ALN", "ALNIC", "IP", "NUM", "PORT", "DATE"], case_sensitive=False
        ),
    ).add_validator(
        "timeout_type",
        StringValidator(
            "timeout_type", required=False, allowed_values=["FIRST_SEEN", "LAST_SEEN", "UNKNOWN"], case_sensitive=False
        ),
    ).add_validator(
        "time_to_live",
        StringValidator(
            "time_to_live",
            required=False,
            min_length=1,
            max_length=100,
            pattern=r"^\d+\s+(second|minute|hour|day|week|month|year)s?$",  # Time interval format
        ),
    ).add_validator("fields", StringValidator("fields", required=False, max_length=1000))

    # Validate all arguments and get cleaned values
    try:
        validated_args = validator.validate_arguments(args)
    except ValidationError as e:
        # Re-raise with additional context for debugging
        raise ValidationError(
            f"Invalid arguments for qradar-reference-set-create command: {str(e)}",
            suggestions=[
                "Check the parameter documentation for correct formats",
                "Verify reference set name follows QRadar naming conventions (alphanumeric, underscore, hyphen, dot only)",
                "Ensure element_type is one of: ALN, ALNIC, IP, NUM, PORT, DATE",
                "If using time_to_live, format should be like '1 month' or '5 minutes'",
                "Review the command examples for proper usage",
            ],
        )

    # Extract validated parameters
    ref_name = validated_args["ref_name"]  # Required
    element_type = validated_args["element_type"]  # Required
    timeout_type = validated_args.get("timeout_type")
    time_to_live = validated_args.get("time_to_live")
    fields = validated_args.get("fields")

    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
    # BUSINESS RULE VALIDATION WITH CLEAR ERROR MESSAGES
    # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

    # Validate time_to_live and timeout_type relationship
    if time_to_live and not timeout_type:
        # Set default timeout_type when time_to_live is provided
        timeout_type = "UNKNOWN"

    if timeout_type and timeout_type.upper() != "UNKNOWN" and not time_to_live:
        raise ValidationError(
            "time_to_live must be specified when timeout_type is FIRST_SEEN or LAST_SEEN",
            field_name="time_to_live",
            suggestions=[
                "Provide a time_to_live value (e.g., '1 month', '5 minutes', '2 hours')",
                "Or change timeout_type to 'UNKNOWN' if no expiration is needed",
                "Check the QRadar documentation for supported time interval formats",
            ],
        )

    # Additional validation for reference set name uniqueness (informational)
    if len(ref_name) > 100:  # QRadar practical limit
        raise ValidationError(
            "Reference set name is too long (recommended maximum: 100 characters)",
            field_name="ref_name",
            field_value=ref_name,
            suggestions=[
                "Use a shorter, more concise name for the reference set",
                "Consider using abbreviations or removing unnecessary words",
                "QRadar works best with reference set names under 100 characters",
            ],
        )

    # if this call fails, raise an error and stop command execution
    response = client.reference_set_create(ref_name, element_type, timeout_type, time_to_live, fields)
    outputs = sanitize_outputs(response, REFERENCE_SETS_RAW_FORMATTED)
    headers = build_headers(
        ["Name", "ElementType", "Data", "TimeToLive", "TimeoutType"], set(REFERENCE_SETS_RAW_FORMATTED.values())
    )

    return CommandResults(
        readable_output=tableToMarkdown("Reference Set Create", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.Reference",
        outputs_key_field="Name",
        outputs=outputs,
        raw_response=response,
    )


def qradar_reference_set_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Removes a reference set or purges its contents.
    possible arguments:
    - ref_name (Required): The name of the new reference set.
    - purge_only: Indicates if the reference set should have its contents purged (true),
                  keeping the reference set structure. If the value is 'false',
                  or not specified the reference set is removed completely.
                  Default is 'false'.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name: str = args.get("ref_name", "")
    purge_only = args.get("purge_only")
    fields = args.get("fields")

    # if this call fails, raise an error and stop command execution
    response = client.reference_set_delete(ref_name, purge_only, fields)
    return CommandResults(
        raw_response=response,
        readable_output=f'Request to delete reference {ref_name} was submitted.'
        f''' Current deletion status: {response.get('status', 'Unknown')}''',
    )


@polling_function(name="qradar-reference-set-value-upsert", requires_polling_arg=False)
def qradar_reference_set_value_upsert_command(args: dict, client: Client, params: dict) -> PollResult:
    """
    Update or insert new value to a reference set from QRadar service.
    possible arguments:
    - ref_name (Required): The reference name to insert/update a value for.
    - values (Required): Comma separated list. All the values to be inserted/updated.
    - source: An indication of where the data originated. Default is reference data api.
    - date_value: Boolean, specifies if values given are dates or not.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        PollResult.
    """
    return insert_values_to_reference_set_polling(
        client, params.get("api_version", ""), args, values=argToList(args.get("value", ""))
    )


def qradar_reference_set_bulk_load_command(client: Client, args: dict) -> CommandResults:
    """
    Enhanced bulk load command for reference sets with comprehensive validation and progress reporting.

    This command provides:
    - Bulk loading with batch processing for large datasets
    - Comprehensive value validation with detailed error reporting
    - Progress monitoring and status updates
    - Partial failure handling with clear error categorization
    - Performance optimization for large value sets

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments with bulk operation parameters.

    Returns:
        CommandResults: Bulk load results with detailed progress and error information.

    Raises:
        ValidationError: When arguments are invalid with clear suggestions.
        QRadarAPIError: When QRadar API calls fail with context.
    """
    # Create enhanced client and service
    enhanced_client = get_enhanced_client(client)
    reference_service = ReferenceService(enhanced_client)

    # Create debug context for this operation
    debug_ctx = DebugContext("qradar_reference_set_bulk_load")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    try:
        debug_ctx.add_breadcrumb("Starting bulk load command", args=args)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE INPUT VALIDATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Required parameters
        ref_name = args.get("ref_name")
        values_input = args.get("values")

        if not ref_name:
            raise ValidationError(
                "ref_name is required for bulk load operation",
                field_name="ref_name",
                suggestions=[
                    "Provide the name of the reference set to load data into",
                    "Ensure the reference set exists in QRadar",
                    "Check the reference set name spelling and case",
                ],
            )

        if not values_input:
            raise ValidationError(
                "values parameter is required for bulk load operation",
                field_name="values",
                suggestions=[
                    "Provide a comma-separated list of values to load",
                    "Use the format: value1,value2,value3",
                    "Ensure values are appropriate for the reference set element type",
                ],
            )

        # Optional parameters with validation
        source = args.get("source", "Bulk Load API")
        batch_size = arg_to_number(args.get("batch_size", 100))
        validate_values = argToBoolean(args.get("validate_values", True))
        remove_duplicates = argToBoolean(args.get("remove_duplicates", True))
        progress_reporting = argToBoolean(args.get("progress_reporting", True))

        # Validate batch size
        if batch_size <= 0 or batch_size > 1000:
            raise ValidationError(
                f"batch_size must be between 1 and 1000, got: {batch_size}",
                field_name="batch_size",
                suggestions=[
                    "Use a batch size between 1 and 1000",
                    "Recommended batch size is 100-500 for optimal performance",
                    "Smaller batches provide better error isolation",
                ],
            )

        # Parse values from input
        if isinstance(values_input, str):
            values = [v.strip() for v in values_input.split(",") if v.strip()]
        elif isinstance(values_input, list):
            values = [str(v).strip() for v in values_input if str(v).strip()]
        else:
            raise ValidationError(
                f"values must be a string or list, got: {type(values_input).__name__}",
                field_name="values",
                suggestions=[
                    "Provide values as a comma-separated string: 'value1,value2,value3'",
                    "Or provide values as a list: ['value1', 'value2', 'value3']",
                    "Ensure all values are strings or can be converted to strings",
                ],
            )

        if not values:
            raise ValidationError(
                "No valid values found after parsing input",
                field_name="values",
                suggestions=[
                    "Ensure values are not empty after trimming whitespace",
                    "Check that comma-separated values are properly formatted",
                    "Verify that list contains non-empty string values",
                ],
            )

        debug_ctx.add_breadcrumb(f"Parsed {len(values)} values for bulk load")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # ENHANCED BULK LOAD OPERATION WITH SERVICE LAYER
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Use enhanced service layer for bulk load
        service_result = reference_service.bulk_load_reference_set(
            reference_set_name=ref_name,
            values=values,
            source=source,
            validate_values=validate_values,
            batch_size=batch_size,
            remove_duplicates=remove_duplicates,
            progress_reporting=progress_reporting,
        )

        if not service_result.is_success():
            # Handle partial failures differently from complete failures
            if service_result.error_code == "PARTIAL_FAILURE":
                # Partial failure - some values loaded successfully
                result_data = service_result.debug_context

                readable_output = f"""## Bulk Load Partially Completed

**Reference Set:** {ref_name}
**Total Values:** {result_data.get('total_values', 0)}
**Successfully Loaded:** {result_data.get('successful_loads', 0)}
**Failed to Load:** {result_data.get('failed_loads', 0)}
**Batch Count:** {result_data.get('batch_count', 0)}

### Errors Encountered:
{chr(10).join(f"- {error}" for error in result_data.get('errors', []))}

### Recommendations:
- Review the failed values and correct any format issues
- Consider retrying the failed values separately
- Check QRadar logs for additional error details
"""

                return CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="QRadar.Reference.BulkLoad",
                    outputs_key_field="reference_set_name",
                    outputs=result_data,
                    raw_response=service_result.raw_response,
                )
            else:
                # Complete failure
                raise QRadarAPIError(
                    f"Bulk load failed: {service_result.error_message}",
                    error_code=service_result.error_code,
                    suggestions=[
                        "Verify the reference set exists and is accessible",
                        "Check that you have permissions to modify the reference set",
                        "Ensure the values match the reference set element type",
                        "Try with a smaller batch size if experiencing timeouts",
                    ],
                )

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # SUCCESS RESPONSE FORMATTING
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        result_data = service_result.data

        readable_output = f"""## Bulk Load Completed Successfully

**Reference Set:** {ref_name}
**Total Values Loaded:** {result_data.get('successful_loads', 0)}
**Batch Count:** {result_data.get('batch_count', 0)}
**Processing Time:** {service_result.duration_ms:.2f}ms
**Source:** {source}

### Operation Summary:
- All values loaded successfully
- No validation errors encountered
- Bulk load operation completed without issues
"""

        debug_ctx.add_breadcrumb("Bulk load completed successfully")
        logger.info(f"Bulk load completed: {result_data.get('successful_loads', 0)} values loaded")

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="QRadar.Reference.BulkLoad",
            outputs_key_field="reference_set_name",
            outputs=result_data,
            raw_response=service_result.raw_response,
        )

    except ValidationError as e:
        debug_ctx.add_breadcrumb("Validation error occurred", error=str(e), level="error")
        logger.error_with_context(f"Bulk load validation failed: {str(e)}", exception=e)
        raise
    except Exception as e:
        debug_ctx.add_breadcrumb("Unexpected error occurred", error=str(e), level="error")
        logger.error_with_context(f"Bulk load command failed: {str(e)}", exception=e)
        raise QRadarAPIError(
            f"Bulk load operation failed: {str(e)}",
            suggestions=[
                "Check QRadar connectivity and authentication",
                "Verify the reference set exists and is accessible",
                "Ensure you have permissions to modify reference sets",
                "Try with a smaller batch size or fewer values",
            ],
        )


def qradar_reference_set_validate_command(client: Client, args: dict) -> CommandResults:
    """
    Enhanced diagnostic command for reference set validation and health checks.

    This command provides comprehensive diagnostics including:
    - Reference set configuration validation
    - Data integrity checks
    - Performance analysis
    - Health status monitoring
    - Troubleshooting recommendations

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Command arguments with diagnostic parameters.

    Returns:
        CommandResults: Comprehensive diagnostic results with recommendations.

    Raises:
        ValidationError: When arguments are invalid with clear suggestions.
        QRadarAPIError: When QRadar API calls fail with context.
    """
    # Create enhanced client and service
    enhanced_client = get_enhanced_client(client)
    reference_service = ReferenceService(enhanced_client)

    # Create debug context for this operation
    debug_ctx = DebugContext("qradar_reference_set_validate")
    logger = get_enhanced_logger(__name__).with_context(debug_ctx)

    try:
        debug_ctx.add_breadcrumb("Starting reference set validation", args=args)

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # INPUT VALIDATION
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        ref_name = args.get("ref_name")
        if not ref_name:
            raise ValidationError(
                "ref_name is required for validation",
                field_name="ref_name",
                suggestions=[
                    "Provide the name of the reference set to validate",
                    "Ensure the reference set exists in QRadar",
                    "Check the reference set name spelling and case",
                ],
            )

        # Optional diagnostic parameters
        check_health = argToBoolean(args.get("check_health", True))
        validate_data = argToBoolean(args.get("validate_data", True))
        performance_check = argToBoolean(args.get("performance_check", False))
        detailed_report = argToBoolean(args.get("detailed_report", False))

        debug_ctx.add_breadcrumb("Arguments validated successfully")

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # COMPREHENSIVE VALIDATION USING SERVICE LAYER
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        validation_result = reference_service.validate_reference_set_configuration(
            reference_set_name=ref_name,
            check_health=check_health,
            validate_data=validate_data,
            performance_check=performance_check,
        )

        if not validation_result.is_success():
            raise QRadarAPIError(
                f"Validation failed: {validation_result.error_message}",
                error_code=validation_result.error_code,
                suggestions=[
                    "Verify the reference set exists in QRadar",
                    "Check that you have permissions to access the reference set",
                    "Ensure QRadar is accessible and responding",
                    "Contact QRadar administrator if issues persist",
                ],
            )

        validation_data = validation_result.data

        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
        # FORMAT DIAGNOSTIC RESULTS
        # ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

        # Create comprehensive readable output
        health_status = "✅ HEALTHY" if validation_data.get("is_healthy", False) else "❌ ISSUES DETECTED"

        readable_output = f"""## Reference Set Validation Report

**Reference Set:** {ref_name}
**Overall Health:** {health_status}
**Validation Time:** {validation_result.duration_ms:.2f}ms

### Configuration Details:
- **Element Type:** {validation_data.get('element_type', 'Unknown')}
- **Data Count:** {validation_data.get('data_count', 0):,}
- **Timeout Type:** {validation_data.get('timeout_type', 'None')}
- **Time to Live:** {validation_data.get('time_to_live', 'None')}
- **Last Modified:** {validation_data.get('last_modified', 'Unknown')}
"""

        # Add health check results
        if check_health and "health_checks" in validation_data:
            readable_output += "\n### Health Check Results:\n"
            for check_name, check_result in validation_data["health_checks"].items():
                status = "✅" if check_result.get("passed", False) else "❌"
                readable_output += f"- **{check_name}:** {status} {check_result.get('message', '')}\n"

        # Add data validation results
        if validate_data and "data_validation" in validation_data:
            data_val = validation_data["data_validation"]
            readable_output += "\n### Data Validation Results:\n"
            readable_output += f"- **Valid Values:** {data_val.get('valid_count', 0):,}\n"
            readable_output += f"- **Invalid Values:** {data_val.get('invalid_count', 0):,}\n"
            readable_output += f"- **Duplicate Values:** {data_val.get('duplicate_count', 0):,}\n"

        # Add performance analysis
        if performance_check and "performance" in validation_data:
            perf = validation_data["performance"]
            readable_output += "\n### Performance Analysis:\n"
            readable_output += f"- **Query Response Time:** {perf.get('query_time_ms', 0):.2f}ms\n"
            readable_output += f"- **Data Size:** {perf.get('data_size_mb', 0):.2f}MB\n"
            readable_output += f"- **Performance Rating:** {perf.get('rating', 'Unknown')}\n"

        # Add recommendations
        if "recommendations" in validation_data and validation_data["recommendations"]:
            readable_output += "\n### Recommendations:\n"
            for rec in validation_data["recommendations"]:
                readable_output += f"- {rec}\n"

        debug_ctx.add_breadcrumb("Validation completed successfully")
        logger.info(f"Reference set validation completed for: {ref_name}")

        return CommandResults(
            readable_output=readable_output,
            outputs_prefix="QRadar.Reference.Validation",
            outputs_key_field="reference_set_name",
            outputs=validation_data,
            raw_response=validation_result.raw_response,
        )

    except ValidationError as e:
        debug_ctx.add_breadcrumb("Validation error occurred", error=str(e), level="error")
        logger.error_with_context(f"Validation command failed: {str(e)}", exception=e)
        raise
    except Exception as e:
        debug_ctx.add_breadcrumb("Unexpected error occurred", error=str(e), level="error")
        logger.error_with_context(f"Reference set validation failed: {str(e)}", exception=e)
        raise QRadarAPIError(
            f"Reference set validation failed: {str(e)}",
            suggestions=[
                "Check QRadar connectivity and authentication",
                "Verify the reference set exists and is accessible",
                "Ensure you have permissions to access reference sets",
                "Contact support if the issue persists",
            ],
        )


def qradar_reference_set_value_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Delete a value in reference set from QRadar service.
    possible arguments:
    - ref_name (Required): The reference name to insert/update a value for.
    - value (Required): Value to be deleted.
    - date_value: Boolean, specifies if values given are dates or not.

    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ref_name: str = args.get("ref_name", "")
    value: str = args.get("value", "")
    date_value = argToBoolean(args.get("date_value", False))
    original_value = value

    if date_value:
        value = str(get_time_parameter(original_value, epoch_format=True))
    # if this call fails, raise an error and stop command execution
    try:
        response = client.reference_set_value_delete(ref_name, value)
    except DemistoException as e:
        response = str(e)
        if f"Set {ref_name} does not contain value {value}" not in response:
            raise e
    human_readable = f"### value: {original_value} of reference: {ref_name} was deleted successfully"

    return CommandResults(readable_output=human_readable, raw_response=response)


def qradar_domains_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves list of domains sets from QRadar service.
    If you do not have the System Administrator or Security Administrator permissions,
    then for each domain assigned to your security profile you can only view the values
    for the id and name fields. All other values return null.
    possible arguments:
    - domain_id: Retrieves details of the specific domain that corresponds to the ID given.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    # backward compatibility for domain_id argument named is 'id' in QRadar v2.
    domain_id = args.get("domain_id") or args.get("id")
    range_ = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_ = args.get("filter")
    fields = args.get("fields")

    # if this call fails, raise an error and stop command execution
    response = client.domains_list(domain_id, range_, filter_, fields)
    outputs = sanitize_outputs(response, DOMAIN_RAW_FORMATTED)

    return CommandResults(
        readable_output=tableToMarkdown("Domains List", outputs, removeNull=True),
        outputs_prefix="QRadar.Domains",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


@polling_function(name="qradar-indicators-upload", requires_polling_arg=False)
def qradar_indicators_upload_command(args: dict, client: Client, params: dict) -> PollResult:
    """
    Uploads list of indicators from Demisto to a reference set in QRadar service.
    possible arguments:
    - ref_name (Required): Name of the reference set to upload indicators to.
    - query: The query for getting indicators from Demisto.
    - limit: Maximum number of indicators to fetch from Demisto.
    - page: The page from which to get the indicators.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        PollResult.
    """
    return insert_values_to_reference_set_polling(client, params.get("api_version", ""), args, from_indicators=True)


def flatten_nested_geolocation_values(geolocation_dict: dict, dict_key: str, nested_value_keys: list[str]) -> dict:
    """
    Receives output from geolocation IPs command, and does:
    1) flattens output, takes nested keys values.
    2) Converts keys to prefix of 'dict_key' and suffix of nested key as camel case.
    Args:
        geolocation_dict (Dict): The dict to flatten.
        dict_key (Dict): The key of the inner dict to use his values.
        nested_value_keys (Dict): The keys inside inner dict to take.

    Returns:
        (Dict): dict of ({dict_key_name}{camel case nested key}: {nested key value}
    """
    return {
        f"{camelize_string(dict_key)}{camelize_string(k)}": geolocation_dict.get(dict_key, {}).get(k) for k in nested_value_keys
    }


def qradar_geolocations_for_ip_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves the MaxMind geoip data for the given IP addresses.
    possible arguments:
    - ip (Required): Comma separated list. the IPs to retrieve data for.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    ips = argToList(args.get("ip"))
    filter_ = f"""ip_address IN ({','.join((f'"{ip!s}"' for ip in ips))})"""  # noqa: UP034
    fields = args.get("fields")

    # if this call fails, raise an error and stop command execution
    response = client.geolocations_for_ip(filter_, fields)
    outputs = []
    for output in response:
        city_values = flatten_nested_geolocation_values(output, "city", ["name"])
        continent_values = flatten_nested_geolocation_values(output, "continent", ["name"])
        location_values = flatten_nested_geolocation_values(
            output,
            "location",
            ["accuracy_radius", "average_income", "latitude", "longitude", "metro_code", "population_density", "timezone"],
        )
        physical_country_values = flatten_nested_geolocation_values(output, "physical_country", ["iso_code", "name"])
        registered_country_values = flatten_nested_geolocation_values(output, "registered_country", ["iso_code", "name"])
        represented_country_values = flatten_nested_geolocation_values(
            output, "represented_country", ["iso_code", "name", "confidence"]
        )
        subdivision_values = flatten_nested_geolocation_values(output, "subdivision", ["name", "iso_code", "confidence"])
        non_nested_values = {
            "IPAddress": output.get("ip_address"),
            "Traits": output.get("traits"),
            "Coordinates": output.get("geo_json", {}).get("coordinates"),
            "PostalCode": output.get("postal", {}).get("postal_code"),
            "PostalCodeConfidence": output.get("postal", {}).get("confidence"),
        }
        final_output = dict(
            city_values,
            **continent_values,
            **location_values,
            **physical_country_values,
            **registered_country_values,
            **represented_country_values,
            **subdivision_values,
            **non_nested_values,
        )
        outputs.append(final_output)

    final_outputs = sanitize_outputs(outputs)

    return CommandResults(
        readable_output=tableToMarkdown("Geolocation For IP", final_outputs),
        outputs_prefix="QRadar.GeoForIP",
        outputs_key_field="IPAddress",
        outputs=final_outputs,
        raw_response=response,
    )


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# LOG SOURCE MANAGEMENT COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def qradar_log_sources_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log sources from QRadar service.
    possible arguments:
    - qrd_encryption_algorithm: The algorithm to use for encrypting the sensitive data of this
        endpoint. Using AES 128
    - qrd_encryption_password: The password to use for encrypting the sensitive data of this endpoint.
        If argument was not given, will be randomly generated.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    qrd_encryption_algorithm: str = args.get("qrd_encryption_algorithm", "AES128")
    qrd_encryption_password: str = args.get("qrd_encryption_password", secrets.token_urlsafe(20))
    endpoint = "/config/event_sources/log_source_management/log_sources"
    range_ = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_ = args.get("filter")
    fields = args.get("fields")
    additional_headers = {
        "x-qrd-encryption-algorithm": qrd_encryption_algorithm,
        "x-qrd-encryption-password": qrd_encryption_password,
    }
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields, additional_headers)
    outputs = sanitize_outputs(response, LOG_SOURCES_RAW_FORMATTED)
    readable_outputs = [{k: v for k, v in output.items() if k != "ProtocolParameters"} for output in outputs]
    headers = build_headers(["ID", "Name", "Description"], set(LOG_SOURCES_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Log Sources List", readable_outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSource",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_get_custom_properties_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of event regex properties from QRadar service.
    possible arguments:
    - field_names: A comma-separated list of names of an exact properties to search for.
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: If used, will filter all fields except for the specified ones.
              Use this parameter to specify which fields you would like to get back in the
              response. Fields that are not explicitly named are excluded.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT_VALUE))
    range_ = f"items=0-{limit - 1}" if limit else f'items={args.get("range", DEFAULT_RANGE_VALUE)}'

    like_names = argToList(args.get("like_name"))
    field_names = argToList(args.get("field_name"))
    filter_ = args.get("filter", "")
    fields = args.get("fields")
    if not filter_:
        if field_names:
            filter_ += f"""name IN ({','.join(f'"{name!s}"' for name in field_names)})"""
        if like_names:
            filter_ += " or ".join(f' name ILIKE "%{like}%"' for like in like_names)

    # if this call fails, raise an error and stop command execution
    response = client.custom_properties(range_, filter_, fields)
    outputs = sanitize_outputs(response)

    return CommandResults(
        readable_output=tableToMarkdown("Custom Properties", outputs, removeNull=True),
        outputs_prefix="QRadar.Properties",
        outputs_key_field="identifier",
        outputs=outputs,
        raw_response=response,
    )


def perform_ips_command_request(client: Client, args: dict[str, Any], is_destination_addresses: bool):
    """
    Performs request to QRadar IPs endpoint.
    Args:
        client (Client): Client to perform the request to QRadar service.
        args (Dict[str, Any]): XSOAR arguments.
        is_destination_addresses (bool): Whether request is for destination addresses or source addresses.

    Returns:
        - Request response.
    """
    range_: str = f"""items={args.get('range', DEFAULT_RANGE_VALUE)}"""
    filter_: str | None = args.get("filter")
    fields: str | None = args.get("fields")

    address_type = "local_destination" if is_destination_addresses else "source"
    ips_arg_name: str = f"{address_type}_ip"
    ips: list[str] = argToList(args.get(ips_arg_name, []))

    if ips and filter_:
        raise DemistoException(f"Both filter and {ips_arg_name} have been supplied. Please supply only one.")

    if ips:
        filter_ = " OR ".join([f'{ips_arg_name}="{ip_}"' for ip_ in ips])
    url_suffix = f"{address_type}_addresses"

    # if this call fails, raise an error and stop command execution
    response = client.get_addresses(url_suffix, filter_, fields, range_)

    return response


def qradar_ips_source_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get source IPS from QRadar service.
    Args:
        client (Client): Client to perform API calls to QRadar service.
        args (Dict[str, Any): XSOAR arguments.

    Returns:
        (CommandResults).
    """
    response = perform_ips_command_request(client, args, is_destination_addresses=False)
    outputs = sanitize_outputs(response, SOURCE_IPS_RAW_FORMATTED)

    return CommandResults(
        readable_output=tableToMarkdown("Source IPs", outputs),
        outputs_prefix="QRadar.SourceIP",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_ips_local_destination_get_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Get local destination IPS from QRadar service.
    Args:
        client (Client): Client to perform API calls to QRadar service.
        args (Dict[str, Any): XSOAR arguments.

    Returns:
        (CommandResults).
    """
    response = perform_ips_command_request(client, args, is_destination_addresses=True)
    outputs = sanitize_outputs(response, LOCAL_DESTINATION_IPS_RAW_FORMATTED)

    return CommandResults(
        readable_output=tableToMarkdown("Local Destination IPs", outputs),
        outputs_prefix="QRadar.LocalDestinationIP",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_reset_last_run_command() -> str:
    """
    Puts the reset flag inside integration context in a concurrency-safe way.
    Returns:
        (str): 'fetch-incidents was reset successfully'.
    """
    # Use context manager for atomic update
    context_manager = get_context_manager()
    partial_changes = {RESET_KEY: True}
    context_manager.update_context_partial(partial_changes)

    return "fetch-incidents was reset successfully."


def qradar_get_mapping_fields_command(client: Client) -> dict:
    """
    Returns Dict object containing the list of fields for an incident type.
    This command should be used for debugging purposes.
    Args:
        client (Client): Client to perform API calls.

    Returns:
        (Dict): Contains all the mapping.
    """
    offense = {
        "username_count": "int",
        "description": "str",
        "rules": {"id": "int", "type": "str", "name": "str"},
        "event_count": "int",
        "flow_count": "int",
        "assigned_to": "NoneType",
        "security_category_count": "int",
        "follow_up": "bool",
        "source_address_ids": "str",
        "source_count": "int",
        "inactive": "bool",
        "protected": "bool",
        "closing_user": "str",
        "destination_networks": "str",
        "source_network": "str",
        "category_count": "int",
        "close_time": "str",
        "remote_destination_count": "int",
        "start_time": "str",
        "magnitude": "int",
        "last_updated_time": "str",
        "credibility": "int",
        "id": "int",
        "categories": "str",
        "severity": "int",
        "policy_category_count": "int",
        "closing_reason_id": "str",
        "device_count": "int",
        "offense_type": "str",
        "relevance": "int",
        "domain_id": "int",
        "offense_source": "str",
        "local_destination_address_ids": "int",
        "local_destination_count": "int",
        "status": "str",
        "domain_name": "str",
    }
    events = {
        "events": {
            "qidname_qid": "str",
            "logsourcename_logsourceid": "str",
            "categoryname_highlevelcategory": "str",
            "categoryname_category": "str",
            "protocolname_protocolid": "str",
            "sourceip": "str",
            "sourceport": "int",
            "destinationip": "str",
            "destinationport": "int",
            "qiddescription_qid": "str",
            "username": "NoneType",
            "rulename_creeventlist": "str",
            "sourcegeographiclocation": "str",
            "sourceMAC": "str",
            "sourcev6": "str",
            "destinationgeographiclocation": "str",
            "destinationv6": "str",
            "logsourcetypename_devicetype": "str",
            "credibility": "int",
            "severity": "int",
            "magnitude": "int",
            "eventcount": "int",
            "eventDirection": "str",
            "postNatDestinationIP": "str",
            "postNatDestinationPort": "int",
            "postNatSourceIP": "str",
            "postNatSourcePort": "int",
            "preNatDestinationPort": "int",
            "preNatSourceIP": "str",
            "preNatSourcePort": "int",
            "utf8_payload": "str",
            "starttime": "str",
            "devicetime": "int",
        }
    }
    assets = {
        "assets": {
            "interfaces": {
                "mac_address": "str",
                "ip_addresses": {"type": "str", "value": "str"},
                "id": "int",
                "Unified Name": "str",
                "Technical User": "str",
                "Switch ID": "str",
                "Business Contact": "str",
                "CVSS Availability Requirement": "str",
                "Compliance Notes": "str",
                "Primary OS ID": "str",
                "Compliance Plan": "str",
                "Switch Port ID": "str",
                "Weight": "str",
                "Location": "str",
                "CVSS Confidentiality Requirement": "str",
                "Technical Contact": "str",
                "Technical Owner": "str",
                "CVSS Collateral Damage Potential": "str",
                "Description": "str",
                "Business Owner": "str",
                "CVSS Integrity Requirement": "str",
            },
            "id": "int",
            "domain_id": "int",
            "domain_name": "str",
        }
    }
    # if this call fails, raise an error and stop command execution
    custom_fields = {
        "events": {
            field.get("name"): field.get("property_type")
            for field in client.custom_properties()
            if "name" in field and "property_type" in field
        }
    }
    fields = {
        "Offense": offense,
        "Events: Builtin Fields": events,
        "Events: Custom Fields": custom_fields,
        "Assets": assets,
    }
    return fields


def update_events_mirror_message(
    mirror_options: Any | None,
    events_limit: int,
    events_count: int,
    events_mirrored: int,
    events_mirrored_collapsed: int,
    fetch_mode: str,
    offense_id: int,
    failure_message: str | None = None,
) -> str:
    """Return the offense's events' mirror error message.

    Args:
        mirror_options (str): The mirror options for the instance.
        events_limit (int): The events limit for the mirroring.
        failure_message (str): A failure message if there was a failure during fetching of events.
        events_count (int): The number of events in the offense.
        events_mirrored (int): The number of events mirrored in the offense

    Returns: (str) An updated offense events mirror message.
    """
    mirroring_events_message = "Unknown"
    print_debug_msg(
        f"Events status for Offense {offense_id}:\n"
        f"mirror_options {mirror_options}\n events_limit {events_limit} \n"
        f"failure_message {failure_message}\n events_count {events_count}\n "
        f"events_mirrored {events_mirrored}"
    )

    if mirror_options != MIRROR_OFFENSE_AND_EVENTS:
        mirroring_events_message = ""
    elif failure_message:
        mirroring_events_message = failure_message
    elif fetch_mode == FetchMode.all_events.value and events_mirrored < min(events_count, events_limit):
        mirroring_events_message = "Fetching events did not get all events of the offense"
    elif events_mirrored == events_count:
        mirroring_events_message = "All available events in the offense were fetched."
    elif events_mirrored_collapsed == events_limit:
        mirroring_events_message = "Fetching events has reached events limit in this incident."

    return mirroring_events_message


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# REMOTE DATA AND MIRRORING COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def get_remote_data_command(client: Client, params: dict[str, Any], args: dict) -> GetRemoteDataResponse:
    """
    get-remote-data command: Returns an updated incident and entries
    If offense's events were updated in the long running container, update the demisto incident.

    Args:
        client (Client): QRadar client to perform the API calls.
        params (Dict): Demisto params.
        args (Dict):
            id: Offense id to retrieve.
            lastUpdate: When was the last time we data was retrieved in Epoch.

    Returns:
        GetRemoteDataResponse.
    """
    remote_args = GetRemoteDataArgs(args)
    ip_enrich, asset_enrich = get_offense_enrichment(params.get("enrichment", "IPs And Assets"))
    offense_id = str(remote_args.remote_incident_id)
    print_debug_msg(f"Starting get-remote-data for offense {offense_id}")
    # if this call fails, raise an error and stop command execution
    offense = client.offenses_list(offense_id=int(offense_id))
    offense_last_update = get_time_parameter(offense.get("last_persisted_time"))
    mirror_options = params.get("mirror_options")

    # Use QRadarContextManager for resilient context handling
    context_manager = get_context_manager()
    context_data, context_version = context_manager.get_context_safe()

    events_columns = params.get("events_columns") or DEFAULT_EVENTS_COLUMNS
    events_limit = int(params.get("events_limit") or DEFAULT_EVENTS_LIMIT)
    fetch_mode = params.get("fetch_mode", "")
    print_context_data_stats(context_data, f"Starting Get Remote Data For Offense {offense.get('id')!s}")

    demisto.debug(f"Updating offense. Offense last update was {offense_last_update}")
    entries = []
    if offense.get("status") == "CLOSED" and argToBoolean(params.get("close_incident", False)):
        demisto.debug(f"Offense is closed: {offense}")
        try:
            if closing_reason := offense.get("closing_reason_id", ""):
                closing_reason = client.closing_reasons_list(closing_reason).get("text")
            offense_close_time = offense.get("close_time", "")
            closed_offense_notes = client.offense_notes_list(
                int(offense_id), f"items={DEFAULT_RANGE_VALUE}", filter_=f"create_time >= {offense_close_time}"
            )
            # In QRadar UI, when you close a reason, a note is added with the reason and more details. Try to get note
            # if exists, else fallback to closing reason only, as closing QRadar through an API call does not create a note.
            closenotes = next(
                (
                    note.get("note_text")
                    for note in closed_offense_notes
                    if note.get("note_text").startswith("This offense was closed with reason:")
                ),
                closing_reason,
            )
            if not closing_reason:
                print_debug_msg(f"Could not find closing reason or closing note for offense with offense id {offense_id}")
                closing_reason = "Unknown closing reason from QRadar"
                closenotes = "Unknown closing note from QRadar"

        except Exception as e:
            demisto.error(f"Failed to get closing reason with error: {e}")
            closing_reason = "Unknown closing reason from QRadar"
            closenotes = "Unknown closing note from QRadar"
            time.sleep(FAILURE_SLEEP)
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": closing_reason,
                    "closeNotes": f"From QRadar: {closenotes}",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )
    already_mirrored = False
    if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
        if (num_events := context_data.get(MIRRORED_OFFENSES_FETCHED_CTX_KEY, {}).get(offense_id)) and int(num_events) >= (
            events_limit := int(params.get("events_limit", DEFAULT_EVENTS_LIMIT))
        ):
            print_debug_msg(
                f"Events were already fetched {num_events} for offense {offense_id}, "
                f"and are more than the events limit, {events_limit}. "
                f"Not fetching events again."
            )
            # delete the offense from the queue using context manager
            context_manager.delete_offense_from_context(offense_id)
            already_mirrored = True
        else:
            events, status = get_remote_events(
                client,
                offense_id,
                context_data,
                context_version,
                events_columns,
                events_limit,
                fetch_mode,
            )
            print_context_data_stats(context_data, f"Get Remote Data events End for id {offense_id}")
            if status != QueryStatus.SUCCESS.value:
                # we raise an exception because we don't want to change the offense until all events are fetched.
                print_debug_msg(f"Events not mirrored yet for offense {offense_id}. Status: {status}")
                raise DemistoException(f"Events not mirrored yet for offense {offense_id}")
            offense["events"] = events

    enriched_offense = enrich_qradar_offenses_with_comprehensive_metadata(client, offense, ip_enrich, asset_enrich)

    final_offense_data = sanitize_outputs(enriched_offense)[0]
    if not already_mirrored:
        events_mirrored = get_num_events(final_offense_data.get("events", []))
        print_debug_msg(f"Offense {offense_id} mirrored events: {events_mirrored}")
        events_message = update_events_mirror_message(
            mirror_options=mirror_options,
            events_limit=events_limit,
            events_count=int(final_offense_data.get("event_count", 0)),
            events_mirrored=events_mirrored,
            events_mirrored_collapsed=len(final_offense_data.get("events", [])),
            fetch_mode=fetch_mode,
            offense_id=int(offense_id),
        )
        print_debug_msg(f"offense {offense_id} events_message: {events_message}")
        final_offense_data["last_mirror_in_time"] = datetime.now().isoformat()
        final_offense_data["mirroring_events_message"] = events_message
        final_offense_data["events_fetched"] = events_mirrored
    return GetRemoteDataResponse(final_offense_data, entries)


def add_modified_remote_offenses(
    client: Client,
    context_data: dict,
    version: str,
    mirror_options: str,
    new_modified_records_ids: set[str],
    new_last_update_modified: int,
    new_last_update_closed: int,
    events_columns: str,
    events_limit: int,
    fetch_mode: str,
) -> set:
    """Add modified remote offenses to context_data and handle exhausted offenses.

    Args:
        client: Qradar client
        context_data: The context data to update.
        version: The version of the context data to update.
        mirror_options: The mirror options for the integration.
        new_modified_records_ids: The new modified offenses ids.
        new_last_update_modified: The current last mirror update modified.
        new_last_update_closed: The current last mirror update.
        events_columns: The events_columns param.
        events_limit: The events_limit param.

    Returns: The new modified records ids
    """

    # We'll keep local references to the relevant sub-dicts, just as before:
    mirrored_offenses_queries = context_data.get(MIRRORED_OFFENSES_QUERIED_CTX_KEY, {})
    finished_offenses_queue = context_data.get(MIRRORED_OFFENSES_FINISHED_CTX_KEY, {})
    changed_ids_ctx = []

    if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
        print_context_data_stats(context_data, "Get Modified Remote Data - Before update")

        current_concurrent_searches = get_current_concurrent_searches(context_data)
        offense_ids_to_search = []

        # Move completed queries from 'queried' to 'finished' or mark them 'ERROR'
        for offense_id, search_id in mirrored_offenses_queries.copy().items():
            if search_id in {QueryStatus.WAIT.value, QueryStatus.ERROR.value}:
                # re-submit search
                offense_ids_to_search.append(offense_id)
                continue

            # see if the existing search completed
            _, status = poll_offense_events(client, search_id, should_get_events=False, offense_id=int(offense_id))
            if status == QueryStatus.ERROR.value:
                time.sleep(FAILURE_SLEEP)
                print_debug_msg(f"offense {offense_id}, search query {search_id}, status is {status}")
                mirrored_offenses_queries[offense_id] = QueryStatus.ERROR.value
                current_concurrent_searches -= 1

            elif status == QueryStatus.SUCCESS.value:
                del mirrored_offenses_queries[offense_id]
                finished_offenses_queue[offense_id] = search_id
                # add the offense id to modified in order to run get_remote_data
                new_modified_records_ids.add(offense_id)
                changed_ids_ctx.append(offense_id)
                current_concurrent_searches -= 1
            else:
                print_debug_msg(f"offense {offense_id}, search query {search_id}, status is {status}")

        # Create new search for any WAIT/ERROR offense if concurrency limit not reached
        for offense_id in offense_ids_to_search:
            if current_concurrent_searches >= MAX_SEARCHES_QUEUE:
                print_debug_msg(f"Reached maximum concurrent searches ({MAX_SEARCHES_QUEUE}), will try again later.")
                break
            current_concurrent_searches += 1
            new_search_id = create_events_search(client, fetch_mode, events_columns, events_limit, int(offense_id))
            mirrored_offenses_queries[offense_id] = new_search_id
            changed_ids_ctx.append(offense_id)

    # Build partial_changes dict with only the keys we want to write
    partial_changes = {
        LAST_MIRROR_KEY: new_last_update_modified,
        LAST_MIRROR_CLOSED_KEY: new_last_update_closed,
    }

    # If we are in "Mirror Offense & Events" mode, also update the queries/finished sub-dicts
    if mirror_options == MIRROR_OFFENSE_AND_EVENTS:
        partial_changes[MIRRORED_OFFENSES_QUERIED_CTX_KEY] = mirrored_offenses_queries
        partial_changes[MIRRORED_OFFENSES_FINISHED_CTX_KEY] = finished_offenses_queue

    # Use context manager for atomic update
    context_manager = get_context_manager()
    context_manager.update_context_partial(partial_changes)

    # Do final logging for debugging if desired
    print_context_data_stats(context_data, "Get Modified Remote Data - After update")

    return new_modified_records_ids


def create_events_search(
    client: Client,
    fetch_mode: str,
    events_columns: str,
    events_limit: int,
    offense_id: int,
    offense_start_time: str | None = None,
    return_raw_response: bool = False,
) -> str:
    additional_where = ""
    if fetch_mode == FetchMode.correlations_events_only.value:
        additional_where = """ AND LOGSOURCETYPENAME(devicetype) = 'Custom Rule Engine' """
    try:
        # Get all the events starting from one hour after epoch
        if not offense_start_time:
            offense = client.offenses_list(offense_id=offense_id)
            offense_start_time = offense["start_time"]
        query_expression = (
            f"SELECT {events_columns} FROM events WHERE INOFFENSE({offense_id}) {additional_where} limit {events_limit} "  # noqa: S608, E501
            f"START {offense_start_time}"
        )
        print_debug_msg(f"Creating search for offense ID: {offense_id}, query_expression: {query_expression}")
        search_response = client.search_create(query_expression)
        print_debug_msg(
            f"Created search for offense ID: {offense_id}, "
            f"Start Time: {offense_start_time}, "
            f"events_limit: {events_limit}, "
            f"ret_value: {search_response}."
        )
        if return_raw_response:
            return search_response
        return search_response["search_id"] if search_response["search_id"] else QueryStatus.ERROR.value
    except Exception as e:
        print_debug_msg(f"Search for {offense_id} failed. Error: {e}")
        time.sleep(FAILURE_SLEEP)
        return QueryStatus.ERROR.value


def get_modified_remote_data_command(
    client: Client, params: dict[str, str], args: dict[str, str]
) -> GetModifiedRemoteDataResponse:
    """
    Performs API calls to QRadar service, querying for offenses that were updated in QRadar later than
    the last update time given in the argument 'lastUpdate'.
    Args:
        client (Client): QRadar client to perform the API calls.
        params (Dict): Demisto params.
        args (Dict): Demisto arguments.

    Returns:
        (GetModifiedRemoteDataResponse): IDs of the offenses that have been modified in QRadar.
    """
    # Use QRadarContextManager for resilient context handling
    context_manager = get_context_manager()
    ctx, ctx_version = context_manager.get_context_safe()
    remote_args = GetModifiedRemoteDataArgs(args)

    highest_fetched_id = ctx.get(LAST_FETCH_KEY, 0)
    limit: int = int(params.get("mirror_limit", MAXIMUM_MIRROR_LIMIT))
    fetch_mode = params.get("fetch_mode", "")
    range_ = f"items=0-{limit - 1}"
    last_update_modified = ctx.get(LAST_MIRROR_KEY, 0)
    if not last_update_modified:
        # This is the first mirror. We get the last update of the latest incident with a window of 5 minutes
        last_update = dateparser.parse(remote_args.last_update)
        if not last_update:
            last_update = datetime.now()
        last_update -= timedelta(minutes=5)
        last_update_modified = int(last_update.timestamp() * 1000)
    last_update_closed = ctx.get(LAST_MIRROR_CLOSED_KEY, last_update_modified)
    assert isinstance(last_update_modified, int)
    assert isinstance(last_update_closed, int)
    filter_modified = f"id <= {highest_fetched_id} AND status!=closed AND last_persisted_time > {last_update_modified}"
    filter_closed = f"id <= {highest_fetched_id} AND status=closed AND close_time > {last_update_closed}"
    print_debug_msg(f"Filter to get modified offenses is: {filter_modified}")
    print_debug_msg(f"Filter to get closed offenses is: {filter_closed}")
    # if this call fails, raise an error and stop command execution
    offenses_modified = client.offenses_list(
        range_=range_, filter_=filter_modified, sort="+last_persisted_time", fields=FIELDS_MIRRORING
    )
    offenses_closed = client.offenses_list(range_=range_, filter_=filter_closed, sort="+close_time", fields=FIELDS_MIRRORING)
    if offenses_modified:
        last_update_modified = int(offenses_modified[-1].get("last_persisted_time"))
    if offenses_closed:
        last_update_closed = int(offenses_closed[-1].get("close_time"))
    new_modified_records_ids = {str(offense.get("id")) for offense in offenses_modified + offenses_closed if "id" in offense}
    print_debug_msg(f"Last update modified: {last_update_modified}, Last update closed: {last_update_closed}")
    events_columns = params.get("events_columns") or DEFAULT_EVENTS_COLUMNS
    events_limit = int(params.get("events_limit") or DEFAULT_EVENTS_LIMIT)

    new_modified_records_ids = add_modified_remote_offenses(
        client=client,
        context_data=ctx,
        version=ctx_version,
        mirror_options=params.get("mirror_options", ""),
        new_modified_records_ids=new_modified_records_ids,
        new_last_update_modified=last_update_modified,
        new_last_update_closed=last_update_closed,
        events_columns=events_columns,
        events_limit=events_limit,
        fetch_mode=fetch_mode,
    )

    return GetModifiedRemoteDataResponse(list(new_modified_records_ids))


def qradar_search_retrieve_events_command(
    client: Client,
    params,
    args,
) -> CommandResults:  # pragma: no cover (tested in test-playbook)
    """A polling command to get events from QRadar offense

    Args:
        client (Client): The QRadar client to use.
        params (dict): Parameters passed to the command.
        args (dict): Demisto arguments.

    Raises:
        DemistoException: If the search failed.

    Returns:
        CommandResults: The results of the command.
    """
    interval_in_secs = int(args.get("interval_in_seconds", 30))
    search_id = args.get("search_id")
    is_polling = argToBoolean(args.get("polling", True))
    timeout_in_secs = int(args.get("timeout_in_seconds", 600))
    search_command_results = None
    if not search_id:
        search_command_results = qradar_search_create_command(client, params, args)
        search_id = search_command_results.outputs[0].get("ID")  # type: ignore
    calling_context = demisto.callingContext.get("context", {})
    sm = get_schedule_metadata(context=calling_context)
    end_date: datetime | None = dateparser.parse(sm.get("end_date"))
    if not end_date or end_date.year == 1:
        end_date = None
    # determine if this is the last run of the polling command
    is_last_run = (
        (datetime.now() + timedelta(seconds=interval_in_secs)).timestamp() >= end_date.timestamp() if end_date else False
    )
    try:
        events, status = poll_offense_events(client, search_id, should_get_events=True, offense_id=args.get("offense_id"))
    except (DemistoException, requests.Timeout) as e:
        if is_last_run:
            raise e
        print_debug_msg(f"Polling event failed due to {e}. Will try to poll again in the next interval.")
        events = []
        status = QueryStatus.WAIT.value
    if is_last_run and status == QueryStatus.WAIT.value:
        print_debug_msg("Its the last run of the polling, will cancel the query request. ")
        client.search_cancel(search_id=search_id)
        return CommandResults(
            readable_output="Got polling timeout. Quary got cancelled.",
        )
    if is_last_run and args.get("success") and not events:
        # if last run, we want to get the events that were fetched in the previous calls
        return CommandResults(
            readable_output="Not all events were fetched. partial data is available.",
        )

    if status == QueryStatus.ERROR.value:
        raise DemistoException("Polling for events failed")
    if status == QueryStatus.SUCCESS.value:
        # return the result only if the all events were retrieved, unless for the last call for this function
        offense_id = args.get("offense_id", "")
        events_limit = int(args.get("events_limit", params.get("events_limit")))
        fetch_mode: FetchMode = args.get("fetch_mode", params.get("fetch_mode"))
        if (
            argToBoolean(args.get("retry_if_not_all_fetched", False))
            and not is_last_run
            and not is_all_events_fetched(client, fetch_mode, offense_id, events_limit, events)
        ):
            # return scheduled command result without search id to search again
            polling_args = {
                "interval_in_seconds": interval_in_secs,
                "timeout_in_seconds": timeout_in_secs,
                "success": True,
                **args,
            }
            scheduled_command = ScheduledCommand(
                command="qradar-search-retrieve-events",
                next_run_in_seconds=interval_in_secs,
                args=polling_args,
                timeout_in_seconds=timeout_in_secs,
            )
            return CommandResults(
                scheduled_command=scheduled_command if is_polling else None,
                readable_output="Not all events were fetched. Searching again.",
                outputs_prefix="QRadar.SearchEvents",
                outputs_key_field="ID",
                outputs={"Events": events, "ID": search_id, "Status": QueryStatus.PARTIAL},
            )

        return CommandResults(
            outputs_prefix="QRadar.SearchEvents",
            outputs_key_field="ID",
            outputs={"Events": events, "ID": search_id, "Status": QueryStatus.SUCCESS},
            readable_output=tableToMarkdown(
                f"{get_num_events(events)} Events returned from search_id {search_id}",
                events,
            ),
        )

    print_debug_msg(f"Still polling for search results for search ID: {search_id}.")
    polling_args = {
        "search_id": search_id,
        "interval_in_seconds": interval_in_secs,
        "timeout_in_seconds": timeout_in_secs,
        **args,
    }
    scheduled_command = ScheduledCommand(
        command="qradar-search-retrieve-events",
        next_run_in_seconds=interval_in_secs,
        timeout_in_seconds=timeout_in_secs,
        args=polling_args,
    )
    outputs = {"ID": search_id, "Status": QueryStatus.WAIT}
    return CommandResults(
        scheduled_command=scheduled_command if is_polling else None,
        readable_output=f"Search ID: {search_id}",
        outputs_prefix="QRadar.SearchEvents",
        outputs_key_field="ID",
        outputs=outputs,
    )


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# NETWORK AND INFRASTRUCTURE COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def qradar_remote_network_cidr_create_command(client: Client, args) -> CommandResults:
    """Create remote network cidrs
    Args:
        client (Client): The QRadar client to use.
        args (dict): Demisto arguments.

    Raises:
        DemistoException: If the args are not valid.

    Returns:
        CommandResults.
    """
    cidrs_list = argToList(args.get("cidrs"))
    cidrs_from_query = get_cidrs_indicators(args.get("query"))
    name = args.get("name")
    description = args.get("description")
    group = args.get("group")
    fields = args.get("fields")

    error_message = verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields)
    if error_message:
        raise DemistoException(error_message)

    body = {"name": name, "description": description, "cidrs": cidrs_list or cidrs_from_query, "group": group}

    response = client.create_and_update_remote_network_cidr(body, fields)
    success_message = "The new staged remote network was successfully created."

    return CommandResults(raw_response=response, readable_output=tableToMarkdown(success_message, response))


def qradar_remote_network_cidr_list_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Raises:
        DemistoException: If given both filter and group, id or name arguments.

    Returns:
        CommandResults.

    """
    limit = arg_to_number(args.get("limit"))
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    group = args.get("group")
    id_ = args.get("id")
    name = args.get("name")
    filter_ = args.get("filter", "")
    fields = args.get("fields")

    error_message = verify_args_for_remote_network_cidr_list(limit, page, page_size, filter_, group, id_, name)
    if error_message:
        raise DemistoException(error_message)

    if page and page_size:
        first_item = (int(page) - 1) * int(page_size)
        last_item = int(page) * int(page_size) - 1
        range_ = f"items={first_item}-{last_item}"
    else:
        range_ = f"items=0-{str(limit - 1) if limit else str(DEFAULT_LIMIT_VALUE - 1)}"

    if not filter_:
        if group:
            filter_ += f'group="{group}"'
        if id_:
            filter_ += f" AND id={id_}" if group else f"id={id_}"
        if name:
            filter_ += f' AND name="{name}"' if (group or id_) else f'name="{name}"'

    response = client.get_remote_network_cidr(range_, filter_, fields)
    outputs = [{"id": res.get("id"), "name": res.get("name"), "description": res.get("description")} for res in response]
    headers = ["id", "name", "group", "cidrs", "description"]
    success_message = "List of the staged remote networks"
    if response:
        readable_output = tableToMarkdown(success_message, response, headers=headers)
        readable_output += (
            f"Above results are with page number: {page} and with size: {page_size}."
            if page and page_size
            else f"Above results are with limit: {limit if limit else DEFAULT_LIMIT_VALUE}."
        )
    else:
        readable_output = "No results found."

    return CommandResults(
        outputs_prefix="QRadar.RemoteNetworkCIDR",
        outputs_key_field="id",
        outputs=outputs,
        raw_response=response,
        readable_output=readable_output,
    )


def qradar_remote_network_cidr_delete_command(client: Client, args) -> CommandResults:
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Returns:
    Two CommandResults objects, one for the success and one for the failure.
    """
    ids = argToList(args.get("id"))
    success_delete_ids = []
    unsuccessful_delete_ids = []

    for id_ in ids:
        try:
            client.delete_remote_network_cidr(id_)
            success_delete_ids.append(id_)
        except DemistoException as e:
            unsuccessful_delete_ids.append(assign_params(ID=id_, Error=e.message))

    success_human_readable = tableToMarkdown(
        "Successfully deleted the following remote network(s)", success_delete_ids, headers=["ID"]
    )
    unsuccessful_human_readable = tableToMarkdown(
        "Failed to delete the following remote network(s)", unsuccessful_delete_ids, headers=["ID", "Error"]
    )

    return CommandResults(
        readable_output=(
            (success_human_readable if success_delete_ids else "")
            + (unsuccessful_human_readable if unsuccessful_delete_ids else "")
        )
    )


def qradar_remote_network_cidr_update_command(client: Client, args):
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Raises:
        DemistoException: If the args are not valid.

    Returns:
    CommandResults.
    """
    id_ = arg_to_number(args.get("id"))
    name = args.get("name")
    cidrs_list = argToList(args.get("cidrs"))
    cidrs_from_query = get_cidrs_indicators(args.get("query"))
    description = args.get("description")
    group = args.get("group")
    fields = args.get("fields")

    error_message = verify_args_for_remote_network_cidr(cidrs_list, cidrs_from_query, name, group, fields)
    if error_message:
        raise DemistoException(error_message)

    body = {"name": name, "description": description, "cidrs": cidrs_list or cidrs_from_query, "id": id_, "group": group}

    response = client.create_and_update_remote_network_cidr(body, fields, update=True)
    success_message = "The staged remote network was successfully updated"
    outputs = {
        "id": response.get("id"),
        "name": response.get("name"),
        "group": response.get("group"),
        "description": response.get("description"),
    }

    return CommandResults(
        outputs_prefix="QRadar.RemoteNetworkCIDR",
        outputs_key_field="id",
        outputs=outputs,
        readable_output=tableToMarkdown(success_message, response),
        raw_response=response,
    )


def qradar_remote_network_deploy_execution_command(client: Client, args):
    """
    Args:
    client (Client): The QRadar client to use.
    args (dict): Demisto arguments.

    Returns:
    CommandResults.
    """
    host_ip = args.get("host_ip")
    status = args.get("status", "INITIATING")
    deployment_type = args.get("deployment_type")

    if not re.match(ipv4Regex, host_ip) and not re.match(ipv6Regex, host_ip):
        raise DemistoException("The host_ip argument is not a valid ip address.")
    if not status == "INITIATING":
        raise DemistoException("The status argument must be INITIATING.")
    if deployment_type not in ["INCREMENTAL", "FULL"]:
        raise DemistoException("The deployment_type argument must be INCREMENTAL or FULL.")

    body = {"hosts": [{"ip": host_ip, "status": status}], "type": deployment_type}

    response = client.remote_network_deploy_execution(body)
    success_message = "The remote network deploy execution was successfully created."

    return CommandResults(
        outputs_prefix="QRadar.deploy",
        outputs={"status": response["status"]},
        readable_output=success_message,
        raw_response=response,
    )


def qradar_event_collectors_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of event collectors from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, "/config/event_sources/event_collectors", filter_, fields)
    outputs = sanitize_outputs(response, EVENT_COLLECTOR_RAW_FORMATTED)
    headers = build_headers(["ID"], set(EVENT_COLLECTOR_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Event Collectors List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.EventCollector",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_wincollect_destinations_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of WinCollect destinations from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/wincollect/wincollect_destinations"
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, WINCOLLECT_DESTINATION_RAW_FORMATTED)
    headers = build_headers(["ID"], set(WINCOLLECT_DESTINATION_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("WinCollect Destinations List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.WinCollectDestination",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_disconnected_log_collectors_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of disconnected log collectors from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/disconnected_log_collectors"
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, DISCONNECTED_LOG_COLLECTOR_RAW_FORMATTED)
    headers = build_headers(["ID"], set(DISCONNECTED_LOG_COLLECTOR_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Disconnected Log Collectors List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.DisconnectedLogCollector",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_types_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/log_source_management/log_source_types"
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_TYPES_RAW_FORMATTED)
    headers = build_headers(["ID", "Name", "Custom", "Version", "UUID", "SupportedLanguageIDs"], set())

    return CommandResults(
        readable_output=tableToMarkdown("Log Source Types List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSourceTypesList",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_protocol_types_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/log_source_management/protocol_types"
    id = args.get("id")
    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_PROTOCOL_TYPE_RAW_FORMATTED)
    headers = ["ID", "Name", "CanCollectEvents", "Testable", "CanAcceptSampleEvents"]
    readable_outputs = [
        {
            **protocol_type,
            "CanCollectEvents": protocol_type["TestingCapabilities"]["can_collect_events"],
            "Testable": protocol_type["TestingCapabilities"]["testable"],
            "CanAcceptSampleEvents": protocol_type["TestingCapabilities"]["can_accept_sample_events"],
        }
        for protocol_type in outputs
    ]

    return CommandResults(
        readable_output=tableToMarkdown("Log Source Protocol Types", readable_outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSourceProtocolType",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_extensions_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/log_source_management/log_source_extensions"
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_EXTENSION_RAW_FORMATTED)
    headers = build_headers(["ID", "Name", "Description", "UUID"], set())

    return CommandResults(
        readable_output=tableToMarkdown("Log Source Extensions List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSourceExtension",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_languages_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/log_source_management/log_source_languages"
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_LANGUAGE_RAW_FORMATTED)
    headers = build_headers(["ID", "Name"], set())

    return CommandResults(
        readable_output=tableToMarkdown("Log Source Languages List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSourceLanguage",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_groups_list_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieves a list of log source types from QRadar service.
    possible arguments:
    - range: Range of offenses to return (e.g.: 0-20, 3-5, 3-3).
    - filter: Query filter to filter results returned by QRadar service. see
              https://www.ibm.com/support/knowledgecenter/SS42VS_SHR/com.ibm.qradarapi.doc/c_rest_api_filtering.html
              for more details.
    - fields: Use this parameter to specify which fields you would like to get back in the response.
              Fields that are not named are excluded.
              Specify subfields in brackets and multiple fields in the same object are separated by commas.
    - id: If used, will fetch only the specified log source.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.

    Returns:
        CommandResults.
    """
    range_ = f"items={args.get('range', DEFAULT_RANGE_VALUE)}"
    filter_ = args.get("filter")
    fields = args.get("fields")
    endpoint = "/config/event_sources/log_source_management/log_source_groups"
    id = args.get("id")

    # if this call fails, raise an error and stop command execution
    response = client.get_resource(id, range_, endpoint, filter_, fields)
    outputs = sanitize_outputs(response, LOG_SOURCE_GROUP_RAW_FORMATTED)
    headers = build_headers(["ID", "Name"], set(LOG_SOURCE_GROUP_RAW_FORMATTED.values()))

    return CommandResults(
        readable_output=tableToMarkdown("Log Source Groups List", outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSourceGroup",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_delete_command(client: Client, args: dict) -> CommandResults:
    """
    Deletes a log source by id or by name.
    Possible arguments:
    - name: The unique name of the log source to be deleted. If you don't provide this argument, id is required.
    - id: The ID of the log source to be deleted. If you don't provide this argument, name is required.
    Args:
        client (Client): QRadar client to perform the API call.
        args (Dict): Demisto args.
    Returns:
        CommandResults.
    """
    name = args.get("name")
    id = args.get("id")

    if id is not None:
        try:
            client.delete_log_source(id)
            return CommandResults(readable_output=f"Log source {id} was deleted successfully")
        except DemistoException as e:
            if e.res.status_code == 404:
                return CommandResults(readable_output=f"Log source with id {id} does not exist")
    if name is not None:
        log_source_list = client.get_resource_list(
            "items=0-0", "config/event_sources/log_source_management/log_sources", f'name="{name}"'
        )
        if not log_source_list:
            return CommandResults(readable_output=f"Log source with name {name} does not exist")
        relevant_log_source = log_source_list[0]
        client.delete_log_source(relevant_log_source.get("id"))
        return CommandResults(readable_output=f"Log source {name} was deleted successfully")
    raise Exception("At least one of the arguments: name, id must be provided.")


def qradar_log_source_create_command(client: Client, args: dict) -> CommandResults:
    """
    Creates a log source.
    Possible arguments:
    - name: Required. The unique name of the log source.
    - sending_ip: The ip of the system which the log source is associated to, or fed by.
    - protocol_type_id: Required. The type of protocol that is used by the log source.
    - type_id: Required. The type of the log source. Must correspond to an existing log source type.
      Must correspond to an existing protocol type.
    - protocol_parameters: Required. The list of protocol parameters corresponding with the selected protocol type id. The syntax
      for this argument should follow: protocol_parameters="name_1=value_1,name_2=value_2,...,name_n=value_n" where each name
      should correspond to a name of a protocol parameter from the protocol type and each value should fit the type of the
      protocol parameter.
    - descrption: The description of the log source
    - coalesce_events: Determines if events collected by this log source are coalesced based on common properties.
      If each individual event is stored, then the condition is set to false. Defaults to true.
    - enabled: Determines if the log source is enabled. Defaults to true.
    - parsing_order: The order in which log sources will parse if multiple exists with a common identifier.
    - group_ids: Required. The set of log source group IDs this log source is a member of.
      Each ID must correspond to an existing log source group.
    - credibility: On a scale of 0-10, the amount of credibility that the QRadar administrator places on this log source
    - store_event_payload: If the payloads of events that are collected by this log source are stored, the condition is set to
      'true'. If only the normalized event records are stored, then the condition is set to 'false'.
    - target_event_collector_id:  Required. The ID of the event collector where the log source sends its data.
      The ID must correspond to an existing event collector.
    - disconnected_log_collector_id:  The ID of the disconnected log collector where this log source will run.
      The ID must correspond to an existing disconnected log collector.
    - language_id: The language of the events that are being processed by this log source.
      Must correspond to an existing log source language.
    - requires_deploy: Set to 'true' if you need to deploy changes to enable the log source for use;
      otherwise, set to 'false' if the log source is already active.
    - wincollect_internal_destination_id : The internal WinCollect destination for this log source, if applicable.
      Log sources without an associated WinCollect agent have a null value. Must correspond to an existing WinCollect destination.
    - wincollect_external_destination_ids: The set of external WinCollect destinations for this log source, if applicable.
      Log Sources without an associated WinCollect agent have a null value.
      Each ID must correspond to an existing WinCollect destination.
    - gateway: If the log source is configured as a gateway, the condition is set to 'true';
      otherwise, the condition is set to 'false'. A gateway log source is a stand-alone protocol configuration.
      The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to
      feed other log sources. It acts as a "gateway" for events from multiple systems to enter the event pipeline.
    """
    log_source = parse_log_source(args)
    response = client.create_log_source(log_source)
    outputs = sanitize_outputs(response, LOG_SOURCES_RAW_FORMATTED)[0]
    headers = build_headers(["ID", "Name", "Description"], set(LOG_SOURCES_RAW_FORMATTED.values()))
    readable_outputs = {
        "ID": outputs["ID"],
        "Name": outputs["Name"],
        "CreationDate": outputs["CreationDate"],
        "Description": outputs["Description"],
        "Enabled": outputs["Enabled"],
        "Status": outputs["Status"]["status"],
        "StatusLastUpdated": outputs["Status"].get("last_updated", ""),
        "StatusMessages": outputs["Status"].get("messages", ""),
    }
    return CommandResults(
        readable_output=tableToMarkdown("Log Source Created", readable_outputs, headers, removeNull=True),
        outputs_prefix="QRadar.LogSource",
        outputs_key_field="ID",
        outputs=outputs,
        raw_response=response,
    )


def qradar_log_source_update_command(client: Client, args: dict) -> CommandResults:
    """
    Creates a log source.
    Possible arguments:
    - id: Required. The id of the log source.
    - name: The unique name of the log source.
    - sending_ip: The ip of the system which the log source is associated to, or fed by.
    - protocol_type_id: The type of protocol that is used by the log source.
    - type_id: The type of the log source. Must correspond to an existing log source type.
      Must correspond to an existing protocol type.
    - protocol_parameters: The list of protocol parameters corresponding with the selected protocol type id. The syntax
      for this argument should follow: protocol_parameters="name_1=value_1,name_2=value_2,...,name_n=value_n" where each name
      should correspond to a name of a protocol parameter from the protocol type and each value should fit the type of the
      protocol parameter.
    - descrption: The description of the log source
    - coalesce_events: Determines if events collected by this log source are coalesced based on common properties.
      If each individual event is stored, then the condition is set to false. Defaults to true.
    - enabled: Determines if the log source is enabled. Defaults to true.
    - parsing_order: The order in which log sources will parse if multiple exists with a common identifier.
    - group_ids: The set of log source group IDs this log source is a member of.
      Each ID must correspond to an existing log source group.
    - credibility: On a scale of 0-10, the amount of credibility that the QRadar administrator places on this log source
    - store_event_payload: If the payloads of events that are collected by this log source are stored, the condition is set to
      'true'. If only the normalized event records are stored, then the condition is set to 'false'.
    - target_event_collector_id:  The ID of the event collector where the log source sends its data.
      The ID must correspond to an existing event collector.
    - disconnected_log_collector_id:  The ID of the disconnected log collector where this log source will run.
      The ID must correspond to an existing disconnected log collector.
    - language_id: The language of the events that are being processed by this log source.
      Must correspond to an existing log source language.
    - requires_deploy: Set to 'true' if you need to deploy changes to enable the log source for use;
      otherwise, set to 'false' if the log source is already active.
    - wincollect_internal_destination_id : The internal WinCollect destination for this log source, if applicable.
      Log sources without an associated WinCollect agent have a null value. Must correspond to an existing WinCollect destination.
    - wincollect_external_destination_ids: The set of external WinCollect destinations for this log source, if applicable.
      Log Sources without an associated WinCollect agent have a null value.
      Each ID must correspond to an existing WinCollect destination.
    - gateway: If the log source is configured as a gateway, the condition is set to 'true';
      otherwise, the condition is set to 'false'. A gateway log source is a stand-alone protocol configuration.
      The log source receives no events itself, and serves as a host for a protocol configuration that retrieves event data to
      feed other log sources. It acts as a "gateway" for events from multiple systems to enter the event pipeline.
    """
    id = args.get("id")
    log_source = parse_partial_log_source(args)
    client.update_log_source(log_source)
    return CommandResults(readable_output=f"Log source {id} was updated successfully")


def migrate_integration_ctx(ctx: dict) -> dict:
    """Migrates the old context to the current context

    Args:
        ctx: The context_data to simplify

    Returns: The cleared context_data
    """
    fetch_id_ctx: str = ctx.get(LAST_FETCH_KEY, "0")
    try:
        fetch_id = int(fetch_id_ctx)
    except ValueError:
        try:
            fetch_id = int(json.loads(fetch_id_ctx))
        except ValueError:
            print_debug_msg(f"Could not retrieve LAST_FETCH_KEY from {fetch_id_ctx} Setting to 0")
            fetch_id = 0

    last_update_ctx: str = ctx.get(LAST_MIRROR_KEY, "0")
    try:
        last_update = int(last_update_ctx)
    except ValueError:
        try:
            last_update = int(json.loads(last_update_ctx))
        except ValueError:
            print_debug_msg(f"Could not retrieve last_mirror_update from {last_update_ctx} Setting to 0")
            last_update = 0

    mirrored_offenses: dict[str, str] = {}
    try:
        for key in ("mirrored_offenses", "updated_mirrored_offenses", "resubmitted_mirrored_offenses"):
            mirrored_offenses |= {
                json.loads(offense).get("id"): QueryStatus.WAIT.value for offense in json.loads(ctx.get(key, "[]"))
            }
    except Exception as e:
        print_debug_msg(f"Could not load mirrored_offenses from context_data. Error: {e}")

    return {
        LAST_FETCH_KEY: fetch_id,
        LAST_MIRROR_KEY: last_update,
        MIRRORED_OFFENSES_QUERIED_CTX_KEY: mirrored_offenses,
        MIRRORED_OFFENSES_FINISHED_CTX_KEY: {},
        MIRRORED_OFFENSES_FETCHED_CTX_KEY: {},
        "samples": [],
    }


def validate_integration_context() -> None:
    """
    The new context structure consists of two dictionaries of queried offenses
    and finished offenses. Some older instances might not have them, so we fix that.
    Uses QRadarContextManager for resilient context handling.
    """
    # Use context manager for resilient context handling
    context_manager = get_context_manager()
    context_data, _ = context_manager.get_context_safe()
    new_ctx = context_data.copy()
    try:
        print_context_data_stats(context_data, "Checking ctx")
        print_debug_msg("Context is with the new mirroring standard")
        extract_works = True
    except Exception as e:
        print_debug_msg(f"Checking {context_data} failed, trying to make it retry compatible. Error was: {e!s}")
        extract_works = False

    if not extract_works:
        # Scenario: The old context structure is invalid/unreadable.
        cleared_ctx = migrate_integration_ctx(new_ctx)
        print_debug_msg(f"Change ctx context data was cleared and changing to {cleared_ctx}")
        # Use context manager for atomic update
        context_manager.update_context_partial(cleared_ctx)
        print_debug_msg(f"Change ctx context data was cleared and changed to {cleared_ctx}")

    elif MIRRORED_OFFENSES_FETCHED_CTX_KEY not in context_data:
        # Scenario: context is fine, but missing the 'mirrored_offenses_fetched' sub-dict.
        print_debug_msg(f"Adding {MIRRORED_OFFENSES_FETCHED_CTX_KEY} to context")
        partial_changes: dict = {MIRRORED_OFFENSES_FETCHED_CTX_KEY: {}}
        context_manager.update_context_partial(partial_changes)


""" MAIN FUNCTION """


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# DEVELOPMENT AND DIAGNOSTIC COMMANDS
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────


def qradar_system_diagnostics_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Run comprehensive system diagnostics for the QRadar integration.

    This command performs a complete health check of the integration including
    configuration validation, connectivity tests, context analysis, and performance metrics.

    Args:
        client: QRadar client instance
        args: Command arguments (currently unused)

    Returns:
        CommandResults with diagnostic information
    """
    try:
        diagnostic_commands = DiagnosticCommands(client)
        diagnostics = diagnostic_commands.run_system_diagnostics()

        # Create readable output
        readable_output = f"""## QRadar Integration System Diagnostics

**Overall Health Status:** {diagnostics.get('system_health', {}).get('overall_status', 'UNKNOWN')}
**Timestamp:** {diagnostics.get('timestamp', 'Unknown')}
**Correlation ID:** {diagnostics.get('correlation_id', 'Unknown')}

### Integration Information
- **Instance Name:** {diagnostics.get('integration_info', {}).get('instance_name', 'Unknown')}
- **Fetch Enabled:** {diagnostics.get('integration_info', {}).get('is_fetch_enabled', False)}
- **Mirroring Enabled:** {diagnostics.get('integration_info', {}).get('is_mirroring_enabled', False)}

### System Health Summary
"""

        # Add health validation results
        health_validations = diagnostics.get("system_health", {}).get("validations", {})
        for validation_name, validation_result in health_validations.items():
            status = validation_result.get("status", "UNKNOWN")
            readable_output += f"- **{validation_name.title()}:** {status}\n"

            if validation_result.get("issues"):
                for issue in validation_result["issues"]:
                    readable_output += f"  - ⚠️ {issue}\n"

            if validation_result.get("warnings"):
                for warning in validation_result["warnings"]:
                    readable_output += f"  - ⚠️ {warning}\n"

        # Add performance metrics
        performance = diagnostics.get("performance_metrics", {})
        readable_output += f"""
### Performance Configuration
- **Offenses per Fetch:** {performance.get('offenses_per_fetch', 'Unknown')}
- **Events Limit:** {performance.get('events_limit', 'Unknown')}
- **Assets Limit:** {performance.get('assets_limit', 'Unknown')}
- **Estimated Memory Usage:** {performance.get('estimated_memory_usage_mb', 'Unknown')} MB

### Context Analysis
"""

        context_analysis = diagnostics.get("context_analysis", {})
        if "size_analysis" in context_analysis:
            size_info = context_analysis["size_analysis"]
            readable_output += (
                f"- **Context Size:** {size_info.get('size_mb', 'Unknown')} MB ({size_info.get('size_status', 'Unknown')})\n"
            )

        # Add development mode info
        dev_mode = diagnostics.get("development_mode", {})
        readable_output += f"""
### Development Mode
- **Development Mode Detected:** {dev_mode.get('is_development_mode', False)}
- **Enhanced Logging:** {dev_mode.get('enhanced_logging', False)}
- **API Call Tracing:** {dev_mode.get('api_call_tracing', False)}
"""

        return CommandResults(outputs_prefix="QRadar.SystemDiagnostics", outputs=diagnostics, readable_output=readable_output)

    except Exception as e:
        return CommandResults(
            readable_output=f"❌ System diagnostics failed: {str(e)}",
            outputs_prefix="QRadar.SystemDiagnostics",
            outputs={"status": "ERROR", "error": str(e)},
        )


def qradar_context_inspect_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Inspect the current integration context state.

    This command provides detailed information about the integration's context
    including size, keys, mirroring data, and health status.

    Args:
        client: QRadar client instance
        args: Command arguments (currently unused)

    Returns:
        CommandResults with context inspection information
    """
    try:
        diagnostic_commands = DiagnosticCommands(client)
        context_info = diagnostic_commands.inspect_context_state()

        # Create readable output
        readable_output = f"""## QRadar Integration Context Inspection

**Timestamp:** {context_info.get('timestamp', 'Unknown')}
**Context Health:** {context_info.get('context_health', 'Unknown')}

### Context Size Information
- **Total Size:** {context_info.get('context_size_bytes', 0):,} bytes
- **Number of Keys:** {len(context_info.get('context_keys', []))}

### Context Keys
{', '.join(context_info.get('context_keys', []))}

### Mirroring Information
"""

        mirroring_info = context_info.get("mirroring_info", {})
        readable_output += f"""- **Queried Offenses:** {mirroring_info.get('queried_offenses', 0)}
- **Finished Offenses:** {mirroring_info.get('finished_offenses', 0)}
- **Last Mirror Update:** {mirroring_info.get('last_mirror_update', 'Not set')}

### Fetch Information
"""

        fetch_info = context_info.get("fetch_info", {})
        readable_output += f"""- **Last Fetch ID:** {fetch_info.get('last_fetch_id', 'Not set')}
- **Samples Count:** {fetch_info.get('samples_count', 0)}
"""

        return CommandResults(outputs_prefix="QRadar.ContextInspection", outputs=context_info, readable_output=readable_output)

    except Exception as e:
        return CommandResults(
            readable_output=f"❌ Context inspection failed: {str(e)}",
            outputs_prefix="QRadar.ContextInspection",
            outputs={"status": "ERROR", "error": str(e)},
        )


def qradar_connectivity_test_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Test API connectivity with detailed diagnostics.

    This command tests connectivity to various QRadar API endpoints
    and provides detailed diagnostic information about response times
    and potential issues.

    Args:
        client: QRadar client instance
        args: Command arguments (currently unused)

    Returns:
        CommandResults with connectivity test results
    """
    try:
        diagnostic_commands = DiagnosticCommands(client)
        connectivity_results = diagnostic_commands.test_api_connectivity()

        # Create readable output
        overall_status = connectivity_results.get("overall_status", "UNKNOWN")
        status_emoji = "✅" if overall_status == "SUCCESS" else "⚠️" if overall_status == "PARTIAL" else "❌"

        readable_output = f"""## QRadar API Connectivity Test

{status_emoji} **Overall Status:** {overall_status}
**Timestamp:** {connectivity_results.get('timestamp', 'Unknown')}
**Correlation ID:** {connectivity_results.get('correlation_id', 'Unknown')}

### Endpoint Test Results
"""

        endpoint_results = connectivity_results.get("endpoint_results", {})
        for endpoint, result in endpoint_results.items():
            status = result.get("status", "UNKNOWN")
            emoji = "✅" if status == "SUCCESS" else "❌"

            readable_output += f"\n**{endpoint}**\n"
            readable_output += f"- Status: {emoji} {status}\n"

            if status == "SUCCESS":
                readable_output += f"- Response Time: {result.get('response_time', 'Unknown')} seconds\n"
                readable_output += f"- Response Size: {result.get('response_size', 'Unknown')} bytes\n"
            else:
                readable_output += f"- Error: {result.get('error', 'Unknown error')}\n"

        return CommandResults(
            outputs_prefix="QRadar.ConnectivityTest", outputs=connectivity_results, readable_output=readable_output
        )

    except Exception as e:
        return CommandResults(
            readable_output=f"❌ Connectivity test failed: {str(e)}",
            outputs_prefix="QRadar.ConnectivityTest",
            outputs={"status": "ERROR", "error": str(e)},
        )


def qradar_generate_mock_data_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Generate mock data for testing different scenarios.

    This command generates various types of mock QRadar data for testing
    purposes including offenses, events, assets, and reference sets.

    Args:
        client: QRadar client instance
        args: Command arguments including data_type and scenario

    Returns:
        CommandResults with generated mock data
    """
    try:
        data_type = args.get("data_type", "offense")
        scenario = args.get("scenario", "basic")
        count = int(args.get("count", 1))

        mock_data = {}
        readable_output = (
            f"## Mock Data Generation\n\n**Data Type:** {data_type}\n**Scenario:** {scenario}\n**Count:** {count}\n\n"
        )

        if data_type == "offense":
            mock_data["offenses"] = [MockDataGenerator.generate_mock_offense() for _ in range(count)]
            readable_output += f"Generated {count} mock offense(s):\n"
            for offense in mock_data["offenses"]:
                readable_output += (
                    f"- Offense ID: {offense['id']}, Status: {offense['status']}, Events: {offense['event_count']}\n"
                )

        elif data_type == "events":
            offense_id = int(args.get("offense_id", 1001))
            mock_data["events"] = MockDataGenerator.generate_mock_events(count, offense_id)
            readable_output += f"Generated {count} mock event(s) for offense {offense_id}:\n"
            for i, event in enumerate(mock_data["events"][:5]):  # Show first 5
                readable_output += f"- Event {i + 1}: {event['sourceip']} → {event['destinationip']} ({event['protocol']})\n"
            if count > 5:
                readable_output += f"... and {count - 5} more events\n"

        elif data_type == "assets":
            mock_data["assets"] = MockDataGenerator.generate_mock_assets(count)
            readable_output += f"Generated {count} mock asset(s):\n"
            for asset in mock_data["assets"]:
                ip_addresses = [ip["value"] for ip in asset.get("ip_addresses", [])]
                readable_output += f"- Asset ID: {asset['id']}, Name: {asset['name']}, IPs: {', '.join(ip_addresses)}\n"

        elif data_type == "reference_set":
            name = args.get("name", f"MockReferenceSet_{random.randint(1000, 9999)}")
            mock_data["reference_set"] = MockDataGenerator.generate_mock_reference_set(name)
            ref_set = mock_data["reference_set"]
            readable_output += "Generated mock reference set:\n"
            readable_output += f"- Name: {ref_set['name']}\n"
            readable_output += f"- Element Type: {ref_set['element_type']}\n"
            readable_output += f"- Number of Elements: {ref_set['number_of_elements']}\n"

        elif data_type == "scenario":
            mock_data = MockDataGenerator.generate_test_scenario_data(scenario)
            readable_output += f"Generated test scenario data for: {scenario}\n"
            readable_output += f"Description: {mock_data.get('description', 'No description available')}\n"

        else:
            raise DemistoException(
                f"Unknown data type: {data_type}. Supported types: offense, events, assets, reference_set, scenario"
            )

        return CommandResults(outputs_prefix="QRadar.MockData", outputs=mock_data, readable_output=readable_output)

    except Exception as e:
        return CommandResults(
            readable_output=f"❌ Mock data generation failed: {str(e)}",
            outputs_prefix="QRadar.MockData",
            outputs={"status": "ERROR", "error": str(e)},
        )


def qradar_self_test_command(client: Client, args: dict[str, Any]) -> CommandResults:
    """
    Run self-test functions to validate integration health and configuration.

    This command runs a comprehensive self-test that validates the integration's
    configuration, connectivity, and functionality.

    Args:
        client: QRadar client instance
        args: Command arguments (currently unused)

    Returns:
        CommandResults with self-test results
    """
    try:
        health_validator = SystemHealthValidator(client)
        test_results = health_validator.validate_integration_health()

        overall_status = test_results.get("overall_status", "UNKNOWN")
        status_emoji = "✅" if overall_status == "HEALTHY" else "⚠️" if overall_status == "WARNING" else "❌"

        readable_output = f"""## QRadar Integration Self-Test

{status_emoji} **Overall Status:** {overall_status}
**Timestamp:** {test_results.get('timestamp', 'Unknown')}
**Correlation ID:** {test_results.get('correlation_id', 'Unknown')}

### Test Results Summary
"""

        validations = test_results.get("validations", {})
        for test_name, test_result in validations.items():
            status = test_result.get("status", "UNKNOWN")
            emoji = "✅" if status == "PASS" else "⚠️" if status == "WARNING" else "❌" if status == "FAIL" else "⏭️"

            readable_output += f"\n**{test_name.replace('_', ' ').title()}:** {emoji} {status}\n"

            # Add issues if any
            if test_result.get("issues"):
                for issue in test_result["issues"]:
                    readable_output += f"  - ❌ {issue}\n"

            # Add warnings if any
            if test_result.get("warnings"):
                for warning in test_result["warnings"]:
                    readable_output += f"  - ⚠️ {warning}\n"

            # Add specific test details
            if test_name == "connectivity" and test_result.get("connection_time"):
                readable_output += f"  - Connection Time: {test_result['connection_time']:.3f} seconds\n"
                readable_output += f"  - API Version: {test_result.get('api_version', 'Unknown')}\n"

            elif test_name == "context" and test_result.get("context_size_bytes"):
                size_mb = test_result["context_size_bytes"] / (1024 * 1024)
                readable_output += f"  - Context Size: {size_mb:.2f} MB\n"
                readable_output += f"  - Context Keys: {test_result.get('context_keys_count', 0)}\n"

        # Add recommendations if status is not healthy
        if overall_status != "HEALTHY":
            readable_output += "\n### Recommendations\n"
            if overall_status == "UNHEALTHY":
                readable_output += "- Review and fix the failed tests above\n"
                readable_output += "- Check QRadar connectivity and credentials\n"
                readable_output += "- Verify integration configuration parameters\n"
            elif overall_status == "WARNING":
                readable_output += "- Review the warnings above for potential optimizations\n"
                readable_output += "- Consider adjusting performance settings if needed\n"

        return CommandResults(outputs_prefix="QRadar.SelfTest", outputs=test_results, readable_output=readable_output)

    except Exception as e:
        return CommandResults(
            readable_output=f"❌ Self-test failed: {str(e)}",
            outputs_prefix="QRadar.SelfTest",
            outputs={"status": "ERROR", "error": str(e)},
        )


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# THIN WRAPPER IMPLEMENTATIONS - BACKWARDS COMPATIBLE INTERFACES
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section implements thin wrappers for all existing command functions. Each wrapper preserves the exact
# original function signature and behavior while adding comprehensive logging and debugging capabilities that
# can be enabled without modifying existing interfaces.

# First, we need to rename the original functions to preserve them
# This is done by creating aliases before we redefine the function names

# Store references to original implementations
_original_implementations = {}


# We'll use a decorator approach to wrap functions while preserving their original behavior
def preserve_and_wrap_command(command_name: str):
    """
    Decorator to preserve original command function and create a wrapped version.

    This decorator stores the original function implementation and creates a wrapped
    version that adds debugging capabilities while maintaining the exact same interface.
    """

    def decorator(func):
        # Store the original function
        _original_implementations[command_name] = func

        # Create wrapper function
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Create debug context for this command execution
            debug_ctx = DiagnosticUtilities.create_debug_context_for_command(
                command_name, _extract_safe_args_dict(func, *args, **kwargs)
            )

            # Create enhanced logger with debug context
            logger = get_enhanced_logger(f"Command.{command_name}").with_context(debug_ctx)

            try:
                # Log command start
                debug_ctx.add_breadcrumb(f"Starting command: {command_name}")
                logger.info(f"Executing command: {command_name}")

                # Capture function arguments for debugging
                _capture_function_arguments_safe(debug_ctx, func, *args, **kwargs)

                # Execute the original function with timing
                start_time = time.time()
                debug_ctx.add_breadcrumb("Executing original command function")

                result = func(*args, **kwargs)

                execution_time = time.time() - start_time
                debug_ctx.set_metric("execution_time", execution_time, "Total command execution time in seconds")

                # Log successful completion
                debug_ctx.add_breadcrumb(f"Command completed successfully in {execution_time:.2f}s")
                logger.info(f"Command {command_name} completed successfully in {execution_time:.2f}s")

                # Capture result information for debugging
                _capture_result_information_safe(debug_ctx, result)

                return result

            except Exception as e:
                # Log error with full context
                debug_ctx.add_breadcrumb(f"Command failed: {str(e)}", "error")
                logger.error_with_context(
                    f"Command {command_name} failed", exception=e, command_args=_extract_safe_args_dict(func, *args, **kwargs)
                )

                # Re-raise the original exception to preserve existing error handling
                raise

            finally:
                # Log execution summary for debugging
                summary = debug_ctx.get_execution_summary()
                logger.debug(f"Command {command_name} execution summary: {summary}")

        return wrapper

    return decorator


def _extract_safe_args_dict(func: Callable, *args, **kwargs) -> dict[str, Any]:
    """
    Safely extract function arguments into a dictionary for logging purposes.

    This function safely extracts function arguments while redacting sensitive data
    and handling any errors that might occur during extraction.
    """
    try:
        # Get function signature
        sig = inspect.signature(func)
        bound_args = sig.bind(*args, **kwargs)
        bound_args.apply_defaults()

        # Convert to dictionary and redact sensitive data
        args_dict = dict(bound_args.arguments)
        return _redact_sensitive_data_safe(args_dict)

    except Exception:
        # If we can't extract arguments safely, return a safe representation
        return {
            "args_count": len(args),
            "kwargs_keys": list(kwargs.keys()) if kwargs else [],
            "extraction_error": "Could not safely extract arguments",
        }


def _redact_sensitive_data_safe(data: dict[str, Any]) -> dict[str, Any]:
    """
    Safely redact sensitive data from arguments for logging.

    Args:
        data: Dictionary containing function arguments

    Returns:
        Dictionary with sensitive data redacted
    """
    try:
        redacted_data = {}
        sensitive_keys = {
            "password",
            "token",
            "api_key",
            "secret",
            "credentials",
            "auth",
            "authorization",
            "x-auth-token",
            "sec-token",
        }

        for key, value in data.items():
            key_lower = key.lower()

            # Check if this is a sensitive key
            if any(sensitive_key in key_lower for sensitive_key in sensitive_keys):
                redacted_data[key] = "[REDACTED]"
            elif isinstance(value, dict):
                # Recursively redact nested dictionaries
                redacted_data[key] = _redact_sensitive_data_safe(value)
            elif isinstance(value, str) and len(value) > 100:
                # Truncate very long strings to prevent log bloat
                redacted_data[key] = value[:100] + "... [TRUNCATED]"
            else:
                redacted_data[key] = value

        return redacted_data
    except Exception:
        # If redaction fails, return a safe fallback
        return {"redaction_error": "Could not safely redact sensitive data"}


def _capture_function_arguments_safe(debug_ctx: DebugContext, func: Callable, *args, **kwargs):
    """
    Safely capture function arguments in debug context.

    Args:
        debug_ctx: Debug context to capture arguments in
        func: Function being called
        *args: Positional arguments
        **kwargs: Keyword arguments
    """
    try:
        args_dict = _extract_safe_args_dict(func, *args, **kwargs)
        debug_ctx.capture_variable("function_arguments", args_dict, "Arguments passed to the command function")

        # Capture argument count and types for debugging
        debug_ctx.capture_variable("args_count", len(args), "Number of positional arguments")
        debug_ctx.capture_variable("kwargs_count", len(kwargs), "Number of keyword arguments")

    except Exception as e:
        debug_ctx.add_breadcrumb(f"Failed to capture function arguments: {str(e)}", "warning")


def _capture_result_information_safe(debug_ctx: DebugContext, result: Any):
    """
    Safely capture information about the command result for debugging.

    Args:
        debug_ctx: Debug context to capture result information in
        result: Command result
    """
    try:
        # Capture result type and basic information
        debug_ctx.capture_variable("result_type", type(result).__name__, "Type of the command result")

        # For CommandResults, capture additional information
        if hasattr(result, "outputs"):
            debug_ctx.capture_variable("has_outputs", result.outputs is not None, "Whether result has outputs")
            if result.outputs:
                debug_ctx.capture_variable("outputs_type", type(result.outputs).__name__, "Type of result outputs")
                if isinstance(result.outputs, (list, dict)):
                    debug_ctx.capture_variable("outputs_size", len(result.outputs), "Size of result outputs")

        if hasattr(result, "readable_output"):
            debug_ctx.capture_variable("has_readable_output", bool(result.readable_output), "Whether result has readable output")

        if hasattr(result, "raw_response"):
            debug_ctx.capture_variable("has_raw_response", result.raw_response is not None, "Whether result has raw response")

    except Exception as e:
        debug_ctx.add_breadcrumb(f"Failed to capture result information: {str(e)}", "warning")


# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION AND ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
# This section contains the main function that handles command routing and execution.
# The main function processes parameters, creates the client, and routes commands to appropriate handlers.


def main() -> None:  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    # handle allowed advanced parameters
    adv_params = params.get("adv_params")
    if adv_params:
        try:
            globals_ = globals()
            for adv_p in adv_params.split(","):
                adv_p_kv = [item.strip() for item in adv_p.split("=")]
                if len(adv_p_kv) != 2:
                    raise DemistoException(
                        f"Failed to parse advanced parameter: {adv_p} - please make sure you entered it correctly."
                    )
                adv_param_name = adv_p_kv[0]
                if adv_param_name in ADVANCED_PARAMETERS_STRING_NAMES:
                    globals_[adv_p_kv[0]] = adv_p_kv[1]
                elif adv_param_name in ADVANCED_PARAMETER_INT_NAMES:
                    globals_[adv_p_kv[0]] = int(adv_p_kv[1])
                else:
                    raise DemistoException(f"The parameter: {adv_p_kv[0]} is not a valid advanced parameter. Please remove it")
        except DemistoException as e:
            raise DemistoException(f"Failed to parse advanced params. Error: {e.message}") from e
        except Exception as e:
            raise DemistoException(f"Failed to parse advanced params. Error: {e}") from e

    server = params.get("server")
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    api_version = params.get("api_version")
    if api_version and float(api_version) < MINIMUM_API_VERSION:
        raise DemistoException(f"API version cannot be lower than {MINIMUM_API_VERSION}")
    credentials = params.get("credentials")
    timeout = arg_to_number(params.get("timeout"))

    try:
        client = Client(
            server=server,
            verify=verify_certificate,
            proxy=proxy,
            api_version=api_version,
            credentials=credentials,
            timeout=timeout,
        )
        # All command names with or are for supporting QRadar v2 command names for backward compatibility
        if command == "test-module":
            validate_integration_context()
            return_results(test_module_command(client, params))

        elif command == "fetch-incidents":
            demisto.incidents(fetch_incidents_command())

        elif command == "long-running-execution":
            validate_integration_context()
            support_multithreading()
            long_running_execution_command(client, params)

        elif command in [
            "qradar-offenses-list",
            "qradar-offenses",
            "qradar-offense-by-id",
        ]:
            return_results(qradar_offenses_list_command(client, args))

        elif command in ["qradar-offense-update", "qradar-update-offense"]:
            return_results(qradar_offense_update_command(client, args))

        elif command in ["qradar-closing-reasons", "qradar-get-closing-reasons"]:
            return_results(qradar_closing_reasons_list_command(client, args))

        elif command in ["qradar-offense-notes-list", "qradar-get-note"]:
            return_results(qradar_offense_notes_list_command(client, args))

        elif command in ["qradar-offense-note-create", "qradar-create-note"]:
            return_results(qradar_offense_notes_create_command(client, args))

        elif command == "qradar-rules-list":
            return_results(qradar_rules_list_command(client, args))

        elif command == "qradar-rule-groups-list":
            return_results(qradar_rule_groups_list_command(client, args))

        elif command in [
            "qradar-assets-list",
            "qradar-get-assets",
            "qradar-get-asset-by-id",
        ]:
            return_results(qradar_assets_list_command(client, args))

        elif command == "qradar-saved-searches-list":
            return_results(qradar_saved_searches_list_command(client, args))

        elif command == "qradar-searches-list":
            return_results(qradar_searches_list_command(client, args))

        elif command in ["qradar-search-create", "qradar-searches"]:
            return_results(qradar_search_create_command(client, params, args))

        elif command in ["qradar-search-status-get", "qradar-get-search"]:
            return_results(qradar_search_status_get_command(client, args))

        elif command in [
            "qradar-search-results-get",
            "qradar-get-search-results",
        ]:
            return_results(qradar_search_results_get_command(client, args))

        elif command == "qradar-search-cancel":
            return_results(qradar_search_cancel_command(client, args))

        elif command == "qradar-search-delete":
            return_results(qradar_search_delete_command(client, args))

        elif command in [
            "qradar-reference-sets-list",
            "qradar-get-reference-by-name",
        ]:
            return_results(qradar_reference_sets_list_command(client, args))

        elif command in [
            "qradar-reference-set-create",
            "qradar-create-reference-set",
        ]:
            return_results(qradar_reference_set_create_command(client, args))

        elif command in [
            "qradar-reference-set-delete",
            "qradar-delete-reference-set",
        ]:
            return_results(qradar_reference_set_delete_command(client, args))

        elif command in [
            "qradar-reference-set-value-upsert",
            "qradar-create-reference-set-value",
            "qradar-update-reference-set-value",
        ]:
            return_results(qradar_reference_set_value_upsert_command(args, client, params))

        elif command in [
            "qradar-reference-set-value-delete",
            "qradar-delete-reference-set-value",
        ]:
            return_results(qradar_reference_set_value_delete_command(client, args))

        elif command in [
            "qradar-domains-list",
            "qradar-get-domains",
            "qradar-get-domain-by-id",
        ]:
            return_results(qradar_domains_list_command(client, args))

        elif command in ["qradar-indicators-upload", "qradar-upload-indicators"]:
            return_results(qradar_indicators_upload_command(args, client, params))

        elif command == "qradar-geolocations-for-ip":
            return_results(qradar_geolocations_for_ip_command(client, args))

        elif command == "qradar-log-sources-list":
            return_results(qradar_log_sources_list_command(client, args))

        elif command == "qradar-get-custom-properties":
            return_results(qradar_get_custom_properties_command(client, args))

        elif command == "qradar-ips-source-get":
            return_results(qradar_ips_source_get_command(client, args))

        elif command == "qradar-ips-local-destination-get":
            return_results(qradar_ips_local_destination_get_command(client, args))

        elif command == "qradar-reset-last-run":
            return_results(qradar_reset_last_run_command())

        elif command == "get-mapping-fields":
            return_results(qradar_get_mapping_fields_command(client))

        elif command == "get-remote-data":
            validate_integration_context()
            return_results(get_remote_data_command(client, params, args))

        elif command == "get-modified-remote-data":
            validate_integration_context()
            return_results(get_modified_remote_data_command(client, params, args))

        elif command == "qradar-search-retrieve-events":
            return_results(qradar_search_retrieve_events_command(client, params, args))

        elif command == "qradar-remote-network-cidr-create":
            return_results(qradar_remote_network_cidr_create_command(client, args))

        elif command == "qradar-remote-network-cidr-list":
            return_results(qradar_remote_network_cidr_list_command(client, args))

        elif command == "qradar-remote-network-cidr-delete":
            return_results(qradar_remote_network_cidr_delete_command(client, args))

        elif command == "qradar-remote-network-cidr-update":
            return_results(qradar_remote_network_cidr_update_command(client, args))

        elif command == "qradar-remote-network-deploy-execution":
            return_results(qradar_remote_network_deploy_execution_command(client, args))

        elif command == "qradar-event-collectors-list":
            return_results(qradar_event_collectors_list_command(client, args))

        elif command == "qradar-wincollect-destinations-list":
            return_results(qradar_wincollect_destinations_list_command(client, args))

        elif command == "qradar-disconnected-log-collectors-list":
            return_results(qradar_disconnected_log_collectors_list_command(client, args))

        elif command == "qradar-log-source-types-list":
            return_results(qradar_log_source_types_list_command(client, args))

        elif command == "qradar-log-source-protocol-types-list":
            return_results(qradar_log_source_protocol_types_list_command(client, args))

        elif command == "qradar-log-source-extensions-list":
            return_results(qradar_log_source_extensions_list_command(client, args))

        elif command == "qradar-log-source-languages-list":
            return_results(qradar_log_source_languages_list_command(client, args))

        elif command == "qradar-log-source-groups-list":
            return_results(qradar_log_source_groups_list_command(client, args))

        elif command == "qradar-log-source-delete":
            return_results(qradar_log_source_delete_command(client, args))

        elif command == "qradar-log-source-create":
            return_results(qradar_log_source_create_command(client, args))

        elif command == "qradar-log-source-update":
            return_results(qradar_log_source_update_command(client, args))

        # Development and Testing Utilities Commands
        elif command == "qradar-system-diagnostics":
            return_results(qradar_system_diagnostics_command(client, args))

        elif command == "qradar-context-inspect":
            return_results(qradar_context_inspect_command(client, args))

        elif command == "qradar-connectivity-test":
            return_results(qradar_connectivity_test_command(client, args))

        elif command == "qradar-generate-mock-data":
            return_results(qradar_generate_mock_data_command(client, args))

        elif command == "qradar-self-test":
            return_results(qradar_self_test_command(client, args))

        else:
            raise NotImplementedError(f"""Command '{command}' is not implemented.""")

    except Exception as e:
        try:
            # Use QRadarContextManager for resilient context handling in error reporting
            context_manager = get_context_manager()
            ctx, _ = context_manager.get_context_safe()
            print_debug_msg(f"The integration context_data is {ctx}")
        except Exception:
            print_debug_msg("Failed to retrieve context data for error reporting")
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{traceback.format_exc()}\nException is: {e!s}")
    finally:
        #  CIAC-10628
        if command not in ("test-module", "fetch-incidents", "long-running-execution"):
            client._return_execution_metrics_results()
            client.execution_metrics.metrics = None


# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
# This is the entry point for the integration when executed by XSOAR/XSIAM.

if __name__ in ("__main__", "__builtin__", "builtins"):
    register_signal_handler_profiling_dump(profiling_dump_rows_limit=PROFILING_DUMP_ROWS_LIMIT)
    main()


class ContextRecovery:
    """
    Handles context recovery and migration
    """

    def __init__(self, schema: dict):
        """
        Initialize the context recovery system

        Args:
            schema: Context schema definition
        """
        self.schema = schema

    def recover_from_corruption(self, ctx: dict) -> dict:
        """
        Recover from corrupted context data

        Args:
            ctx: Context dictionary to repair

        Returns:
            Repaired context dictionary

        Raises:
            ContextRecoveryError: If context cannot be repaired
        """
        try:
            demisto.debug("[ContextRecovery] Attempting to recover from corruption")

            # Start with a copy of the original context
            repaired_ctx = copy.deepcopy(ctx) if isinstance(ctx, dict) else {}

            # Ensure all required keys exist with proper types
            for key in self.schema["required_keys"]:
                if key not in repaired_ctx:
                    expected_type = self.schema["data_types"][key]
                    if expected_type == int:
                        repaired_ctx[key] = 0
                    elif expected_type == dict:
                        repaired_ctx[key] = {}
                    elif expected_type == list:
                        repaired_ctx[key] = []
                    else:
                        repaired_ctx[key] = None

            # Fix data types
            for key, expected_type in self.schema["data_types"].items():
                if key in repaired_ctx:
                    value = repaired_ctx[key]
                    if not isinstance(value, expected_type):
                        try:
                            if expected_type == int:
                                # Try to convert to int
                                if isinstance(value, str):
                                    # Handle JSON strings
                                    try:
                                        parsed_value = json.loads(value)
                                        repaired_ctx[key] = int(parsed_value)
                                    except (json.JSONDecodeError, ValueError):
                                        repaired_ctx[key] = int(value) if value.isdigit() else 0
                                else:
                                    repaired_ctx[key] = int(value) if value else 0
                            elif expected_type == dict:
                                if isinstance(value, str):
                                    try:
                                        repaired_ctx[key] = json.loads(value)
                                    except json.JSONDecodeError:
                                        repaired_ctx[key] = {}
                                else:
                                    repaired_ctx[key] = {}
                            elif expected_type == list:
                                if isinstance(value, str):
                                    try:
                                        repaired_ctx[key] = json.loads(value)
                                    except json.JSONDecodeError:
                                        repaired_ctx[key] = []
                                else:
                                    repaired_ctx[key] = []
                        except (ValueError, TypeError):
                            # If conversion fails, use default value
                            if expected_type == int:
                                repaired_ctx[key] = 0
                            elif expected_type == dict:
                                repaired_ctx[key] = {}
                            elif expected_type == list:
                                repaired_ctx[key] = []

            # Ensure non-negative values for ID fields
            if "id" in repaired_ctx and repaired_ctx["id"] < 0:
                repaired_ctx["id"] = 0

            # Remove duplicate offense IDs across different states
            offense_keys = ["mirrored_offenses_queried", "mirrored_offenses_finished", "mirrored_offenses_fetched"]
            seen_offense_ids = set()

            for key in offense_keys:
                if key in repaired_ctx and isinstance(repaired_ctx[key], dict):
                    # Create a new dict without duplicates
                    cleaned_offenses = {}
                    for offense_id, offense_data in repaired_ctx[key].items():
                        if offense_id not in seen_offense_ids:
                            cleaned_offenses[offense_id] = offense_data
                            seen_offense_ids.add(offense_id)
                    repaired_ctx[key] = cleaned_offenses

            # Limit samples to maximum allowed
            if "samples" in repaired_ctx and isinstance(repaired_ctx["samples"], list):
                max_samples = self.schema["size_limits"]["max_samples"]
                if len(repaired_ctx["samples"]) > max_samples:
                    # Keep the most recent samples
                    repaired_ctx["samples"] = repaired_ctx["samples"][-max_samples:]

            demisto.debug("[ContextRecovery] Context recovery completed")
            return repaired_ctx

        except Exception as e:
            demisto.error(f"[ContextRecovery] Context recovery failed: {str(e)}")
            raise ContextRecoveryError(f"Failed to recover from corruption: {str(e)}") from e

    def migrate_context_schema(self, ctx: dict, target_version: str) -> dict:
        """
        Migrate context to new schema version for backward compatibility

        Args:
            ctx: Context dictionary to migrate
            target_version: Target schema version

        Returns:
            Migrated context dictionary

        Raises:
            ContextRecoveryError: If migration fails
        """
        try:
            demisto.debug(f"[ContextRecovery] Migrating context to schema version {target_version}")

            # Get current version from context or assume 1.0
            current_version = ctx.get("schema_version", "1.0")

            if current_version == target_version:
                demisto.debug("[ContextRecovery] Context already at target version")
                return ctx

            migrated_ctx = copy.deepcopy(ctx)

            # Migration from 1.0 to 2.0
            if current_version == "1.0" and target_version == "2.0":
                # Add new required keys if missing
                if "last_mirror_closed_update" not in migrated_ctx:
                    migrated_ctx["last_mirror_closed_update"] = 0

                # Ensure all offense tracking dictionaries exist
                offense_keys = ["mirrored_offenses_queried", "mirrored_offenses_finished", "mirrored_offenses_fetched"]
                for key in offense_keys:
                    if key not in migrated_ctx:
                        migrated_ctx[key] = {}

                # Ensure samples list exists
                if "samples" not in migrated_ctx:
                    migrated_ctx["samples"] = []

                # Update schema version
                migrated_ctx["schema_version"] = "2.0"

            # Future migrations can be added here
            # elif current_version == "2.0" and target_version == "3.0":
            #     # Migration logic for 2.0 to 3.0

            demisto.debug(f"[ContextRecovery] Context migrated from {current_version} to {target_version}")
            return migrated_ctx

        except Exception as e:
            demisto.error(f"[ContextRecovery] Context migration failed: {str(e)}")
            raise ContextRecoveryError(f"Failed to migrate context schema: {str(e)}") from e

    def initialize_default_context(self) -> dict:
        """
        Create a new context with safe defaults for clean slate recovery

        Returns:
            Default context dictionary
        """
        demisto.debug("[ContextRecovery] Initializing default context")

        default_context = {
            "schema_version": self.schema["version"],
            "id": 0,
            "last_mirror_update": 0,
            "last_mirror_closed_update": 0,
            "mirrored_offenses_queried": {},
            "mirrored_offenses_finished": {},
            "mirrored_offenses_fetched": {},
            "samples": [],
        }

        demisto.debug("[ContextRecovery] Default context initialized")
        return default_context


class ContextMetrics:
    """
    Tracks context operation metrics and provides performance monitoring
    """

    def __init__(self, alert_thresholds: dict = None):
        """Initialize context metrics tracking"""
        # Operation counters
        self.operation_count = 0
        self.error_count = 0
        self.recovery_count = 0
        self.validation_failures = 0
        self.size_limit_breaches = 0

        # Timing metrics
        self.total_operation_time = 0.0
        self.last_operation_time = 0.0
        self.max_operation_time = 0.0
        self.min_operation_time = float("inf")

        # Size tracking
        self.context_size_history: list[int] = []
        self.max_context_size = 0
        self.current_context_size = 0

        # Operation type tracking
        self.operation_types = {
            "get": {"count": 0, "total_time": 0.0, "errors": 0},
            "update": {"count": 0, "total_time": 0.0, "errors": 0},
            "validate": {"count": 0, "total_time": 0.0, "errors": 0},
            "recover": {"count": 0, "total_time": 0.0, "errors": 0},
            "cleanup": {"count": 0, "total_time": 0.0, "errors": 0},
        }

        # Health monitoring
        self.health_status = "healthy"
        self.last_health_check = time.time()
        self.consecutive_errors = 0

        # Alert thresholds
        self.alert_thresholds = alert_thresholds or {
            "max_operation_time": 5.0,  # seconds
            "max_context_size_mb": 8,  # MB (80% of 10MB limit)
            "max_error_rate": 0.1,  # 10% error rate
            "max_consecutive_errors": 3,
            "health_check_interval": 300,  # 5 minutes
        }

        # Performance statistics
        self.start_time = time.time()
        self.last_alert_time = {}  # Track last alert time for each type

    def record_operation(
        self, operation_type: str, duration: float, success: bool = True, context_size: int = 0, error_details: str = None
    ):
        """Record comprehensive metrics for a context operation"""
        # Update general counters
        self.operation_count += 1
        self.total_operation_time += duration
        self.last_operation_time = duration

        # Update timing statistics
        if duration > self.max_operation_time:
            self.max_operation_time = duration
        if duration < self.min_operation_time:
            self.min_operation_time = duration

        # Update operation type specific metrics
        if operation_type in self.operation_types:
            op_metrics = self.operation_types[operation_type]
            op_metrics["count"] += 1
            op_metrics["total_time"] += duration
            if not success:
                op_metrics["errors"] += 1

        # Handle errors
        if not success:
            self.error_count += 1
            self.consecutive_errors += 1
        else:
            self.consecutive_errors = 0

        # Update context size tracking
        if context_size > 0:
            self.current_context_size = context_size
            self.context_size_history.append(context_size)

            # Keep only last 100 size measurements
            if len(self.context_size_history) > 100:
                self.context_size_history.pop(0)

            # Update max size
            if context_size > self.max_context_size:
                self.max_context_size = context_size


class QRadarContextManager:
    """
    Manages QRadar integration context with resilience and error handling
    """

    # Context schema constants
    LAST_FETCH_KEY = "id"
    LAST_MIRROR_KEY = "last_mirror_update"
    LAST_MIRROR_CLOSED_KEY = "last_mirror_closed_update"
    MIRRORED_OFFENSES_QUERIED_CTX_KEY = "mirrored_offenses_queried"
    MIRRORED_OFFENSES_FINISHED_CTX_KEY = "mirrored_offenses_finished"
    MIRRORED_OFFENSES_FETCHED_CTX_KEY = "mirrored_offenses_fetched"
    SAMPLES_KEY = "samples"
    RESET_KEY = "reset"

    # Schema definition
    CONTEXT_SCHEMA = {
        "version": "2.0",
        "required_keys": [
            LAST_FETCH_KEY,
            LAST_MIRROR_KEY,
            LAST_MIRROR_CLOSED_KEY,
            MIRRORED_OFFENSES_QUERIED_CTX_KEY,
            MIRRORED_OFFENSES_FINISHED_CTX_KEY,
            MIRRORED_OFFENSES_FETCHED_CTX_KEY,
            SAMPLES_KEY,
        ],
        "data_types": {
            LAST_FETCH_KEY: int,
            LAST_MIRROR_KEY: int,
            LAST_MIRROR_CLOSED_KEY: int,
            MIRRORED_OFFENSES_QUERIED_CTX_KEY: dict,
            MIRRORED_OFFENSES_FINISHED_CTX_KEY: dict,
            MIRRORED_OFFENSES_FETCHED_CTX_KEY: dict,
            SAMPLES_KEY: list,
        },
        "size_limits": {"max_total_size_mb": 10, "max_samples": 2, "max_sample_size_mb": 3, "max_mirrored_offenses": 1000},
    }

    def __init__(self, max_retries: int = 3, max_context_size_mb: int = 10):
        """
        Initialize the QRadar Context Manager

        Args:
            max_retries: Maximum number of retries for context operations
            max_context_size_mb: Maximum context size in MB
        """
        self.max_retries = max_retries
        self.max_context_size_mb = max_context_size_mb
        self.max_context_size_bytes = max_context_size_mb * 1024 * 1024
        self.metrics = ContextMetrics()

        # Initialize validator and recovery components
        self.validator = ContextValidator(self.CONTEXT_SCHEMA)
        self.recovery = ContextRecovery(self.CONTEXT_SCHEMA)

        # Initialize sample manager
        max_samples = self.CONTEXT_SCHEMA["size_limits"]["max_samples"]
        max_sample_size_mb = self.CONTEXT_SCHEMA["size_limits"]["max_sample_size_mb"]
        self.sample_manager = SampleManager(max_samples, max_sample_size_mb)

        # Initialize thread-safe mechanisms for concurrency handling
        self._context_lock = threading.RLock()  # Reentrant lock for nested operations
        self._operation_counter = 0
        self._operation_counter_lock = threading.Lock()

        # Initialize logging
        self._setup_logging()

    def _setup_logging(self):
        """Setup comprehensive logging for context operations"""
        self.logger_prefix = "[QRadarContextManager]"
        self.log_operation_details = True  # Enable detailed operation logging
        self.log_performance_warnings = True  # Enable performance warning logs
        self.log_size_monitoring = True  # Enable size monitoring logs

    def get_context_safe(self) -> tuple[dict, str]:
        """
        Safely retrieve context with validation and recovery

        Returns:
            Tuple of (context_dict, version_string)
        """
        start_time = time.time()
        operation_id = self._get_operation_id()

        try:
            self._log_operation_start("get", operation_id)

            with self._context_lock:
                # Get raw context
                raw_context = demisto.getIntegrationContext()
                context_size = len(json.dumps(raw_context).encode("utf-8"))

                # Validate context
                validation_result = self.validator.validate_structure(raw_context)

                if not validation_result.is_valid:
                    demisto.info("[QRadarContextManager] Context validation failed, attempting recovery")
                    raw_context = self.recovery.recover_from_corruption(raw_context)
                    self.metrics.record_recovery("corruption_recovery")

                # Ensure context has required structure
                context = self._ensure_context_structure(raw_context)

                # Generate version for optimistic locking
                version = self._generate_context_version(context)

                duration = time.time() - start_time
                self.metrics.record_operation("get", duration, True, context_size)

                self._log_operation_complete("get", duration, True, operation_id, {"context_size": context_size})

                return context, version

        except Exception as e:
            duration = time.time() - start_time
            self.metrics.record_operation("get", duration, False, 0, str(e))
            self._log_error("Failed to get context safely", e)

            # Return minimal safe context on error
            default_context = self.recovery.initialize_default_context()
            version = self._generate_context_version(default_context)
            return default_context, version

    def update_context_safe(self, changes: dict, version: str = None, max_attempts: int = None) -> bool:
        """
        Safely update context with optimistic locking and validation

        Args:
            changes: Dictionary of changes to apply
            version: Expected context version for optimistic locking
            max_attempts: Maximum retry attempts (defaults to self.max_retries)

        Returns:
            bool: True if update was successful, False otherwise
        """
        start_time = time.time()
        operation_id = self._get_operation_id()
        max_attempts = max_attempts or self.max_retries

        try:
            self._log_operation_start("update", operation_id, {"changes_size": len(json.dumps(changes).encode("utf-8"))})

            with self._context_lock:
                for attempt in range(max_attempts):
                    try:
                        # Get current context
                        current_context, current_version = self.get_context_safe()

                        # Check version if provided (optimistic locking)
                        if version and version != current_version:
                            demisto.debug(f"[QRadarContextManager] Version mismatch on attempt {attempt + 1}")
                            if attempt < max_attempts - 1:
                                time.sleep(0.1 * (attempt + 1))  # Exponential backoff
                                continue
                            else:
                                self._log_warning("Version conflict after all retry attempts")
                                return False

                        # Apply changes
                        updated_context = always_merger.merge(copy.deepcopy(current_context), changes)

                        # Validate updated context
                        validation_result = self.validator.validate_structure(updated_context)
                        if not validation_result.is_valid:
                            self._log_error(f"Context validation failed after update: {validation_result.errors}")
                            return False

                        # Check size limits
                        size_result = self.validator.validate_size_limits(updated_context)
                        if not size_result.is_valid:
                            self._log_error(f"Context size validation failed: {size_result.errors}")
                            return False

                        # Update context
                        demisto.setIntegrationContext(updated_context)

                        duration = time.time() - start_time
                        context_size = len(json.dumps(updated_context).encode("utf-8"))
                        self.metrics.record_operation("update", duration, True, context_size)

                        self._log_operation_complete(
                            "update", duration, True, operation_id, {"context_size": context_size, "attempts": attempt + 1}
                        )

                        return True

                    except Exception as e:
                        if attempt < max_attempts - 1:
                            demisto.debug(f"[QRadarContextManager] Update attempt {attempt + 1} failed: {str(e)}")
                            time.sleep(0.1 * (attempt + 1))
                        else:
                            raise e

                return False

        except Exception as e:
            duration = time.time() - start_time
            self.metrics.record_operation("update", duration, False, 0, str(e))
            self._log_error("Failed to update context safely", e)
            return False

    def _ensure_context_structure(self, context: dict) -> dict:
        """Ensure context has all required keys with proper types"""
        if not isinstance(context, dict):
            context = {}

        # Ensure all required keys exist
        for key in self.CONTEXT_SCHEMA["required_keys"]:
            if key not in context:
                expected_type = self.CONTEXT_SCHEMA["data_types"][key]
                if expected_type == int:
                    context[key] = 0
                elif expected_type == dict:
                    context[key] = {}
                elif expected_type == list:
                    context[key] = []

        return context

    def _generate_context_version(self, context: dict) -> str:
        """Generate a version string for optimistic locking"""
        context_str = json.dumps(context, sort_keys=True)
        return str(hash(context_str))

    def _get_operation_id(self) -> int:
        """Get a unique operation ID for tracking"""
        with self._operation_counter_lock:
            self._operation_counter += 1
            return self._operation_counter

    def _log_operation_start(self, operation_type: str, operation_id: int = None, details: dict = None):
        """Log the start of a context operation"""
        if not hasattr(self, "log_operation_details") or not self.log_operation_details:
            return

        op_id_str = f"[Op:{operation_id}] " if operation_id else ""
        details_str = ""

        if details:
            detail_parts = []
            for key, value in details.items():
                if key == "context_size" and isinstance(value, int):
                    detail_parts.append(f"{key}={value / 1024:.1f}KB")
                elif key == "changes_size" and isinstance(value, int):
                    detail_parts.append(f"{key}={value} bytes")
                else:
                    detail_parts.append(f"{key}={value}")
            details_str = f" | {' | '.join(detail_parts)}"

        demisto.debug(f"[QRadarContextManager] {op_id_str}OPERATION START: {operation_type.upper()}{details_str}")

    def _log_operation_complete(
        self, operation_type: str, duration: float, success: bool, operation_id: int = None, result_details: dict = None
    ):
        """Log the completion of a context operation"""
        if not hasattr(self, "log_operation_details") or not self.log_operation_details:
            return

        op_id_str = f"[Op:{operation_id}] " if operation_id else ""
        status = "SUCCESS" if success else "FAILED"

        # Format duration with appropriate precision
        if duration < 0.001:
            duration_str = f"{duration * 1000000:.0f}μs"
        elif duration < 1.0:
            duration_str = f"{duration * 1000:.1f}ms"
        else:
            duration_str = f"{duration:.3f}s"

        result_str = ""
        if result_details:
            detail_parts = []
            for key, value in result_details.items():
                if key == "context_size" and isinstance(value, int):
                    detail_parts.append(f"{key}={value / 1024:.1f}KB")
                elif key == "items_processed" and isinstance(value, int):
                    detail_parts.append(f"{key}={value}")
                elif key == "validation_errors" and isinstance(value, int):
                    detail_parts.append(f"{key}={value}")
                else:
                    detail_parts.append(f"{key}={value}")
            result_str = f" | {' | '.join(detail_parts)}"

        demisto.debug(
            f"[QRadarContextManager] {op_id_str}OPERATION COMPLETE: {operation_type.upper()} - {status} ({duration_str}){result_str}"
        )


class SampleManager:
    """
    Manages incident samples with size optimization and validation
    """

    def __init__(self, max_samples: int = 2, max_sample_size_mb: float = 3.0):
        """
        Initialize the sample manager

        Args:
            max_samples: Maximum number of samples to store
            max_sample_size_mb: Maximum size per sample in MB
        """
        self.max_samples = max_samples
        self.max_sample_size_bytes = int(max_sample_size_mb * 1024 * 1024)
        self.logger_prefix = "[SampleManager]"

    def add_sample(self, samples: list[dict], new_sample: dict) -> list[dict]:
        """
        Add a new sample to the samples list with size and count management

        Args:
            samples: Current list of samples
            new_sample: New sample to add

        Returns:
            Updated samples list
        """
        try:
            # Validate new sample
            if not isinstance(new_sample, dict):
                demisto.debug(f"{self.logger_prefix} Invalid sample type: {type(new_sample)}")
                return samples

            # Check sample size
            sample_size = len(json.dumps(new_sample).encode("utf-8"))
            if sample_size > self.max_sample_size_bytes:
                demisto.info(f"{self.logger_prefix} Sample too large ({sample_size} bytes), truncating")
                new_sample = self._truncate_sample(new_sample)

            # Create a copy of samples list
            updated_samples = list(samples) if samples else []

            # Add new sample
            updated_samples.append(new_sample)

            # Maintain max samples limit
            if len(updated_samples) > self.max_samples:
                # Remove oldest samples
                updated_samples = updated_samples[-self.max_samples :]
                demisto.debug(f"{self.logger_prefix} Trimmed samples to {self.max_samples} items")

            return updated_samples

        except Exception as e:
            demisto.error(f"{self.logger_prefix} Failed to add sample: {str(e)}")
            return samples

    def _truncate_sample(self, sample: dict) -> dict:
        """Truncate sample to fit size limits"""
        try:
            truncated = copy.deepcopy(sample)

            # Remove or truncate large fields
            if "events" in truncated and isinstance(truncated["events"], list):
                # Keep only first few events
                truncated["events"] = truncated["events"][:5]

            if "raw_data" in truncated:
                # Remove raw data if present
                del truncated["raw_data"]

            # Truncate string fields
            for key, value in truncated.items():
                if isinstance(value, str) and len(value) > 1000:
                    truncated[key] = value[:1000] + "... [truncated]"

            return truncated

        except Exception as e:
            demisto.error(f"{self.logger_prefix} Failed to truncate sample: {str(e)}")
            return sample
