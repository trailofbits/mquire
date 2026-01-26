"""JSON output comparison utilities."""

import json
from dataclasses import dataclass
from typing import Any


@dataclass
class ComparisonResult:
    """Result of comparing actual vs expected JSON output."""

    passed: bool
    message: str
    expected_row_count: int
    actual_row_count: int
    diff_details: str | None = None


def _extract_row_list(data: Any) -> tuple[list[Any] | None, list[str] | None, str | None]:
    """Extract row_list and column_order from mquire JSON output format.

    mquire outputs: {"column_order": [...], "row_list": [...]}

    Args:
        data: Parsed JSON data

    Returns:
        Tuple of (row_list, column_order, error_message)
    """
    if not isinstance(data, dict):
        return None, None, f"Expected dict, got {type(data).__name__}"
    if "row_list" not in data:
        return None, None, "JSON object missing 'row_list' key"
    if "column_order" not in data:
        return None, None, "JSON object missing 'column_order' key"

    row_list = data["row_list"]
    column_order = data["column_order"]

    if not isinstance(row_list, list):
        return None, None, f"row_list is not a list, got {type(row_list).__name__}"
    if not isinstance(column_order, list):
        return None, None, f"column_order is not a list, got {type(column_order).__name__}"

    return row_list, column_order, None


def compare_json_output(
    actual: str,
    expected: str,
) -> ComparisonResult:
    """Compare actual mquire JSON output against expected output.

    Handles mquire's JSON format: {"column_order": [...], "row_list": [...]}
    Performs exact comparison: row count and content must match.

    Args:
        actual: Actual JSON output from mquire
        expected: Expected JSON content

    Returns:
        ComparisonResult with pass/fail status and details
    """
    try:
        actual_data = json.loads(actual)
    except json.JSONDecodeError as e:
        return ComparisonResult(
            passed=False,
            message=f"Failed to parse actual output as JSON: {e}",
            expected_row_count=-1,
            actual_row_count=-1,
        )

    try:
        expected_data = json.loads(expected)
    except json.JSONDecodeError as e:
        return ComparisonResult(
            passed=False,
            message=f"Failed to parse expected output as JSON: {e}",
            expected_row_count=-1,
            actual_row_count=-1,
        )

    actual_rows, actual_cols, actual_err = _extract_row_list(actual_data)
    if actual_err:
        return ComparisonResult(
            passed=False,
            message=f"Actual output: {actual_err}",
            expected_row_count=-1,
            actual_row_count=-1,
        )

    expected_rows, expected_cols, expected_err = _extract_row_list(expected_data)
    if expected_err:
        return ComparisonResult(
            passed=False,
            message=f"Expected output: {expected_err}",
            expected_row_count=-1,
            actual_row_count=-1,
        )

    # Type narrowing: if no error, values are not None
    assert actual_rows is not None
    assert expected_rows is not None
    assert actual_cols is not None
    assert expected_cols is not None

    if actual_cols != expected_cols:
        return ComparisonResult(
            passed=False,
            message=f"Column order mismatch: expected {expected_cols}, got {actual_cols}",
            expected_row_count=len(expected_rows),
            actual_row_count=len(actual_rows),
        )

    expected_count = len(expected_rows)
    actual_count = len(actual_rows)

    if expected_count != actual_count:
        return ComparisonResult(
            passed=False,
            message=f"Row count mismatch: expected {expected_count}, got {actual_count}",
            expected_row_count=expected_count,
            actual_row_count=actual_count,
        )

    if actual_rows != expected_rows:
        diff = _find_differences(actual_rows, expected_rows)
        return ComparisonResult(
            passed=False,
            message="Content mismatch",
            expected_row_count=expected_count,
            actual_row_count=actual_count,
            diff_details=diff,
        )

    return ComparisonResult(
        passed=True,
        message="OK",
        expected_row_count=expected_count,
        actual_row_count=actual_count,
    )


def _find_differences(actual: list[Any], expected: list[Any]) -> str:
    """Find and describe differences between actual and expected data.

    Args:
        actual: Actual data list
        expected: Expected data list

    Returns:
        Human-readable description of differences
    """
    differences = []
    max_diffs = 5

    for i, (act_row, exp_row) in enumerate(zip(actual, expected, strict=True)):
        if act_row != exp_row:
            if isinstance(act_row, dict) and isinstance(exp_row, dict):
                row_diffs = _compare_dicts(act_row, exp_row)
                differences.append(f"Row {i}: {row_diffs}")
            else:
                differences.append(f"Row {i}: expected {exp_row!r}, got {act_row!r}")

            if len(differences) >= max_diffs:
                remaining = sum(
                    1 for a, e in zip(actual[i + 1 :], expected[i + 1 :], strict=True) if a != e
                )
                if remaining > 0:
                    differences.append(f"... and {remaining} more differences")
                break

    return "\n".join(differences)


def _compare_dicts(actual: dict[str, Any], expected: dict[str, Any]) -> str:
    """Compare two dictionaries and describe differences.

    Args:
        actual: Actual dictionary
        expected: Expected dictionary

    Returns:
        Description of field-level differences
    """
    diffs = []

    all_keys = set(actual.keys()) | set(expected.keys())
    for key in sorted(all_keys):
        if key not in actual:
            diffs.append(f"missing field '{key}'")
        elif key not in expected:
            diffs.append(f"extra field '{key}'")
        elif actual[key] != expected[key]:
            diffs.append(f"field '{key}': expected {expected[key]!r}, got {actual[key]!r}")

    return "; ".join(diffs) if diffs else "unknown difference"
