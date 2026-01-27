"""Test runner for executing mquire queries."""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from mquire_sql_query_verifier.comparator import ComparisonResult, compare_json_output
from mquire_sql_query_verifier.config import ManifestConfig


@dataclass
class TestCase:
    """A single test case (SQL query + expected output)."""

    name: str
    sql_path: Path
    expected_path: Path
    snapshot_name: str


@dataclass
class TestResult:
    """Result of running a single test case."""

    test_case: TestCase
    passed: bool
    query: str = ""
    comparison: ComparisonResult | None = None
    error: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    duration_ms: float = 0.0


@dataclass
class SnapshotResults:
    """Results for all tests on a single snapshot."""

    snapshot_name: str
    results: list[TestResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    @property
    def total(self) -> int:
        return len(self.results)


class TestRunner:
    """Runs mquire queries and compares results."""

    def __init__(
        self,
        config: ManifestConfig,
        console: Console | None = None,
    ):
        """Initialize the test runner.

        Args:
            config: Manifest configuration
            console: Rich console for output
        """
        self.config = config
        self.console = console or Console()

    def discover_tests(self, snapshot_name: str) -> list[TestCase]:
        """Discover test cases for a snapshot.

        Looks for .sql files with matching .json expected output files
        in the query path for this snapshot.

        Args:
            snapshot_name: Name of the snapshot (e.g., "ubuntu2404_6.14.0-37-generic.lime")

        Returns:
            List of discovered test cases
        """
        sql_path = self.config.get_sql_path_for_snapshot(snapshot_name)

        if not sql_path.exists():
            self.console.print(f"[yellow]Warning: SQL path does not exist: {sql_path}[/yellow]")
            return []

        tests = []
        for sql_file in sorted(sql_path.glob("*.sql")):
            expected_file = sql_file.with_suffix(".json")
            if expected_file.exists():
                tests.append(
                    TestCase(
                        name=sql_file.stem,
                        sql_path=sql_file,
                        expected_path=expected_file,
                        snapshot_name=snapshot_name,
                    )
                )
            else:
                self.console.print(
                    f"[yellow]Warning: No expected output for {sql_file.name}[/yellow]"
                )

        return tests

    def run_test(self, test_case: TestCase, snapshot_path: Path) -> TestResult:
        """Run a single test case.

        Args:
            test_case: The test case to run
            snapshot_path: Path to the snapshot file

        Returns:
            TestResult with pass/fail status and details
        """
        import time

        mquire_path = self.config.get_mquire_path()

        try:
            sql_query = test_case.sql_path.read_text().strip()
        except Exception as e:
            return TestResult(
                test_case=test_case,
                passed=False,
                error=f"Failed to read SQL file: {e}",
            )

        try:
            expected_output = test_case.expected_path.read_text()
        except Exception as e:
            return TestResult(
                test_case=test_case,
                passed=False,
                error=f"Failed to read expected output: {e}",
            )

        cmd = [
            str(mquire_path),
            "query",
            str(snapshot_path),
            sql_query,
            "--format",
            "json",
        ]

        start_time = time.perf_counter()
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
            )
            duration_ms = (time.perf_counter() - start_time) * 1000
        except subprocess.TimeoutExpired:
            return TestResult(
                test_case=test_case,
                passed=False,
                error=f"Query timed out after {self.config.timeout_seconds}s",
                duration_ms=(time.perf_counter() - start_time) * 1000,
            )
        except Exception as e:
            return TestResult(
                test_case=test_case,
                passed=False,
                error=f"Failed to execute mquire: {e}",
            )

        if result.returncode != 0:
            return TestResult(
                test_case=test_case,
                passed=False,
                error=f"mquire returned exit code {result.returncode}",
                stdout=result.stdout,
                stderr=result.stderr,
                duration_ms=duration_ms,
            )

        comparison = compare_json_output(result.stdout, expected_output)

        return TestResult(
            test_case=test_case,
            passed=comparison.passed,
            comparison=comparison,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=duration_ms,
        )

    def run_snapshot_tests(
        self,
        snapshot_name: str,
        snapshot_path: Path,
        test_filter: str | None = None,
        fail_fast: bool = False,
    ) -> SnapshotResults:
        """Run all tests for a snapshot.

        Args:
            snapshot_name: Name of the snapshot
            snapshot_path: Path to the snapshot file
            test_filter: Optional test name filter
            fail_fast: Stop on first failure

        Returns:
            SnapshotResults with all test results
        """
        tests = self.discover_tests(snapshot_name)

        if test_filter:
            tests = [t for t in tests if test_filter in t.name]

        if not tests:
            self.console.print(f"[yellow]No tests found for {snapshot_name}[/yellow]")
            return SnapshotResults(snapshot_name=snapshot_name)

        results = SnapshotResults(snapshot_name=snapshot_name)

        for test_case in tests:
            status_msg = f"Running {snapshot_name} / {test_case.name}..."

            # In CI/non-TTY, print progress explicitly
            if self.console.is_terminal:
                with self.console.status(f"[bold blue]{status_msg}[/bold blue]"):
                    result = self.run_test(test_case, snapshot_path)
            else:
                self.console.print(status_msg)
                result = self.run_test(test_case, snapshot_path)

            results.results.append(result)

            if not result.passed and fail_fast:
                break

        return results

    def update_snapshot_tests(
        self,
        snapshot_name: str,
        snapshot_path: Path,
        test_filter: str | None = None,
    ) -> tuple[int, int]:
        """Update expected JSON files with actual mquire output.

        Args:
            snapshot_name: Name of the snapshot
            snapshot_path: Path to the snapshot file
            test_filter: Optional test name filter

        Returns:
            Tuple of (updated count, failed count)
        """
        import time

        tests = self.discover_tests(snapshot_name)

        if test_filter:
            tests = [t for t in tests if test_filter in t.name]

        if not tests:
            self.console.print(f"[yellow]No tests found for {snapshot_name}[/yellow]")
            return 0, 0

        updated = 0
        failed = 0
        mquire_path = self.config.get_mquire_path()

        self.console.print()
        self.console.print(f"[bold]{snapshot_name}[/bold]")

        for test_case in tests:
            status_msg = f"Updating {snapshot_name} / {test_case.name}..."

            try:
                sql_query = test_case.sql_path.read_text().strip()
            except Exception as e:
                self.console.print(f"  [red]✗[/red] {test_case.name}")
                self.console.print(f"    [red]Error:[/red] Failed to read SQL: {e}")
                failed += 1
                continue

            cmd = [
                str(mquire_path),
                "query",
                str(snapshot_path),
                sql_query,
                "--format",
                "json",
            ]

            start_time = time.perf_counter()
            if self.console.is_terminal:
                with self.console.status(f"[bold blue]{status_msg}[/bold blue]"):
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=self.config.timeout_seconds,
                    )
            else:
                self.console.print(status_msg)
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout_seconds,
                )
            duration_ms = (time.perf_counter() - start_time) * 1000

            if result.returncode != 0:
                self.console.print(
                    f"  [red]✗[/red] {test_case.name} [dim]({duration_ms:.0f}ms)[/dim]"
                )
                self.console.print(f"    [dim]{sql_query}[/dim]")
                self.console.print(f"    [red]Error:[/red] mquire failed: {result.stderr}")
                failed += 1
                continue

            try:
                data = json.loads(result.stdout)
                formatted = json.dumps(data, indent=2) + "\n"
            except json.JSONDecodeError:
                self.console.print(
                    f"  [red]✗[/red] {test_case.name} [dim]({duration_ms:.0f}ms)[/dim]"
                )
                self.console.print(f"    [dim]{sql_query}[/dim]")
                self.console.print("    [red]Error:[/red] Invalid JSON output")
                failed += 1
                continue

            # Check if content actually changed
            try:
                existing = test_case.expected_path.read_text()
            except Exception:
                existing = None

            if existing == formatted:
                self.console.print(
                    f"  [green]✓[/green] {test_case.name} [dim]({duration_ms:.0f}ms)[/dim]"
                )
                self.console.print(f"    [dim]{sql_query}[/dim]")
            else:
                test_case.expected_path.write_text(formatted)
                self.console.print(
                    f"  [red]✗[/red] {test_case.name} [dim]({duration_ms:.0f}ms)[/dim]"
                )
                self.console.print(f"    [dim]{sql_query}[/dim]")
                self.console.print(f"    [yellow]Updated {test_case.expected_path}[/yellow]")
                updated += 1

        if updated > 0:
            self.console.print(f"  [yellow]{updated} file(s) updated[/yellow]")
        self.console.print()

        return updated, failed
