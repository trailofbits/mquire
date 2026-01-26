"""Test result reporting utilities."""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table

from mquire_sql_query_verifier.runner import SnapshotResults, TestResult


@dataclass
class TestSummary:
    """Summary of all test results."""

    snapshot_results: list[SnapshotResults] = field(default_factory=list)

    @property
    def total_passed(self) -> int:
        return sum(sr.passed for sr in self.snapshot_results)

    @property
    def total_failed(self) -> int:
        return sum(sr.failed for sr in self.snapshot_results)

    @property
    def total_tests(self) -> int:
        return sum(sr.total for sr in self.snapshot_results)

    @property
    def all_passed(self) -> bool:
        return self.total_failed == 0 and self.total_tests > 0


class ConsoleReporter:
    """Rich console output for test results."""

    def __init__(self, console: Console):
        """Initialize the console reporter.

        Args:
            console: Rich console for output
        """
        self.console = console

    def report_test_result(self, result: TestResult) -> None:
        """Report a single test result.

        Args:
            result: Test result to report
        """
        status = "[green]\u2713[/green]" if result.passed else "[red]\u2717[/red]"
        duration = f"[dim]({result.duration_ms:.0f}ms)[/dim]"

        self.console.print(f"  {status} {result.test_case.name} {duration}")

        try:
            query = result.test_case.sql_path.read_text().strip()
            self.console.print(f"    [dim]{query}[/dim]")
        except Exception:
            pass

        if not result.passed:
            if result.error:
                self.console.print(f"      [red]Error:[/red] {result.error}")
            if result.comparison and not result.comparison.passed:
                self.console.print(f"      [red]Failure:[/red] {result.comparison.message}")
                if result.comparison.diff_details:
                    for line in result.comparison.diff_details.split("\n"):
                        self.console.print(f"        {line}")
            if result.stderr:
                self.console.print(f"      [dim]stderr: {result.stderr[:500]}[/dim]")

    def report_snapshot_results(self, results: SnapshotResults) -> None:
        """Report results for a snapshot.

        Args:
            results: Snapshot test results
        """
        self.console.print()
        self.console.print(f"[bold]{results.snapshot_name}[/bold]")

        for result in results.results:
            self.report_test_result(result)

        if results.total > 0:
            status_color = "green" if results.failed == 0 else "red"
            self.console.print(
                f"  [{status_color}]{results.passed}/{results.total} passed[/{status_color}]"
            )
            self.console.print()

    def report_summary(self, summary: TestSummary) -> None:
        """Report overall test summary.

        Args:
            summary: Test summary
        """
        self.console.print()
        self.console.print("[bold]Summary[/bold]")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Snapshot")
        table.add_column("Passed", justify="right")
        table.add_column("Failed", justify="right")
        table.add_column("Total", justify="right")

        for sr in summary.snapshot_results:
            status_color = "green" if sr.failed == 0 else "red"
            table.add_row(
                sr.snapshot_name,
                f"[green]{sr.passed}[/green]",
                f"[{status_color}]{sr.failed}[/{status_color}]",
                str(sr.total),
            )

        self.console.print(table)

        self.console.print()
        if summary.all_passed:
            self.console.print(
                f"[bold green]\u2713 All {summary.total_tests} tests passed[/bold green]"
            )
        else:
            failed = summary.total_failed
            total = summary.total_tests
            self.console.print(f"[bold red]\u2717 {failed}/{total} tests failed[/bold red]")


class JUnitReporter:
    """JUnit XML output for CI integration."""

    def __init__(self, output_path: Path):
        """Initialize the JUnit reporter.

        Args:
            output_path: Path to write JUnit XML file
        """
        self.output_path = output_path

    def write(self, summary: TestSummary) -> None:
        """Write JUnit XML report.

        Args:
            summary: Test summary to write
        """
        testsuites = ET.Element("testsuites")
        testsuites.set("tests", str(summary.total_tests))
        testsuites.set("failures", str(summary.total_failed))

        for sr in summary.snapshot_results:
            testsuite = ET.SubElement(testsuites, "testsuite")
            testsuite.set("name", sr.snapshot_name)
            testsuite.set("tests", str(sr.total))
            testsuite.set("failures", str(sr.failed))

            total_time = sum(r.duration_ms for r in sr.results) / 1000.0
            testsuite.set("time", f"{total_time:.3f}")

            for result in sr.results:
                testcase = ET.SubElement(testsuite, "testcase")
                testcase.set("name", result.test_case.name)
                testcase.set("classname", sr.snapshot_name)
                testcase.set("time", f"{result.duration_ms / 1000.0:.3f}")

                if not result.passed:
                    failure = ET.SubElement(testcase, "failure")
                    if result.error:
                        failure.set("message", result.error)
                        failure.text = result.error
                    elif result.comparison:
                        failure.set("message", result.comparison.message)
                        if result.comparison.diff_details:
                            failure.text = result.comparison.diff_details

                    # Add stdout/stderr if present
                    if result.stdout:
                        stdout_elem = ET.SubElement(testcase, "system-out")
                        stdout_elem.text = result.stdout[:10000]
                    if result.stderr:
                        stderr_elem = ET.SubElement(testcase, "system-err")
                        stderr_elem.text = result.stderr[:10000]

        tree = ET.ElementTree(testsuites)
        ET.indent(tree, space="  ")
        tree.write(self.output_path, encoding="unicode", xml_declaration=True)
