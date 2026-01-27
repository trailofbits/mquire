"""Command-line interface for mquire-sql-query-verifier."""

import sys
from pathlib import Path

import click
from rich.console import Console

from mquire_sql_query_verifier.config import ManifestConfig, S3Config
from mquire_sql_query_verifier.reporter import ConsoleReporter, JUnitReporter, TestSummary
from mquire_sql_query_verifier.runner import TestRunner
from mquire_sql_query_verifier.s3 import SnapshotManager


@click.command()
@click.argument("manifest", type=click.Path(exists=True, path_type=Path))
@click.argument("junit_xml", type=click.Path(path_type=Path))
@click.option("--fail-fast", "-x", is_flag=True, help="Stop on first failure")
@click.option("--snapshot", "-s", help="Run tests for specific snapshot only")
@click.option("--test", "-t", help="Run specific test by name (substring match)")
@click.option(
    "--skip-download",
    is_flag=True,
    help="Skip downloading snapshots (use local files)",
)
@click.option(
    "--keep-snapshots",
    is_flag=True,
    help="Keep downloaded snapshots after tests complete",
)
def main(
    manifest: Path,
    junit_xml: Path,
    fail_fast: bool,
    snapshot: str | None,
    test: str | None,
    skip_download: bool,
    keep_snapshots: bool,
) -> None:
    """Run mquire integration tests.

    MANIFEST is the path to a test manifest JSON file.
    JUNIT_XML is the path to write the JUnit XML report.
    """
    console = Console()

    if skip_download and not keep_snapshots:
        console.print("[yellow]Warning: --skip-download implies --keep-snapshots[/yellow]")
        keep_snapshots = True

    try:
        config = ManifestConfig.load(manifest)
    except Exception as e:
        console.print(f"[red]Error loading manifest: {e}[/red]")
        sys.exit(1)

    mquire_path = config.get_mquire_path()
    if not mquire_path.exists():
        console.print(f"[red]Error: mquire binary not found at {mquire_path}[/red]")
        console.print("[dim]Build with: cargo build --release[/dim]")
        sys.exit(1)

    snapshots = config.get_snapshot_names()
    if snapshot:
        snapshots = [s for s in snapshots if snapshot in s]
        if not snapshots:
            console.print(f"[red]Error: No snapshots match filter '{snapshot}'[/red]")
            sys.exit(1)

    console.print("[bold]mquire Integration Tests[/bold]")
    console.print(f"  Architecture: {config.architecture}")
    console.print(f"  Operating System: {config.operating_system}")
    console.print(f"  Snapshots path: {config.get_snapshots_path()}")
    console.print(f"  Timeout per query: {config.timeout_seconds}s")
    console.print(f"  mquire: {mquire_path}")
    console.print()

    runner = TestRunner(config, console=console)
    reporter = ConsoleReporter(console)
    summary = TestSummary()

    s3_manager: SnapshotManager | None = None
    if not skip_download:
        try:
            s3_config = S3Config.from_env()
            s3_manager = SnapshotManager(
                s3_config,
                config.get_snapshots_path(),
                config.operating_system,
                config.architecture,
                console=console,
            )
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            console.print("[dim]Use --skip-download to use local snapshots[/dim]")
            sys.exit(1)

    try:
        for snapshot_name in snapshots:
            if s3_manager:
                snapshot_path = s3_manager.download(snapshot_name)
            else:
                snapshot_path = config.get_snapshots_path() / snapshot_name
                if not snapshot_path.exists():
                    console.print(f"[red]Error: Snapshot not found: {snapshot_path}[/red]")
                    continue

            results = runner.run_snapshot_tests(
                snapshot_name,
                snapshot_path,
                test_filter=test,
                fail_fast=fail_fast,
            )
            summary.snapshot_results.append(results)
            reporter.report_snapshot_results(results)

            if fail_fast and results.failed > 0:
                console.print("[yellow]Stopping due to --fail-fast[/yellow]")
                break

    finally:
        if s3_manager and not keep_snapshots:
            s3_manager.cleanup()

    reporter.report_summary(summary)

    junit_reporter = JUnitReporter(junit_xml)
    junit_reporter.write(summary)
    console.print(f"[dim]JUnit XML written to {junit_xml}[/dim]")

    sys.exit(0 if summary.all_passed else 1)


if __name__ == "__main__":
    main()
