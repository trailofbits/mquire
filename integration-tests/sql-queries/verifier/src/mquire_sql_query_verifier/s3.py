"""S3/Spaces snapshot management."""

import shutil
from pathlib import Path

import boto3
from botocore.config import Config
from rich.console import Console
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from mquire_sql_query_verifier.config import S3Config


class SnapshotManager:
    """Manages downloading and cleanup of memory snapshots from S3/Spaces."""

    def __init__(
        self,
        s3_config: S3Config,
        local_path: Path,
        operating_system: str,
        architecture: str,
        console: Console | None = None,
    ):
        """Initialize the snapshot manager.

        Args:
            s3_config: S3/Spaces configuration
            local_path: Local directory for downloaded snapshots
            operating_system: OS name for S3 path (e.g., "linux")
            architecture: Architecture name for S3 path (e.g., "intel")
            console: Rich console for output
        """
        self.s3_config = s3_config
        self.local_path = local_path
        self.operating_system = operating_system.lower()
        self.architecture = architecture.lower()
        self.console = console or Console()

        # Create S3 client with S3v4 signature for Digital Ocean compatibility
        self._client = boto3.client(
            "s3",
            endpoint_url=s3_config.endpoint,
            aws_access_key_id=s3_config.access_key_id,
            aws_secret_access_key=s3_config.secret_access_key,
            config=Config(signature_version="s3v4"),
        )

        self.local_path.mkdir(parents=True, exist_ok=True)

    def _get_object_size(self, key: str) -> int:
        """Get the size of an S3 object in bytes."""
        response = self._client.head_object(Bucket=self.s3_config.bucket, Key=key)
        return response["ContentLength"]

    def get_snapshot_size(self, snapshot_name: str) -> int:
        """Get the size of a snapshot on S3 in bytes.

        Args:
            snapshot_name: Name of the snapshot file

        Returns:
            Size in bytes
        """
        s3_key = f"snapshots/{self.operating_system}/{self.architecture}/{snapshot_name}"
        return self._get_object_size(s3_key)

    def get_available_disk_space(self) -> int:
        """Get available disk space at the local snapshots path in bytes.

        Returns:
            Available space in bytes
        """
        return shutil.disk_usage(self.local_path).free

    @staticmethod
    def _format_bytes(size_bytes: int) -> str:
        """Format bytes as human-readable string."""
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if abs(size_bytes) < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024  # type: ignore[assignment]
        return f"{size_bytes:.1f} PB"

    def maybe_cleanup_for_download(self, snapshot_name: str, no_cleanup: bool) -> None:
        """Cleanup snapshots in the folder if needed to make space for download.

        Args:
            snapshot_name: Name of the snapshot about to be downloaded
            no_cleanup: Whether --no-cleanup was specified
        """
        local_file = self.local_path / snapshot_name
        if local_file.exists():
            return

        try:
            snapshot_size = self.get_snapshot_size(snapshot_name)
        except Exception:
            return

        available_space = self.get_available_disk_space()

        self.console.print(
            f"  [dim]Available disk space:[/dim] {self._format_bytes(available_space)}"
        )
        self.console.print(f"  [dim]Snapshot size:[/dim] {self._format_bytes(snapshot_size)}")

        if no_cleanup:
            self.console.print("  [dim]Cleanup:[/dim] disabled (--no-cleanup is set)")
            return

        if available_space >= snapshot_size:
            self.console.print("  [dim]Cleanup:[/dim] not needed (enough space available)")
            return

        # Get all snapshot files, sorted by size (largest first)
        snapshot_files = sorted(
            self.local_path.glob("*.lime"),
            key=lambda p: p.stat().st_size,
            reverse=True,
        )

        if not snapshot_files:
            self.console.print("  [dim]Cleanup:[/dim] no snapshots to delete")
            return

        self.console.print(
            "  [dim]Cleanup:[/dim] [yellow]deleting snapshots to free space[/yellow]"
        )

        for snapshot_path in snapshot_files:
            if available_space >= snapshot_size:
                break
            file_size = snapshot_path.stat().st_size
            size_str = self._format_bytes(file_size)
            self.console.print(f"    [yellow]Deleting[/yellow] {snapshot_path.name} ({size_str})")
            snapshot_path.unlink()
            available_space += file_size

    def download(self, snapshot_name: str, no_cleanup: bool = False) -> Path:
        """Download a snapshot if not already cached locally.

        Args:
            snapshot_name: Name of the snapshot file (e.g., "ubuntu2404_6.14.0-37-generic.lime")
            no_cleanup: Whether to disable automatic cleanup when disk space is low

        Returns:
            Path to the snapshot file (cached or newly downloaded)
        """
        local_file = self.local_path / snapshot_name

        if local_file.exists():
            self.console.print(f"[green]Using cached[/green] {snapshot_name}")
            return local_file

        self.maybe_cleanup_for_download(snapshot_name, no_cleanup)

        s3_key = f"snapshots/{self.operating_system}/{self.architecture}/{snapshot_name}"

        try:
            total_size = self._get_object_size(s3_key)
        except Exception as e:
            self.console.print(f"[red]Error getting snapshot info: {e}[/red]")
            raise

        self.console.print(f"[blue]Downloading[/blue] {snapshot_name}")

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=self.console,
        ) as progress:
            task_id: TaskID = progress.add_task("Downloading", total=total_size)

            def progress_callback(bytes_transferred: int) -> None:
                progress.update(task_id, advance=bytes_transferred)

            with local_file.open("wb") as f:
                self._client.download_fileobj(
                    Bucket=self.s3_config.bucket,
                    Key=s3_key,
                    Fileobj=f,
                    Callback=progress_callback,
                )

        self.console.print(f"[green]Downloaded[/green] {snapshot_name}")
        return local_file

    def get_local_snapshot_path(self, snapshot_name: str) -> Path:
        """Get the local path for a snapshot (whether downloaded or not).

        Args:
            snapshot_name: Name of the snapshot file

        Returns:
            Path where the snapshot would be/is stored locally
        """
        return self.local_path / snapshot_name

    def snapshot_exists_locally(self, snapshot_name: str) -> bool:
        """Check if a snapshot already exists locally.

        Args:
            snapshot_name: Name of the snapshot file

        Returns:
            True if the snapshot exists locally
        """
        return (self.local_path / snapshot_name).exists()
