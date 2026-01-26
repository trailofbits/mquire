"""S3/Spaces snapshot management."""

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
        self._current_snapshot: Path | None = None

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

    def download(self, snapshot_name: str) -> Path:
        """Download a snapshot, deleting any previous snapshot first.

        Args:
            snapshot_name: Name of the snapshot file (e.g., "ubuntu2404_6.14.0-37-generic.lime")

        Returns:
            Path to the downloaded snapshot file
        """
        self.cleanup()

        local_file = self.local_path / snapshot_name
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

        self._current_snapshot = local_file
        self.console.print(f"[green]Downloaded[/green] {snapshot_name}")
        return local_file

    def cleanup(self) -> None:
        """Delete the current snapshot file if it exists."""
        if self._current_snapshot and self._current_snapshot.exists():
            self.console.print(f"[yellow]Cleaning up[/yellow] {self._current_snapshot.name}")
            self._current_snapshot.unlink()
            self._current_snapshot = None

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

    def __enter__(self) -> "SnapshotManager":
        """Context manager entry."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        """Context manager exit - cleanup on exit."""
        self.cleanup()
