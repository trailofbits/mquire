"""Configuration models and environment handling."""

import os
from pathlib import Path

from pydantic import BaseModel, Field, field_validator


class S3Config(BaseModel):
    """S3/Spaces configuration from environment variables."""

    bucket: str
    endpoint: str
    access_key_id: str
    secret_access_key: str

    @classmethod
    def from_env(cls) -> "S3Config":
        """Load S3 configuration from environment variables."""
        bucket = os.environ.get("MQUIRE_TEST_S3_BUCKET")
        endpoint = os.environ.get("MQUIRE_TEST_S3_ENDPOINT")
        access_key_id = os.environ.get("MQUIRE_TEST_AWS_ACCESS_KEY_ID")
        secret_access_key = os.environ.get("MQUIRE_TEST_AWS_SECRET_ACCESS_KEY")

        missing = []
        if not bucket:
            missing.append("MQUIRE_TEST_S3_BUCKET")
        if not endpoint:
            missing.append("MQUIRE_TEST_S3_ENDPOINT")
        if not access_key_id:
            missing.append("MQUIRE_TEST_AWS_ACCESS_KEY_ID")
        if not secret_access_key:
            missing.append("MQUIRE_TEST_AWS_SECRET_ACCESS_KEY")

        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        # Type narrowing: all values are guaranteed to be set after the check above
        assert bucket is not None
        assert endpoint is not None
        assert access_key_id is not None
        assert secret_access_key is not None

        return cls(
            bucket=bucket,
            endpoint=endpoint,
            access_key_id=access_key_id,
            secret_access_key=secret_access_key,
        )


class ManifestConfig(BaseModel):
    """Configuration loaded from manifest.json."""

    mquire_path: str = Field(description="Path to mquire binary (relative to manifest)")
    tests: dict[str, str] = Field(
        description="Mapping of snapshot filename to SQL test directory path"
    )
    architecture: str = Field(default="intel", description="CPU architecture")
    operating_system: str = Field(default="linux", description="Operating system")
    local_snapshots_path: str = Field(
        default="../snapshots", description="Local path for downloaded snapshots"
    )
    timeout_seconds: int = Field(default=300, description="Timeout per query in seconds")

    # Set after loading, not from JSON
    _manifest_dir: Path | None = None

    @field_validator("tests")
    @classmethod
    def validate_tests(cls, v: dict[str, str]) -> dict[str, str]:
        """Validate tests mapping."""
        if not v:
            raise ValueError("tests mapping cannot be empty")
        return v

    def set_manifest_dir(self, manifest_path: Path) -> None:
        """Set the manifest directory for path resolution."""
        self._manifest_dir = manifest_path.parent.resolve()

    def resolve_path(self, path: str) -> Path:
        """Resolve a path relative to the manifest directory."""
        if self._manifest_dir is None:
            raise ValueError("Manifest directory not set. Call set_manifest_dir() first.")
        p = Path(path)
        if p.is_absolute():
            return p
        return (self._manifest_dir / p).resolve()

    def get_mquire_path(self) -> Path:
        """Get resolved mquire binary path."""
        return self.resolve_path(self.mquire_path)

    def get_snapshots_path(self) -> Path:
        """Get resolved local snapshots path: <local_snapshots_path>/<os>/<arch>/."""
        base = self.resolve_path(self.local_snapshots_path)
        return base / self.operating_system.lower() / self.architecture.lower()

    def get_snapshot_names(self) -> list[str]:
        """Get list of snapshot filenames."""
        return list(self.tests.keys())

    def get_sql_path_for_snapshot(self, snapshot_name: str) -> Path:
        """Get the SQL query path for a specific snapshot."""
        if snapshot_name not in self.tests:
            raise ValueError(f"Snapshot '{snapshot_name}' not found in tests mapping")
        return self.resolve_path(self.tests[snapshot_name])

    @classmethod
    def load(cls, manifest_path: Path) -> "ManifestConfig":
        """Load configuration from a manifest file."""
        import json

        with manifest_path.open() as f:
            data = json.load(f)

        config = cls.model_validate(data)
        config.set_manifest_dir(manifest_path)
        return config
