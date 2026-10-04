"""DWE Nessie — Pulumi entry point. Delegates to cloud provider module."""

import yaml
from pathlib import Path

_hydration = Path(__file__).parent / "dwe-hydration.yaml"
if _hydration.exists():
    cloud_provider = yaml.safe_load(_hydration.read_text()).get("cloud_provider", "azure")
else:
    import pulumi
    cloud_provider = pulumi.Config().get("cloud_provider") or "azure"

if cloud_provider == "azure":
    import _azure  # noqa: F401
else:
    import _aws  # noqa: F401
