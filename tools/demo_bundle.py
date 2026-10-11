"""Explicit DEVELOPMENT demo; persist public evidence only, never signing keys."""

from __future__ import annotations

import argparse
from contextlib import ExitStack
from pathlib import Path

from libs.blackbox_core.canonical import canonicalize
from tools.attack_suite.fixture import build_demo
from tools.ceremony import generate_dev_keys


def write_demo(output: Path) -> None:
    """Fixed ten-entry workload/timestamps, freshly random ephemeral signing identities."""
    if not output.is_dir():
        raise NotADirectoryError(f"output directory must already exist: {output}")
    paths = (output / "bundle.json", output / "pinned-keys.json")
    for path in paths:
        if path.exists() or path.is_symlink():
            raise FileExistsError(f"refusing to overwrite existing output: {path}")
    bundle, pins = build_demo(generate_dev_keys())
    payloads = (canonicalize(bundle.model_dump()), canonicalize(pins.model_dump()))
    created = []
    try:
        with ExitStack() as stack:
            streams = []
            for path in paths:
                streams.append(stack.enter_context(path.open("xb")))
                created.append(path)
            for stream, payload in zip(streams, payloads):
                stream.write(payload)
    except OSError:
        for path in created:
            path.unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Development-only public demo bundle; ephemeral keys are never persisted"
    )
    parser.add_argument("--output", type=Path, default=Path("artifacts"))
    args = parser.parse_args()
    try:
        write_demo(args.output)
    except OSError as exc:
        parser.error(str(exc))
    print(f"Development public evidence written to {args.output}")


if __name__ == "__main__":
    main()
