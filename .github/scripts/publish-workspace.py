"""Publish new workspace versions; unchanged dependency crates are already available."""

import json
import subprocess
from urllib.error import HTTPError
from urllib.request import Request, urlopen


metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"]
    )
)
members = set(metadata["workspace_members"])
pending = []
for package in metadata["packages"]:
    if package["id"] not in members or package.get("publish") == []:
        continue
    name, version = package["name"], package["version"]
    request = Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": "StackPulse release (github.com/pablogsal/stackpulse)"},
    )
    try:
        with urlopen(request, timeout=30):
            print(f"{name} {version} is already published", flush=True)
    except HTTPError as error:
        if error.code != 404:
            raise
        pending.extend(["--package", name])

if pending:
    # Cargo orders workspace packages by their dependencies and waits for indexing.
    subprocess.run(["cargo", "publish", "--locked", *pending], check=True)
