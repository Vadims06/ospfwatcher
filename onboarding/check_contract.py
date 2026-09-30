"""Keeps onboarding/manifest.json, client.py, docker-compose.yml and VERSION in step.

Topolograph builds its Add watcher form from the manifest, client.py reads the
answers by field id, and the install checks out the tag in VERSION.
"""
import ast
import json
import pathlib
import re
import subprocess
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent


def get_client_attributes() -> set:
    tree = ast.parse((ROOT / "client.py").read_text())
    watcher_config = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "WATCHER_CONFIG")
    init = next(node for node in watcher_config.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    return {target.attr for node in ast.walk(init) if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Attribute)}


def get_image_errors(image: str) -> list:
    errors = []
    name, _, image_tag = image.rpartition(":")
    if not name or "/" in image_tag or image_tag == "latest":
        errors.append(f"{image}: pin an explicit tag")
    first_segment = image.split("/")[0]
    if "/" in image and ("." in first_segment or ":" in first_segment):
        errors.append(f"{image}: only Docker Hub images, so one mirror prefix serves them all")
    return errors


def get_errors(tag: str) -> list:
    errors = []
    manifest = json.loads((ROOT / "onboarding" / "manifest.json").read_text())
    version = (ROOT / "VERSION").read_text().strip()

    attributes = get_client_attributes()
    for field in manifest["fields"]:
        if field["source"] != "server" and "env" not in field and field["id"] not in attributes:
            errors.append(f"manifest field {field['id']} is not a WATCHER_CONFIG attribute in client.py")

    if f"WATCHER_VERSION={version}\n" not in (ROOT / ".env.template").read_text():
        errors.append(".env.template WATCHER_VERSION differs from VERSION")
    if tag and tag != version:
        errors.append(f"tag {tag} differs from VERSION {version}")

    compose = json.loads(subprocess.run(
        ["docker", "compose", "--profile", "*", "config", "--format", "json"],
        cwd=ROOT, check=True, capture_output=True, text=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(pathlib.Path.home()), "WATCHER_VERSION": version},
    ).stdout)
    images = [service["image"] for service in compose["services"].values() if "build" not in service]
    client_source = (ROOT / "client.py").read_text()
    pinned = re.search(r"PINNED_IMAGES = \{(.*?)\n    \}", client_source, re.S).group(1)
    images += [image.replace("{version}", version) for image in re.findall(r'"([a-z0-9./-]+:[^"]+)"', pinned)]
    images += re.findall(r'LOGROTATION_IMAGE = "([^"]+)"', client_source)
    for image in images:
        errors += get_image_errors(image)
    if tag and not is_published("vadims06/ospf-watcher", version):
        errors.append(f"vadims06/ospf-watcher:{version} is not published on Docker Hub")
    return errors


def is_published(name: str, image_tag: str) -> bool:
    url = f"https://hub.docker.com/v2/repositories/{name}/tags/{image_tag}"
    try:
        with urllib.request.urlopen(url, timeout=20):
            return True
    except OSError:
        return False


if __name__ == "__main__":
    found = get_errors(sys.argv[1] if len(sys.argv) > 1 else "")
    for error in found:
        print(f"::error::{error}")
    sys.exit(1 if found else 0)
