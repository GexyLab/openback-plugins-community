"""Builds an OpenBack plugin repository (openback-plugins-official, openback-plugins-community): checks every plugin (the
folders plugins/integrations/, plugins/serverless-function-libraries/, plugins/templates/, plugins/mcp-servers/ and
plugins/apps/), packs the archive of each version not yet published into dist/, and writes the catalog OpenBack reads,
index.json, signed with the repository's key (index.json.sig).

SHARED FILE: the master copy is tools/plugins/repo_build.py of the OpenBack repository; each plugin repository carries
it as tools/build.py -- copy, never fork.

    python tools/build.py                build (the signing key: --key FILE, or the PEM in env OPENBACK_PLUGIN_SIGNING_KEY)
    python tools/build.py --check        only check the plugins and that dist/ and index.json are up to date (pull requests)

Layout of a repository:

    repository.json                      {"channel": "official"|"community", "publisher": "<signing key id>",
                                          "license": "<SPDX id>", "name": "..."}
    categories.json                      {"integration"|"library"|"template"|"mcp-server"|"app": {"<key>": {"it": ..., "en": ...}}}
    plugins/integrations/<slug>/         an integration package (SDK): manifest.json, integration.py, doc/, ...
    plugins/serverless-function-libraries/<slug>/  a serverless function (LogicBlock) library: manifest.json, library.py (or "provided_by": "engine"), doc/
    plugins/templates/<slug>/            a function template: template.json, doc/
    plugins/mcp-servers/<slug>/          an MCP server (mcp-service): manifest.json ("native": tools on an integration's
                                         operations, on functions from templates and on OpenBack's own administration
                                         (platform tools); "proxy": a remote MCP server; optional guide), doc/
    plugins/apps/<slug>/                 a ready-made project or app (scope bundle, imported by OpenBack's bundle importer):
                                         an unpacked .obapp -- bundle.json (its manifest), sections/, data/ -- plus doc/
    plugins/<type folder>/<slug>/plugin.json   optional, the catalog's extra data: {"license", "pricing",
                                         "tags", "author", "homepage", "requires": {"plugins": [{"type", "slug"}]}}
                                         (an app: also "name", "description", "category", "icon" for its card)
    dist/<type>/<slug>/<slug>-<version>.<ext>   the published archives (never changed once published)
    index.json, index.json.sig           the catalog and its signature

A plugin's license is its plugin.json "license"; without one, the repository's (repository.json). Its documentation is
the doc/ folder inside it (README.md first), shipped in its archive.

Authoring-only files live next to a plugin but are never part of it: the plugin folder's own build.py, build_docs.py and
build_manifest.py (the scripts that write its manifest and docs), any tests/ folder, __pycache__/ and *.pyc. They never go
into an archive, and adding, changing or removing them never alters a published version: a version published while one
of them was still packed (before this rule) is compared without it. Line endings are not content either: text files
are kept LF (the repository's .gitattributes), and a version once packed from a CRLF working copy still matches.

An app (plugins/apps/<slug>/) is a scope bundle as OpenBack exports it (format "openback-bundle"), unzipped, with "slug"
and "version" added to its bundle.json (tools/app_build/ of the official repository does it from an exported .obapp).
A catalog app carries no secret values, no storage files, no encryption, no people or groups to map, and database data
only as SEED (each database of meta.databases with data marked "seed": true, at most 10 MB of database files); its
requires.plugins are the bundle's requirements.plugins (derived when plugin.json has none, else they must match). Its
archive (.obapp) is the bundle itself: bundle.json at the root, every file of the folder but plugin.json and the
authoring-only files of its root -- dot files and folders like dist/ or build/ inside sections/ and data/ are the
bundle's content (a site's source) and are packed.

Only the standard library and `cryptography` (Ed25519).
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import zipfile
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TYPES = {  # type -> (folder, manifest file, archive extension)
    "integration": ("integrations", "manifest.json", ".obint"),
    "library": ("serverless-function-libraries", "manifest.json", ".oblib"),
    "template": ("templates", "template.json", ".obtpl"),
    "mcp-server": ("mcp-servers", "manifest.json", ".obmcp"),
    "app": ("apps", "bundle.json", ".obapp"),
}
INDEX_SCHEMA = 1
SLUG = {
    "integration": re.compile(r"^[a-z][a-z0-9-]{1,39}$"),
    "library": re.compile(r"^[a-z][a-z0-9_-]{1,30}(\.[a-z0-9][a-z0-9_-]{0,30})?$"),
    "template": re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$"),
    "mcp-server": re.compile(r"^[a-z][a-z0-9-]{1,39}$"),
    "app": re.compile(r"^[a-z][a-z0-9-]{1,39}$"),
}
SEMVER = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,6})$")
PRICING = ("free", "paid")
SKIP_DIRS = {"__pycache__", ".git", ".venv", "venv", ".pytest_cache", ".mypy_cache", "tests", "dist", "build"}
AUTHORING_FILES = {"build.py", "build_docs.py", "build_manifest.py"}  # in the plugin's root folder only
SKIP_FILES = {"plugin.json"} | AUTHORING_FILES
SKIP_SUFFIXES = (".pyc", ".pyo", ".obint", ".oblib", ".obtpl", ".obmcp", ".obapp")
# Text files: the repository keeps them LF (.gitattributes); a published archive packed from a CRLF working copy is
# still the same version (see same_content).
TEXT_SUFFIXES = (".md", ".py", ".json", ".txt", ".yml", ".yaml", ".toml", ".cfg", ".ini", ".csv", ".html", ".js", ".css", ".sql", ".svg")
MAX_ARCHIVE_BYTES = {"integration": 12 * 1024 * 1024, "library": 4 * 1024 * 1024, "template": 4 * 1024 * 1024,
                     "mcp-server": 1024 * 1024,
                     "app": 16 * 1024 * 1024}  # the integration-service downloads at most 16 MB (plugin_sources.py)
# An app (scope bundle, OpenBack's backend bundles/format.py): what a catalog bundle may hold.
APP_FORMAT = "openback-bundle"
APP_FORMAT_VERSION = 1
APP_KINDS = ("project", "app")
APP_MAX_SEED_BYTES = 10 * 1024 * 1024  # every file under data/databases/ when the bundle carries seed data
APP_ENTRY_NAME = re.compile(r"^[A-Za-z0-9._@+=,~\- ()\[\]/]+$")  # as the importer checks them (format.check_name)
APP_PLUGIN_TYPES = ("integration", "library", "template", "mcp-server")  # what a plugin may require (never an app)
# An MCP server plugin (mcp-service): its tools and what they run. "native": operations / query templates of one
# integration, functions made from templates and platform tools (OpenBack's own administration API, by area: no
# integration needed); "proxy": a remote MCP server reached through the "mcp" integration. A guide (rules on how to use
# the tools, read by the clients through one tool) may come with it.
MCP_TOOL_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MCP_TOOL_KINDS = ("operation", "function", "platform")  # query templates are the project's own: not in plugins
MCP_PLATFORM_OP = re.compile(r"^[a-z][a-z0-9_]{1,63}$")  # OpenBack's own administration (mcp-service platform_tools.py)
MCP_TOPIC = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
MCP_MAX_RULES = 100
MCP_APPROVALS = ("none", "client", "portal")
MCP_REMOTE_AUTH = ("oauth", "bearer", "header", "none")
SIGNATURE = "SIGNATURE.json"
ZIP_DATE = (2020, 1, 1, 0, 0, 0)


class BuildError(Exception):
    pass


def semver(v: str) -> tuple:
    m = SEMVER.match(v or "")
    return tuple(int(x) for x in m.groups()) if m else (-1, -1, -1)


def text(value, fallback: str = "") -> dict:
    if isinstance(value, str):
        return {"it": value, "en": value}
    if isinstance(value, dict):
        it = str(value.get("it") or value.get("en") or fallback)
        return {"it": it, "en": str(value.get("en") or it)}
    return {"it": fallback, "en": fallback}


def read_json(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")


# ---------------------------------------------------------------- archives

def plugin_files(folder: str, ptype: str = "") -> dict:
    """{relative path: bytes} of what goes in the archive (plugin.json and build leftovers excluded). An app's folders
    below its root are the bundle's own content (a site's source may have dot files, dist/, build/, tests/): only .git
    folders are left out there."""
    out = {}
    for current, dirs, files in os.walk(folder):
        content = ptype == "app" and current != folder
        if content:
            dirs[:] = sorted(d for d in dirs if d != ".git")
        else:
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(files):
            if not content and (name in SKIP_FILES and current == folder or name.startswith(".") or name.endswith(SKIP_SUFFIXES)):
                continue
            full = os.path.join(current, name)
            if os.path.islink(full):
                raise BuildError(f"{full}: symbolic links are not allowed")
            with open(full, "rb") as f:
                out[os.path.relpath(full, folder).replace(os.sep, "/")] = f.read()
    return out


def content_digest(files: dict) -> str:
    """The .oblib digest (run-service oblib.py): SHA-256 of "<path>\\0<sha256>\\n" per file but SIGNATURE.json, sorted."""
    lines = "".join(f"{p}\0{hashlib.sha256(c).hexdigest()}\n" for p, c in sorted(files.items()) if p != SIGNATURE)
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


def zip_bytes(files: dict) -> bytes:
    """A deterministic ZIP: same files, same bytes (sorted, fixed dates and modes)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=ZIP_DATE)
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, files[name])
    return buffer.getvalue()


def authoring_only(path: str, ptype: str = "") -> bool:
    """True for a path (inside a plugin, '/'-separated) that is never part of the plugin: see the module's docstring.
    An app: only its root's authoring files (everything below is the bundle's content)."""
    parts = path.split("/")
    if ptype == "app":
        return len(parts) == 1 and parts[0] in AUTHORING_FILES
    return ((len(parts) == 1 and parts[0] in AUTHORING_FILES) or "tests" in parts[:-1] or "__pycache__" in parts[:-1]
            or path.endswith((".pyc", ".pyo")))


def _lf(name: str, data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n") if name.lower().endswith(TEXT_SUFFIXES) else data


def same_content(published: bytes, files: dict, ptype: str = "") -> bool:
    """Whether a published archive holds these files, leaving out its authoring-only files (packed by older builds) and
    a library's SIGNATURE.json (it only signs the rest), and reading text files whatever their line endings (older
    builds packed some from CRLF working copies)."""
    try:
        with zipfile.ZipFile(io.BytesIO(published)) as archive:
            old = {n: _lf(n, archive.read(n)) for n in archive.namelist()
                   if not n.endswith("/") and n != SIGNATURE and not authoring_only(n, ptype)}
    except (zipfile.BadZipFile, OSError):
        return False
    return old == {n: _lf(n, c) for n, c in files.items() if n != SIGNATURE}


def load_key(args):
    pem = None
    if args.key:
        with open(args.key, "rb") as f:
            pem = f.read()
    elif os.environ.get("OPENBACK_PLUGIN_SIGNING_KEY"):
        pem = os.environ["OPENBACK_PLUGIN_SIGNING_KEY"].encode()
    if not pem:
        return None
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise BuildError("the signing key must be Ed25519")
    return key


def sign_text(key, value: str) -> str:
    return base64.b64encode(key.sign(value.encode("ascii"))).decode()


def build_archive(ptype: str, files: dict, key, publisher: str) -> bytes:
    if ptype == "library":  # signed like any .oblib (Ed25519 signatures are deterministic: same files, same archive)
        files = {k: v for k, v in files.items() if k != SIGNATURE}
        digest = content_digest(files)
        files[SIGNATURE] = json.dumps({"publisher": publisher, "algorithm": "ed25519", "digest": digest,
                                       "signature": sign_text(key, digest)}, indent=2).encode()
    data = zip_bytes(files)
    if len(data) > MAX_ARCHIVE_BYTES[ptype]:
        raise BuildError(f"archive too large ({len(data)} bytes, max {MAX_ARCHIVE_BYTES[ptype]})")
    return data


# ---------------------------------------------------------------- checks and catalog entries

def _requires(plugin: dict, errors: list) -> dict:
    req = plugin.get("requires") or {}
    deps = []
    for dep in req.get("plugins") or []:
        if (not isinstance(dep, dict) or dep.get("type") not in APP_PLUGIN_TYPES
                or not SLUG[dep["type"]].match(str(dep.get("slug") or ""))):
            errors.append(f"requires.plugins: invalid entry {dep!r}")
            continue
        deps.append({"type": dep["type"], "slug": dep["slug"]})
    return {"plugins": deps}


def entry_integration(slug: str, m: dict, errors: list) -> dict:
    try:  # the SDK's own checks, when it is installed (OpenBack's CI installs it)
        from openback_integrations.manifest import validate_manifest
        m = validate_manifest(m)
    except ImportError:
        pass
    except Exception as exc:  # ManifestError
        errors.append(f"manifest.json: {'; '.join(getattr(exc, 'errors', [str(exc)]))}")
    # The platform services it needs (as the integration-service's packages.services_of): saving files needs Storage.
    required = list(m.get("requires_services") or [])
    optional = [x for x in m.get("optional_services") or [] if x not in required]
    if any(op.get("save_to_storage") for op in m.get("operations") or []) and "storage" not in required + optional:
        optional.append("storage")
    words_it, words_en = [], []
    for item in (m.get("operations") or []) + (m.get("webhooks") or []):
        label = text(item.get("label"), item.get("name") or "")
        words_it.append(label["it"])
        words_en.append(label["en"])
    return {"name": text(m.get("name"), slug), "description": text(m.get("description")), "category": str(m.get("category") or "other").lower(),
            "icon": m.get("icon") or "plug", "author": m.get("author") or "", "homepage": m.get("homepage") or "",
            "keywords": {"it": words_it, "en": words_en},
            "details": {"operations": len(m.get("operations") or []), "webhooks": len(m.get("webhooks") or []),
                        "sdk_version": m.get("sdk_version") or "", "libraries": list(m.get("libraries") or []),
                        "requires_services": required, "optional_services": optional}}


def entry_library(slug: str, m: dict, files: dict, publisher: str, errors: list) -> dict:
    if m.get("schema_version") != 1:
        errors.append("manifest.json: schema_version must be 1")
    if m.get("publisher") != publisher:
        errors.append(f"manifest.json: publisher must be this repository's ({publisher})")
    engine = m.get("provided_by") == "engine"
    if not engine and "library.py" not in files:
        errors.append("library.py is missing")
    blocks = m.get("blocks") or []
    if engine and not blocks:
        errors.append("manifest.json: an engine library lists its blocks")
    return {"name": text(m.get("name"), slug), "description": text(m.get("description")), "category": str(m.get("category") or "other").lower(),
            "icon": m.get("icon") or "blocks", "author": m.get("author") or "", "homepage": m.get("homepage") or "",
            "keywords": {"it": [text(b.get("label"))["it"] for b in blocks], "en": [text(b.get("label"))["en"] for b in blocks]},
            "details": {"provided_by": "engine" if engine else "code", "blocks": blocks, "service": m.get("service"),
                        "engine": m.get("engine") or ">=1"}}


def entry_template(slug: str, t: dict, errors: list) -> dict:
    if t.get("schema_version") != 1:
        errors.append("template.json: schema_version must be 1")
    for field in ("level", "category", "product"):
        if not t.get(field):
            errors.append(f"template.json: {field} is required")
    if not isinstance((t.get("build") or {}).get("it"), dict) or not isinstance((t.get("build") or {}).get("en"), dict):
        errors.append("template.json: build.it and build.en (the function's fields) are required")
    return {"name": text(t.get("name"), slug), "description": text(t.get("description")), "category": str(t.get("category") or "other"),
            "icon": t.get("icon") or "", "author": t.get("author") or "", "homepage": t.get("homepage") or "",
            "keywords": {"it": [text(t.get("product_name"))["it"]] + list(t.get("tags") or []),
                         "en": [text(t.get("product_name"))["en"]] + list(t.get("tags") or [])},
            "details": {"level": t.get("level"), "product": t.get("product"), "product_name": text(t.get("product_name"), t.get("product") or ""),
                        "trigger": t.get("trigger") or "manual", "blocks": int(t.get("block_count") or 0),
                        "integrations": list(t.get("integrations") or []), "libraries": list(t.get("libraries") or []),
                        "steps": text(t.get("steps"))}}


def entry_mcp_server(slug: str, m: dict, errors: list) -> dict:
    """The checks mcp-service repeats when it stores the plugin (server_plugins.validate)."""
    if m.get("schema_version") != 1:
        errors.append("manifest.json: schema_version must be 1")
    mode = m.get("mode")
    if mode not in ("native", "proxy"):
        errors.append('manifest.json: mode must be "native" or "proxy"')
    tools, names, keys = m.get("tools") or [], set(), set()
    if not isinstance(tools, list):
        errors.append("manifest.json: tools must be a list")
        tools = []
    integration = (m.get("integration") or {}).get("package") if isinstance(m.get("integration"), dict) else None
    remote = m.get("remote") if isinstance(m.get("remote"), dict) else None
    if mode == "native":
        if not integration and any((t.get("kind") or "operation") == "operation" for t in tools if isinstance(t, dict)):
            errors.append("manifest.json: integration.package is required for operation tools")
        if not tools:
            errors.append("manifest.json: a native server lists its tools")
    if mode == "proxy":
        if not remote or not str(remote.get("url") or "").startswith("https://"):
            errors.append("manifest.json: remote.url (https) is required for a proxy server")
        elif any(a not in MCP_REMOTE_AUTH for a in remote.get("auth") or []) or not remote.get("auth"):
            errors.append(f"manifest.json: remote.auth must list some of {MCP_REMOTE_AUTH}")
        if tools:
            errors.append("manifest.json: a proxy server has no tools (they are imported from the remote server)")
    templates = []
    for i, t in enumerate(tools):
        at = f"tools[{i}]"
        if not isinstance(t, dict):
            errors.append(f"{at}: must be an object")
            continue
        name = str(t.get("name") or "")
        if not MCP_TOOL_NAME.match(name):
            errors.append(f"{at}: invalid name {name!r}")
        if name in names:
            errors.append(f"{at}: duplicate name {name}")
        names.add(name)
        key = str(t.get("key") or name)
        if key in keys:
            errors.append(f"{at}: duplicate key {key}")
        keys.add(key)
        kind = t.get("kind") or "operation"
        if kind not in MCP_TOOL_KINDS:
            errors.append(f"{at}: kind must be one of {MCP_TOOL_KINDS}")
        if kind == "operation" and not t.get("operation"):
            errors.append(f"{at}: operation is required")
        if kind == "function":
            if not SLUG["template"].match(str(t.get("template") or "")):
                errors.append(f"{at}: template (a function template's slug) is required")
            else:
                templates.append(t["template"])
            schema = t.get("input_schema")
            if schema is not None and (not isinstance(schema, dict) or schema.get("type", "object") != "object"):
                errors.append(f"{at}: input_schema must be a JSON Schema of type object")
        if kind == "platform" and not MCP_PLATFORM_OP.match(str(t.get("platform_op") or "")):
            errors.append(f"{at}: platform_op (a platform tool of OpenBack's mcp-service, e.g. functions_read) is required")
        if (t.get("approval") or "none") not in MCP_APPROVALS:
            errors.append(f"{at}: approval must be one of {MCP_APPROVALS}")
        if not isinstance(t.get("fixed_params") or {}, dict):
            errors.append(f"{at}: fixed_params must be an object")
        # A platform tool may leave its description to OpenBack (the platform tool's own, always current).
        if not text(t.get("description"))["en"] and kind != "platform":
            errors.append(f"{at}: description (English first: models read it) is required")
    rules = _mcp_guide(m.get("guide"), keys, errors)
    return {"name": text(m.get("name"), slug), "description": text(m.get("description")), "category": str(m.get("category") or "other").lower(),
            "icon": m.get("icon") or "server", "author": m.get("author") or "", "homepage": m.get("homepage") or "",
            "keywords": {"it": [t.get("name", "") for t in tools if isinstance(t, dict)] + [text(m.get("vendor"))["it"]],
                         "en": [t.get("name", "") for t in tools if isinstance(t, dict)] + [text(m.get("vendor"))["en"]]},
            "details": {"mode": mode, "integration": integration, "tools": len(tools),
                        "functions": len([t for t in tools if isinstance(t, dict) and t.get("kind") == "function"]),
                        "templates": sorted(set(templates)), "vendor": text(m.get("vendor")),
                        "remote_url": (remote or {}).get("url") or "", "remote_auth": list((remote or {}).get("auth") or []),
                        "read_only": len([t for t in tools if isinstance(t, dict) and t.get("read_only")]),
                        "platform": len([t for t in tools if isinstance(t, dict) and t.get("kind") == "platform"]),
                        "guide_rules": rules}}


def _mcp_guide(g, tool_keys: set, errors: list) -> int:
    """The server's guide (mcp-service guide.py): {"tool_name", "enabled", "rules": [{key, topic, title, text, required,
    enabled, tools: [tool keys]}]}. -> the number of rules."""
    if g is None:
        return 0
    if not isinstance(g, dict):
        errors.append("manifest.json: guide must be an object")
        return 0
    if g.get("tool_name") is not None and not MCP_TOOL_NAME.match(str(g["tool_name"])):
        errors.append("guide.tool_name: an MCP tool name")
    rules = g.get("rules") or []
    if not isinstance(rules, list) or len(rules) > MCP_MAX_RULES:
        errors.append(f"guide.rules: a list of at most {MCP_MAX_RULES}")
        return 0
    keys = set()
    for i, r in enumerate(rules):
        at = f"guide.rules[{i}]"
        if not isinstance(r, dict):
            errors.append(f"{at}: must be an object")
            continue
        if not MCP_TOPIC.match(str(r.get("key") or "")) or r.get("key") in keys:
            errors.append(f"{at}: invalid or duplicate key")
        keys.add(r.get("key"))
        if not MCP_TOPIC.match(str(r.get("topic") or "")):
            errors.append(f"{at}: topic must be lower-case letters, digits, - and _ (at most 40)")
        title, body = text(r.get("title"))["en"], text(r.get("text"))["en"]
        if not title or not body:
            errors.append(f"{at}: title and text (English: models read them) are required")
        if len(title) > 120 or len(body) > 4000:
            errors.append(f"{at}: title (120 characters) or text (4000) too long")
        unknown = [k for k in r.get("tools") or [] if k not in tool_keys]
        if unknown:
            errors.append(f"{at}: tools not in the server: {', '.join(map(str, unknown[:5]))}")
    return len(rules)


def _listed(value) -> list:
    """A bundle requirement group as a list (the exporter may key it by ref)."""
    if isinstance(value, dict):
        return [v for v in value.values() if isinstance(v, dict)]
    return [v for v in value or [] if isinstance(v, dict)] if isinstance(value, list) else []


def _db_has_data(db: dict) -> bool:
    return any(db.get(k) for k in ("data", "has_data", "data_files", "rows"))


def entry_app(slug: str, m: dict, plugin: dict, files: dict, errors: list) -> dict:
    """A scope bundle offered in the catalog: what OpenBack's importer reads (backend bundles/format.py), minus what a
    published bundle must never carry -- secret values, storage files, encryption, people / groups to map -- and with
    database data only as seed."""
    if m.get("format") != APP_FORMAT:
        errors.append(f'bundle.json: format must be "{APP_FORMAT}"')
    if m.get("format_version") != APP_FORMAT_VERSION:
        errors.append(f"bundle.json: format_version must be {APP_FORMAT_VERSION}")
    kind = m.get("kind")
    if kind not in APP_KINDS:
        errors.append(f"bundle.json: kind must be one of {APP_KINDS}")
    if m.get("encryption") is not None:
        errors.append("bundle.json: a catalog bundle is not encrypted (encryption must be null: export it without a passphrase)")
    contains = m.get("contains") if isinstance(m.get("contains"), dict) else {}
    if contains.get("secret_values"):
        errors.append("bundle.json: a catalog bundle carries no secret values (contains.secret_values)")
    if contains.get("storage_data"):
        errors.append("bundle.json: a catalog bundle carries no storage files (contains.storage_data)")
    requirements = m.get("requirements") if isinstance(m.get("requirements"), dict) else {}
    if _listed(requirements.get("principals")):
        errors.append("bundle.json: a catalog bundle names no people or groups (requirements.principals)")
    meta = m.get("meta") if isinstance(m.get("meta"), dict) else {}
    databases = _listed(meta.get("databases"))
    seed_bytes = sum(len(c) for p, c in files.items() if p.startswith("data/databases/"))
    if contains.get("database_data"):
        # The databases holding data (all of them when none says): each one must be seed.
        with_data = [d for d in databases if _db_has_data(d)] or databases
        unseeded = [str(d.get("name") or d.get("ref") or i) for i, d in enumerate(with_data) if d.get("seed") is not True]
        if unseeded:
            errors.append(f"bundle.json: database data only as seed (meta.databases[].seed: true): {', '.join(unseeded[:10])}")
        if seed_bytes > APP_MAX_SEED_BYTES:
            errors.append(f"data/databases/: {seed_bytes} bytes of seed data (max {APP_MAX_SEED_BYTES})")
    # The files, as the importer reads them.
    for path in files:
        parts = path.split("/")
        if len(path) > 512 or not APP_ENTRY_NAME.match(path) or any(p in ("", ".", "..") for p in parts):
            errors.append(f"{path[:80]!r}: a file name the importer refuses")
        elif path.endswith(".enc"):
            errors.append(f"{path}: encrypted files are not allowed in a catalog bundle")
        elif path.startswith("data/storage/"):
            errors.append(f"{path}: storage files are not allowed in a catalog bundle")
        elif path.startswith("data/databases/") and not contains.get("database_data") and not contains.get("database_schema"):
            errors.append(f"{path}: database files, but bundle.json declares neither a schema nor data")
    sections = m.get("sections") if isinstance(m.get("sections"), dict) else {}
    counts = {}
    for key, value in sorted(sections.items()):
        if f"sections/{key}.json" not in files:
            errors.append(f"bundle.json: section {key} has no sections/{key}.json")
        items = value.get("items") if isinstance(value, dict) else value
        counts[key] = items if isinstance(items, int) and not isinstance(items, bool) and items >= 0 else 0
    services = sorted({str(s.get("slug")) for s in _listed(requirements.get("services")) if s.get("slug")})
    plugins = []
    for p in _listed(requirements.get("plugins")):
        if p.get("type") not in APP_PLUGIN_TYPES or not SLUG[p["type"]].match(str(p.get("slug") or "")):
            errors.append(f"bundle.json: requirements.plugins: invalid entry {p!r}")
            continue
        plugins.append({"type": p["type"], "slug": p["slug"], "version": str(p.get("version") or ""),
                        "name": str(p.get("name") or p["slug"])})
    plugins.sort(key=lambda p: (p["type"], p["slug"]))
    installations = sorted(({"package_slug": str(i.get("package_slug") or ""), "name": str(i.get("name") or ""),
                             "version": str(i.get("version") or ""), "database": bool(i.get("database"))}
                            for i in _listed(requirements.get("installations"))), key=lambda i: (i["package_slug"], i["name"]))
    external = sorted(({"entity_type": str(e.get("entity_type") or ""), "name": str(e.get("name") or "")}
                       for e in _listed(requirements.get("external"))), key=lambda e: (e["entity_type"], e["name"]))
    words = list(counts) + [p["slug"] for p in plugins] + services
    return {"name": text(plugin.get("name") or m.get("name"), slug), "description": text(plugin.get("description") or m.get("description")),
            "category": str(plugin.get("category") or m.get("category") or "other").lower(),
            "icon": plugin.get("icon") or m.get("icon") or "boxes", "author": "", "homepage": "",
            "keywords": {"it": words, "en": words},
            "details": {"kind": kind, "format_version": m.get("format_version"), "sections": counts,
                        "items": sum(counts.values()),
                        "requirements": {"services": services, "plugins": plugins, "installations": installations,
                                         "service_accounts": len(_listed(requirements.get("service_accounts"))),
                                         "external": external},
                        "contains": {"database_schema": bool(contains.get("database_schema")),
                                     "seed_data": bool(contains.get("database_data"))},
                        "databases": len(databases), "seed_bytes": seed_bytes if contains.get("database_data") else 0}}


def app_requires(plugin: dict, entry: dict, errors: list) -> dict:
    """An app's requires.plugins: its bundle's requirements.plugins. plugin.json may list them (then they must be the
    same plugins); without them they are derived."""
    derived = [{"type": p["type"], "slug": p["slug"]} for p in ((entry.get("details") or {}).get("requirements") or {}).get("plugins") or []]
    if (plugin.get("requires") or {}).get("plugins") is None:
        return {"plugins": derived}
    listed = _requires(plugin, errors)["plugins"]
    want, have = {(d["type"], d["slug"]) for d in derived}, {(d["type"], d["slug"]) for d in listed}
    if want - have:
        errors.append("plugin.json: requires.plugins lacks what bundle.json requires: "
                      + ", ".join(f"{t} {s}" for t, s in sorted(want - have)))
    if have - want:
        errors.append("plugin.json: requires.plugins lists what bundle.json does not require: "
                      + ", ".join(f"{t} {s}" for t, s in sorted(have - want)))
    return {"plugins": derived}


def collect(repo: dict, key, check_only: bool) -> tuple:
    """-> (catalog entries, problems, archives written)."""
    entries, problems, written = [], [], []
    publisher = repo["publisher"]
    for ptype, (folder, manifest_name, ext) in TYPES.items():
        base = os.path.join(ROOT, "plugins", folder)
        for slug in sorted(os.listdir(base)) if os.path.isdir(base) else []:
            pdir = os.path.join(base, slug)
            if not os.path.isdir(pdir) or slug.startswith((".", "_")):
                continue
            errors = []
            if not SLUG[ptype].match(slug):
                errors.append("invalid folder name (slug)")
            try:
                manifest = read_json(os.path.join(pdir, manifest_name))
                plugin = read_json(os.path.join(pdir, "plugin.json")) if os.path.isfile(os.path.join(pdir, "plugin.json")) else {}
                files = plugin_files(pdir, ptype)
            except (OSError, ValueError, BuildError) as exc:
                problems.append(f"{ptype} {slug}: {exc}")
                continue
            if manifest.get("slug") != slug:
                errors.append(f"{manifest_name}: slug must be the folder's name ({slug})")
            version = manifest.get("version")
            if not SEMVER.match(str(version or "")):
                errors.append(f"{manifest_name}: version must be semantic (e.g. 1.0.0)")
            pricing = plugin.get("pricing") or "free"
            if pricing not in PRICING:
                errors.append(f"plugin.json: pricing must be one of {PRICING}")
            if ptype == "integration":
                entry = entry_integration(slug, manifest, errors)
            elif ptype == "library":
                entry = entry_library(slug, manifest, files, publisher, errors)
            elif ptype == "mcp-server":
                entry = entry_mcp_server(slug, manifest, errors)
            elif ptype == "app":
                entry = entry_app(slug, manifest, plugin, files, errors)
            else:
                entry = entry_template(slug, manifest, errors)
            requires = app_requires(plugin, entry, errors) if ptype == "app" else _requires(plugin, errors)
            if errors:
                problems.extend(f"{ptype} {slug}: {e}" for e in errors)
                continue
            # The published versions (dist/) and this one, packed when new.
            ddir = os.path.join(ROOT, "dist", ptype, slug)
            name = f"{slug}-{version}{ext}"
            target = os.path.join(ddir, name)
            if not check_only:
                data = build_archive(ptype, files, key, publisher)
                if os.path.isfile(target):
                    with open(target, "rb") as f:
                        published = f.read()
                    # The published archive is never rewritten: same files (authoring-only ones aside) = same version.
                    if published != data and not same_content(published, files, ptype):
                        problems.append(f"{ptype} {slug}: version {version} is already published with different content: "
                                        "raise the version")
                        continue
                else:
                    os.makedirs(ddir, exist_ok=True)
                    with open(target, "wb") as f:
                        f.write(data)
                    written.append(os.path.relpath(target, ROOT))
            elif not os.path.isfile(target):
                problems.append(f"{ptype} {slug}: version {version} is not built (run tools/build.py)")
            versions = []
            for archive in sorted(os.listdir(ddir)) if os.path.isdir(ddir) else []:
                m = re.match(rf"^{re.escape(slug)}-(\d+\.\d+\.\d+){re.escape(ext)}$", archive)
                if not m:
                    continue
                with open(os.path.join(ddir, archive), "rb") as f:
                    content = f.read()
                versions.append({"version": m.group(1), "path": f"dist/{ptype}/{slug}/{archive}",
                                 "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)})
            versions.sort(key=lambda v: semver(v["version"]), reverse=True)
            if versions and semver(versions[0]["version"]) > semver(version):
                problems.append(f"{ptype} {slug}: version {version} is older than the published {versions[0]['version']}")
                continue
            tags = [str(t)[:40] for t in plugin.get("tags") or []][:20]
            entries.append({
                "type": ptype, "slug": slug, "version": version, "versions": versions,
                "license": str(plugin.get("license") or repo["license"]), "pricing": pricing, "tags": tags,
                "author": plugin.get("author") or entry.pop("author"), "homepage": plugin.get("homepage") or entry.pop("homepage"),
                "has_docs": "doc/README.md" in files, "requires": requires,
                **{k: v for k, v in entry.items() if k not in ("author", "homepage")},
            })
    # Dependencies: of this repository, or of the official one (a community plugin may need an official plugin).
    known = {(e["type"], e["slug"]) for e in entries}
    for e in entries:
        for dep in e["requires"]["plugins"]:
            if (dep["type"], dep["slug"]) not in known and repo["channel"] == "official":
                problems.append(f"{e['type']} {e['slug']}: requires the unknown {dep['type']} {dep['slug']}")
    return entries, problems, written


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an OpenBack plugin repository")
    parser.add_argument("--check", action="store_true", help="only check (no key needed)")
    parser.add_argument("--key", help="the repository's Ed25519 private key (PEM file)")
    args = parser.parse_args()
    repo = read_json(os.path.join(ROOT, "repository.json"))
    for field in ("channel", "publisher", "license"):
        if not repo.get(field):
            print(f"repository.json: {field} is required", file=sys.stderr)
            return 2
    key = None if args.check else load_key(args)
    if not args.check and key is None:
        print("The signing key is missing: --key FILE or env OPENBACK_PLUGIN_SIGNING_KEY", file=sys.stderr)
        return 2
    try:
        entries, problems, written = collect(repo, key, args.check)
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    categories = read_json(os.path.join(ROOT, "categories.json")) if os.path.isfile(os.path.join(ROOT, "categories.json")) else {}
    for e in entries:
        if e["category"] not in (categories.get(e["type"]) or {}):
            print(f"warning: {e['type']} {e['slug']}: category '{e['category']}' has no label in categories.json")
    for p in problems:
        print(f"error: {p}", file=sys.stderr)
    if problems:
        return 1
    index = {"schema_version": INDEX_SCHEMA, "channel": repo["channel"], "publisher": repo["publisher"], "license": repo["license"],
             "name": repo.get("name") or repo["channel"], "categories": categories,
             "plugins": sorted(entries, key=lambda e: (e["type"], e["slug"]))}
    body = json.dumps(index, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8") + b"\n"
    index_path = os.path.join(ROOT, "index.json")
    if args.check:
        current = open(index_path, "rb").read() if os.path.isfile(index_path) else b""
        if json.loads(current or b"{}").get("plugins") != json.loads(body)["plugins"]:
            print("error: index.json is not up to date (run tools/build.py)", file=sys.stderr)
            return 1
        print(f"ok: {len(entries)} plugins")
        return 0
    old = open(index_path, "rb").read() if os.path.isfile(index_path) else b""
    if old and json.loads(old).get("plugins") == index["plugins"] and not written:
        print(f"up to date: {len(entries)} plugins")
        return 0
    index["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    body = json.dumps(index, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8") + b"\n"
    with open(index_path, "wb") as f:
        f.write(body)
    digest = hashlib.sha256(body).hexdigest()
    write_json(os.path.join(ROOT, "index.json.sig"), {"publisher": repo["publisher"], "algorithm": "ed25519", "sha256": digest,
                                                      "signature": sign_text(key, digest)})
    print(f"built: {len(entries)} plugins, {len(written)} new archives")
    return 0


if __name__ == "__main__":
    sys.exit(main())
