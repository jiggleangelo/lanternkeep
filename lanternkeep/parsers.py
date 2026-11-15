import re
import time
import tomllib
from bisect import bisect_right

MAX_FILE = 200 * 1024
MAX_LINE = 2000
MAX_MATCHED_LINES = 200
MAX_DEPENDENCIES = 500
SECRET_NAME = r"(?:storePassword|keyPassword|api[_-]?key|client[_-]?secret|password|private[_-]?key|access[_-]?token|auth|token)"
SECRET = re.compile(
    r"(?i)(?:"
    r"(?<![\w.:-])" + SECRET_NAME + r"\b\s*+(?:=|:\s|\s+[\"'])"
    r"|[\"'][^\"'\n]*(?:api[_-]?key|client[_-]?secret|password|private[_-]?key|access[_-]?token)[\"']"
    r"|https?://[^\s/:'\"]+(?::[^\s/@'\"]*)?@"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"
    r")"
)
CATALOG_VERSION = re.compile(
    r'''\s*(?:auth|token)\s*=\s*(["'])(?:\d+(?:[._-]\d+)*(?:[-.](?:SNAPSHOT|alpha|beta|rc)\d*)?\+?|\+|latest\.(?:release|integration))\1\s*(?:#.*)?$''', re.I)
SDK_EXPR = re.compile(
    r"\b(targetSdk(?:Version)?|compileSdk(?:Version)?|minSdk(?:Version)?)"
    r"(?:[ \t]*[=(][ \t]*|[ \t]+)([A-Za-z0-9_.\[\]\"'-]+)")
PROPERTY = re.compile(r"\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*+=\s*+(\d++)\b")
EXTRA_PROPERTY = re.compile(r"\b([A-Za-z_]\w*+)\s++by\s++extra\(\s*+(\d++)\s*+\)")
APP_ID = re.compile(r"\b(applicationId|versionName|versionCode)(?:[ \t]*[=(][ \t]*|[ \t]+)[\"']?([A-Za-z0-9_.+-]+)")
COORD = re.compile(r"[\"']([A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:([A-Za-z0-9_.+!\[\](),-]+))[\"']")
CATALOG_DEP = re.compile(r"\b(?:implementation|api|compileOnly|runtimeOnly|testImplementation|androidTestImplementation|kapt|ksp)\s*+(?:\(\s*+)?(libs(?:\.[A-Za-z0-9_]+)+)")
DEP = re.compile(r"^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+!\[\](),-]+)$")
PERMISSION = re.compile(r"<uses-permission(?:-sdk-\d+)?\b[^<>]*?\bandroid:name\s*=\s*[\"']([A-Za-z_][A-Za-z0-9_.]*)[\"']", re.I)
PERMISSION_START = re.compile(r"<uses-permission(?:-sdk-\d+)?\b", re.I)
MANIFEST_TARGET = re.compile(r"targetSdkVersion\s*=\s*[\"'](\d+)[\"']", re.I)
PLIST_KEY = re.compile(r"<key>\s*(NS\w+UsageDescription)\s*</key>")
XML_TAG = re.compile(r"<[^<>]*>")
IDENTIFIER = re.compile(r"[A-Za-z_]\w*")


class ParseError(ValueError):
    pass


def _check(deadline):
    if time.monotonic() > deadline:
        raise ParseError("Parsing exceeded two seconds")


def _lines(text):
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def redact(text, deadline=None, *, version_catalog=False):
    changed = False
    output = []
    private_key = False
    in_versions = False
    for line in _lines(text):
        if deadline is not None:
            _check(deadline)
        if version_catalog and line.lstrip().startswith("["):
            in_versions = bool(re.fullmatch(r"\s*\[versions\]\s*(?:#.*)?", line))
        private_key = private_key or "-----BEGIN " in line and "PRIVATE KEY-----" in line
        candidate = line
        if in_versions and CATALOG_VERSION.fullmatch(line):
            candidate = re.sub(r"^(\s*)(auth|token)(\s*=)", r'\1"\2"\3', line, flags=re.I)
        if private_key or SECRET.search(candidate):
            output.append("<redacted by Lanternkeep>")
            changed = True
        else:
            output.append(line)
        if "-----END " in line and "PRIVATE KEY-----" in line:
            private_key = False
    return "\n".join(output), changed


def _hit(number, line, value, start, end, source=None):
    result = {"value": int(value), "line": number, "text": line,
              "value_start": start, "value_end": end}
    if source:
        result["source_file"] = source
    return result


def _catalog_alias(name):
    return re.sub(r"[-_.]+", ".", name)


def parse_catalog(text, deadline):
    _check(deadline)
    clean, redacted = redact(text, deadline, version_catalog=True)
    clean = clean.replace("<redacted by Lanternkeep>", "# redacted by Lanternkeep")
    try:
        data = tomllib.loads(clean)
    except tomllib.TOMLDecodeError as exc:
        raise ParseError("Invalid libs.versions.toml; check TOML syntax") from exc
    _check(deadline)
    versions, libraries = data.get("versions", {}), data.get("libraries", {})
    if not isinstance(versions, dict) or not isinstance(libraries, dict):
        raise ParseError("Catalog versions and libraries must be tables")
    resolved = {}
    for alias, item in libraries.items():
        _check(deadline)
        coordinate = None
        if isinstance(item, str):
            coordinate = item
        elif isinstance(item, dict):
            module = item.get("module")
            if not module and isinstance(item.get("group"), str) and isinstance(item.get("name"), str):
                module = item["group"] + ":" + item["name"]
            version = item.get("version", "")
            if isinstance(version, dict):
                version = versions.get(version.get("ref"), "")
            if isinstance(module, str) and isinstance(version, str):
                coordinate = module + ":" + version
        if coordinate and DEP.fullmatch(coordinate):
            resolved["libs." + _catalog_alias(alias)] = coordinate
    return resolved, versions, redacted


def _lex(clean, deadline):
    """Linear scanner with bounded ordinary tokens and shared deadline."""
    lines = _lines(clean)
    clean = "\n".join(lines)
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    masked = list(clean)
    tokens = []
    pos = 0
    while pos < len(clean):
        _check(deadline)
        number = bisect_right(starts, pos) - 1
        line_end = starts[number] + len(lines[number])
        if pos == line_end:
            pos += 1
            continue
        oversized = len(lines[number]) > MAX_LINE
        if oversized and pos == starts[number]:
            tokens.append((";reset;", pos, pos, number + 1))
        if clean.startswith("/*", pos):
            end = clean.find("*/", pos + 2)
            end = len(clean) if end < 0 else end + 2
            for index in range(pos, end):
                if index % 1024 == 0:
                    _check(deadline)
                if masked[index] != "\n":
                    masked[index] = " "
            pos = end
            continue
        if clean.startswith("//", pos):
            masked[pos:line_end] = " " * (line_end - pos)
            pos = line_end
            continue
        char = clean[pos]
        if char.isspace():
            pos += 1
            continue
        start = pos
        if char in "\"'":
            pos += 1
            closed = False
            while pos < line_end:
                if pos % 1024 == 0:
                    _check(deadline)
                if clean[pos] == "\\":
                    pos = min(line_end, pos + 2)
                elif clean[pos] == char:
                    pos += 1
                    closed = True
                    break
                else:
                    pos += 1
            if not closed:
                masked[start:line_end] = " " * (line_end - start)
                continue
        elif not oversized:
            match = IDENTIFIER.match(clean, pos, line_end)
            pos = match.end() if match else pos + 1
        else:
            pos += 1
        if not oversized:
            tokens.append((clean[start:pos], start, pos, number + 1))
    _check(deadline)
    return tokens, "".join(masked).split("\n")


def _repository_hits(tokens, deadline):
    stack, previous = [], []
    jcenter, http = {}, {}
    for index, (token, start, end, line) in enumerate(tokens):
        _check(deadline)
        if token == ";reset;":
            stack, previous = [], []
        elif token == "{":
            stack.append(previous[-1] if previous else "")
            previous = []
        elif token == "}":
            if stack:
                stack.pop()
            previous = []
        elif token == ";":
            previous = []
        elif token == "jcenter" and "repositories" in stack:
            if [item[0] for item in tokens[index + 1:index + 3]] == ["(", ")"]:
                jcenter.setdefault(line, []).append((start, end))
        elif token.startswith(("\"", "'")):
            if "maven" in stack and "url" in previous and token[1:].startswith("http://"):
                http.setdefault(line, []).append(start + 1)
        else:
            previous = (previous + [token])[-8:]
    return jcenter, http


def _prepare_gradle(text, deadline, source):
    clean, redacted = redact(text, deadline)
    tokens, code_lines = _lex(clean, deadline)
    lines = _lines(clean)
    properties = {}
    for number, (line, code) in enumerate(zip(lines, code_lines), 1):
        _check(deadline)
        if len(line) > MAX_LINE:
            continue
        for pattern in (PROPERTY, EXTRA_PROPERTY):
            for match in pattern.finditer(code):
                _check(deadline)
                name = match.group(1)
                hit = _hit(number, line, match.group(2), match.start(2), match.end(2), source)
                properties[name] = hit
                if name.startswith("ext."):
                    properties[name[4:]] = hit
    return clean, redacted, tokens, code_lines, properties


def parse_gradle(text, deadline=None, catalog=None, versions=None, retained=None,
                 root_properties=None, source="App Gradle", prepared=None):
    deadline = time.monotonic() + 2 if deadline is None else deadline
    retained = retained if retained is not None else {"remaining": MAX_MATCHED_LINES}
    catalog, versions = catalog or {}, versions or {}
    clean, redacted, tokens, code_lines, properties = prepared or _prepare_gradle(text, deadline, source)
    lines = _lines(clean)
    facts = {"sdk": {}, "sdk_unresolved": {}, "metadata": {}, "dependencies": [],
             "jcenter": [], "http_repositories": [], "matched_lines": [], "redacted": redacted,
             "redacted_lines": [n for n, line in enumerate(lines, 1) if line == "<redacted by Lanternkeep>"]}
    repo_jcenter, repo_http = _repository_hits(tokens, deadline)
    kept = set()

    def retain(number, line, file=source):
        identity = (file, number)
        if identity in kept:
            return True
        if retained["remaining"] <= 0 or len(line) > MAX_LINE:
            return False
        retained["remaining"] -= 1
        kept.add(identity)
        facts["matched_lines"].append({"line": number, "text": line, "source_file": file})
        return True

    offset = 0
    for number, (line, code) in enumerate(zip(lines, code_lines), 1):
        _check(deadline)
        if len(line) > MAX_LINE:
            facts["truncated"] = True
            offset += len(line) + 1
            continue
        for match in SDK_EXPR.finditer(code):
            name = match.group(1).replace("Version", "")
            expression = match.group(2).strip("\"'")
            hit = None
            if expression.isdigit():
                hit = _hit(number, line, expression, match.start(2), match.end(2), source)
            else:
                if expression.startswith("rootProject.ext."):
                    key = expression[len("rootProject.ext."):]
                    table = root_properties if root_properties is not None else properties
                    hit = table.get(key) or table.get("ext." + key)
                elif expression.startswith("ext."):
                    hit = properties.get(expression) or properties.get(expression[4:])
                else:
                    hit = properties.get(expression)
                    if hit is None and root_properties is not None:
                        hit = root_properties.get(expression)
                if expression.startswith("libs.versions."):
                    alias = expression[len("libs.versions."):].removesuffix(".get")
                    value = next((v for k, v in versions.items() if _catalog_alias(k) == alias), None)
                    if isinstance(value, str) and value.isdigit():
                        hit = {"value": int(value), "catalog": alias}
            if hit and ("text" not in hit or retain(hit["line"], hit["text"], hit.get("source_file", source))):
                facts["sdk"][name] = dict(hit)
                facts["sdk_unresolved"].pop(name, None)
            else:
                facts["sdk_unresolved"][name] = {"expression": expression}
                facts["sdk"].pop(name, None)
        app_match = APP_ID.search(code)
        if app_match:
            facts["metadata"][app_match.group(1)] = app_match.group(2)
        for match in COORD.finditer(code):
            if len(facts["dependencies"]) >= MAX_DEPENDENCIES:
                facts["truncated"] = True
                break
            coordinate = match.group(1)
            group, artifact, version = coordinate.split(":", 2)
            facts["dependencies"].append({"coordinate": coordinate, "name": group + ":" + artifact,
                                          "version": version, "line": number})
        for match in CATALOG_DEP.finditer(code):
            if len(facts["dependencies"]) >= MAX_DEPENDENCIES:
                facts["truncated"] = True
                break
            alias = match.group(1)
            coordinate = catalog.get(alias)
            if coordinate:
                group, artifact, version = coordinate.split(":", 2)
                facts["dependencies"].append({"coordinate": coordinate, "name": group + ":" + artifact,
                                              "version": version, "alias": alias, "line": number})
            else:
                facts["dependencies"].append({"coordinate": alias + " (version catalog)", "name": alias,
                                              "version": "", "version_unknown": True, "line": number})
        if number in repo_jcenter and retain(number, line):
            for start, end in repo_jcenter[number]:
                facts["jcenter"].append({"line": number, "text": line,
                                         "value_start": start - offset, "value_end": end - offset})
        if number in repo_http and retain(number, line):
            for start in repo_http[number]:
                facts["http_repositories"].append({"line": number, "text": line,
                                                   "value_start": start - offset, "value_end": start - offset + 7})
        offset += len(line) + 1
    facts["matched_lines"].sort(key=lambda item: (item["source_file"], item["line"]))
    return facts


def _xml_input(text, deadline):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
        raise ParseError("DOCTYPE and ENTITY declarations are not accepted")
    # Skip oversized lines before any XML attribute regex. A marker breaks a
    # pending tag, so attributes on either side cannot be joined into evidence.
    bounded, truncated = [], False
    for line in _lines(text):
        _check(deadline)
        if len(line) > MAX_LINE:
            bounded.append("<omitted/>")
            truncated = True
        else:
            bounded.append(line)
    clean, redacted = redact("\n".join(bounded), deadline)
    # Mask comments in linear time, retaining offsets and newline positions.
    masked = list(clean)
    pos = 0
    while True:
        _check(deadline)
        start = clean.find("<!--", pos)
        if start < 0:
            break
        end = clean.find("-->", start + 4)
        end = len(clean) if end < 0 else end + 3
        for index in range(start, end):
            if index % 1024 == 0:
                _check(deadline)
            if masked[index] != "\n":
                masked[index] = " "
        pos = end
    return clean, "".join(masked), redacted, truncated


def parse_manifest(text, deadline=None, retained=None):
    deadline = time.monotonic() + 2 if deadline is None else deadline
    retained = retained if retained is not None else {"remaining": MAX_MATCHED_LINES}
    clean, code, redacted, truncated = _xml_input(text, deadline)
    lines = _lines(clean)
    starts, offset = [], 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    permissions, target, target_hit = [], None, None
    seen_permissions = 0
    # Neither XML_TAG nor PERMISSION can consume another '<'. Failed starts
    # therefore cannot repeatedly scan the rest of the document.
    for tag_match in XML_TAG.finditer(code):
        _check(deadline)
        tag = tag_match.group()
        if len(tag) > MAX_LINE:
            truncated = True
            continue
        permission = PERMISSION.match(tag)
        if permission:
            seen_permissions += 1
            if len(permissions) < 300:
                permissions.append(permission.group(1))
            else:
                truncated = True
        match = MANIFEST_TARGET.search(tag)
        if target is None and match:
            target = int(match.group(1))
            absolute_start = tag_match.start() + match.start(1)
            number = bisect_right(starts, absolute_start) - 1
            line = lines[number]
            if retained["remaining"] > 0:
                retained["remaining"] -= 1
                start = absolute_start - starts[number]
                target_hit = _hit(number + 1, line, match.group(1), start,
                                  start + len(match.group(1)), "AndroidManifest.xml")
            else:
                target_hit = {"value": target}
    declared_permissions = sum(1 for _ in PERMISSION_START.finditer(code))
    _check(deadline)
    return {"permissions": permissions, "targetSdk": target, "targetSdk_hit": target_hit,
            "redacted": redacted, "truncated": truncated,
            "permissions_not_assessed": truncated or redacted or declared_permissions != seen_permissions}


def parse_plist(text, deadline=None):
    deadline = time.monotonic() + 2 if deadline is None else deadline
    clean, code, redacted, truncated = _xml_input(text, deadline)
    keys = []
    for line in _lines(code):
        _check(deadline)
        if len(line) > MAX_LINE:
            truncated = True
            continue
        found = PLIST_KEY.findall(line)
        if len(keys) + len(found) > 300:
            truncated = True
        keys.extend(found[:max(0, 300 - len(keys))])
    return {"usage_keys": keys, "redacted": redacted, "truncated": truncated}


def parse_dependencies(text, deadline=None):
    deadline = time.monotonic() + 2 if deadline is None else deadline
    clean, redacted = redact(text, deadline)
    dependencies, skipped = [], 0
    for line in _lines(clean):
        _check(deadline)
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        coordinate = line.split("=", 1)[0]
        match = DEP.fullmatch(coordinate)
        if not match or len(dependencies) >= MAX_DEPENDENCIES:
            skipped += 1
            continue
        dependencies.append({"coordinate": coordinate, "name": match.group(1) + ":" + match.group(2), "version": match.group(3)})
    return {"dependencies": dependencies, "skipped": skipped, "redacted": redacted}


def parse_all(documents):
    gradles = documents.get("gradle", [])[:2]
    all_text = list(gradles) + [documents.get(name, "") for name in ("manifest", "plist", "dependencies", "catalog")]
    if any(len(text.encode()) > MAX_FILE for text in all_text):
        raise ParseError("Each file is limited to 200 KB")
    if sum(len(text.encode()) for text in all_text) > 1024 * 1024:
        raise ParseError("Documents are limited to 1 MB per request")
    facts = {"gradle": [], "manifest": {}, "plist": {},
             "dependency_list": {"dependencies": [], "skipped": 0},
             "provided": {name: bool(documents.get(name)) for name in ("gradle", "manifest", "plist", "dependencies", "catalog")},
             "redacted": False}
    deadline = time.monotonic() + 2
    retained = {"remaining": MAX_MATCHED_LINES}
    catalog, versions = {}, {}
    if documents.get("catalog"):
        catalog, versions, facts["redacted"] = parse_catalog(documents["catalog"], deadline)
    prepared = [_prepare_gradle(text, deadline, "App Gradle" if index == 0 else "Root Gradle")
                for index, text in enumerate(gradles)]
    root = prepared[1][4] if len(prepared) > 1 else None
    for index, text in enumerate(gradles):
        parsed = parse_gradle(text, deadline, catalog, versions, retained,
                              root_properties=root if index == 0 else None,
                              source="App Gradle" if index == 0 else "Root Gradle", prepared=prepared[index])
        if index > 0:
            parsed["sdk"], parsed["sdk_unresolved"] = {}, {}
        facts["gradle"].append(parsed)
        facts["redacted"] |= parsed["redacted"]
    for name, parser in (("manifest", parse_manifest), ("plist", parse_plist), ("dependencies", parse_dependencies)):
        if documents.get(name):
            parsed = parser(documents[name], deadline, retained) if name == "manifest" else parser(documents[name], deadline)
            facts["dependency_list" if name == "dependencies" else name] = parsed
            facts["redacted"] |= parsed["redacted"]
    remaining = MAX_DEPENDENCIES
    for group in [facts["dependency_list"], *facts["gradle"]]:
        dependencies = group["dependencies"]
        if len(dependencies) > remaining:
            group["truncated"] = True
        group["dependencies"] = dependencies[:remaining]
        remaining -= len(group["dependencies"])
    facts["matched_line_limit_reached"] = retained["remaining"] == 0
    return facts
