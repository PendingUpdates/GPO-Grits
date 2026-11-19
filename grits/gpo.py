"""Read declarations and scope metadata from Microsoft Get-GPOReport XML."""

import re
from uuid import UUID
from xml.etree import ElementTree as ET

BASE = "http://www.microsoft.com/GroupPolicy"
NS = {
    "g": BASE + "/Settings",
    "t": BASE + "/Types",
    "p": BASE + "/Types/Security",
    "s": BASE + "/Settings/Security",
    "r": BASE + "/Settings/Registry",
}

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_ELEMENTS = 100_000
MAX_DEPTH = 64

CATALOG_VERSION = "1.0"
POLICIES = (
    {"id": "minimum-password-length", "name": "Minimum password length",
     "scope": "computer", "units": "characters"},
    {"id": "screen-saver-timeout", "name": "Screen saver timeout",
     "scope": "user", "units": "seconds"},
)


class _ReportTree(ET.TreeBuilder):
    """Enforce structure limits as Expat reads, before building the full tree."""

    def __init__(self):
        super().__init__()
        self.elements = 0
        self.depth = 0

    def doctype(self, name, public_id, system_id):
        raise ValueError("XML document type declarations are prohibited.")

    def start(self, tag, attrs):
        self.elements += 1
        self.depth += 1
        if self.elements > MAX_ELEMENTS:
            raise ValueError("XML exceeds 100,000 elements.")
        if self.depth > MAX_DEPTH:
            raise ValueError("XML exceeds 64 nesting levels.")
        if tag.startswith("{http://www.w3.org/2001/XInclude}"):
            raise ValueError("XML XInclude elements are prohibited.")
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)


def load_xml(data):
    """Parse in-memory bytes with no resolver or include processing."""
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("XML exceeds 16 MiB.")
    try:
        return ET.fromstring(data, parser=ET.XMLParser(target=_ReportTree()))
    except (ET.ParseError, LookupError, UnicodeError) as exc:
        raise ValueError("Invalid XML: " + str(exc)) from exc


def _text(node, path):
    """A scalar field must occur exactly once and contain only text."""
    fields = node.findall(path, NS)
    if len(fields) == 1 and not len(fields[0]):
        return (fields[0].text or "").strip() or None
    return None


def _boolean(node, path):
    return {"true": True, "false": False, "1": True, "0": False}.get(_text(node, path))


def _uint(text):
    # All supported GPMC integer fields fit an unsigned DWORD.
    if text is not None and re.fullmatch(r"[0-9]{1,10}", text):
        number = int(text)
        if number <= 0xffffffff:
            return number
    return None


def _gpo_id(node):
    raw = _text(node, "g:Identifier/t:Identifier")
    if raw:
        try:
            return str(UUID(raw))
        except ValueError:
            pass
    return None


def _metadata(node, field, source, sha256):
    permissions = []
    for entry in node.findall("g:SecurityDescriptor/p:Permissions/p:TrusteePermissions", NS):
        permissions.append({
            "trustee": _text(entry, "p:Trustee/t:Name"),
            "sid": _text(entry, "p:Trustee/t:SID"),
            "type": _text(entry, "p:Type/p:PermissionType"),
            "access": _text(entry, "p:Standard/p:GPOGroupedAccessEnum"),
            "inherited": _boolean(entry, "p:Inherited"),
        })
    links = []
    for link in node.findall("g:LinksTo", NS):
        links.append({
            "target": _text(link, "g:SOMPath"),
            "name": _text(link, "g:SOMName"),
            "enabled": _boolean(link, "g:Enabled"),
            "enforced": _boolean(link, "g:NoOverride"),
        })
    return {
        "gpo_id": _gpo_id(node),
        "gpo_name": _text(node, "g:Name"),
        "domain": _text(node, "g:Identifier/t:Domain"),
        "source": source, "sha256": sha256, "field": field,
        "reported_time": _text(node, "g:ReadTime"),
        "sections": {"computer": _boolean(node, "g:Computer/g:Enabled"),
                     "user": _boolean(node, "g:User/g:Enabled")},
        "links": links,
        "permissions_present": _boolean(node, "g:SecurityDescriptor/p:PermissionsPresent"),
        "permissions": permissions,
        "wmi_filter": {"name": _text(node, "g:FilterName"), "id": _text(node, "g:FilterId"),
                       "data_available": _boolean(node, "g:FilterDataAvailable")},
    }


def _declarations(section, path, policy):
    """Select only direct children of the setting's own extension namespace."""
    tag = "s:Account" if policy["id"] == "minimum-password-length" else "r:Policy"
    for group_index, group in enumerate(section.findall("g:ExtensionData", NS), 1):
        for ext_index, ext in enumerate(group.findall("g:Extension", NS), 1):
            for index, entry in enumerate(ext.findall(tag, NS), 1):
                reading = parse_setting(entry, policy["id"])
                if reading is not None:
                    path_to_ext = f"{path}/ExtensionData[{group_index}]/Extension[{ext_index}]"
                    field = f"{path_to_ext}/{tag.split(':')[1]}[{index}]" + reading["value_field"]
                    yield reading, field


def _reading(state=None, value=None, field="", reason=None):
    return {"state": state, "value": value, "value_field": field, "reason": reason}


def _number_reading(text, field, state=None):
    value = _uint(text)
    if value is None:
        return _reading(state=state, field=field,
                        reason="The numeric setting is missing, ambiguous, or unsupported.")
    return _reading(state=state, value=value, field=field)


def parse_setting(element, policy_id):
    """Read a catalog entry within a known GPO or RSoP extension and scope.

    Unrelated records return None. A recognized setting with insufficient or
    ambiguous evidence returns a reason and no numeric value.
    """
    if policy_id == "minimum-password-length":
        prefix, tag, name = "s", "Account", "MinimumPasswordLength"
    elif policy_id == "screen-saver-timeout":
        prefix, tag, name = "r", "Policy", "Screen saver timeout"
    else:
        return None
    if element.tag != "{" + NS[prefix] + "}" + tag:
        return None
    name_path = prefix + ":Name"
    names = element.findall(name_path, NS)
    if not any((node.text or "").strip().casefold() == name.casefold() for node in names):
        return None
    if len(names) != 1 or len(names[0]):
        return _reading(reason="The setting name is ambiguous.")

    if policy_id == "minimum-password-length":
        if element.findall("s:Type", NS) and _text(element, "s:Type") != "Password":
            return _reading(reason="The account setting has an ambiguous or unsupported type.")
        return _number_reading(_text(element, "s:SettingNumber"), "/SettingNumber")

    # GPMC emits localized display names, not the ADMX policy's internal ID.
    # Require the matching category to exclude unrelated templates with the same name.
    category = (_text(element, "r:Category") or "").replace("\\", "/").casefold()
    if category not in {"control panel/personalization", "control panel/display"}:
        return _reading(reason="The report does not identify the supported Control Panel template category.")
    state = _text(element, "r:State")
    if state == "Disabled":
        return _reading(state=state, field="/State")
    if state != "Enabled":
        return _reading(reason="Policy state is missing, ambiguous, or unsupported.")
    options = element.findall("r:Numeric", NS)
    if len(options) != 1 or (_text(options[0], "r:Name") or "").casefold().rstrip(": ") != "seconds":
        return _reading(state=state, reason="An unambiguous numeric Seconds option is required.")
    if options[0].findall("r:State", NS) and _text(options[0], "r:State") != "Enabled":
        return _reading(state=state, reason="The Seconds option is disabled or has an unsupported state.")
    return _number_reading(_text(options[0], "r:Value"), "/Numeric/Value", state)


def _finding(node, meta, policy):
    section_name = policy["scope"].capitalize()
    section_path = f"{meta['field']}/{section_name}"
    finding = {
        "policy_id": policy["id"], "scope": policy["scope"], "status": "Not assessed",
        "value": None, "state": None, "units": policy["units"], "reason": None,
        "section_enabled": meta["sections"][policy["scope"]],
        "gpo_id": meta["gpo_id"], "gpo_name": meta["gpo_name"], "source": meta["source"],
        "sha256": meta["sha256"], "field": section_path, "reported_time": meta["reported_time"],
    }
    sections = node.findall("g:" + section_name, NS)
    if not meta["gpo_id"]:
        finding["reason"] = "The source GPO GUID is absent, ambiguous, or invalid."
    elif len(sections) != 1:
        finding["reason"] = "The configuration section is missing or appears more than once."
    else:
        candidates = list(_declarations(sections[0], section_path, policy))
        if not candidates:
            finding["reason"] = "This section contains no recognized declaration for this setting."
        elif len(candidates) > 1:
            finding["reason"] = "Several declarations match this setting in the same GPO section."
        else:
            reading, field = candidates[0]
            finding.update(field=field, state=reading["state"], value=reading["value"],
                           reason=reading["reason"])
            if reading["reason"] is None:
                finding["status"] = "Declared"
    return finding


def parse_gpo(root, source, sha256):
    """Return one inventory record and one row per catalog policy for each GPO.

    A declaration describes the source section, including a disabled section.
    Group membership, link precedence and effective client policy are separate evidence.
    """
    ns = "{" + NS["g"] + "}"
    if root.tag == ns + "GPO":
        entries = [(root, "/GPO")]
    elif root.tag in {"GPOs", "GPOS", ns + "GPOs", ns + "GPOS"}:
        if not len(root) or any(child.tag != ns + "GPO" for child in root):
            raise ValueError("The GPO collection is empty or contains an unsupported record.")
        root_name = root.tag.split("}")[-1]
        entries = [(child, f"/{root_name}/GPO[{i}]") for i, child in enumerate(root, 1)]
    else:
        raise ValueError("Expected a Microsoft Get-GPOReport XML report.")
    gpos, findings = [], []
    for node, field in entries:
        if not len(node):
            raise ValueError("Empty GPO record in XML report.")
        meta = _metadata(node, field, source, sha256)
        gpos.append(meta)
        findings.extend(_finding(node, meta, policy) for policy in POLICIES)
    return {"gpos": gpos, "findings": findings}
