"""Read only resultant settings connected to a specific logging observation."""
from datetime import datetime
import re
from uuid import UUID

from .gpo import parse_setting

RS = "{http://www.microsoft.com/GroupPolicy/Rsop}"
SET = "{http://www.microsoft.com/GroupPolicy/Settings}"
BASE = "{http://www.microsoft.com/GroupPolicy/Settings/Base}"
TYPES = "{http://www.microsoft.com/GroupPolicy/Types}"


def _single_text(parent, path):
    nodes = parent.findall(path)
    if len(nodes) == 1 and not len(nodes[0]):
        return (nodes[0].text or "").strip() or None
    return None


def _reported_time(root):
    text = _single_text(root, RS + "ReadTime")
    try:
        if text and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|[+-]\d\d:\d\d)?", text):
            # GPMC uses 100 ns ticks. Older Python accepts only 3 or 6 fractional digits.
            normalized = re.sub(r"\.(\d+)", lambda m: "." + m[1][:6].ljust(6, "0"), text)
            datetime.fromisoformat(normalized.replace("Z", "+00:00"))
            return text
    except ValueError:
        pass
    return None


def _winner(section, policy_id):
    candidates = []
    for i, ext_data in enumerate(section.findall(RS + "ExtensionData"), start=1):
        for j, ext in enumerate(ext_data.findall(SET + "Extension"), start=1):
            for k, node in enumerate(ext, start=1):
                setting = parse_setting(node, policy_id)
                if setting is None:
                    continue
                rank = _single_text(node, BASE + "Precedence")
                if not rank or not re.fullmatch(r"[0-9]{1,10}", rank) or not 1 <= int(rank) <= 0xffffffff:
                    return None, "A matching setting has missing or invalid precedence."
                if int(rank) != 1:
                    continue
                field = f"/ExtensionData[{i}]/Extension[{j}]/*[{k}]"
                guid = _single_text(node, BASE + "GPO/" + TYPES + "Identifier")
                try:
                    guid = str(UUID(guid or ""))
                except ValueError:
                    guid = None
                candidates.append((setting, guid, field))
    if len(candidates) != 1:
        reason = ("No supported winning setting value in this target section." if not candidates
                  else "Multiple entries claim precedence 1 for this setting.")
        return None, reason
    setting, guid, field = candidates[0]
    if setting["reason"]:
        return None, setting["reason"]
    return {"state": setting["state"], "value": setting["value"], "gpo_id": guid,
            "source_gpo_status": "Identified" if guid else "Not assessed",
            "field": field + setting["value_field"]}, None


def parse_rsop(root, source, sha256):
    if root.tag != RS + "Rsop":
        raise ValueError("Expected a Microsoft RSoP XML report")
    logged = _single_text(root, RS + "DataType") == "LoggedData"
    time = _reported_time(root)
    hosts = root.findall(RS + "ComputerResults")
    computer = _single_text(hosts[0], RS + "Name") if len(hosts) == 1 else None
    observations = []
    for scope, policy_id, units in (("computer", "minimum-password-length", "characters"),
                                    ("user", "screen-saver-timeout", "seconds")):
        section_name = scope.title() + "Results"
        sections = root.findall(RS + section_name)
        section = sections[0] if len(sections) == 1 else None
        target = _single_text(section, RS + "Name") if section is not None else None
        prefix = "/Rsop/" + section_name
        row = {"source": source, "sha256": sha256, "field": prefix,
               "reported_time": time, "target": target, "scope": scope, "policy_id": policy_id,
               "domain": _single_text(section, RS + "Domain") if section is not None else None,
               "computer": computer, "source_gpo_status": "Not assessed",
               "units": units, "value": None, "state": None, "gpo_id": None,
               "status": "Not assessed"}
        if not logged:
            reason = "The report does not identify its data as LoggedData."
        elif section is None:
            reason = "The target section is absent or ambiguous."
        elif not target or not time:
            reason = "The target identity or report timestamp is missing or ambiguous."
        else:
            winner, reason = _winner(section, policy_id)
            if winner:
                row.update(winner)
                row["field"] = prefix + winner["field"]
                row["status"] = "Observed"
        row["reason"] = reason
        observations.append(row)
    return observations
