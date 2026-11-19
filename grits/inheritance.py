"""Read the properties of a saved Get-GPInheritance result."""
import json
from uuid import UUID


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Repeated property in inheritance JSON")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError(f"Invalid JSON constant {value}")


def _integer(value):
    if len(value) > 11:
        raise ValueError("Inheritance JSON contains an oversized integer")
    return int(value)


def _text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid {field}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"Invalid Unicode in {field}") from exc
    return value.strip()


def _boolean(value, field):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in ("yes", "true"):
            return True
        if token in ("no", "false"):
            return False
    raise ValueError(f"Unrecognized {field} flag")


def _links(obj, key):
    records = obj.get(key)
    if not isinstance(records, list):
        raise ValueError(f"{key} must be an array of link objects")
    result = []
    for index, item in enumerate(records):
        if not isinstance(item, dict):
            raise ValueError(f"Invalid link in {key}")
        try:
            guid = str(UUID(_text(item.get("GpoId"), "GpoId")))
        except ValueError as exc:
            raise ValueError(f"{key}[{index}].GpoId needs a GUID") from exc
        link = {"gpo_id": guid, "gpo_name": _text(item.get("DisplayName"), "DisplayName"),
                "target": _text(item.get("Target"), "Target"),
                "enabled": _boolean(item.get("Enabled"), "Enabled"),
                "enforced": _boolean(item.get("Enforced"), "Enforced"),
                "field": f"{key}[{index}]"}
        order = item.get("Order")
        if order is not None and (type(order) is not int or order < 1):
            raise ValueError(f"Invalid link order in {key}")
        link["link_order"] = order
        if key == "InheritedGpoLinks":
            if not link["enabled"]:
                raise ValueError("An InheritedGpoLinks entry is disabled")
            link["precedence"] = index + 1
        result.append(link)
    return result


def parse_inheritance(data, source, sha256):
    try:
        obj = json.loads(data, object_pairs_hook=_unique, parse_int=_integer, parse_constant=_invalid_constant)
    except (RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid inheritance JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("Expected one Get-GPInheritance result per file")
    return {"target": _text(obj.get("Path"), "Path"),
            "blocked": _boolean(obj.get("GpoInheritanceBlocked"), "GpoInheritanceBlocked"),
            "direct_links": _links(obj, "GpoLinks"),
            "precedence": _links(obj, "InheritedGpoLinks"),
            "source": source, "sha256": sha256}
