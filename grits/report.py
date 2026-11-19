"""Self-contained, printable HTML companion to the audit JSON."""
import base64
from html import escape
from pathlib import Path

from .gpo import POLICIES

LABELS = {p["id"]: p["name"] for p in POLICIES}
STYLE = """
*{box-sizing:border-box}html{color-scheme:light}body{margin:0;background:#f6f2e8;color:#222b28;font:16px/1.55 system-ui,sans-serif}
header{background:#193c34;color:white;border-bottom:5px solid #e2a645}header div,main{max-width:78rem;margin:auto;padding:1.5rem clamp(1rem,4vw,3rem)}
header div{display:flex;align-items:center;gap:1rem}header img{width:4rem;height:4rem;object-fit:contain}h1,h2,h3,p{margin:0}h1{font:700 clamp(1.8rem,4vw,3rem)/1.1 Georgia,serif}
h2{font:700 1.6rem Georgia,serif;margin:2rem 0 .55rem}h3{margin:.8rem 0 .35rem;font-size:1.05rem}
nav{display:flex;flex-wrap:wrap;gap:.6rem 1.4rem;padding:.2rem 0 1rem;border-bottom:1px solid #a8b5a8}a{color:#18503f;text-underline-offset:.23em}a:focus-visible,summary:focus-visible{outline:3px solid #956122;outline-offset:3px}
.box,details{padding:.85rem 1rem;background:#fffdf7;border:1px solid #c3cabe;border-radius:5px;margin:.55rem 0}.wrap{overflow:auto}
table{border-collapse:collapse;width:100%;background:#fffdf7;font-size:.93rem}th,td{text-align:left;vertical-align:top;padding:.55rem .8rem;border-bottom:1px solid #ced5c9}th{background:#e5ebdf}
td{overflow-wrap:anywhere}small{display:block;color:#46534b}code{overflow-wrap:anywhere;font-size:.88em}summary{cursor:pointer}section>p{margin:.35rem 0 .7rem}
.cell-label{display:none}
@media screen and (max-width:680px){
table,tbody,tr{display:block}thead{position:absolute;clip-path:inset(50%);width:1px;height:1px;overflow:hidden}
tbody tr{padding:.45rem .7rem;border-bottom:2px solid #c3cabe}
td{display:grid;grid-template-columns:5.6rem minmax(0,1fr);gap:.7rem;padding:.36rem 0;border:0}
.cell-label{display:block;color:#46534b;font-size:.84rem;font-weight:650}
}
@media print{body{background:white;font-size:11pt}header{background:white;color:black}nav{display:none}details::details-content{display:block}details{break-inside:avoid}.wrap{overflow:visible}}
"""


def h(value):
    if value is None:
        return "Unreported"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return escape(str(value))


def _table(columns, rows):
    header = "".join("<th scope='col'>" + h(title) + "</th>" for title in columns)
    body = "".join("<tr>" + "".join(
        f"<td><span class='cell-label' aria-hidden='true'>{h(title)}</span><div>{cell}</div></td>"
        for title, cell in zip(columns, cells)) + "</tr>" for cells in rows)
    return f"<div class='wrap'><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>"


def _source(obj):
    return "<small>" + h(obj["source"]) + "<br><code>" + h(obj["field"]) + "</code></small>"


def _readings(records, observed=False):
    rows = []
    for row in records:
        status = h(row["status"])
        if row["value"] is not None:
            status += f" · <strong>{h(row['value'])} {h(row['units'])}</strong>"
        if row["state"]:
            status += "<small>Policy " + h(row["state"]) + "</small>"
        if row["reason"]:
            status += "<small>" + h(row["reason"]) + "</small>"
        if "comparison" in row:
            status += "<small>" + h(row["comparison"]["outcome"]) + " · threshold " + h(row["comparison"]["threshold"]) + "</small>"
        origin = h(row.get("target") if observed else row.get("gpo_name"))
        if row.get("gpo_id"):
            origin += "<small>GPO <code>" + h(row["gpo_id"]) + "</code></small>"
        elif observed and row["status"] == "Observed":
            origin += "<small>Source GPO attribution · Not assessed</small>"
        if observed and row.get("domain"):
            origin += "<small>" + h(row["domain"]) + "</small>"
        if observed and row["scope"] == "user" and row.get("computer"):
            origin += "<small>Computer · " + h(row["computer"]) + "</small>"
        if not observed:
            origin += "<small>Section enabled · " + h(row["section_enabled"]) + "</small>"
        rows.append([h(LABELS[row["policy_id"]]) + "<small>" + h(row["scope"]) + "</small>",
                     origin, status, h(row["reported_time"]) + _source(row)])
    return _table(("Setting", "Target" if observed else "GPO", "Result", "Time and source"), rows)


def _inventory(gpo):
    links = _table(("Target", "Link enabled", "Enforced"),
                   ([h(l["target"] or l["name"]), h(l["enabled"]), h(l["enforced"])] for l in gpo["links"]))
    perms = _table(("Trustee", "Access", "Type", "Inherited"),
                   ([h(p["trustee"]) + "<small>" + h(p["sid"]) + "</small>", h(p["access"]),
                     h(p["type"]), h(p["inherited"])] for p in gpo["permissions"]))
    wmi = gpo["wmi_filter"]
    return (f"<details><summary><strong>{h(gpo['gpo_name'])}</strong> · {h(gpo['domain'])}</summary>"
            f"<p>GPO <code>{h(gpo['gpo_id'])}</code> · Reported {h(gpo['reported_time'])}</p>"
            f"<p>Computer section enabled · {h(gpo['sections']['computer'])}<br>"
            f"User section enabled · {h(gpo['sections']['user'])}</p><h3>Links</h3>"
            + (links if gpo["links"] else "<p>No links recorded.</p>")
            + f"<h3>Filters and permissions</h3><p>WMI filter · {h(wmi['name'])} · ID {h(wmi['id'])}"
            + f"<br>Filter data available · {h(wmi['data_available'])}<br>Permissions present · {h(gpo['permissions_present'])}</p>"
            + (perms if gpo["permissions"] else "<p>No trustee entries recorded.</p>") + _source(gpo) + "</details>")


def _inheritance(snapshot):
    details = [f"<div class='box'><strong>{h(snapshot['target'])}</strong>",
               f"<p>Inheritance blocked · {h(snapshot['blocked'])}</p>"]
    for key, title, rank in (("direct_links", "Direct links", "link_order"),
                             ("precedence", "Precedence for this container", "precedence")):
        links = snapshot[key]
        details.append("<h3>" + title + "</h3>")
        if links:
            details.append(_table(("Order", "GPO", "Link target", "Enabled", "Enforced", "Source field"),
                                  ([h(l[rank]), h(l["gpo_name"]) + "<small>" + h(l["gpo_id"]) + "</small>",
                                    h(l["target"]), h(l["enabled"]), h(l["enforced"]), h(l["field"])] for l in links)))
        else:
            details.append("<p>No entries in the supplied list.</p>")
    return "".join(details) + "<small>" + h(snapshot["source"]) + "</small></div>"


def render(data):
    art = Path(__file__).resolve().parent.parent / "assets" / "gpo-grits-icon.png"
    icon = base64.b64encode(art.read_bytes()).decode("ascii")
    parts = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
             "<meta name='viewport' content='width=device-width, initial-scale=1'>",
             "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'\">",
             "<title>GPO Grits · Group Policy audit</title><style>", STYLE, "</style></head><body>",
             f"<header><div><img alt='' width='64' height='64' src='data:image/png;base64,{icon}'>",
             "<section><h1>GPO Grits</h1><p>On-premises Active Directory · Group Policy audit</p></section></div></header><main>",
             "<nav aria-label='Report sections'><a href='#declarations'>Declarations</a><a href='#precedence'>OU precedence</a>",
             "<a href='#observed'>Target observations</a><a href='#inventory'>GPO inventory</a><a href='#sources'>Source files</a></nav>"]
    counts = [("GPOs", len(data["gpos"])), ("Inheritance snapshots", len(data["inheritance"])),
              ("Source files", len(data["inputs"])), ("Rejected", sum(i["status"] == "Rejected" for i in data["inputs"]))]
    parts.append("<p class='box'>" + " &nbsp; · &nbsp; ".join(f"<b>{n}</b> {label}" for label, n in counts) + "</p>")
    for section, title, key, coverage, renderer in (
        ("declarations", "Declared settings", "findings", "declarations", _readings),
        ("precedence", "Domain and OU link precedence", "inheritance", "ou_precedence",
         lambda records: "".join(_inheritance(s) for s in records)),
        ("observed", "Target observations", "observations", "effective_settings", lambda rows: _readings(rows, True)),
    ):
        parts.append(f"<section id='{section}'><h2>{title}</h2>")
        info = data["coverage"][coverage]
        if info["reason"]:
            parts.append("<p><strong>Not assessed.</strong> " + h(info["reason"]) + "</p>")
        if info["rejected_files"]:
            parts.append("<p>Rejected inputs in this section · " + h(info["rejected_files"]) + "</p>")
        if data[key]:
            parts.append(renderer(data[key]))
        parts.append("</section>")
    parts.append("<section id='inventory'><h2>GPO inventory</h2>")
    parts.extend(_inventory(gpo) for gpo in data["gpos"])
    parts.append("</section><section id='sources'><h2>Source files</h2>")
    parts.append(_table(("File", "Evidence", "Read status", "SHA-256"),
                        ([h(i["source"]), h(i["type"]), h(i["status"]) + "<small>" + h(i.get("reason", "")) + "</small>",
                          "<code>" + h(i["sha256"]) + "</code>"] for i in data["inputs"])))
    parts.append("</section><p><small>GPO Grits " + h(data["tool_version"]) + " · Catalog " + h(data["catalog_version"])
                 + " · JSON schema " + h(data["schema_version"]) + "</small></p></main></body></html>")
    return "".join(parts)
