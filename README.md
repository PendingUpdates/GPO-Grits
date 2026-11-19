# GPO Grits

![A grits bowl and spoon on the counter in front of three Group Policy monitors](assets/gpo-grits-banner.png)

GPO Grits audits on-premises Active Directory Group Policy from files you export. It inventories the supplied GPOs, reviews computer **minimum password length** and user **screen saver timeout**, and writes a local HTML report and matching JSON. You can compare the reported values with your own thresholds.

## Run your first audit

1. Extract the entire GPO Grits folder. Install Python 3.9 or later on the reviewing computer. The auditor uses the Python standard library and ordinary local file permissions.
2. Obtain a Group Policy XML report. If you already have one, go to step 3. To export all GPOs, open Windows PowerShell on a domain-connected administration workstation with the GroupPolicy module (GPMC/RSAT) and read access to the desired domain. Choose an existing folder and a fresh filename.

   ```powershell
   Get-GPOReport -All -ReportType Xml -Path C:\Audit\domain.xml
   ```

3. Open a terminal in the extracted GPO Grits folder. Supply the XML file and choose a **new** report directory.

   ```powershell
   py -3 grits.py audit --gpo C:\Audit\domain.xml --out C:\Audit\grits-report
   ```

4. Open `C:\Audit\grits-report\report.html` in your browser. Use `report.json` for structured results. Both files contain local directory and policy information. Keep them with the source exports under your normal access controls.

On macOS or Linux, use `python3 grits.py audit --gpo domain.xml --out grits-report`. You can review exported evidence on a disconnected computer. Only the administrator’s separate export step needs the relevant Windows tooling and permissions. [Microsoft Get-GPOReport reference](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gporeport)

## Read the results

| Report section | Evidence and interpretation |
| --- | --- |
| Declared settings | Each supplied GPO gets one row per supported setting, with section status, source GUID, value or reason, and field location. Different declarations from different GPOs remain visible. |
| Domain and OU link precedence | An optional inheritance snapshot gives the named container’s direct links, blocked-inheritance flag, and the eligible links in reported precedence order. Security filtering, WMI filtering and target processing can affect the result on a particular machine or user. |
| Target observations | A logging RSoP report can show a supported setting for the named user or computer at the report time. Grits checks for the winning setting record. A list of applied GPOs alone, modeling data, or ambiguous results yield **Not assessed**. |
| GPO inventory | Open a GPO for its section flags, reported link targets and enforcement status, WMI-filter reference, and reported trustee permissions. These are the entries visible in the export. |
| Source files | The report names each input, records the SHA-256 of every file fully read within the import limits, and explains each rejection. |

The initial catalog recognizes the Security extension’s `MinimumPasswordLength` and the English Administrative Templates **Screen saver timeout** entry under Control Panel. Localized or unsupported representations yield **Not assessed**. A timeout is measured in seconds. The timeout setting alone cannot establish whether the screen saver is enabled, locks the session, or has a valid executable. Password length is a Group Policy setting. Individual accounts may be subject to fine-grained password policies. [Microsoft screen saver policy reference](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-controlpaneldisplay#cpl_personalization_screensavertimeout)

### Compare with a local requirement

```powershell
py -3 grits.py audit --gpo C:\Audit\domain.xml --min-password-length 14 --max-screen-saver-seconds 900 --out C:\Audit\threshold-review
```

Replace 14 and 900 with your organization's requirements. Each comparison belongs to its sourced declaration or observation. A timeout of zero falls outside a positive timeout threshold. A disabled policy, disabled or unknown declaration section, or missing value leaves the comparison **Not assessed**. An omitted threshold leaves that setting unscored.

## Add evidence for a container or target

For a domain or OU, run the following on an administration workstation in Windows PowerShell with the GroupPolicy module. Supply the actual distinguished name when prompted. Preserve the arrays even when a list contains only one link, and retain the order supplied by Windows.

```powershell
$container = Get-GPInheritance -Target (Read-Host 'Domain or OU distinguished name') -ErrorAction Stop
function Convert-GritsLink ($link) {
    [ordered]@{
        DisplayName = $link.DisplayName
        GpoId       = [string]$link.GpoId
        Target      = [string]$link.Target
        Enabled     = [string]$link.Enabled
        Enforced    = [string]$link.Enforced
        Order       = $link.Order
    }
}
[ordered]@{
    Path                  = $container.Path
    GpoInheritanceBlocked = [string]$container.GpoInheritanceBlocked
    GpoLinks              = @(foreach ($link in $container.GpoLinks) { Convert-GritsLink $link })
    InheritedGpoLinks     = @(foreach ($link in $container.InheritedGpoLinks) { Convert-GritsLink $link })
} | ConvertTo-Json -Depth 5 | Out-File -LiteralPath C:\Audit\inheritance.json -Encoding utf8 -NoClobber
```

For a target observation, export RSoP logging data for the user or computer you are authorized to review. On the target, the following requests the current user's and computer's logging report. Windows access requirements depend on the requested target and scope. [Microsoft RSoP reference](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpresultantsetofpolicy) · [Microsoft inheritance reference](https://learn.microsoft.com/en-us/powershell/module/grouppolicy/get-gpinheritance)

```powershell
Get-GPResultantSetOfPolicy -ReportType Xml -Path C:\Audit\target.xml
py -3 grits.py audit --gpo C:\Audit\domain.xml --inheritance C:\Audit\inheritance.json --rsop C:\Audit\target.xml --out C:\Audit\grits-target-review
```

Each input switch accepts one or more paths. You can also review inheritance or RSoP alone. If you supply snapshots from different containers, targets or times, Grits reports each snapshot separately.

## File handling and exit codes

Grits reads local files and creates a new report directory for each run. XML intake rejects DTDs and XInclude, with limits of 16 MiB per input, 64 MiB per import, 64 XML nesting levels and 100,000 XML elements per file. A rejected file contributes no partial findings. Other readable files still appear in the report.

| Exit code | Meaning |
| --- | --- |
| 0 | All inputs were read. See the report for assessment gaps and threshold results. |
| 1 | At least one input was rejected. The report records the error. |
| 2 | The command or output destination was invalid, or the reports could not be written. |
