// Threat Hunt: Suspicious Rundll32 Proxy Execution
// MITRE ATT&CK: T1218.011 (System Binary Proxy Execution: Rundll32)

// --- 1. BASE TELEMETRY SCOPE ---
#event_simpleName=ProcessRollup2
| event_platform=Win
| ImageFileName=/\\rundll32\.exe$/i

// --- 2. ENVIRONMENT EXCLUSIONS (Customize allowlists for your environment) ---
| !in(field="ParentBaseFileName", values=["approved_installer.exe"])
| CommandLine!=/\\ApprovedEnterpriseTool\\.+\.dll/i

// --- 3. MODULAR BEHAVIOR INDICATORS ---
| case {
    CommandLine=/(javascript:|vbscript:|mshtml,RunHTMLApplication)/i | Indicator := "Script Protocol / MSHTML Handler";
    CommandLine=/(\\\\|https?:\/\/)/i | Indicator := "Remote UNC or HTTP Path";
    CommandLine=/(\\Users\\Public\\|\\AppData\\|\\ProgramData\\|\\Windows\\Temp\\|\\Temp\\)/i | Indicator := "Execution from User-Writable Path";
    CommandLine=/#\d+\s*$/ | Indicator := "Ordinal-Only Export Execution";
    ParentBaseFileName=/^(winword|excel|powerpnt|outlook|mshta|wscript|cscript)\.exe$/i | Indicator := "Suspicious Parent Process";
}
| Indicator=*

// --- 4. TRIAGE OUTPUT ---
| table([@timestamp, ComputerName, UserName, ParentBaseFileName, Indicator, CommandLine, TargetProcessId, aid], limit=500)
| sort(@timestamp, order=desc)
