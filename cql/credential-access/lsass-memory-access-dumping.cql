// Threat Hunt: LSASS Memory Dumping via LOLBins & Tools
// MITRE ATT&CK: T1003.001 (OS Credential Dumping: LSASS Memory)

// --- 1. BASE TELEMETRY SCOPE ---
#event_simpleName=ProcessRollup2
| event_platform=Win

// --- 2. TARGET BINARIES & ENVIRONMENT EXCLUSIONS (Customize allowlists here) ---
| in(field="ImageFileName", values=[
    /rundll32\.exe$/i,
    /procdump(64)?\.exe$/i,
    /sqldumper\.exe$/i,
    /createdump\.exe$/i,
    /taskmgr\.exe$/i,
    /mimikatz\.exe$/i,
    /nanodump.*\.exe$/i,
    /pypykatz\.exe$/i,
    /powershell\.exe$/i,
    /pwsh\.exe$/i
])
| !in(field="UserName", values=["authorized_ir_admin"])

// --- 3. MODULAR BEHAVIOR INDICATORS ---
| case {
    CommandLine=/comsvcs\.dll.*MiniDump/i | DumpMethod := "comsvcs.dll MiniDump";
    CommandLine=/lsass/i AND CommandLine=/(-ma|-mp|-r|MiniDump|Out-Minidump|sekurlsa)/i | DumpMethod := "Explicit LSASS Dump Flag";
    ImageFileName=/(mimikatz|nanodump|pypykatz)\.exe$/i | DumpMethod := "Known Credential Dumper Binary";
    ImageFileName=/sqldumper\.exe$/i AND CommandLine=/0x01100/i | DumpMethod := "SQLDumper Full Memory Dump";
}
| DumpMethod=*

// --- 4. AGGREGATION & TRIAGE OUTPUT ---
| groupBy([ComputerName, UserName, DumpMethod], function=[
    count(as=ExecCount),
    min(@timestamp, as=FirstSeen),
    max(@timestamp, as=LastSeen),
    collect([ParentBaseFileName, ImageFileName, CommandLine, SHA256HashData])
])
| sort(LastSeen, order=desc)
