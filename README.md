# Fortify

Windows 11 hardening tool. Modular, transparent, no hidden behavior. Every change is logged to the console as it runs.

Combines four hardening areas that most tools treat separately:

- **Telemetry** elimination (services, registry, scheduled tasks)
- **AI/Copilot** removal with reinstall prevention
- **Network** hardening (firewall, protocol security, service reduction)
- **Security** deep configuration (ASR, Defender, credentials, TLS, PowerShell)

## Requirements

- Windows 11 (tested on 24H2/26200)
- Administrator privileges
- PowerShell 5.1+

## Quick Start

Run everything:

```powershell
.\fortify.ps1
```

Run specific modules:

```powershell
.\fortify.ps1 -Modules telemetry,ai
.\fortify.ps1 -Modules security
```

List available modules:

```powershell
.\fortify.ps1 -List
```

Run a single module directly:

```powershell
.\modules\telemetry.ps1 -Standalone
```

## Modules

### telemetry

Disables Microsoft telemetry at three levels: services (DiagTrack, dmwappushservice, Diagnostic Policy, etc.), registry policies (AllowTelemetry=0, advertising ID, CEIP, activity history, feedback, cloud content, location, Edge/Office telemetry), and scheduled tasks (Compatibility Appraiser, CEIP, disk diagnostics, flighting, sustainability telemetry).

Sets Delivery Optimization to HTTP only rather than fully disabling it, which would break Windows Update.

### ai

Removes all Microsoft AI integration from Windows. This is the most thorough module and covers:

- **Services**: Copilot Elevation Service, AI Fabric Service
- **Scheduled Tasks**: WindowsAI model caching, Recall, settings configuration
- **Registry**: 50+ policies covering Copilot, Recall, ClickToDo, Edge AI (sidebar, compose, shopping, themes, Bing chat), Start menu Bing search, Office Copilot, widgets, content suggestions
- **Deep Policies**: Capability Access Manager deny for generativeAI and systemAIModels, AI agent creation/access, Paint AI (cocreator, image creator, generative erase/fill/expand), Notepad AI, Office AI training
- **Package Removal**: Copilot, M365Companions, AIFabric, aimgr, AIX, GameAssist, ActionsServer, WritingAssist
- **Reinstall Prevention**: End-of-life entries, deprovisioned entries, Group Policy removal policies, Recall optional feature removal

### network

Hardens the network stack while preserving RDP, core networking, and Hyper-V integration:

- **Firewall**: Sets default inbound to BLOCK, disables 35+ categories of unnecessary inbound rules (Xbox, Teams, Edge, Store, Cast to Device, etc.), verifies critical rules remain enabled
- **Protocols**: Disables SMB1, requires SMB signing, enables RDP NLA, disables LLMNR/WPAD/NetBIOS (common lateral movement and MITM vectors)
- **Services**: Disables Print Spooler, SSDP, ICS, WebDAV, push notifications, SysMain, and other attack surface

### security

Deep security configuration covering five areas:

- **ASR Rules**: 15 Attack Surface Reduction rules (13 enforced, 2 in audit mode for compatibility). Covers email executables, Office child processes, obfuscated scripts, LSASS credential stealing, ransomware protection, USB unsigned code, WMI persistence
- **Defender**: Enables all scanning features, sets cloud block level to High+, enables network protection, PUA detection, file hash computation, 8 hour signature updates
- **Credentials**: Disables WDigest (prevents cleartext passwords in memory), disables LM hash storage, enforces NTLMv2 only, enables LSA audit, restricts anonymous SAM enumeration, enables SMB encryption
- **TLS**: Disables SSL 2.0/3.0 and TLS 1.0, enables TLS 1.2 and 1.3, sets DH minimum key size to 4096 bit, enables .NET strong crypto across all framework versions
- **PowerShell**: Disables v2 engine (defense evasion vector), enables script block logging, enables transcription with invocation headers, disables WinRM basic auth
- **Misc**: DEP OptOut, SEHOP, Windows Script Host disabled, zone info preservation, TCP timestamp removal (prevents OS fingerprinting)

## What This Tool Does NOT Do

- Does not disable Windows Update or Windows Defender
- Does not remove non-AI system apps (Calculator, Photos, etc.)
- Does not modify the Windows shell or UI beyond removing AI buttons
- Does not install any third party software
- Does not phone home or collect any data

## Reverting Changes

Registry changes can be reverted by deleting the keys or restoring from a system restore point. Disabled services can be re-enabled via `Set-Service -StartupType Automatic`. Removed packages can be reinstalled from the Microsoft Store after clearing the reinstall prevention entries.

Create a system restore point before running if you want a simple rollback path:

```powershell
Checkpoint-Computer -Description "Pre-Fortify" -RestorePointType MODIFY_SETTINGS
```

## License

MIT

## Credits

Built by [Game Deity Studios LLC](https://gamedeitystudios.com). Informed by gap analysis of existing tools including [simeononsecurity/Windows-Optimize-Harden-Debloat](https://github.com/simeononsecurity/Windows-Optimize-Harden-Debloat), [AveYo/RemoveWindowsAI](https://github.com/AveYo/RemoveWindowsAI), and [Raphire/Win11Debloat](https://github.com/Raphire/Win11Debloat).
