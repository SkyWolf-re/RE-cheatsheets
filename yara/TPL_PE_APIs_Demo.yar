// TPL_PE_APIs_Demo.yar
//
// Author: SkyWolf
// Date: 2025-09-24
// Purpose: Minimal, educational YARA rule showing rule anatomy (RE-cheatsheets)
// Usage: Demo of import-based detection (classic injection triad). Use imports as behavior hints; pair with other signals

import "pe"


// Use when: You want a simple heuristic that many injectors share
// Strength: Fast, readable, good as a building block with other guards
// Caveat: Malware can resolve APIs dynamically (GetProcAddress/syscalls), so imports
// alone are not proof. Pair with PE/file size/entropy or other signals
rule TPL_PE_Import_Demo : tpl pe imports injection
{
  meta:
    author   = "SkyWolf"
    date     = "2025-09-24"
    version  = "1.0"
    purpose  = "Educational import checks for injection APIs"
    rationale= "Imports are stable across tiny edits; good behavior cue"
    reference= "RE-cheatsheets/yara"

  strings:
    $s = "SkyWolf::imports demo" ascii

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    // Any two of three classic APIs
    ( ( pe.imports("KERNEL32.dll", "VirtualAlloc") or pe.imports("KERNEL32.dll","VirtualAllocEx") ) ? 1 : 0 ) +
    ( pe.imports("KERNEL32.dll", "WriteProcessMemory") ? 1 : 0 ) +
    ( pe.imports("KERNEL32.dll", "CreateRemoteThread") ? 1 : 0 ) >= 2 and
    $s
}

// Use when: Scoping candidates for CRT/NtCreateThreadEx/RtlCreateUserThread-style chains
// Strength: Covers KERNEL32/KERNELBASE + NTDLL variants; N-of logic reduces FPs
// Caveat: Dynamic resolution or shellcode-only loaders may bypass import checks
rule TPL_PE_Injection_CreateRemoteThread_Family : tpl pe injection crt
{
  meta:
    author    = "SkyWolf"
    date      = "2025-09-24"
    version   = "1.0"
    purpose   = "Heuristic: classic remote thread injection (N-of APIs)"
    rationale = "Cover KERNEL32/KERNELBASE forwarding + NTDLL variants"
    reference = "RE-cheatsheets/yara"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    // Count hits across DLLs/APIs, require >=3 for robustness
    ( 
      // Target/process handle
      (pe.imports("KERNEL32.dll","OpenProcess") or pe.imports("KERNELBASE.dll","OpenProcess")) ? 1 : 0
    ) +
    (
      // Remote allocation
      (pe.imports("KERNEL32.dll","VirtualAllocEx") or pe.imports("KERNELBASE.dll","VirtualAllocEx") or
       pe.imports("NTDLL.DLL","NtAllocateVirtualMemory") or pe.imports("NTDLL.DLL","ZwAllocateVirtualMemory")) ? 1 : 0
    ) +
    (
      // Remote write
      (pe.imports("KERNEL32.dll","WriteProcessMemory") or pe.imports("KERNELBASE.dll","WriteProcessMemory") or
       pe.imports("NTDLL.DLL","NtWriteVirtualMemory") or pe.imports("NTDLL.DLL","ZwWriteVirtualMemory")) ? 1 : 0
    ) +
    (
      // Make RX
      (pe.imports("KERNEL32.dll","VirtualProtectEx") or pe.imports("KERNELBASE.dll","VirtualProtectEx") or
       pe.imports("NTDLL.DLL","NtProtectVirtualMemory")) ? 1 : 0
    ) +
    (
      // Thread creation
      (pe.imports("KERNEL32.dll","CreateRemoteThread") or pe.imports("KERNEL32.dll","CreateRemoteThreadEx") or
       pe.imports("KERNELBASE.dll","CreateRemoteThreadEx") or
       pe.imports("NTDLL.DLL","NtCreateThreadEx") or pe.imports("NTDLL.DLL","RtlCreateUserThread")) ? 1 : 0
    ) >= 3
}

// Use when: Hunting CreateProcess(SUSPENDED) + QueueUserAPC/NtQueueApcThread patterns
// Strength: Captures suspended process + remote alloc/write + APC + resume sequence
// Caveat: Some benign tools use APCs - combine with context (targets, entropy, size)
rule TPL_PE_Injection_APC_Family : tpl pe injection apc
{
  meta:
    author    = "SkyWolf"
    date      = "2025-09-24"
    version   = "1.0"
    purpose   = "Heuristic: APC-based remote execution (QueueUserAPC/NtQueueApcThread)"
    reference = "RE-cheatsheets/yara"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (
      (pe.imports("KERNEL32.dll","CreateProcessW") or pe.imports("KERNELBASE.dll","CreateProcessW")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","VirtualAllocEx") or pe.imports("KERNELBASE.dll","VirtualAllocEx") or
       pe.imports("NTDLL.DLL","NtAllocateVirtualMemory")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","WriteProcessMemory") or pe.imports("KERNELBASE.dll","WriteProcessMemory") or
       pe.imports("NTDLL.DLL","NtWriteVirtualMemory")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","QueueUserAPC") or
       pe.imports("NTDLL.DLL","NtQueueApcThread") or pe.imports("NTDLL.DLL","NtQueueApcThreadEx")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","ResumeThread") or pe.imports("KERNELBASE.dll","ResumeThread")) ? 1 : 0
    ) >= 3
}

// Use when: Looking for NtUnmapViewOfSection + alloc/write + SetThreadContext + resume
// Strength: Encodes the characteristic hollowing steps with N-of coverage
// Caveat: Not all hollowers unmap - context-only hijack variants may partially match
rule TPL_PE_Injection_Hollowing_Family : tpl pe injection hollow
{
  meta:
    author    = "SkyWolf"
    date      = "2025-09-24"
    version   = "1.0"
    purpose   = "Heuristic: process hollowing / thread context pivot"
    reference = "RE-cheatsheets/yara"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (
      (pe.imports("KERNEL32.dll","CreateProcessW") or pe.imports("KERNELBASE.dll","CreateProcessW")) ? 1 : 0
    ) +
    (
      (pe.imports("NTDLL.DLL","NtUnmapViewOfSection")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","VirtualAllocEx") or pe.imports("KERNELBASE.dll","VirtualAllocEx") or
       pe.imports("NTDLL.DLL","NtAllocateVirtualMemory")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","WriteProcessMemory") or pe.imports("KERNELBASE.dll","WriteProcessMemory") or
       pe.imports("NTDLL.DLL","NtWriteVirtualMemory")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","SetThreadContext") or pe.imports("KERNELBASE.dll","SetThreadContext") or
       pe.imports("NTDLL.DLL","NtSetContextThread")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","ResumeThread") or pe.imports("KERNELBASE.dll","ResumeThread")) ? 1 : 0
    ) >= 4
}

// Use when: Detecting CreateFileMapping/MapViewOfFile or NtCreateSection/NtMapViewOfSection flows
// Strength: Spots less “noisy” injectors that avoid WriteProcessMemory
// Caveat: Mapping APIs are common - require N-of and pair with execution step (thread/APC)
rule TPL_PE_Injection_Section_Family : tpl pe injection section
{
  meta:
    author    = "SkyWolf"
    date      = "2025-09-24"
    version   = "1.0"
    purpose   = "Heuristic: shared section mapping (local+remote)"
    reference = "RE-cheatsheets/yara"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (
      (pe.imports("KERNEL32.dll","CreateFileMappingW") or pe.imports("KERNELBASE.dll","CreateFileMappingW") or
       pe.imports("NTDLL.DLL","NtCreateSection")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","MapViewOfFile") or pe.imports("KERNELBASE.dll","MapViewOfFile") or
       pe.imports("NTDLL.DLL","NtMapViewOfSection")) ? 1 : 0
    ) +
    (
      (pe.imports("KERNEL32.dll","OpenProcess") or pe.imports("KERNELBASE.dll","OpenProcess")) ? 1 : 0
    ) +
    (
      // Some variants still use CRT/Nt threading to execute
      (pe.imports("KERNEL32.dll","CreateRemoteThread") or pe.imports("NTDLL.DLL","NtCreateThreadEx") or
       pe.imports("KERNEL32.dll","QueueUserAPC") or pe.imports("NTDLL.DLL","NtQueueApcThread")) ? 1 : 0
    ) >= 3
}

// Use when: Searching for SetWindowsHookEx + LoadLibrary patterns (keyboard/CBT hooks)
// Strength: Simple, high-signal combo when matched together
// Caveat: Developer utilities and accessibility software can legitimately use hooks -
// validate with path, signer, and persistence context
rule TPL_PE_Injection_SetWindowsHookEx : tpl pe injection hook
{
  meta:
    author    = "SkyWolf"
    date      = "2025-09-24"
    version   = "1.0"
    purpose   = "Heuristic: global hook injection patterns"
    reference = "RE-cheatsheets/yara"

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and
    (
      pe.imports("USER32.dll","SetWindowsHookExW") or pe.imports("USER32.dll","SetWindowsHookExA")
    ) and
    (
      pe.imports("KERNEL32.dll","LoadLibraryW") or pe.imports("KERNEL32.dll","LoadLibraryA") or
      pe.imports("KERNELBASE.dll","LoadLibraryW")
    )
}
