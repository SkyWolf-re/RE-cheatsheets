// TPL_String_Signature_Demo.yar
//
// Author: SkyWolf
// Date: 2025-09-20
// Purpose: Minimal, educational YARA rule showing rule anatomy (RE-cheatsheets)
// Usage: Detects a unique marker string in any file; uncomment one guard to scope by format

rule TPL_String_Signature_Demo : tpl demo string
{
  //Printable metadata of the rule 
  meta: 
    author    = "SkyWolf"
    date      = "2025-09-20"
    version   = "1.0"
    purpose   = "educational template for a simple string-based signature"
    rationale = "Show how to codify a distinctive artifact (string) as a rule."
    reference = "RE-cheatsheets/yara"

  strings:
    //Deliberately unique marker so you can create a benign test file
    //Note: remove 'fullword' if you want matches inside larger tokens
    $marker = "SkyWolf::YARA demo artifact" ascii wide fullword

  condition:
    // -------- Choose ONE guard (uncomment) --------
    // File-type guard: uncomment exactly one magic-number check to scope this rule (YARA reads integers little-endian)

    // PE (Windows Portable Executable): 'MZ' at offset 0
    // uint16(0) == 0x5A4D and

    // ELF (any): 0x7F 'E' 'L' 'F' → little-endian uint32 = 0x464C457F
    // uint32(0) == 0x464C457F and

    // ELF x64 only: ELF magic + EI_CLASS (byte 4) == 2 (64-bit)
    // ( uint32(0) == 0x464L457F and uint8(4) == 2 ) and

    // Mach-O (macOS): common 32/64 variants (YARA reads little-endian)
    // ( uint32(0) == 0xFEEDFACE or  // MH_MAGIC (32-bit, little-endian)
    //   uint32(0) == 0xCEFAEDFE or  // MH_CIGAM (byteswapped)
    //   uint32(0) == 0xFEEDFACF or  // MH_MAGIC_64 (64-bit, little-endian)
    //   uint32(0) == 0xCFFAEDFE )   // MH_CIGAM_64 (byteswapped)
    // and

    // Android DEX: "dex\n035\0" → 'dex\n' @0 and '035\0' @4
    // ( uint32(0) == 0x0A786564 and uint32(4) == 0x00353330 ) and

    // -------- End guards --------

    //Match if the marker string is present at least once
    $marker
}
