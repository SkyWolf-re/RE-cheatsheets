// TPL_File_Size_Guard.yar
//
// Author: SkyWolf
// Date: 2025-09-21
// Purpose: Minimal, educational YARA rule showing rule anatomy (RE-cheatsheets)
// Usage: Constraining matches by file size

rule TPL_File_Size_Guard_Demo : tpl size guard
{
  // Printable metadata of the rule
  meta:
    author    = "SkyWolf"
    date      = "2025-09-21"
    version   = "1.0"
    purpose   = "educational template for filesize guards (min/max, ranges)"
    rationale = "Reduce false positives and speed scanning by excluding implausible sizes."
    reference = "RE-cheatsheets/yara"

  strings:
    // Optional: a harmless marker so you can test quickly; replace/remove in real rules
    $marker = "SkyWolf::filesize demo" ascii wide

  condition:
    // -------- Choose ONE size guard (uncomment) --------
    // Uncomment ONE size guard below to scope the rule. Keep or replace $marker as needed
    // Notes:
    // - YARA supports size suffixes: KB, MB, GB (binary multiples)
    // - Use guards to exclude tiny stubs or giant blobs depending on context

    // Minimum size only (ignore smaller stubs < 1KB)
    // filesize >= 1KB and

    // Maximum size only (ignore bigger dumps > 20MB)
    // filesize <= 20MB and

    // Range (typical PE payload window)
    // filesize >= 4KB and filesize <= 69MB and

    // -------- End guards --------

    // Final indicator(s). Keep simple for the demo; real rules would combine multiple signals
    $marker
}
