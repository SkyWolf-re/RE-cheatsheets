// TPL_Embedded_PE_Demo.yar
//
// Author: SkyWolf
// Date: 2025-09-24
// Purpose: Minimal, educational YARA rule showing rule anatomy (RE-cheatsheets)
// Usage: Detect a PE header embedded inside another file (not at offset 0).Triage for payloads in resources/archives/overlays

rule TPL_Embedded_PE_Demo : tpl embedded pe
{
  // Printable metadata of the rule
  meta:
    author    = "SkyWolf"
    date      = "2025-09-24"
    version   = "1.0"
    purpose   = "Detect inner PE headers (MZ…PE\\0\\0) at a non-zero offset"
    rationale = "Common technique: stash a PE in resources/overlay. We look for an 'MZ' followed by a nearby 'PE\\0\\0' well within file bounds."
    reference = "RE-cheatsheets/yara"

  strings:
    // Optional: harmless marker for quick testing; replace/remove in real rules
    $marker = "SkyWolf::embedded pe demo" ascii

    // Core markers for a PE header pair
    $mz = "MZ" ascii
    $pe = "PE\0\0" ascii

  condition:
    // ------- Tunable guards (uncomment/adjust as needed) -------
    // Notes:
    // - Require the inner MZ to be away from the file start (offset > 0)
    // - Bound the search window so 'PE\\0\\0' follows reasonably soon after MZ
    // - Keep upper bound generous for safety; tighten per your corpus
    // @var ->  The offsets or virtual addresses where a given string appears

    // Distance window between MZ and PE (liberal default)
    //   @pe > @mz and @pe - @mz < 0x4000

    // Stricter distance window (closer header pair)
    //   @pe > @mz and @pe - @mz < 0x0800
    // ------- End guards -------

    // Final matching logic
    for any i in (1..filesize-1):                  // inner MZ at offset > 0
      ( @mz == i and @mz + 0x200 <= filesize and   // ensure room for header fields
        @pe > @mz and @pe - @mz < 0x4000           // default window; tighten if needed
      ) and
    $marker
}
