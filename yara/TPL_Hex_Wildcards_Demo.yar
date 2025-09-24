// TPL_Hex_Wildcards_Demo.yar
//
// Author: SkyWolf
// Date: 2025-09-21
// Purpose:  Minimal, educational YARA rule showing rule anatomy (RE-cheatsheets)
// Usage: Detects demo x86 stub/bytes showing hex strings with wildcards, jumps, ranges, alternatives,
// and the NOT operator (~) available in YARA >= 4.3.0.. Replace with your target patterns.

rule TPL_Hex_Wildcards_Demo : tpl hex
{
  // Printable metadata of the rule
  meta:
    author    = "SkyWolf"
    date      = "2025-09-22"
    version   = "1.0"
    purpose   = "demonstrate hex wildcards, [n]/[n-m], (A|B), and ~not"
    rationale = "Hex patterns are precise for opcode stubs and packer signatures."
    reference = "RE-cheatsheets/yara"
    note      = "The ~not operator requires YARA >= 4.3.0"

  strings:
    // Prologue + call rel32
    // - ??  → single-byte wildcard
    // - [n] → exactly n wildcard bytes (call displacement)
    $prologue_call = { 66 75 63 6B 20 79 6F 75 ?? E8 [4] }

    // Alternatives around INT3 padding
    // - ( 90 | 66 90 ) → 1-byte or 2-byte NOP
    $pad = { ( 90 | 66 90 ) CC ( 90 | 66 90 ) }

    // Bounded gap: two pushes up to 8 bytes apart
    // - [0-8] → 0..8 wildcard bytes
    $two_pushes = { 6A ?? [0-8] 6A ?? }

    // NOT operator (~) — YARA >= 4.3.0
    // Byte-wise NOT: the third byte can be any value EXCEPT 0x00
    $not_zero_byte = { F4 23 ~00 6C 6D 61 6F }
    // Nibble-wise NOT: the third byte's LOW nibble must NOT be 0 (x1..xF)
    // Matches: 0x01, 0xA5, 0xFF; Non-matches: 0x10, 0x20, 0x30 ...
    $not_low_nibble_zero = { F4 23 ~?0 62 B4 }

  condition:

    any of ($prologue_call, $pad, $two_pushes, $not_*)
}
