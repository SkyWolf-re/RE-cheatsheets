// TPL_Regex_Demo.yar
//
// Author: SkyWolf
// Date: 2025-09-22
// Purpose: Minimal, educational YARA rule showing rule anatomy (RE-cheatsheets)
// Usage: Educational rule showing regex strings in YARAs. Tune the regex or add guards

rule TPL_Regex_Demo : tpl regex
{
  // Printable metadata of the rule
  meta:
    author    = "SkyWolf"
    date      = "2025-09-21"
    version   = "1.0"
    purpose   = "demonstrate regex strings"
    rationale = "Regex is handy for IOCs with variable parts (URLs, emails, GUIDs)."
    reference = "RE-cheatsheets/yara"

  strings:
    // Basic HTTP/HTTPS URL (conservative; adjust as needed)
    $re_url = /https?:\/\/[A-Za-z0-9\.\-]+(?:\/[^\s"]*)?/

    // Hostname with TLD (very loose, avoids IPs; tweak if needed)
    $re_host = /\b[a-z0-9][a-z0-9\-]{1,62}\.(?:com|net|org|io|ru|pl|fr|de)\b/i

    // Example GUID (8-4-4-4-12 hex)
    $re_guid = /\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b/

  condition:
    // Optional: uncomment to scope to PE/ELF/etc. (see String_Signature_Demo)
    // uint16(0) == 0x5A4D and  // PE 'MZ'

    1 of ($re_*)
}
