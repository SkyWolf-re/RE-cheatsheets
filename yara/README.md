# YARA Templates

YARA is a rule language for identifying files (or memory) by their contents and structure.  
Think “grep + hex + regex + PE awareness”, all in one.  
In this directory, you will find educational rules to demonstrate patterns (strings, hex, regex, PE module, heuristics). 

---

## Why YARA  

YARA lets you codify analyst knowledge as small, testable rules that match on bytes, strings, regex, and file structure (via modules like pe/elf). It scales from quick local triage to enterprise-wide hunts, is reproducible (rules live in Git, reviewed and versioned), and is explainable - every match is tied to clear conditions. By combining weak indicators (strings, opcodes) with structural checks (sections, imports, entropy), YARA reduces false positives while staying fast enough to sweep large corpora and memory dumps. In short: it’s the common language for detection, hunting, and documenting what “malicious” looks like.

---

## Notes
- Each file contains a single rule
- Use tags (e.g., , , , ) to filter
- These are templates—tune strings/thresholds for real targets

## Learn more

- [Official YARA docs – syntax, strings, modules, best practices](https://yara.readthedocs.io/en/latest/#)
