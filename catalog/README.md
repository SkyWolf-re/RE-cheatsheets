# Catalog
A portable detection catalog for reverse engineering & DFIR

- **Regex** (portable across PCRE/YARA/Sigma)
- (**Artifacts**) (durable fingerprints: config hashes, JA3/JA3S/JARM, persistence templates, toolchain)
- (**Atoms**) (volatile: domains/IPs/hashes with optional expiry)
- (**TTPs**) (behavior bundles: injection chains, LOLBins, persistence)

Contrib rules: prefer **3-of-N** bundles and durable fingerprints over one-off atoms. Tag entries with `stability`, `confidence`, and `visibility`
