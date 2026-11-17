# Phase 3 — Data Quality & Leakage Audit Report
**Dataset:** UCI PhiUSIIL Phishing URL Dataset (UCI ID 967)  
**File Audited:** `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`  
**Audit Utility:** `scripts/audit_phiusiil.py`  
**Execution Mode:** Read-only, deterministic, zero-network execution  
**Status:** Step 2 Final Corrections Verified  

---

## Executive Summary

A comprehensive, read-only data-quality and domain-leakage audit was conducted on the raw UCI PhiUSIIL dataset (`data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`). The audit utility was refined to resolve all review items: strict raw-string preservation without trimming, complete physical line and row reconciliation, accurate destination-port validation separate from userinfo credentials, multi-stage diagnostic normalization (Stages 0 to 4), public-suffix-aware domain extraction with explicit IP handling and fallback reporting, and a deterministic group-aware domain-disjoint split simulation across three random seeds.

### Note on Audit Utility & Report Generation:
The audit utility [`scripts/audit_phiusiil.py`](file:///d:/Projects/PhishShield-AI-Phishing-URL-Detection-System/scripts/audit_phiusiil.py) outputs structured terminal logs and programmatic assertions; it does **not** automatically overwrite this Markdown document. This report is maintained as the curated, permanent documentation artifact, updated directly from verified utility outputs.

### Key Measured Findings:
1. **Physical Line & Row Reconciliation:** Exactly **235,796 physical lines** in the raw CSV, reconciling to **1 header line + 235,795 valid data records**. There are **zero** malformed rows, **zero** rows with incorrect column counts (all 56 columns present across all rows), **zero** empty URLs, **zero** empty labels, and **zero** invalid label values.
2. **Exact Raw String Duplicates (Stage 0):** **235,370 distinct raw URL strings**. Exactly **425 duplicate groups** containing **425 extra rows**. **Zero exact duplicate groups have conflicting labels** (100.0% label consistency for identical strings). There are **zero whitespace-padded URLs** in the raw CSV.
3. **Multi-Stage Diagnostic Normalization:**
   * **Stage 1 (Hostname Lowercase):** 437 duplicate groups (+12 groups due to host casing), 0 conflicting groups.
   * **Stage 2 (Default Ports):** 439 duplicate groups (+2 groups from `:80` / `:443`), 0 conflicting groups.
   * **Stage 3 (Root Trailing Slash):** 893 duplicate groups (+454 groups from `domain.com/` vs `domain.com`), **1 conflicting group** affecting 2 rows (`https://www.education.gouv.fr/` [Phishing] vs `https://www.education.gouv.fr` [Legitimate]).
   * **Stage 4 (Scheme Removal / Cross-Protocol):** 2,577 duplicate groups, **43 conflicting groups** affecting 86 rows. In all 43 cases, the `https://` version is legitimate while the `http://` version is phishing. Protocol variants must not be collapsed.
4. **Strong URL Structural & Port Validation:**
   * Supported schemes: 100.0% (184,046 `https`, 51,749 `http`). Unsupported schemes: 0.
   * Missing hostnames: 0. URL parsing exceptions: 0.
   * Destination port classification (4 mutually exclusive categories):
     - Valid destination ports (1–65535): **26 URLs** across 11 port numbers (443: 10, 8080: 4, 2096: 3, 9595: 2, etc.).
     - Out-of-range numeric ports (< 1 or > 65535): **0 URLs**.
     - Malformed destination ports (non-numeric / invalid syntax): **0 URLs**.
     - Missing destination ports (default scheme port implied): **235,769 URLs**.
   * Userinfo credential obfuscation: Exactly **10 URLs** use HTTP Basic Authentication (`@` in netloc) for phishing obfuscation (e.g. `paypal.com:911@...`). The userinfo credentials are separated from network ports.
5. **Registered Domain Landscape (Public-Suffix Aware & Fallback Policy):**
   * Total grouping keys: **175,509**
   * Registered domains (`ext.domain + ext.suffix`): **175,352** (235,187 records)
   * Raw IP addresses: **157** (608 records)
   * Fallback hostnames (no recognized suffix and not an IP): **0** (0 records)
   * Domain distribution: **Median is 1 URL** (P95 is 1; P99 is 3; max is 5,754 on `web.app`).
   * Phishing URLs cluster on free hosting platforms (`web.app`, `firebaseapp.com`, `repl.co`), whereas legitimate URLs are dispersed across 131,997 distinct domains.
6. **Mixed-Label Domains:** Exactly **120 domains** (`0.07%`) host both legitimate and phishing URLs (e.g., `duckdns.org`, `pinata.cloud`).
7. **Domain-Disjoint Split Feasibility:** A multi-objective greedy domain allocation was simulated across seeds **42, 100, and 2026**. With targets of 70% train, 10% val, and 20% test:
   * **Seed 42:** Train: 165,056 URLs (`69.99979%`, dev: `-0.5` URLs), Val: 23,579 URLs (`9.99979%`, dev: `-0.5` URLs), Test: 47,160 URLs (`20.00042%`, dev: `+1.0` URLs). Phishing prevalence: **42.81%** in all splits.
   * **Zero domain overlap** was verified programmatically across all partitions.

---

## 1. Environment & Cryptographic Integrity

### Active Environment:
* **Python Runtime:** Python 3.14.0 (`C:\Python314\python.exe`) / Python 3.11.9 (`.venv/Scripts/python.exe`)
* **Domain Extractor:** `tldextract 5.3.0`
* **PSL Mode:** Strictly offline snapshot (`suffix_list_urls=None`; zero external network requests)
* **Dependency Discovery:** Native import from active Python environment (zero hardcoded user paths)

### Cryptographic Checksum Verification:
Both the extracted CSV and raw ZIP archive were recomputed directly from disk bytes using SHA-256 and verified against `data/raw/dataset_manifest.json`.

**Verification Failure Policy:**
- If the CSV exists but its expected SHA-256 is missing or empty in the manifest, an explicit `ValueError` is raised.
- If the ZIP archive exists on disk, its expected checksum must be present in the manifest and match; if missing, empty, or mismatched, an explicit `ValueError` is raised.
- A missing expected checksum is **never** treated as a successful match.
- If the ZIP archive is not present on disk, ZIP verification is explicitly reported as **SKIPPED** rather than as a successful match.

| File | Byte Size | Computed SHA-256 | Manifest SHA-256 | Match |
|---|---|---|---|---|
| `PhiUSIIL_Phishing_URL_Dataset.csv` | 56,854,345 | `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` | `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6` | **True** |
| `phiusiil_phishing_url_dataset.zip` | 15,376,007 | `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a` | `0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a` | **True** |

---

## 2. Physical File Integrity & Row Reconciliation

The CSV was parsed without silently skipping any lines. Every record was evaluated. Reconciliation failures, column count errors, missing fields, or invalid labels trigger explicit `AssertionError` audit failures:

| Integrity Check | Count | Reconciliation Status |
|---|---|---|
| **Physical Lines in File** | 235,796 | 1 Header Line + 235,795 Data Rows |
| **Header Column Count** | 56 | Matches official UCI documentation |
| **Total Data Records Parsed** | 235,795 | 100.0% of lines accounted for |
| **Rows with Incorrect Column Counts** | **0** | All rows have exactly 56 columns |
| **Empty URL Rows** | **0** | No missing URL values |
| **Empty Label Rows** | **0** | No missing label values |
| **Invalid Label Rows** | **0** | All labels are integer `0` or `1` |
| **Whitespace-Padded URLs** | **0** | `raw_url == raw_url.strip()` for all records |
| **Total Malformed Records** | **0** | Complete integrity verified |
| **Line-to-Record Match** | **True** | `235,796 == 1 + 235,795` |

### Original Class Distribution (Raw UCI Labels):
* **Class 1 (Legitimate):** `134,850` records (`57.19%`)
* **Class 0 (Phishing):** `100,945` records (`42.81%`)
* **Population Phishing Prevalence:** `42.81%`

---

## 3. URL Structural, Destination Port & Userinfo Validation

URL strings were analyzed on their trimmed representation for protocol and structural compliance.

### Destination Port Classification Logic:
Destination port analysis explicitly decomposes `netloc` into `userinfo` (everything prior to the last `@`) and destination `hostport`. For IPv6 hosts, bracket boundaries `[...]` are respected so internal IPv6 colons are never misidentified as port separators. Destination ports are strictly classified into four mutually exclusive categories without conflating generic `urllib.parse` exceptions. A port is accepted as numeric only if `port_str.isascii() and port_str.isdecimal()`, strictly rejecting non-URL numeric syntax (e.g., `+80`, ` 80`, `1_000`, non-ASCII digits):
1. **Valid Destination Ports:** ASCII decimal integers in the RFC-defined range $1 \dots 65,535$.
2. **Out-of-Range Numeric Ports:** ASCII decimal integers outside $1 \dots 65,535$ (e.g., $\le 0$ or $> 65,535$).
3. **Malformed Destination Ports:** Non-ASCII-decimal or syntactically invalid port tokens (e.g., `:abc`, `:+80`, `: 80`, `:1_000`, empty string after `:`).
4. **Missing Destination Ports:** No port specified in `netloc`; default protocol port (80 for HTTP, 443 for HTTPS) is implied.

| Attribute / Category | Measured Count | Details |
|---|---|---|
| **Schemes Observed** | 235,795 | `https`: 184,046 (`78.05%`), `http`: 51,749 (`21.95%`) |
| **Unsupported Schemes** | 0 | No `ftp://`, `data:`, `javascript:`, or scheme-less URLs |
| **Missing Hostnames** | 0 | Netloc present on all 235,795 URLs |
| **URL Parsing Exceptions** | 0 | `urlsplit` succeeded without exception across all records |
| **1. Valid Destination Ports (1–65535)** | **26** | 26 URLs on 11 distinct ports (443: 10, 8080: 4, 2096: 3, 9595: 2, 8085: 1, 8087: 1, 8443: 1, 4000: 1, 10003: 1, 8383: 1, 30332: 1) |
| **2. Out-of-Range Numeric Ports** | **0** | Zero ports outside the valid range $1 \dots 65,535$ |
| **3. Malformed Destination Ports** | **0** | Zero non-numeric port strings; no syntax errors |
| **4. Missing Destination Ports** | **235,769** | Explicit port absent; default scheme port implied |
| **Userinfo Credential Obfuscation** | **10** | URLs using `userinfo@host` phishing spoofing (all 10 are Phishing) |

*Reconciliation Check:* $\text{Valid} (26) + \text{Out-of-Range} (0) + \text{Malformed} (0) + \text{Missing} (235,769) = 235,795$ total records ($100.0\%$).

### The 10 Userinfo Credential-Spoofed URLs:
In these URLs, `@` is present in the network location component. In 6 cases, a colon separates username and password (e.g. `paypal.com:911@...`). The token `911` is part of the user credentials, **not a destination port**:
1. Row 5,262: `http://www.paypal.com:911@xn--80aaahorunoimsf3p.xn--p1ai/fix-account/` [Label 0, Userinfo: `'www.paypal.com:911'`]
2. Row 62,414: `http://netflixaccount.node:911@env-2949886.node.cloudlets.zone/` [Label 0, Userinfo: `'netflixaccount.node:911'`]
3. Row 84,979: `https://vystar..0rg@client.iebetanialaargentina.edu.co` [Label 0, Userinfo: `'vystar..0rg'`]
4. Row 117,081: `http://account.venmo.com.sign-in:911@xn--80aaahorunoimsf3p.xn--p1ai/v/` [Label 0, Userinfo: `'account.venmo.com.sign-in:911'`]
5. Row 117,258: `https://support.ionos.de@safebikehelmet.com/n#redacted@abuse.ionos.com` [Label 0, Userinfo: `'support.ionos.de'`]
6. Row 149,966: `https://mail.lonos.com:authentification-release@dheed.com/media` [Label 0, Userinfo: `'mail.lonos.com:authentification-release'`]
7. Row 164,333: `http://www.accntnetflix.com:911@s954760881.onlinehome.us/aq` [Label 0, Userinfo: `'www.accntnetflix.com:911'`]
8. Row 178,792: `https://valoresareceber@aux1.ru/go/` [Label 0, Userinfo: `'valoresareceber'`]
9. Row 204,965: `http://restart-membership.com:911@s955723798.onlinehome.us/ven` [Label 0, Userinfo: `'restart-membership.com:911'`]
10. Row 209,376: `http://exu0wgk0298bi9oj8c3f@2muchlove.one/vlnssjjebk1vnznzmzmyczduynduk21ha1hyuutiyzvvulrjyvvtqwlvdlvlbe9rredmy3c0nuljekp4vudmdtfwrhvfdfdymi9ibw9rsm96ew9uagtmstzrmty1bfrfcufxsxderxpgtlu9` [Label 0, Userinfo: `'exu0wgk0298bi9oj8c3f'`]

*Extraction note:* `tldextract` parses userinfo correctly and extracts the true destination domain (`xn--80aaahorunoimsf3p.xn--p1ai`, `onlinehome.us`, etc.), preventing domain spoofing during split allocation.

---

## 4. Exact Raw String Duplicate Audit (Stage 0)

Exact duplicate tracking evaluated the unstripped original CSV field:

* **Distinct Exact URL Strings:** `235,370` (`99.82%` of dataset)
* **Exact Duplicate Groups:** `425` groups
* **Extra Redundant Rows:** `425` rows (`0.18%` of dataset)
* **Consistent-Label Groups:** `425` groups (`100.0%`)
* **Conflicting-Label Groups:** **`0` groups (`0.0%`)**
* **Records Affected by Exact Conflicts:** **`0` rows**

### Finding:
There are **zero exact URL label conflicts** in the raw PhiUSIIL dataset. Every duplicate instance carries the exact same label as its original. Exact deduplication (`keep="first"`) eliminates 425 redundant rows with zero label ambiguity.

---

## 5. Multi-Stage Diagnostic Normalization Audit

To understand which transformations introduce duplicates and label conflicts, each normalization stage was applied progressively using parsed URL components (`urlsplit` / `urlunsplit`).

### IPv6-Safe Component Reconstruction:
Stages 1 through 3 strictly decompose `netloc` into `userinfo`, bracketed IPv6 or standard `hostname`, and `port`. Reassembly preserves:
- IPv6 brackets (e.g. `[2001:db8::1]`), avoiding colon misidentification.
- Raw userinfo credentials before `@`.
- Non-default destination ports. In Stages 2 and 3, default ports are normalized based on their integer value (`80` for HTTP, `443` for HTTPS), while non-numeric/malformed port tokens are preserved as-is for diagnostics.
- Query strings and URL fragments.
- HTTP vs. HTTPS protocol variants (never collapsed).

| Normalization Stage | Distinct Keys | Duplicate Groups | Extra Redundant Rows | Consistent Groups | Conflicting Groups | Affected Conflict Rows |
|---|---|---|---|---|---|---|
| **Stage 0: Exact Original URL** | 235,370 | 425 | 425 | 425 | **0** | **0** |
| **Stage 1: Hostname Lowercase (IPv6-Safe)** | 235,358 | 437 | 437 | 437 | **0** | **0** |
| **Stage 2: Default-Port Normalization** | 235,356 | 439 | 439 | 439 | **0** | **0** |
| **Stage 3: Root Trailing Slash Normalization** | 234,895 | 893 | 900 | 892 | **1** | **2** |
| **Stage 4: Scheme Removal (Cross-Protocol)** | 233,111 | 2,577 | 2,684 | 2,534 | **43** | **86** |

### Detailed Stage Observations:
* **Stage 1 (+12 groups):** Hostname case-folding (`EXAMPLE.COM` -> `example.com`, preserving IPv6 brackets and userinfo) discovers 12 duplicate groups, all with 100% consistent labels.
* **Stage 2 (+2 groups):** Stripping default ports (`:80` on HTTP, `:443` on HTTPS) discovers 2 duplicate groups, both with 100% consistent labels.
* **Stage 3 (+454 groups, 1 conflict):** Normalizing root trailing slashes (`domain.com/` -> `domain.com`) introduces **1 label conflict**:
  * `https://www.education.gouv.fr/` (with trailing slash) -> **Label 0 (Phishing)**
  * `https://www.education.gouv.fr` (without trailing slash) -> **Label 1 (Legitimate)**
  * *Policy:* Do not automatically strip slashes; retain original string representation.
* **Stage 4 (+1,684 groups, 43 conflicts):** Removing protocols reveals 43 groups (86 rows) where the HTTP version is labeled Phishing (`0`) while the HTTPS version is labeled Legitimate (`1`):
  * `http://www.w3.org` (Phishing) vs `https://www.w3.org` (Legitimate)
  * `http://www.ikarussecurity.com` (Phishing) vs `https://www.ikarussecurity.com` (Legitimate)
  * `http://www.tracemyip.org` (Phishing) vs `https://www.tracemyip.org` (Legitimate)
  * `http://www.electrum.org` (Phishing) vs `https://www.electrum.org` (Legitimate)
  * *Policy:* **Do not merge HTTP and HTTPS variants.** Protocol presence is a genuine predictive signal.

---

## 6. Registered Domain Landscape & Fallback Policy

Using `tldextract 5.3.0` with an offline snapshot of the Public Suffix List:

### Fallback Policy:
1. **Registered Domain:** If `ext.domain` and `ext.suffix` are both present, group by `f"{ext.domain}.{ext.suffix}".lower()`.
2. **IP Address:** If host is an IPv4 or IPv6 address, group by normalized IP.
3. **Fallback Hostname:** If the PSL cannot establish a suffix and host is not an IP, group conservatively by the **complete normalized hostname**. Subdomain information is never discarded.

### Measured Domain Entities:
| Grouping Category | Unique Entities | Records Accounted For |
|---|---|---|
| **PSL Registered Domains** | 175,352 | 235,187 records |
| **Raw IP Addresses** | 157 | 608 records |
| **Fallback Hostnames (Unrecognized PSL)** | **0** | **0 records** |
| **Total Grouping Keys** | **175,509** | **235,795 records** |

*Class Composition of Grouping Keys:*
* **Legitimate-Only Groups:** `131,997` (`75.21%` of all groups)
* **Phishing-Only Groups:** `43,392` (`24.72%` of all groups)
* **Mixed-Label Groups:** `120` (`0.07%` of all groups)

### Domain Size Distribution:
* **Min / P25 / Median / P75 / P95:** `1` URL
* **99th Percentile:** `3` URLs
* **Maximum:** `5,754` URLs (`web.app`)

### Top 15 Registered Domains:
| Rank | Domain | Total URLs | Legitimate | Phishing | Type | Phish Rate |
|---|---|---|---|---|---|---|
| 1 | `web.app` | 5,754 | 0 | 5,754 | Phish-Only | 100.0% |
| 2 | `firebaseapp.com` | 5,594 | 0 | 5,594 | Phish-Only | 100.0% |
| 3 | `repl.co` | 3,754 | 0 | 3,754 | Phish-Only | 100.0% |
| 4 | `weeblysite.com` | 3,097 | 0 | 3,097 | Phish-Only | 100.0% |
| 5 | `ipfs.io` | 1,559 | 0 | 1,559 | Phish-Only | 100.0% |
| 6 | `workers.dev` | 1,438 | 0 | 1,438 | Phish-Only | 100.0% |
| 7 | `square.site` | 1,199 | 0 | 1,199 | Phish-Only | 100.0% |
| 8 | `dweb.link` | 975 | 0 | 975 | Phish-Only | 100.0% |
| 9 | `xsph.ru` | 928 | 0 | 928 | Phish-Only | 100.0% |
| 10 | `pantheonsite.io` | 900 | 0 | 900 | Phish-Only | 100.0% |
| 11 | `google.com` | 782 | 0 | 782 | Phish-Only | 100.0% |
| 12 | `godaddysites.com` | 781 | 0 | 781 | Phish-Only | 100.0% |
| 13 | `duckdns.org` | 643 | 1 | 642 | Mixed | 99.8% |
| 14 | `webwave.dev` | 567 | 0 | 567 | Phish-Only | 100.0% |
| 15 | `weebly.com` | 555 | 0 | 555 | Phish-Only | 100.0% |

*Concentration:* The Top 10 domains comprise `25,198` URLs (`10.69%` of total). All top 10 domains are shared hosting platforms hosting phishing pages.

---

## 7. Mixed-Label Domain Analysis

Only **120 domains** (`0.07%`) host both legitimate and phishing URLs, representing `1,324` URLs (`0.56%` of the dataset).

### Top Mixed Domains:
| Domain | Total URLs | Legitimate | Phishing | Phishing Rate |
|---|---|---|---|---|
| `duckdns.org` | 643 | 1 | 642 | 99.8% |
| `pinata.cloud` | 276 | 1 | 275 | 99.6% |
| `cutt.ly` | 36 | 1 | 35 | 97.2% |
| `eu.org` | 28 | 3 | 25 | 89.3% |
| `uk.com` | 23 | 22 | 1 | 4.3% |
| `wikidot.com` | 19 | 1 | 18 | 94.7% |
| `org.ru` | 16 | 3 | 13 | 81.2% |
| `washington.edu` | 12 | 11 | 1 | 8.3% |

*Policy:* Mixed domains are kept together as indivisible units during domain partitioning.

---

## 8. Deterministic Domain-Disjoint Split Simulation (Actual Output & Precision)

The simulation implemented inside `scripts/audit_phiusiil.py` allocates domains using greedy multi-objective bin-packing across target capacities:
* **Train Target:** `70.0%` (`165,056.5` URLs)
* **Validation Target:** `10.0%` (`23,579.5` URLs)
* **Test Target:** `20.0%` (`47,159.0` URLs)

### Programmatic Assertions:
* `assert len(domain_set(train) & domain_set(val)) == 0` -> **PASSED**
* `assert len(domain_set(train) & domain_set(test)) == 0` -> **PASSED**
* `assert len(domain_set(val) & domain_set(test)) == 0` -> **PASSED**
* `assert total_allocated_domains == 175,509` -> **PASSED**
* `assert total_allocated_urls == 235,795` -> **PASSED**

### Exact Simulation Results Across Random Seeds:

| Seed | Partition | Exact URLs | Actual Percentage | Deviation from Target | Grouping Keys | Legitimate (1) | Phishing (0) | Phishing Prevalence |
|---|---|---|---|---|---|---|---|---|
| **Seed 42** | **Train** | `165,056` | 69.99979% | -0.5 URLs | 123,954 | 94,395 | 70,661 | **42.81%** |
| | **Validation** | `23,579` | 9.99979% | -0.5 URLs | 16,443 | 13,485 | 10,094 | **42.81%** |
| | **Test** | `47,160` | 20.00042% | +1.0 URL | 35,112 | 26,970 | 20,190 | **42.81%** |
| **Seed 100** | **Train** | `165,053` | 69.99852% | -3.5 URLs | 123,603 | 94,395 | 70,658 | **42.81%** |
| | **Validation** | `23,581` | 10.00064% | +1.5 URLs | 16,575 | 13,485 | 10,096 | **42.81%** |
| | **Test** | `47,161` | 20.00085% | +2.0 URLs | 35,331 | 26,970 | 20,191 | **42.81%** |
| **Seed 2026** | **Train** | `165,056` | 69.99979% | -0.5 URLs | 123,900 | 94,395 | 70,661 | **42.81%** |
| | **Validation** | `23,579` | 9.99979% | -0.5 URLs | 16,438 | 13,485 | 10,094 | **42.81%** |
| | **Test** | `47,160` | 20.00042% | +1.0 URL | 35,171 | 26,970 | 20,190 | **42.81%** |

### Algorithmic Limitations of Greedy Allocation:
Because registered domains are treated as indivisible integer groups, exact floating-point equality (e.g. 165,056.5 URLs) cannot be achieved. The greedy allocation introduces tiny integer deviations of `-3.5` to `+2.0` URLs (at most `0.0015%`). Furthermore, because massive platforms (e.g., `web.app` with 5,754 URLs) are placed first, in smaller datasets this could skew partition sizes; in PhiUSIIL, the vast tail of 175k single-URL domains compensates with high precision.

---

## 9. Recommended Data Cleaning & Split Policy for Step 3

1. **Exact Duplicate Removal:** Drop the 425 exact duplicate rows with `keep="first"`. Zero label conflicts exist.
2. **Protocol Variants:** Retain both HTTP and HTTPS variants as distinct candidates.
3. **Primary Benchmark:** Output domain-disjoint splits to `data/processed/disjoint/` using the verified greedy bin-packing algorithm.
4. **Secondary Benchmark:** Output random stratified splits to `data/processed/random/`.
5. **Label Inversion:** Invert raw labels (`df["label"] = 1 - df["label"]`) in `data_loading.py` so that `0 = legitimate`, `1 = phishing`.
6. **No File Overwrite:** Raw files in `data/raw/` remain completely untouched.
