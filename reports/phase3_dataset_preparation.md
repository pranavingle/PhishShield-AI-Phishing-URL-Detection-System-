# Phase 3 — Dataset Preparation & Partitioning Report
**Dataset:** UCI PhiUSIIL Phishing URL Dataset (UCI ID 967)  
**License:** CC BY 4.0  
**Raw Source File:** `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`  
**Raw File SHA-256:** `a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6`  
**Pipeline Script:** `src/data_loading.py`  
**Status:** Completed & Programmatically Verified  

---

## 1. Executive Summary

The official UCI PhiUSIIL Phishing URL Dataset was ingested, verified against its cryptographic manifest, normalized to the project label convention (`0 = legitimate`, `1 = phishing`), deduplicated on exact raw URL strings, and partitioned into two independent 70/10/20 benchmarks:
1. **Primary Generalization Benchmark (`data/processed/disjoint/`):** Group-aware domain-disjoint allocation using the audited multi-objective greedy algorithm. Strictly guarantees **zero domain/IP/hostname overlap** between train, validation, and test sets.
2. **Secondary Literature Baseline (`data/processed/random/`):** Standard stratified random split preserving exact population class proportions across splits, enabling fair comparison against conventional published results.

---

## 2. Ingestion & Deduplication Metrics

* **Raw Input Records:** `235,795`
* **Deduplication Policy:** Exact raw string match, keeping first occurrence (`drop_duplicates(subset=['url'], keep='first')`).
* **Exact Duplicate Rows Dropped:** `425`
* **Duplicate Label Conflicts:** `0` (100.0% label consistency for identical strings; all 425 duplicate rows were phishing).
* **Retained Unique URL Records:** `235,370`
* **Post-Deduplication Class Distribution:**
  * **Class 0 (Legitimate / Benign):** `134,850` (57.29%)
  * **Class 1 (Phishing):** `100,520` (42.71%)
  * **Phishing Prevalence:** `42.71%`

---

## 3. Registered Domain Extraction Landscape

* **Extraction Library:** `tldextract 5.3.0`
* **PSL Configuration:** Offline snapshot (`suffix_list_urls=None`)
* **Fallback Policy:** `registered_domain -> normalized_ip -> complete_normalized_hostname`
* **Total Grouping Keys:** `175,509`
  * Registered Domains (`domain + suffix`): `175,352` distinct domains (`234,764` records)
  * Raw IP Addresses: `157` distinct IPs (`606` records)
  * Fallback Hostnames: `0` distinct hostnames (`0` records)

---

## 4. Benchmark Allocations & Class Prevalences

### Primary Benchmark: Domain-Disjoint Splits (Seed 42)
*Algorithm: Audited greedy bin-packing (`simulate_domain_disjoint_split`). Indivisible grouping units.*

| Split | URL Count | Percentage | Grouping Keys | Legitimate (0) | Phishing (1) | Phishing % |
|---|---|---|---|---|---|---|
| **Train** | `164,759` | 70.0000% | `123,822` | `94,395` | `70,364` | 42.71% |
| **Validation** | `23,536` | 9.9996% | `16,439` | `13,485` | `10,051` | 42.70% |
| **Test** | `47,075` | 20.0004% | `35,248` | `26,970` | `20,105` | 42.71% |
| **Total** | **`235,370`** | **100.0%** | **`175,509`** | **`134,850`** | **`100,520`** | **42.71%** |

*Universal Overlap Check:* **`0` shared keys** (Train ∩ Val = ∅, Train ∩ Test = ∅, Val ∩ Test = ∅). Verified across all domains, IPs, and hostnames.

### Secondary Benchmark: Random Stratified Splits (Seed 42)
*Algorithm: Two-stage stratified random split on project label.*

| Split | URL Count | Percentage | Legitimate (0) | Phishing (1) | Phishing % |
|---|---|---|---|---|---|
| **Train** | `164,759` | 70.0000% | `94,395` | `70,364` | 42.71% |
| **Validation** | `23,537` | 10.0000% | `13,485` | `10,052` | 42.71% |
| **Test** | `47,074` | 20.0000% | `26,970` | `20,104` | 42.71% |
| **Total** | **`235,370`** | **100.0%** | **`134,850`** | **`100,520`** | **42.71%** |

---

## 5. Exported Partition Checksums

All CSV files were written with `encoding="utf-8"`, `lineterminator="\n"`, and sorted alphabetically by exact `url`.

### Primary Disjoint Splits (`data/processed/disjoint/`):
* `urls_train.csv`: `e62d341b01c0cd69f863eae08d5d3da6066da0e4582474e93bddd894d7304621`
* `urls_val.csv`: `1018e661dfbb24de27d94824bb6dc556915a31ef09b9658bdbf113b5fc1d423f`
* `urls_test.csv`: `db87cecc78b9eeca25f269f6475494911ea1f0a352104e96809d26fe3bb1ed69`

### Secondary Random Splits (`data/processed/random/`):
* `urls_train.csv`: `5c3b5685512e1879e11ee2fb56c199f88b153751ea977df58e728b8aa268b6a3`
* `urls_val.csv`: `bfa54e6ae835f0415ad84878aef0bf03b334f79bad662e260af6ccb47df4eac1`
* `urls_test.csv`: `43eb58723b234996af2d677122998262dcfc3776ab3a3199912c36533d32d947`

---

## 6. Programmatic Integrity Verification

- [x] Raw source CSV SHA-256 matches manifest expectation.
- [x] Exact raw URLs preserved byte-for-byte; no string modification or normalization applied.
- [x] Exactly 425 duplicate rows dropped; exactly 235,370 records retained.
- [x] Universal grouping key overlap strictly 0 across all domains, IPs, and hostnames.
- [x] Both benchmarks reconcile to 100% of deduplicated records (235,370).
- [x] Zero duplicate URLs across partitions within each benchmark.
- [x] All exported CSV files contain strictly `['url', 'label']` with binary integer labels in {0, 1}.
- [x] Platform-independent deterministic serialization verified with POSIX newlines (`\n`).
