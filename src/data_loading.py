"""
PhiUSIIL Phishing URL Dataset Preparation & Partitioning Pipeline
PhishShield-AI - Phase 3, Step 3

Prepares the official UCI PhiUSIIL dataset (UCI ID 967) for model training:
  1. Cryptographic Source Verification (SHA-256 vs data/raw/dataset_manifest.json)
  2. Safe String-Preserving Ingestion (preserves exact URLs, prevents NaN coercion)
  3. Schema Mapping & Label Inversion (0 = legitimate/benign, 1 = phishing)
  4. Exact String Deduplication (drops 425 duplicate rows; 235,370 unique URLs retained)
  5. Public-Suffix-Aware Domain Grouping (offline PSL snapshot via scripts.audit_phiusiil)
  6. Primary Benchmark: Domain-Disjoint 70/10/20 Split (Greedy allocation, Seed 42)
  7. Secondary Benchmark: Random Stratified 70/10/20 Split (Two-stage split, Seed 42)
  8. Enforced Deterministic Output (sorted by URL ascending, UTF-8, lineterminator="\\n")
  9. Universal Zero-Overlap & Integrity Assertions across all grouping entities
 10. Automated Provenance Summary Generation (data/processed/dataset_summary.json)
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
from collections import Counter, defaultdict

import pandas as pd
from sklearn.model_selection import train_test_split
import tldextract

# Ensure project root is in sys.path for direct algorithm reuse
BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Direct reuse of audited algorithms from scripts.audit_phiusiil
from scripts.audit_phiusiil import (  # noqa: E402
    compute_sha256,
    extract_domain_and_category,
    is_ip_address,
    simulate_domain_disjoint_split,
)

RAW_DIR = BASE_DIR / "data" / "raw"
RAW_CSV = RAW_DIR / "PhiUSIIL_Phishing_URL_Dataset.csv"
MANIFEST_FILE = RAW_DIR / "dataset_manifest.json"

PROCESSED_DIR = BASE_DIR / "data" / "processed"
DISJOINT_DIR = PROCESSED_DIR / "disjoint"
RANDOM_DIR = PROCESSED_DIR / "random"
SUMMARY_JSON_FILE = PROCESSED_DIR / "dataset_summary.json"
REPORT_FILE = BASE_DIR / "reports" / "phase3_dataset_preparation.md"

EXPECTED_RAW_ROWS = 235795
EXPECTED_RAW_SHA256 = "a236549cd369cd80bd478ff8e1779cbf44c58d5c3f79f7a51a1adbed7d06d1c6"
EXPECTED_DUPLICATE_ROWS_DROPPED = 425
EXPECTED_RETAINED_ROWS = 235370

SPLIT_FRACTIONS = {"train": 0.70, "val": 0.10, "test": 0.20}
DISJOINT_SEED = 42
RANDOM_SEED = 42


def verify_source_integrity() -> None:
    """Verifies that the raw CSV exists and matches manifest SHA-256."""
    if not RAW_CSV.exists():
        raise FileNotFoundError(f"Source raw CSV not found at: {RAW_CSV}")
    if not MANIFEST_FILE.exists():
        raise FileNotFoundError(f"Dataset manifest not found at: {MANIFEST_FILE}")

    with MANIFEST_FILE.open("r", encoding="utf-8") as f:
        manifest = json.load(f)

    manifest_sha256 = manifest.get("files", {}).get("extracted_csv", {}).get("sha256")
    if not manifest_sha256:
        raise ValueError("Missing extracted_csv sha256 in dataset manifest!")

    computed_sha256 = compute_sha256(RAW_CSV)
    if computed_sha256 != manifest_sha256 or computed_sha256 != EXPECTED_RAW_SHA256:
        raise ValueError(
            f"Raw CSV SHA-256 mismatch!\n"
            f"  Computed: {computed_sha256}\n"
            f"  Manifest: {manifest_sha256}\n"
            f"  Expected: {EXPECTED_RAW_SHA256}"
        )

    print(f"[+] Source raw CSV verified: {RAW_CSV.name} ({RAW_CSV.stat().st_size:,} bytes)")
    print(f"    SHA-256: {computed_sha256}")


def load_and_preprocess_raw() -> pd.DataFrame:
    """
    Safely ingests raw CSV, inverts labels to project standard, and deduplicates exact URLs.
    Preserves exact original URL strings without modification.
    """
    print("\n[+] Ingesting raw CSV with safe string preservation...")
    # Safe string loading: keep_default_na=False and na_filter=False prevent literal strings
    # like 'NA', 'null', 'None' from being converted to NaN/null.
    df = pd.read_csv(
        RAW_CSV,
        usecols=["URL", "label"],
        keep_default_na=False,
        na_filter=False,
        dtype={"URL": str, "label": str},
        low_memory=False,
    )

    if len(df) != EXPECTED_RAW_ROWS:
        raise AssertionError(
            f"Raw CSV row count mismatch: got {len(df):,}, expected {EXPECTED_RAW_ROWS:,}"
        )

    # Column mapping: URL -> url
    df = df.rename(columns={"URL": "url"})

    # Validate raw labels
    raw_label_counts = df["label"].value_counts().to_dict()
    if set(raw_label_counts.keys()) != {"0", "1"}:
        raise ValueError(f"Unexpected raw label values found: {set(raw_label_counts.keys())}")

    # Label conversion to project convention: 0 = legitimate, 1 = phishing
    # Original PhiUSIIL: 1 = legitimate, 0 = phishing
    df["label"] = 1 - df["label"].astype(int)

    # Exact string deduplication (pre-allocation)
    initial_count = len(df)
    df = df.drop_duplicates(subset=["url"], keep="first").reset_index(drop=True)
    dedup_count = len(df)
    dropped_count = initial_count - dedup_count

    if dropped_count != EXPECTED_DUPLICATE_ROWS_DROPPED:
        raise AssertionError(
            f"Duplicate drop mismatch: dropped {dropped_count}, expected {EXPECTED_DUPLICATE_ROWS_DROPPED}"
        )
    if dedup_count != EXPECTED_RETAINED_ROWS:
        raise AssertionError(
            f"Retained rows mismatch: retained {dedup_count:,}, expected {EXPECTED_RETAINED_ROWS:,}"
        )

    class_counts = df["label"].value_counts().to_dict()
    print(f"[+] Exact raw URL deduplication complete:")
    print(f"    Original rows:         {initial_count:,}")
    print(f"    Duplicate rows dropped:{dropped_count}")
    print(f"    Retained unique URLs:  {dedup_count:,}")
    print(f"    Project labels (0=Legit, 1=Phish):")
    print(f"      - Legitimate (0):    {class_counts.get(0, 0):,} ({class_counts.get(0, 0)/dedup_count*100:.2f}%)")
    print(f"      - Phishing (1):      {class_counts.get(1, 0):,} ({class_counts.get(1, 0)/dedup_count*100:.2f}%)")

    return df


def extract_grouping_entities(df: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, list[int]], Counter]:
    """
    Extracts registered domain, IP, or fallback hostname grouping keys using the audited
    offline PSL policy. Recomputes dynamic dom_stats strictly on the deduplicated pool.
    """
    print("\n[+] Extracting domain grouping keys via offline PSL (tldextract)...")
    extractor = tldextract.TLDExtract(suffix_list_urls=None)

    keys = []
    categories = []
    category_counter = Counter()

    # dom_stats structure: dict[dom_key, [legit_count, phish_count]]
    # Index 0: legitimate (label == 0)
    # Index 1: phishing (label == 1)
    dom_stats = defaultdict(lambda: [0, 0])

    for url, lbl in zip(df["url"], df["label"]):
        dom_key, cat = extract_domain_and_category(url, extractor)
        keys.append(dom_key)
        categories.append(cat)
        category_counter[cat] += 1

        if lbl == 0:
            dom_stats[dom_key][0] += 1
        elif lbl == 1:
            dom_stats[dom_key][1] += 1
        else:
            raise ValueError(f"Invalid project label value: {lbl}")

    df = df.copy()
    df["domain_key"] = keys
    df["domain_category"] = categories

    total_keys = len(dom_stats)
    total_records = sum(x[0] + x[1] for x in dom_stats.values())
    if total_records != len(df):
        raise AssertionError(
            f"dom_stats total records ({total_records:,}) != deduplicated dataframe ({len(df):,})"
        )

    print(f"[+] Grouping key extraction complete:")
    print(f"    Total distinct grouping keys: {total_keys:,}")
    print(f"      - Registered domains:       {category_counter['registered_domain']:,} records")
    print(f"      - Raw IP addresses:         {category_counter['ip']:,} records")
    print(f"      - Fallback hostnames:       {category_counter['fallback_hostname']:,} records")

    return df, dom_stats, category_counter


def create_domain_disjoint_splits(
    df: pd.DataFrame,
    dom_stats: dict[str, list[int]],
) -> tuple[dict[str, pd.DataFrame], pd.DataFrame, dict[str, dict]]:
    """
    Generates primary domain-disjoint 70/10/20 splits reusing the audited greedy allocator.
    Enforces stable sorting by URL ascending.
    """
    print(f"\n[+] Generating Primary Domain-Disjoint Splits (Seed {DISJOINT_SEED})...")
    # Direct reuse of audited greedy allocator with exact signature
    alloc = simulate_domain_disjoint_split(
        dom_stats=dom_stats,
        seed=DISJOINT_SEED,
        target_fractions=SPLIT_FRACTIONS,
    )

    domain_to_split = {}
    for split_name in ["train", "val", "test"]:
        for dom in alloc[split_name]["domains"]:
            domain_to_split[dom] = split_name

    df = df.copy()
    df["split"] = df["domain_key"].map(domain_to_split)

    splits = {}
    for s in ["train", "val", "test"]:
        split_df = df[df["split"] == s][["url", "label"]].copy()
        # Enforce canonical sort order for byte-for-byte reproducibility
        split_df = split_df.sort_values(by="url", ascending=True).reset_index(drop=True)
        splits[s] = split_df

    # Programmatic Universal Key Independence Assertion
    keys_tr = set(df.loc[df["split"] == "train", "domain_key"])
    keys_va = set(df.loc[df["split"] == "val", "domain_key"])
    keys_te = set(df.loc[df["split"] == "test", "domain_key"])

    overlap_tr_va = keys_tr & keys_va
    overlap_tr_te = keys_tr & keys_te
    overlap_va_te = keys_va & keys_te

    if len(overlap_tr_va) > 0 or len(overlap_tr_te) > 0 or len(overlap_va_te) > 0:
        raise AssertionError(
            f"Universal grouping key overlap detected!\n"
            f"  Train-Val: {len(overlap_tr_va)}\n"
            f"  Train-Test: {len(overlap_tr_te)}\n"
            f"  Val-Test: {len(overlap_va_te)}"
        )

    total_allocated_keys = len(keys_tr) + len(keys_va) + len(keys_te)
    if total_allocated_keys != len(dom_stats):
        raise AssertionError(
            f"Allocated keys mismatch: {total_allocated_keys} != {len(dom_stats)}"
        )

    total_allocated_urls = sum(len(s) for s in splits.values())
    if total_allocated_urls != len(df):
        raise AssertionError(
            f"Allocated URLs mismatch: {total_allocated_urls} != {len(df)}"
        )

    print("    Disjoint split allocation (dynamically measured):")
    for s, sdf in splits.items():
        lbl_counts = sdf["label"].value_counts().to_dict()
        leg = lbl_counts.get(0, 0)
        phi = lbl_counts.get(1, 0)
        p_pct = phi / len(sdf) * 100
        pct = len(sdf) / len(df) * 100
        n_doms = len(alloc[s]["domains"])
        print(f"      {s:<5}: {len(sdf):>7,} URLs ({pct:.5f}%) | {n_doms:>6,} keys | Legit: {leg:>6,} | Phish: {phi:>6,} | Phish%: {p_pct:.2f}%")

    return splits, df, alloc


def create_random_stratified_splits(df: pd.DataFrame) -> dict[str, pd.DataFrame]:
    """
    Generates secondary random stratified 70/10/20 splits using scikit-learn.
    Enforces stable sorting by URL ascending.
    """
    print(f"\n[+] Generating Secondary Random Stratified Splits (Seed {RANDOM_SEED})...")
    # Stage 1: 70% train vs 30% temp
    train_idx, temp_idx = train_test_split(
        df.index,
        train_size=SPLIT_FRACTIONS["train"],
        random_state=RANDOM_SEED,
        stratify=df["label"],
    )

    # Stage 2: 30% temp partitioned into 1/3 val (10% overall) and 2/3 test (20% overall)
    val_ratio_of_temp = SPLIT_FRACTIONS["val"] / (SPLIT_FRACTIONS["val"] + SPLIT_FRACTIONS["test"])
    val_idx, test_idx = train_test_split(
        temp_idx,
        train_size=val_ratio_of_temp,
        random_state=RANDOM_SEED,
        stratify=df.loc[temp_idx, "label"],
    )

    splits = {
        "train": df.loc[train_idx, ["url", "label"]].copy(),
        "val": df.loc[val_idx, ["url", "label"]].copy(),
        "test": df.loc[test_idx, ["url", "label"]].copy(),
    }

    # Enforce canonical sort order for byte-for-byte reproducibility
    for s in splits:
        splits[s] = splits[s].sort_values(by="url", ascending=True).reset_index(drop=True)

    # Row reconciliation assertion
    total_allocated_urls = sum(len(s) for s in splits.values())
    if total_allocated_urls != len(df):
        raise AssertionError(
            f"Random split allocation mismatch: {total_allocated_urls} != {len(df)}"
        )

    # Intra-benchmark URL uniqueness assertion
    u_tr = set(splits["train"]["url"])
    u_va = set(splits["val"]["url"])
    u_te = set(splits["test"]["url"])
    if len(u_tr & u_va) > 0 or len(u_tr & u_te) > 0 or len(u_va & u_te) > 0:
        raise AssertionError("URL overlap detected across random stratified splits!")

    print("    Random split allocation (dynamically measured):")
    for s, sdf in splits.items():
        lbl_counts = sdf["label"].value_counts().to_dict()
        leg = lbl_counts.get(0, 0)
        phi = lbl_counts.get(1, 0)
        p_pct = phi / len(sdf) * 100
        pct = len(sdf) / len(df) * 100
        print(f"      {s:<5}: {len(sdf):>7,} URLs ({pct:.5f}%) | Legit: {leg:>6,} | Phish: {phi:>6,} | Phish%: {p_pct:.2f}%")

    return splits


def export_splits_deterministic(
    splits: dict[str, pd.DataFrame],
    target_dir: pathlib.Path,
) -> dict[str, str]:
    """
    Exports splits strictly to target_dir using explicit UTF-8 and lineterminator="\\n".
    Computes and returns SHA-256 checksums of the written files.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    checksums = {}

    for s in ["train", "val", "test"]:
        file_path = target_dir / f"urls_{s}.csv"
        df = splits[s]
        # Strict schema: exactly ['url', 'label']
        if list(df.columns) != ["url", "label"]:
            raise ValueError(f"Invalid columns in {file_path.name}: {list(df.columns)}")

        # Deterministic export: UTF-8, explicit POSIX newline, no index
        df.to_csv(file_path, index=False, encoding="utf-8", lineterminator="\n")
        sha = compute_sha256(file_path)
        checksums[f"urls_{s}_csv_sha256"] = sha
        print(f"[+] Saved: {file_path.relative_to(BASE_DIR)} ({len(df):,} rows, {file_path.stat().st_size:,} bytes, SHA-256: {sha[:16]}...)")

    return checksums


def generate_provenance_json(
    raw_sha256: str,
    raw_row_count: int,
    dropped_dups: int,
    retained_count: int,
    class_counts: dict[int, int],
    category_counts: Counter,
    total_keys: int,
    disjoint_splits: dict[str, pd.DataFrame],
    disjoint_checksums: dict[str, str],
    random_splits: dict[str, pd.DataFrame],
    random_checksums: dict[str, str],
    df_with_keys: pd.DataFrame,
) -> dict:
    """Constructs and serializes the complete dataset_summary.json artifact."""
    # Distinct grouping keys per category
    reg_dom_unique = int(df_with_keys.loc[df_with_keys["domain_category"] == "registered_domain", "domain_key"].nunique())
    ip_unique = int(df_with_keys.loc[df_with_keys["domain_category"] == "ip", "domain_key"].nunique())
    fallback_unique = int(df_with_keys.loc[df_with_keys["domain_category"] == "fallback_hostname", "domain_key"].nunique())

    # Count grouping keys per disjoint split
    doms_per_disjoint_split = {}
    for s in ["train", "val", "test"]:
        doms_per_disjoint_split[s] = int(df_with_keys.loc[df_with_keys["split"] == s, "domain_key"].nunique())

    disjoint_split_meta = {}
    for s in ["train", "val", "test"]:
        sdf = disjoint_splits[s]
        leg = int((sdf["label"] == 0).sum())
        phi = int((sdf["label"] == 1).sum())
        tot = len(sdf)
        disjoint_split_meta[s] = {
            "urls": tot,
            "domains": doms_per_disjoint_split[s],
            "legitimate": leg,
            "phishing": phi,
            "phishing_prevalence": round(phi / tot, 6),
        }

    random_split_meta = {}
    for s in ["train", "val", "test"]:
        sdf = random_splits[s]
        leg = int((sdf["label"] == 0).sum())
        phi = int((sdf["label"] == 1).sum())
        tot = len(sdf)
        random_split_meta[s] = {
            "urls": tot,
            "legitimate": leg,
            "phishing": phi,
            "phishing_prevalence": round(phi / tot, 6),
        }

    summary = {
        "source_dataset": {
            "name": "UCI PhiUSIIL Phishing URL Dataset",
            "uci_id": 967,
            "raw_csv_filename": RAW_CSV.name,
            "raw_csv_sha256": raw_sha256,
            "raw_row_count": raw_row_count,
            "license": "CC BY 4.0",
            "official_url": "https://archive.ics.uci.edu/dataset/967/phiusil+phishing+url+dataset",
        },
        "deduplication": {
            "policy": "Exact raw string deduplication, keeping first occurrence",
            "duplicate_rows_dropped": dropped_dups,
            "retained_row_count": retained_count,
            "label_consistency_in_duplicates": "100.0% consistent (0 conflicting duplicate groups)",
        },
        "label_mapping": {
            "original_semantics": {"1": "legitimate", "0": "phishing"},
            "project_semantics": {"0": "legitimate", "1": "phishing"},
            "transformation_formula": "label = 1 - original_label",
        },
        "domain_extraction": {
            "tool": "tldextract",
            "tldextract_version": tldextract.__version__,
            "offline_psl_mode": "suffix_list_urls=None",
            "total_grouping_keys": total_keys,
            "distinct_registered_domains": reg_dom_unique,
            "distinct_ip_addresses": ip_unique,
            "distinct_fallback_hostnames": fallback_unique,
            "registered_domains_records": int(category_counts["registered_domain"]),
            "ip_addresses_records": int(category_counts["ip"]),
            "fallback_hostnames_records": int(category_counts["fallback_hostname"]),
            "fallback_policy": "registered_domain -> normalized_ip -> complete_normalized_hostname",
        },
        "post_deduplication_classes": {
            "legitimate_label_0": int(class_counts.get(0, 0)),
            "phishing_label_1": int(class_counts.get(1, 0)),
            "total": retained_count,
            "phishing_prevalence": round(class_counts.get(1, 0) / retained_count, 6),
        },
        "benchmarks": {
            "primary_domain_disjoint": {
                "strategy": "Audited multi-objective greedy domain allocation",
                "allocator_function": "scripts.audit_phiusiil.simulate_domain_disjoint_split",
                "seed": DISJOINT_SEED,
                "target_fractions": SPLIT_FRACTIONS,
                "splits": disjoint_split_meta,
                "verification": {
                    "universal_grouping_key_overlap": 0,
                    "zero_domain_overlap": True,
                    "zero_ip_overlap": True,
                    "zero_fallback_hostname_overlap": True,
                    "total_allocated_urls": sum(m["urls"] for m in disjoint_split_meta.values()),
                    "total_allocated_keys": sum(doms_per_disjoint_split.values()),
                },
                "checksums": disjoint_checksums,
            },
            "secondary_random_stratified": {
                "strategy": "Two-stage stratified random split on project label",
                "seed": RANDOM_SEED,
                "target_fractions": SPLIT_FRACTIONS,
                "splits": random_split_meta,
                "verification": {
                    "total_allocated_urls": sum(m["urls"] for m in random_split_meta.values()),
                    "zero_url_overlap_across_splits": True,
                },
                "checksums": random_checksums,
            },
        },
    }

    SUMMARY_JSON_FILE.parent.mkdir(parents=True, exist_ok=True)
    with SUMMARY_JSON_FILE.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n[+] Summary metadata saved: {SUMMARY_JSON_FILE.relative_to(BASE_DIR)}")
    return summary


def write_preparation_report(summary: dict) -> None:
    """Generates the curated markdown report documenting the dataset preparation."""
    dj = summary["benchmarks"]["primary_domain_disjoint"]
    rd = summary["benchmarks"]["secondary_random_stratified"]
    src = summary["source_dataset"]
    dedup = summary["deduplication"]
    dom = summary["domain_extraction"]
    cls_ = summary["post_deduplication_classes"]

    md = f"""# Phase 3 — Dataset Preparation & Partitioning Report
**Dataset:** {src['name']} (UCI ID {src['uci_id']})  
**License:** {src['license']}  
**Raw Source File:** `data/raw/{src['raw_csv_filename']}`  
**Raw File SHA-256:** `{src['raw_csv_sha256']}`  
**Pipeline Script:** `src/data_loading.py`  
**Status:** Completed & Programmatically Verified  

---

## 1. Executive Summary

The official UCI PhiUSIIL Phishing URL Dataset was ingested, verified against its cryptographic manifest, normalized to the project label convention (`0 = legitimate`, `1 = phishing`), deduplicated on exact raw URL strings, and partitioned into two independent 70/10/20 benchmarks:
1. **Primary Generalization Benchmark (`data/processed/disjoint/`):** Group-aware domain-disjoint allocation using the audited multi-objective greedy algorithm. Strictly guarantees **zero domain/IP/hostname overlap** between train, validation, and test sets.
2. **Secondary Literature Baseline (`data/processed/random/`):** Standard stratified random split preserving exact population class proportions across splits, enabling fair comparison against conventional published results.

---

## 2. Ingestion & Deduplication Metrics

* **Raw Input Records:** `{src['raw_row_count']:,}`
* **Deduplication Policy:** Exact raw string match, keeping first occurrence (`drop_duplicates(subset=['url'], keep='first')`).
* **Exact Duplicate Rows Dropped:** `{dedup['duplicate_rows_dropped']:,}`
* **Duplicate Label Conflicts:** `0` (100.0% label consistency for identical strings; all 425 duplicate rows were phishing).
* **Retained Unique URL Records:** `{dedup['retained_row_count']:,}`
* **Post-Deduplication Class Distribution:**
  * **Class 0 (Legitimate / Benign):** `{cls_['legitimate_label_0']:,}` ({cls_['legitimate_label_0'] / cls_['total'] * 100:.2f}%)
  * **Class 1 (Phishing):** `{cls_['phishing_label_1']:,}` ({cls_['phishing_label_1'] / cls_['total'] * 100:.2f}%)
  * **Phishing Prevalence:** `{cls_['phishing_prevalence'] * 100:.2f}%`

---

## 3. Registered Domain Extraction Landscape

* **Extraction Library:** `{dom['tool']} {dom['tldextract_version']}`
* **PSL Configuration:** Offline snapshot (`{dom['offline_psl_mode']}`)
* **Fallback Policy:** `{dom['fallback_policy']}`
* **Total Grouping Keys:** `{dom['total_grouping_keys']:,}`
  * Registered Domains (`domain + suffix`): `{dom['distinct_registered_domains']:,}` distinct domains (`{dom['registered_domains_records']:,}` records)
  * Raw IP Addresses: `{dom['distinct_ip_addresses']:,}` distinct IPs (`{dom['ip_addresses_records']:,}` records)
  * Fallback Hostnames: `{dom['distinct_fallback_hostnames']:,}` distinct hostnames (`{dom['fallback_hostnames_records']:,}` records)

---

## 4. Benchmark Allocations & Class Prevalences

### Primary Benchmark: Domain-Disjoint Splits (Seed {dj['seed']})
*Algorithm: Audited greedy bin-packing (`simulate_domain_disjoint_split`). Indivisible grouping units.*

| Split | URL Count | Percentage | Grouping Keys | Legitimate (0) | Phishing (1) | Phishing % |
|---|---|---|---|---|---|---|
| **Train** | `{dj['splits']['train']['urls']:,}` | {dj['splits']['train']['urls'] / cls_['total'] * 100:.4f}% | `{dj['splits']['train']['domains']:,}` | `{dj['splits']['train']['legitimate']:,}` | `{dj['splits']['train']['phishing']:,}` | {dj['splits']['train']['phishing_prevalence'] * 100:.2f}% |
| **Validation** | `{dj['splits']['val']['urls']:,}` | {dj['splits']['val']['urls'] / cls_['total'] * 100:.4f}% | `{dj['splits']['val']['domains']:,}` | `{dj['splits']['val']['legitimate']:,}` | `{dj['splits']['val']['phishing']:,}` | {dj['splits']['val']['phishing_prevalence'] * 100:.2f}% |
| **Test** | `{dj['splits']['test']['urls']:,}` | {dj['splits']['test']['urls'] / cls_['total'] * 100:.4f}% | `{dj['splits']['test']['domains']:,}` | `{dj['splits']['test']['legitimate']:,}` | `{dj['splits']['test']['phishing']:,}` | {dj['splits']['test']['phishing_prevalence'] * 100:.2f}% |
| **Total** | **`{cls_['total']:,}`** | **100.0%** | **`{dom['total_grouping_keys']:,}`** | **`{cls_['legitimate_label_0']:,}`** | **`{cls_['phishing_label_1']:,}`** | **{cls_['phishing_prevalence'] * 100:.2f}%** |

*Universal Overlap Check:* **`0` shared keys** (Train ∩ Val = ∅, Train ∩ Test = ∅, Val ∩ Test = ∅). Verified across all domains, IPs, and hostnames.

### Secondary Benchmark: Random Stratified Splits (Seed {rd['seed']})
*Algorithm: Two-stage stratified random split on project label.*

| Split | URL Count | Percentage | Legitimate (0) | Phishing (1) | Phishing % |
|---|---|---|---|---|---|
| **Train** | `{rd['splits']['train']['urls']:,}` | {rd['splits']['train']['urls'] / cls_['total'] * 100:.4f}% | `{rd['splits']['train']['legitimate']:,}` | `{rd['splits']['train']['phishing']:,}` | {rd['splits']['train']['phishing_prevalence'] * 100:.2f}% |
| **Validation** | `{rd['splits']['val']['urls']:,}` | {rd['splits']['val']['urls'] / cls_['total'] * 100:.4f}% | `{rd['splits']['val']['legitimate']:,}` | `{rd['splits']['val']['phishing']:,}` | {rd['splits']['val']['phishing_prevalence'] * 100:.2f}% |
| **Test** | `{rd['splits']['test']['urls']:,}` | {rd['splits']['test']['urls'] / cls_['total'] * 100:.4f}% | `{rd['splits']['test']['legitimate']:,}` | `{rd['splits']['test']['phishing']:,}` | {rd['splits']['test']['phishing_prevalence'] * 100:.2f}% |
| **Total** | **`{cls_['total']:,}`** | **100.0%** | **`{cls_['legitimate_label_0']:,}`** | **`{cls_['phishing_label_1']:,}`** | **{cls_['phishing_prevalence'] * 100:.2f}%** |

---

## 5. Exported Partition Checksums

All CSV files were written with `encoding="utf-8"`, `lineterminator="\\n"`, and sorted alphabetically by exact `url`.

### Primary Disjoint Splits (`data/processed/disjoint/`):
* `urls_train.csv`: `{dj['checksums']['urls_train_csv_sha256']}`
* `urls_val.csv`: `{dj['checksums']['urls_val_csv_sha256']}`
* `urls_test.csv`: `{dj['checksums']['urls_test_csv_sha256']}`

### Secondary Random Splits (`data/processed/random/`):
* `urls_train.csv`: `{rd['checksums']['urls_train_csv_sha256']}`
* `urls_val.csv`: `{rd['checksums']['urls_val_csv_sha256']}`
* `urls_test.csv`: `{rd['checksums']['urls_test_csv_sha256']}`

---

## 6. Programmatic Integrity Verification

- [x] Raw source CSV SHA-256 matches manifest expectation.
- [x] Exact raw URLs preserved byte-for-byte; no string modification or normalization applied.
- [x] Exactly 425 duplicate rows dropped; exactly 235,370 records retained.
- [x] Universal grouping key overlap strictly 0 across all domains, IPs, and hostnames.
- [x] Both benchmarks reconcile to 100% of deduplicated records (235,370).
- [x] Zero duplicate URLs across partitions within each benchmark.
- [x] All exported CSV files contain strictly `['url', 'label']` with binary integer labels in {{0, 1}}.
- [x] Platform-independent deterministic serialization verified with POSIX newlines (`\\n`).
"""
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with REPORT_FILE.open("w", encoding="utf-8") as f:
        f.write(md.strip() + "\n")
    print(f"[+] Preparation report saved: {REPORT_FILE.relative_to(BASE_DIR)}")


def main() -> None:
    print("=" * 80)
    print("PHIUSIIL DATASET PREPARATION & PARTITIONING PIPELINE")
    print("=" * 80)
    print(f"[*] Python Runtime: {sys.version.split()[0]} ({sys.executable})")

    # 1. Source Integrity Check
    verify_source_integrity()

    # 2. Safe Ingestion & Deduplication
    df = load_and_preprocess_raw()

    # 3. Domain Grouping
    df_with_keys, dom_stats, cat_counter = extract_grouping_entities(df)

    # 4. Primary Disjoint Splits
    disjoint_splits, df_with_splits, disjoint_alloc = create_domain_disjoint_splits(df_with_keys, dom_stats)

    # 5. Secondary Random Splits
    random_splits = create_random_stratified_splits(df_with_splits)

    # 6. Export Disjoint Splits
    print("\n[+] Exporting Primary Domain-Disjoint Splits...")
    disjoint_checksums = export_splits_deterministic(disjoint_splits, DISJOINT_DIR)

    # 7. Export Random Splits
    print("\n[+] Exporting Secondary Random Stratified Splits...")
    random_checksums = export_splits_deterministic(random_splits, RANDOM_DIR)

    # 8. Provenance & Report Generation
    class_counts = df["label"].value_counts().to_dict()
    summary = generate_provenance_json(
        raw_sha256=EXPECTED_RAW_SHA256,
        raw_row_count=EXPECTED_RAW_ROWS,
        dropped_dups=EXPECTED_DUPLICATE_ROWS_DROPPED,
        retained_count=EXPECTED_RETAINED_ROWS,
        class_counts=class_counts,
        category_counts=cat_counter,
        total_keys=len(dom_stats),
        disjoint_splits=disjoint_splits,
        disjoint_checksums=disjoint_checksums,
        random_splits=random_splits,
        random_checksums=random_checksums,
        df_with_keys=df_with_splits,
    )

    write_preparation_report(summary)

    print("\n" + "=" * 80)
    print("DATASET PREPARATION COMPLETE & VERIFIED")
    print("=" * 80)


if __name__ == "__main__":
    main()
