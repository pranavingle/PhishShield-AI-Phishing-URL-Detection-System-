from __future__ import annotations

import csv
import hashlib
import json
import os
import pathlib
import sys
import zipfile
from datetime import datetime, timezone

import requests

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
RAW_DIR = BASE_DIR / "data" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

# Official UCI Machine Learning Repository endpoint
UCI_DATASET_ID = 967
DATASET_NAME = "PhiUSIIL Phishing URL Dataset"
DATASET_LICENSE = "CC BY 4.0"
OFFICIAL_LANDING_PAGE = "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset"
OFFICIAL_ZIP_URL = "https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip"

ZIP_TARGET_FILE = RAW_DIR / "phiusiil_phishing_url_dataset.zip"
CSV_TARGET_NAME = "PhiUSIIL_Phishing_URL_Dataset.csv"
CSV_TARGET_FILE = RAW_DIR / CSV_TARGET_NAME
MANIFEST_FILE = RAW_DIR / "dataset_manifest.json"


def compute_sha256(file_path: pathlib.Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculates SHA-256 checksum of a file efficiently using chunks."""
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def download_official_zip(url: str, target_path: pathlib.Path, timeout: int = 60) -> None:
    """Downloads archive from official UCI endpoint with error handling and streaming."""
    print(f"[*] Downloading official dataset archive from: {url}")
    headers = {
        "User-Agent": "PhishShield-AI/1.0 (Defensive Security Research; Python/requests)"
    }
    temp_target = target_path.with_suffix(".tmp")
    try:
        with requests.get(url, headers=headers, stream=True, timeout=timeout) as resp:
            resp.raise_for_status()
            total_bytes = int(resp.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 1024 * 64

            with temp_target.open("wb") as f:
                for chunk in resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_bytes > 0:
                            percent = (downloaded / total_bytes) * 100
                            print(
                                f"\r[+] Progress: {downloaded:,} / {total_bytes:,} bytes ({percent:.1f}%)",
                                end="",
                                flush=True,
                            )
                        else:
                            print(f"\r[+] Downloaded: {downloaded:,} bytes", end="", flush=True)

            print()  # newline after progress

        # Atomic rename once download is complete
        temp_target.replace(target_path)
        print(f"[+] Successfully saved archive to: {target_path}")

    except Exception as e:
        if temp_target.exists():
            temp_target.unlink()
        raise RuntimeError(f"Failed to download official dataset archive from {url}: {e}") from e


def extract_csv(zip_path: pathlib.Path, expected_csv_name: str, target_dir: pathlib.Path) -> pathlib.Path:
    """Extracts the exact CSV from the zip archive without altering contents."""
    print(f"[*] Validating and extracting {expected_csv_name} from: {zip_path}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        namelist = zf.namelist()
        if expected_csv_name not in namelist:
            raise FileNotFoundError(
                f"Expected CSV file '{expected_csv_name}' not found in archive. Contained: {namelist}"
            )

        # Test archive integrity
        corrupt = zf.testzip()
        if corrupt is not None:
            raise RuntimeError(f"Zip archive corrupted at entry: {corrupt}")

        # Extract file preserving exact content
        extracted_path = target_dir / expected_csv_name
        zf.extract(expected_csv_name, path=target_dir)

    if not extracted_path.exists():
        raise FileNotFoundError(f"Extraction failed; {extracted_path} does not exist.")

    print(f"[+] Extracted raw CSV to: {extracted_path} ({extracted_path.stat().st_size:,} bytes)")
    return extracted_path


def inspect_and_verify_csv(csv_path: pathlib.Path) -> dict:
    """
    Inspects CSV structure, verifies required columns, counts rows and labels,
    ensuring original raw values are untouched.
    """
    print(f"[*] Verifying CSV structure: {csv_path}")

    row_count = 0
    null_url_count = 0
    label_counts: dict[int, int] = {0: 0, 1: 0}
    other_labels: dict[str, int] = {}

    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError(f"CSV file is empty: {csv_path}")

        # Clean any BOM if present in first column header
        if header and header[0].startswith("\ufeff"):
            header[0] = header[0][1:]

        # Case-insensitive column resolution for verification
        col_map = {col.strip().lower(): (idx, col.strip()) for idx, col in enumerate(header)}

        # Verify URL column
        if "url" not in col_map:
            raise ValueError(f"Required URL column not found in CSV header. Header: {header}")
        url_idx, canonical_url_col = col_map["url"]

        # Verify label column
        if "label" not in col_map:
            raise ValueError(f"Required label column not found in CSV header. Header: {header}")
        label_idx, canonical_label_col = col_map["label"]

        # Stream rows to handle 200k+ rows efficiently without heavy memory footprint
        for row_num, row in enumerate(reader, start=1):
            if not row or len(row) <= max(url_idx, label_idx):
                continue
            row_count += 1

            url_val = row[url_idx].strip()
            if not url_val:
                null_url_count += 1

            raw_label_val = row[label_idx].strip()
            try:
                int_label = int(raw_label_val)
                if int_label in label_counts:
                    label_counts[int_label] += 1
                else:
                    other_labels[raw_label_val] = other_labels.get(raw_label_val, 0) + 1
            except ValueError:
                other_labels[raw_label_val] = other_labels.get(raw_label_val, 0) + 1

    # Sanity checks
    if other_labels:
        raise ValueError(
            f"Unexpected label values found in raw CSV: {other_labels}. Expected only 0 and 1."
        )

    if row_count < 200000:
        raise ValueError(
            f"Row count ({row_count:,}) is unexpectedly low for PhiUSIIL dataset (expected ~235,795)."
        )

    if null_url_count > 0:
        print(f"[!] Warning: {null_url_count} rows have empty URL strings.")

    # Verification report
    print("\n" + "=" * 60)
    print("VERIFICATION REPORT — OFFICIAL PHIUSIIL CSV")
    print("=" * 60)
    print(f"Total Rows:            {row_count:,}")
    print(f"Total Columns:         {len(header)}")
    print(f"URL Column Name:       '{canonical_url_col}' (index {url_idx})")
    print(f"Empty URLs:            {null_url_count}")
    print(f"Label Column Name:     '{canonical_label_col}' (index {label_idx})")
    print("Original Label Distribution (UCI format: 1=legitimate, 0=phishing):")
    print(f"  Class 1 (Legitimate): {label_counts[1]:,} ({label_counts[1] / row_count * 100:.2f}%)")
    print(f"  Class 0 (Phishing):   {label_counts[0]:,} ({label_counts[0] / row_count * 100:.2f}%)")
    print("=" * 60 + "\n")

    return {
        "row_count": row_count,
        "column_count": len(header),
        "columns": header,
        "canonical_url_col": canonical_url_col,
        "canonical_label_col": canonical_label_col,
        "null_url_count": null_url_count,
        "label_counts": {
            "1_legitimate": label_counts[1],
            "0_phishing": label_counts[0],
        },
    }


def write_manifest(
    zip_path: pathlib.Path,
    csv_path: pathlib.Path,
    verification_info: dict,
    manifest_path: pathlib.Path,
) -> None:
    """Generates provenance manifest recording integrity, checksums, and metadata."""
    zip_sha256 = compute_sha256(zip_path)
    csv_sha256 = compute_sha256(csv_path)

    manifest_data = {
        "dataset_name": DATASET_NAME,
        "uci_id": UCI_DATASET_ID,
        "license": DATASET_LICENSE,
        "official_source_url": OFFICIAL_ZIP_URL,
        "official_landing_page": OFFICIAL_LANDING_PAGE,
        "download_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "files": {
            "archive": {
                "filename": zip_path.name,
                "size_bytes": zip_path.stat().st_size,
                "sha256": zip_sha256,
            },
            "extracted_csv": {
                "filename": csv_path.name,
                "size_bytes": csv_path.stat().st_size,
                "sha256": csv_sha256,
            },
        },
        "schema": {
            "row_count": verification_info["row_count"],
            "column_count": verification_info["column_count"],
            "columns": verification_info["columns"],
            "url_column": verification_info["canonical_url_col"],
            "label_column": verification_info["canonical_label_col"],
            "null_url_count": verification_info["null_url_count"],
            "original_label_distribution": verification_info["label_counts"],
            "original_label_semantics": {
                "1": "legitimate",
                "0": "phishing",
            },
        },
    }

    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest_data, f, indent=2)

    print(f"[+] Dataset provenance manifest saved to: {manifest_path}")
    print(f"    ZIP SHA-256: {zip_sha256}")
    print(f"    CSV SHA-256: {csv_sha256}")


def main() -> None:
    print(f"[*] Working Directory: {BASE_DIR}")
    print(f"[*] Target Raw Dir:    {RAW_DIR}")

    # Step 1: Check existing download or perform download
    if ZIP_TARGET_FILE.exists() and ZIP_TARGET_FILE.stat().st_size > 1000000:
        print(f"[+] Found existing dataset archive: {ZIP_TARGET_FILE} ({ZIP_TARGET_FILE.stat().st_size:,} bytes)")
    else:
        download_official_zip(OFFICIAL_ZIP_URL, ZIP_TARGET_FILE)

    # Step 2: Extract CSV from archive
    csv_file = extract_csv(ZIP_TARGET_FILE, CSV_TARGET_NAME, RAW_DIR)

    # Step 3: Inspect, verify rows, columns, and labels
    verification_info = inspect_and_verify_csv(csv_file)

    # Step 4: Write dataset provenance manifest with SHA-256
    write_manifest(ZIP_TARGET_FILE, csv_file, verification_info, MANIFEST_FILE)

    print("[*] Dataset download and verification completed successfully.")


if __name__ == "__main__":
    main()
