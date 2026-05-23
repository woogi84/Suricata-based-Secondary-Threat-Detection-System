# -*- coding: utf-8 -*-

# ============================================================
# Large TSV-to-CSV Dataset Conversion Script
# ------------------------------------------------------------
# This script converts a large tab-separated dataset (TSV)
# into a standard CSV format while preserving all original data.
#
# Features:
# - Reads very large files in chunks to reduce memory usage
# - Converts TAB-separated data into CSV format
# - Prevents memory overflow during processing
# - Preserves all data as string type
# - Displays processing progress in real time
# - Generates a UTF-8-SIG encoded CSV for Excel compatibility
#
# Input:
#   training_set.csv (TAB-separated file)
#
# Output:
#   training_set_converted.csv
#
# Recommended Use:
# - Large-scale dataset preprocessing
# - Network intrusion detection datasets
# - AI / Machine Learning data preparation
#
# Notes:
# - chunksize=100,000 reduces RAM usage
# - dtype=str preserves original values exactly
# - on_bad_lines='warn' skips malformed rows with warnings
# ============================================================

import pandas as pd
import os

INPUT_PATH  = "training_set.csv"
OUTPUT_PATH = "training_set_converted.csv"

print(f"Starting conversion: {INPUT_PATH}")

total_rows = 0
first_chunk = True

# Read the file in chunks to avoid memory overflow
for chunk in pd.read_csv(
    INPUT_PATH,
    sep='\t',
    chunksize=100_000,
    dtype=str,
    on_bad_lines='warn'
):
    
    # Save chunk to CSV
    chunk.to_csv(
        OUTPUT_PATH,
        mode='w' if first_chunk else 'a',
        header=first_chunk,
        index=False,
        encoding='utf-8-sig'
    )

    total_rows += len(chunk)
    first_chunk = False

    # Print progress every 1 million rows
    if total_rows % 1_000_000 == 0:
        print(f"  {total_rows:,} rows processed")

print(f"\nCompleted! Total rows: {total_rows:,}")
print(f"Output file size: {os.path.getsize(OUTPUT_PATH) / 1024 / 1024:.1f} MB")

# Preview first 3 rows of the converted CSV
df = pd.read_csv(OUTPUT_PATH, nrows=3, encoding='utf-8-sig')

print("\n=== Preview ===")
print(df.to_string())
