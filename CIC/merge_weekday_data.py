# -*- coding: utf-8 -*-
# ============================================================
# CICIDS CSV Dataset Lossless Merge Script
# ------------------------------------------------------------
# This script automatically merges multiple CSV files located
# in the same directory into a single combined CSV file.
#
# Features:
# - Reads all CSV files in the current folder
# - Excludes the final merged output file itself
# - Preserves all original data without modification
# - Appends files sequentially into one dataset
# - Prevents duplicate header rows
# - Displays progress and total row counts
#
# Output:
#   CICIDS_Total_Raw_Combined.csv
import pandas as pd
import os

# 1. Set paths
current_dir = os.path.dirname(os.path.abspath(__file__))
output_file = "CICIDS_Total_Raw_Combined.csv"

# List CSV files in the folder (excluding the merged output file)
all_csv_files = [
    f for f in os.listdir(current_dir)
    if f.lower().endswith('.csv') and f != output_file
]

print(f"--- Starting lossless merge of 8 files (Location: {current_dir}) ---")

total_check = 0

for i, file_name in enumerate(all_csv_files):
    file_path = os.path.join(current_dir, file_name)

    # 2. Read file without modifying anything
    # low_memory=False improves stability for large files
    # dtype=object prevents mixed-type column errors
    df = pd.read_csv(file_path, low_memory=False)

    # Count total rows
    total_check += len(df)
    print(f"▶ [{i+1}/{len(all_csv_files)}] Merging {file_name}... ({len(df):,} rows)")

    # 3. Save data
    # First file creates a new CSV, others are appended
    if i == 0:
        df.to_csv(
            os.path.join(current_dir, output_file),
            index=False,
            encoding='utf-8-sig',
            mode='w'
        )
    else:
        # header=False prevents duplicate header rows
        df.to_csv(
            os.path.join(current_dir, output_file),
            index=False,
            encoding='utf-8-sig',
            mode='a',
            header=False
        )

print("\n" + "=" * 50)
print(f"Merge completed. Output file: {output_file}")
print(f"Expected total row count: {total_check:,} rows")
print("=" * 50)

input("\nTask completed. Press Enter to exit...")
