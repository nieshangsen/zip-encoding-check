#!/usr/bin/env python3
"""
ZIP File Encoding Analyzer
Analyzes ZIP files and displays filenames decoded with multiple encodings.
Helps identify the correct encoding for Chinese characters in ZIP filenames.
"""

import sys
import argparse
import zipfile
from pathlib import Path
import chardet


# List of encodings to try
ENCODINGS_TO_TRY = [
    'utf-8',
    'gbk',
    'gb18030',
    'gb2312',
    'cp936',      # Windows Simplified Chinese
    'cp437',      # DOS/OEM US
    'shift_jis',  # Japanese
    'big5',       # Traditional Chinese
    'iso-8859-1', # Latin-1
]


def get_raw_filename_bytes(zip_path):
    """
    Extract raw filename bytes from ZIP file without decoding.
    Returns list of tuples: (raw_bytes, is_directory)
    """
    results = []
    
    with open(zip_path, 'rb') as f:
        zip_data = f.read()
    
    # Use zipfile to parse structure, but extract raw bytes
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            # Get raw bytes - zipfile stores the original bytes
            # The filename in ZipInfo is decoded, so we need to get raw bytes
            # by encoding back with 'cp437' (ZIP default) or 'latin-1'
            try:
                # Try to get original bytes by re-encoding
                # ZipFile uses CP437 or UTF-8 flag to decode
                if info.flag_bits & 0x800:
                    # UTF-8 flag is set
                    raw_bytes = info.filename.encode('utf-8')
                else:
                    # Use CP437 (DOS encoding)
                    raw_bytes = info.filename.encode('cp437')
            except:
                # Fallback: encode as latin-1 which is 1:1 byte mapping
                raw_bytes = info.filename.encode('latin-1', errors='surrogateescape')
            
            results.append((raw_bytes, info.is_dir()))
    
    return results


def decode_with_encoding(raw_bytes, encoding):
    """
    Try to decode raw bytes with specified encoding.
    Returns decoded string with replacement characters if decoding fails.
    """
    try:
        return raw_bytes.decode(encoding, errors='replace')
    except Exception as e:
        return f"[ERROR: {str(e)}]"


def format_hex_bytes(raw_bytes, max_length=60):
    """Format bytes as hex string with truncation for display."""
    hex_str = raw_bytes.hex()
    if len(hex_str) > max_length:
        return hex_str[:max_length] + '...'
    return hex_str


def analyze_zip_file(zip_path, max_entries=10):
    """
    Main analysis function that displays all encodings for each file in ZIP.
    
    Args:
        zip_path: Path to the ZIP file
        max_entries: Maximum number of entries to analyze (default: 10)
                     Set to None or 0 to analyze all entries
    """
    print(f"\n{'='*80}")
    print(f"ZIP File Encoding Analysis: {zip_path}")
    print(f"{'='*80}\n")
    
    try:
        file_entries = get_raw_filename_bytes(zip_path)
    except FileNotFoundError:
        print(f"ERROR: File not found: {zip_path}")
        return
    except zipfile.BadZipFile:
        print(f"ERROR: Invalid or corrupted ZIP file: {zip_path}")
        return
    except Exception as e:
        print(f"ERROR: Failed to read ZIP file: {e}")
        return
    
    if not file_entries:
        print("ZIP file is empty (no entries found).")
        return
    
    total_entries = len(file_entries)
    
    # Limit entries if max_entries is specified
    if max_entries and max_entries > 0:
        file_entries = file_entries[:max_entries]
        print(f"Found {total_entries} total entries in ZIP file.")
        print(f"Analyzing first {len(file_entries)} entries (use --all to analyze all)\n")
    else:
        print(f"Found {total_entries} entries in ZIP file.\n")
    
    for idx, (raw_bytes, is_dir) in enumerate(file_entries, 1):
        entry_type = "DIR " if is_dir else "FILE"
        
        print(f"\n{'─'*80}")
        print(f"Entry #{idx} [{entry_type}]")
        print(f"{'─'*80}")
        
        # Display hex representation
        print(f"Raw Bytes (hex): {format_hex_bytes(raw_bytes)}")
        print(f"Raw Bytes (len): {len(raw_bytes)} bytes")
        print()
        
        # Try chardet detection
        detection = chardet.detect(raw_bytes)
        detected_encoding = detection.get('encoding', 'unknown')
        confidence = detection.get('confidence', 0)
        print(f"Chardet Detection: {detected_encoding} (confidence: {confidence:.2%})")
        print()
        
        # Try all encodings
        print("Decoding Attempts:")
        print("-" * 80)
        
        for encoding in ENCODINGS_TO_TRY:
            decoded = decode_with_encoding(raw_bytes, encoding)
            # Highlight if this matches chardet's suggestion
            marker = " ★" if encoding.upper() == str(detected_encoding).upper() else ""
            print(f"  {encoding:12s} → {decoded}{marker}")
        
        print()


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(
        description='Analyze ZIP file encoding and display filenames in multiple encodings.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s my_archive.zip
  %(prog)s /path/to/archive.zip --max 20
  %(prog)s large_archive.zip --all

This tool helps identify the correct encoding for ZIP files with Chinese
characters that appear garbled when extracted. It displays each filename
decoded with multiple common encodings (GBK, GB18030, UTF-8, etc.).

For large ZIP files, only the first few entries are analyzed by default.
        """
    )
    
    parser.add_argument(
        'zip_file',
        type=str,
        help='Path to the ZIP file to analyze'
    )
    
    parser.add_argument(
        '-m', '--max',
        type=int,
        default=10,
        metavar='N',
        help='Maximum number of entries to analyze (default: 10)'
    )
    
    parser.add_argument(
        '--all',
        action='store_true',
        help='Analyze all entries in the ZIP file (may be slow for large files)'
    )
    
    args = parser.parse_args()
    
    # Validate file exists
    zip_path = Path(args.zip_file)
    if not zip_path.exists():
        print(f"ERROR: File does not exist: {zip_path}", file=sys.stderr)
        sys.exit(1)
    
    if not zip_path.is_file():
        print(f"ERROR: Path is not a file: {zip_path}", file=sys.stderr)
        sys.exit(1)
    
    # Determine max entries
    max_entries = None if args.all else args.max
    
    # Run analysis
    analyze_zip_file(str(zip_path), max_entries=max_entries)


if __name__ == '__main__':
    main()
