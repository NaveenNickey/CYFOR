"""
CYFOR - Cyber Forensic Workstation
Flask Application Entry Point

A student cybersecurity forensic project for academic submission.
"""

import os
import re
import hashlib
import ctypes
from datetime import datetime

from flask import Flask, render_template, request, jsonify, send_file, after_this_request
import filetype
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, HRFlowable
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from io import BytesIO
from PIL import Image, ExifTags
import numpy as np

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = 'cyfor-forensic-tool-secret-key-change-in-prod'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ============================================================
# HELPER FUNCTIONS - INTEGRITY ANALYSIS
# ============================================================

def calculate_file_hashes(filepath):
    """
    Calculate MD5, SHA-1, and SHA-256 hashes of a file.
    Reads file in chunks for memory efficiency with large files.
    """
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()

    chunk_size = 8192

    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            md5_hash.update(chunk)
            sha1_hash.update(chunk)
            sha256_hash.update(chunk)

    return {
        'md5': md5_hash.hexdigest(),
        'sha1': sha1_hash.hexdigest(),
        'sha256': sha256_hash.hexdigest()
    }


def detect_file_type(filepath):
    """
    Detect file type using magic bytes via the filetype library.
    Returns MIME type, extension, and confidence.
    """
    kind = filetype.guess(filepath)

    if kind is None:
        # filetype couldn't detect - might be text or unknown binary
        return {
            'mime': 'application/octet-stream',
            'extension': 'bin',
            'confidence': 'unknown'
        }

    return {
        'mime': kind.mime,
        'extension': kind.extension,
        'confidence': 'detected'
    }


def get_extension_from_mime(mime_type):
    """
    Map common MIME types to file extensions.
    """
    mime_to_ext = {
        'application/pdf': 'pdf',
        'image/jpeg': 'jpg',
        'image/png': 'png',
        'image/gif': 'gif',
        'image/bmp': 'bmp',
        'image/tiff': 'tiff',
        'image/webp': 'webp',
        'application/x-executable': 'exe',
        'application/x-dosexec': 'exe',
        'application/x-sharedlib': 'so',
        'application/zip': 'zip',
        'application/x-rar-compressed': 'rar',
        'application/x-7z-compressed': '7z',
        'application/x-tar': 'tar',
        'application/gzip': 'gz',
        'text/html': 'html',
        'text/css': 'css',
        'text/javascript': 'js',
        'application/json': 'json',
        'application/xml': 'xml',
        'text/plain': 'txt',
        'application/msword': 'doc',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
        'application/vnd.ms-excel': 'xls',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
        'application/vnd.ms-powerpoint': 'ppt',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    }
    return mime_to_ext.get(mime_type, 'bin')


def analyze_file_integrity(filepath, filename):
    """
    Perform complete integrity analysis on an uploaded file.
    Returns all analysis results as a dictionary.
    """
    # Get file metadata
    file_size = os.path.getsize(filepath)
    file_size_kb = round(file_size / 1024, 2)
    file_size_mb = round(file_size / (1024 * 1024), 4)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Calculate hashes
    hashes = calculate_file_hashes(filepath)

    # Detect file type from magic bytes
    file_type = detect_file_type(filepath)

    # Get declared extension from filename
    declared_ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else 'none'

    # Get actual extension from detected MIME
    actual_ext = file_type['extension']
    actual_mime = file_type['mime']

    # Compare declared vs actual
    if file_type['confidence'] == 'unknown':
        mime_status = 'UNKNOWN'
        risk_level = 'MEDIUM'
    elif declared_ext.lower() == actual_ext.lower():
        mime_status = 'MATCH'
        risk_level = 'LOW'
    else:
        mime_status = 'MISMATCH'
        risk_level = 'HIGH'

    return {
        'filename': filename,
        'size_bytes': file_size,
        'size_kb': file_size_kb,
        'size_mb': file_size_mb,
        'timestamp': timestamp,
        'md5': hashes['md5'],
        'sha1': hashes['sha1'],
        'sha256': hashes['sha256'],
        'declared_ext': declared_ext,
        'actual_mime': actual_mime,
        'actual_ext': actual_ext,
        'mime_status': mime_status,
        'risk_level': risk_level,
        'magic_bytes': file_type['confidence']
    }


# ============================================================
# HELPER FUNCTIONS - IMAGE FORENSICS ANALYSIS
# ============================================================

def analyze_lsb_steganography(image_path):
    """
    Analyze image for LSB steganography using statistical methods.
    Returns bit distribution and entropy analysis.
    """
    img = Image.open(image_path)

    # Convert to RGB if necessary
    if img.mode != 'RGB':
        img = img.convert('RGB')

    img_array = np.array(img)

    # Extract LSBs from each channel
    r_lsb = img_array[:, :, 0] & 1
    g_lsb = img_array[:, :, 1] & 1
    b_lsb = img_array[:, :, 2] & 1

    # Count zeros and ones in LSBs
    total_bits = r_lsb.size * 3  # 3 channels
    total_zeros = (r_lsb == 0).sum() + (g_lsb == 0).sum() + (b_lsb == 0).sum()
    total_ones = total_bits - total_zeros

    zeros_ratio = float(total_zeros / total_bits)
    ones_ratio = float(total_ones / total_bits)

    # Calculate entropy for each channel
    def calculate_entropy(channel_data):
        """Calculate Shannon entropy for a channel."""
        values, counts = np.unique(channel_data, return_counts=True)
        probabilities = counts / counts.sum()
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    r_entropy = calculate_entropy(img_array[:, :, 0])
    g_entropy = calculate_entropy(img_array[:, :, 1])
    b_entropy = calculate_entropy(img_array[:, :, 2])

    # Determine if suspicious (ratio significantly different from 50/50)
    # Natural images tend toward 50/50 in LSBs
    ratio_deviation = abs(zeros_ratio - 0.5)

    if ratio_deviation < 0.05:
        verdict = 'CLEAN'
        confidence = 'HIGH'
    elif ratio_deviation < 0.10:
        verdict = 'CLEAN'
        confidence = 'MEDIUM'
    elif ratio_deviation < 0.15:
        verdict = 'SUSPICIOUS'
        confidence = 'MEDIUM'
    else:
        verdict = 'SUSPICIOUS'
        confidence = 'HIGH'

    return {
        'verdict': verdict,
        'confidence': confidence,
        'zeros_ratio': round(zeros_ratio * 100, 2),
        'ones_ratio': round(ones_ratio * 100, 2),
        'r_entropy': round(r_entropy, 4),
        'g_entropy': round(g_entropy, 4),
        'b_entropy': round(b_entropy, 4)
    }


def extract_exif_metadata(image_path):
    """
    Extract EXIF metadata from image using PIL.ExifTags.
    Returns categorized metadata.
    """
    img = Image.open(image_path)

    exif_data = {
        'file_info': {},
        'device': {},
        'capture': {},
        'gps': {},
        'software': {}
    }

    # File info
    exif_data['file_info']['filename'] = os.path.basename(image_path)
    exif_data['file_info']['size'] = os.path.getsize(image_path)
    exif_data['file_info']['dimensions'] = f"{img.width} x {img.height}"
    exif_data['file_info']['mode'] = img.mode

    # Extract EXIF tags
    try:
        exif = img._getexif()
        if exif:
            for tag_id, value in exif.items():
                tag = ExifTags.TAGS.get(tag_id, tag_id)

                # Skip binary/complex data
                if isinstance(value, bytes) or tag in ['MakerNote', 'UserComment']:
                    continue

                # Device information
                if tag in ['Make', 'Model']:
                    exif_data['device'][tag] = value

                # Capture information
                elif tag in ['DateTimeOriginal', 'DateTimeDigitized', 'DateTime']:
                    exif_data['capture'][tag] = value
                elif tag in ['ExposureTime', 'FNumber', 'ISO', 'FocalLength']:
                    exif_data['capture'][tag] = value
                elif tag in ['ExposureProgram', 'MeteringMode', 'Flash']:
                    exif_data['capture'][tag] = value

                # GPS information
                elif tag in ['GPSLatitude', 'GPSLongitude', 'GPSAltitude', 'GPSDateStamp']:
                    exif_data['gps'][tag] = value

                # Software information
                elif tag in ['Software', 'Artist', 'Copyright']:
                    exif_data['software'][tag] = value
    except (AttributeError, KeyError, TypeError):
        pass

    # Process GPS coordinates if present
    if 'GPSLatitude' in exif_data['gps'] and 'GPSLongitude' in exif_data['gps']:
        lat = exif_data['gps']['GPSLatitude']
        lon = exif_data['gps']['GPSLongitude']

        if isinstance(lat, tuple) and isinstance(lon, tuple):
            lat_deg = lat[0] + lat[1]/60 + lat[2]/(60*60)
            lon_deg = lon[0] + lon[1]/60 + lon[2]/(60*60)
            exif_data['gps']['coordinates'] = f"{lat_deg:.6f}, {lon_deg:.6f}"

    return exif_data


def analyze_image_forensics(filepath, filename):
    """
    Perform complete image forensics analysis.
    Returns combined LSB and EXIF analysis results.
    """
    # LSB Steganography Analysis
    lsb_results = analyze_lsb_steganography(filepath)

    # EXIF Metadata Extraction
    exif_results = extract_exif_metadata(filepath)

    return {
        'filename': filename,
        'lsb_analysis': lsb_results,
        'exif_data': exif_results
    }


# ============================================================
# HELPER FUNCTIONS - HEX VIEWER ANALYSIS
# ============================================================

def generate_hex_dump(filepath, max_bytes=512):
    """
    Generate hex dump of first max_bytes of file.
    Returns list of dicts with offset, hex, and ascii columns.
    """
    hex_rows = []

    with open(filepath, 'rb') as f:
        data = f.read(max_bytes)

    bytes_read = len(data)

    # Process 16 bytes per row
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]

        # Format hex bytes - 16 bytes per row, grouped in 8
        hex_part1 = ' '.join(f'{b:02X}' for b in chunk[:8])
        hex_part2 = ' '.join(f'{b:02X}' for b in chunk[8:16])

        # Pad if needed for shorter final row
        hex_part1 = hex_part1.ljust(23)  # 8 bytes * 3 chars - 1 space
        hex_part2 = hex_part2.ljust(23)

        hex_string = f"{hex_part1} {hex_part2}"

        # Format ASCII - printable chars only, rest become '.'
        ascii_string = ''.join(
            chr(b) if 32 <= b <= 126 else '.'
            for b in chunk
        )

        hex_rows.append({
            'offset': f'{offset:08X}',
            'hex': hex_string,
            'ascii': ascii_string
        })

    return hex_rows, bytes_read


def extract_strings(filepath, min_length=4, max_results=200):
    """
    Extract printable ASCII strings from entire file.
    Uses sliding window for memory efficiency.
    Returns interesting_strings and regular_strings.
    """
    # Patterns for interesting string detection
    patterns = {
        'url': re.compile(r'https?://|ftp://', re.IGNORECASE),
        'ip_address': re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        'email': re.compile(r'\S+@\S+\.\S+'),
        'windows_path': re.compile(r'[A-Za-z]:\\|%appdata%|%temp%|\\\\', re.IGNORECASE),
        'registry_key': re.compile(r'HKEY_|SOFTWARE\\', re.IGNORECASE),
        'suspicious_keyword': re.compile(
            r'cmd|powershell|exec|eval|base64|decode|encrypt|payload|exploit',
            re.IGNORECASE
        )
    }

    interesting_strings = []
    regular_strings = []
    seen_strings = set()

    # Read file in chunks for memory efficiency
    chunk_size = 8192
    current_string = []

    def is_printable_ascii(byte):
        return 32 <= byte <= 126

    def process_string(s):
        """Process an extracted string and categorize it."""
        if len(s) < min_length:
            return

        if s in seen_strings:
            return

        seen_strings.add(s)

        if len(regular_strings) + len(interesting_strings) >= max_results:
            return

        # Check for interesting patterns
        reasons = []
        if patterns['url'].search(s):
            reasons.append('URL DETECTED')
        if patterns['ip_address'].search(s):
            reasons.append('IP ADDRESS')
        if patterns['email'].search(s):
            reasons.append('EMAIL ADDRESS')
        if patterns['windows_path'].search(s):
            reasons.append('WINDOWS PATH')
        if patterns['registry_key'].search(s):
            reasons.append('REGISTRY KEY')
        if patterns['suspicious_keyword'].search(s):
            reasons.append('SUSPICIOUS KEYWORD')

        if reasons:
            interesting_strings.append({
                'value': s,
                'reason': ', '.join(reasons)
            })
        else:
            regular_strings.append(s)

    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            for byte in chunk:
                if is_printable_ascii(byte):
                    current_string.append(chr(byte))
                else:
                    if current_string:
                        process_string(''.join(current_string))
                        current_string = []

            # Prevent memory buildup on very long runs
            if len(current_string) > 1000:
                current_string = current_string[-100:]

    # Process any remaining string at end of file
    if current_string:
        process_string(''.join(current_string))

    return interesting_strings, regular_strings


def detect_file_type_by_magic(magic_bytes):
    """
    Detect file type based on magic bytes.
    Returns human-readable file type description.
    """
    if magic_bytes.startswith('4D 5A'):
        return 'Windows Executable (PE)'
    elif magic_bytes.startswith('89 50 4E 47'):
        return 'PNG Image'
    elif magic_bytes.startswith('FF D8 FF'):
        return 'JPEG Image'
    elif magic_bytes.startswith('25 50 44 46'):
        return 'PDF Document'
    elif magic_bytes.startswith('50 4B'):
        return 'ZIP Archive'
    elif magic_bytes.startswith('45 4C 46'):
        return 'ELF Executable (Linux)'
    elif magic_bytes.startswith('1F 8B'):
        return 'GZIP Compressed'
    elif magic_bytes.startswith('52 61 72 21'):
        return 'RAR Archive'
    elif magic_bytes.startswith('7F 45 4C 46'):
        return 'ELF Executable'
    else:
        return 'Unknown Format'


def analyze_hex_viewer(filepath, filename):
    """
    Perform complete hex viewer analysis.
    Returns hex dump and extracted strings.
    """
    # Generate hex dump (first 512 bytes)
    hex_rows, bytes_read = generate_hex_dump(filepath, max_bytes=512)

    # Extract strings from entire file
    interesting_strings, regular_strings = extract_strings(filepath)

    # Get file magic (first 4 bytes)
    with open(filepath, 'rb') as f:
        magic_bytes = f.read(4)
    file_magic = ' '.join(f'{b:02X}' for b in magic_bytes)

    # Detect file type
    file_type = detect_file_type_by_magic(file_magic)

    return {
        'filename': filename,
        'file_size': os.path.getsize(filepath),
        'bytes_read': bytes_read,
        'hex_rows': hex_rows,
        'interesting_strings': interesting_strings,
        'regular_strings': regular_strings,
        'total_strings': len(interesting_strings) + len(regular_strings),
        'file_magic': file_magic,
        'file_type': file_type
    }


# ============================================================
# HELPER FUNCTIONS - ARTIFACT SCANNER ANALYSIS
# ============================================================

# Windows file attribute constants
FILE_ATTRIBUTE_HIDDEN = 0x02
FILE_ATTRIBUTE_SYSTEM = 0x04

# Extension to MIME type mappings
EXTENSION_MIME_MAP = {
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.png': 'image/png',
    '.gif': 'image/gif',
    '.bmp': 'image/bmp',
    '.tiff': 'image/tiff',
    '.webp': 'image/webp',
    '.pdf': 'application/pdf',
    '.zip': 'application/zip',
    '.exe': 'application/x-msdownload',
    '.mp4': 'video/mp4',
    '.mp3': 'audio/mpeg',
    '.wav': 'audio/x-wav',
    '.docx': 'application/zip',  # docx is a zip
    '.xlsx': 'application/zip',  # xlsx is a zip
    '.pptx': 'application/zip',  # pptx is a zip
    '.doc': 'application/msword',
    '.xls': 'application/vnd.ms-excel',
    '.txt': 'text/plain',
    '.html': 'text/html',
    '.htm': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.py': 'text/x-python',
    '.java': 'text/x-java',
    '.c': 'text/x-c',
    '.cpp': 'text/x-c++',
    '.h': 'text/x-c',
    '.dll': 'application/x-msdownload',
    '.sys': 'application/x-msdownload',
}

# Executable extensions for risk calculation
EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.sys', '.bat', '.cmd', '.ps1', '.vbs', '.scr'}


def is_hidden_file(filepath):
    """
    Check if a file is hidden.
    Windows: uses ctypes to check FILE_ATTRIBUTE_HIDDEN
    Unix: checks if filename starts with '.'
    Returns tuple: (is_hidden, is_system)
    """
    filename = os.path.basename(filepath)
    is_hidden = False
    is_system = False

    # Check Unix-style hidden (starts with .)
    if filename.startswith('.'):
        is_hidden = True

    # Check system file (starts with $)
    if filename.startswith('$'):
        is_system = True

    # Windows hidden attribute check via ctypes
    if os.name == 'nt':
        try:
            attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
            if attrs != -1:
                if attrs & FILE_ATTRIBUTE_HIDDEN:
                    is_hidden = True
                if attrs & FILE_ATTRIBUTE_SYSTEM:
                    is_system = True
        except (OSError, AttributeError):
            pass

    return is_hidden, is_system


def check_extension_match(filepath, filename):
    """
    Check if file extension matches actual content type.
    Returns tuple: (mime_status, actual_type, expected_mime)
    """
    # Get file extension
    _, ext = os.path.splitext(filename)
    ext = ext.lower()

    # Detect actual type using filetype library
    try:
        kind = filetype.guess(filepath)
    except Exception:
        return ('Undetectable', 'unknown', None)

    if kind is None:
        # filetype couldn't detect - might be text or unknown
        return ('Undetectable', 'unknown', EXTENSION_MIME_MAP.get(ext))

    actual_mime = kind.mime

    # Get expected MIME from extension
    expected_mime = EXTENSION_MIME_MAP.get(ext)

    if expected_mime is None:
        # Unknown extension - just report what we found
        return ('Detected', actual_mime, None)

    # Compare
    if actual_mime == expected_mime:
        return ('MATCH', actual_mime, expected_mime)
    else:
        return ('MISMATCH', actual_mime, expected_mime)


def calculate_risk_level(is_hidden, is_system, mime_status, extension):
    """
    Calculate risk level for a file.
    Returns: 'HIGH', 'MEDIUM', or 'LOW'
    """
    ext = extension.lower() if extension else ''

    # HIGH: extension mismatch OR hidden + executable extension
    if mime_status == 'MISMATCH':
        return 'HIGH'

    if is_hidden and ext in EXECUTABLE_EXTENSIONS:
        return 'HIGH'

    # MEDIUM: hidden file OR undetectable type OR system file
    if is_hidden or mime_status == 'Undetectable' or is_system:
        return 'MEDIUM'

    # LOW: normal file
    return 'LOW'


def scan_directory(directory_path, deep_scan=False):
    """
    Scan a directory for artifacts.
    Returns analysis results for all files found.
    """
    results = {
        'directory': directory_path,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_files': 0,
        'hidden_count': 0,
        'mismatch_count': 0,
        'high_risk': 0,
        'medium_risk': 0,
        'low_risk': 0,
        'files': [],
        'warnings': []
    }

    # Validate directory
    if not os.path.isdir(directory_path):
        results['warnings'].append(f"Invalid directory path: {directory_path}")
        return results

    # Get files to scan
    files_to_scan = []

    try:
        if deep_scan:
            # Recursive scan with os.walk()
            for root, dirs, files in os.walk(directory_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    files_to_scan.append((filepath, filename))
                    if len(files_to_scan) >= 500:
                        results['warnings'].append("File limit (500) reached - some files were not scanned")
                        break
                if len(files_to_scan) >= 500:
                    break
        else:
            # Top-level only
            for filename in os.listdir(directory_path):
                filepath = os.path.join(directory_path, filename)
                if os.path.isfile(filepath):
                    files_to_scan.append((filepath, filename))

    except PermissionError as e:
        results['warnings'].append(f"Permission denied: {str(e)}")
        return results
    except OSError as e:
        results['warnings'].append(f"Directory access error: {str(e)}")
        return results

    # Scan each file
    for filepath, filename in files_to_scan:
        if len(results['files']) >= 500:
            break

        try:
            # Get file size
            file_size = os.path.getsize(filepath)
            file_size_kb = round(file_size / 1024, 2)

            # Get extension
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            # Check hidden/system status
            is_hidden, is_system = is_hidden_file(filepath)

            # Check extension match
            mime_status, actual_type, expected_mime = check_extension_match(filepath, filename)

            # Calculate risk level
            risk_level = calculate_risk_level(is_hidden, is_system, mime_status, ext)

            # Build file result
            file_result = {
                'name': filename,
                'path': filepath,
                'size_kb': file_size_kb,
                'extension': ext if ext else '(none)',
                'actual_type': actual_type,
                'mime_status': mime_status,
                'is_hidden': is_hidden,
                'is_system': is_system,
                'risk_level': risk_level
            }

            results['files'].append(file_result)

            # Update counts
            results['total_files'] += 1
            if is_hidden:
                results['hidden_count'] += 1
            if mime_status == 'MISMATCH':
                results['mismatch_count'] += 1
            if risk_level == 'HIGH':
                results['high_risk'] += 1
            elif risk_level == 'MEDIUM':
                results['medium_risk'] += 1
            else:
                results['low_risk'] += 1

        except PermissionError:
            results['warnings'].append(f"Permission denied: {filename}")
        except OSError as e:
            results['warnings'].append(f"Error reading {filename}: {str(e)}")

    # Sort files by risk level (HIGH first)
    risk_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
    results['files'].sort(key=lambda x: risk_order.get(x['risk_level'], 3))

    return results


# ============================================================
# HELPER FUNCTIONS - KEYWORD SEARCH ANALYSIS
# ============================================================

# Text file extensions to scan
TEXT_EXTENSIONS = {
    '.txt', '.log', '.csv', '.json', '.xml', '.html', '.htm',
    '.py', '.js', '.php', '.sql', '.md', '.ini', '.cfg', '.conf',
    '.bat', '.sh', '.yaml', '.yml'
}

# Max file size to scan (10MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Preset regex patterns
PRESET_PATTERNS = {
    'credit_card': re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
    'ip_address': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
    'api_key': re.compile(r'\b[A-Za-z0-9]{32,45}\b'),
    'phone': re.compile(r'\b[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}\b'),
    'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    'windows_path': re.compile(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*')
}

# Pattern display names
PATTERN_NAMES = {
    'credit_card': 'Credit Card',
    'ip_address': 'IP Address',
    'email': 'Email Address',
    'ssn': 'SSN (US)',
    'api_key': 'API Key / Token',
    'phone': 'Phone Number',
    'url': 'URL',
    'windows_path': 'Windows Path'
}


def is_text_file(filepath):
    """Check if file is a text file based on extension."""
    _, ext = os.path.splitext(filepath)
    return ext.lower() in TEXT_EXTENSIONS


def search_keywords(filepath, keywords):
    """
    Search for custom keywords in a file.
    Returns list of match dicts.
    """
    matches = []

    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                for keyword in keywords:
                    if keyword.lower() in line.lower():
                        matches.append({
                            'file': filepath,
                            'filename': os.path.basename(filepath),
                            'line_number': line_num,
                            'line_content': line,
                            'matched_text': keyword,
                            'match_type': f'KEYWORD: {keyword}'
                        })
    except (PermissionError, OSError, UnicodeDecodeError):
        pass

    return matches


def search_patterns(filepath, patterns):
    """
    Search for preset regex patterns in a file.
    Returns list of match dicts.
    """
    matches = []

    try:
        with open(filepath, 'r', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                for pattern_name, pattern_regex in patterns.items():
                    for match in pattern_regex.finditer(line):
                        matches.append({
                            'file': filepath,
                            'filename': os.path.basename(filepath),
                            'line_number': line_num,
                            'line_content': line,
                            'matched_text': match.group(),
                            'match_type': PATTERN_NAMES.get(pattern_name, pattern_name)
                        })
    except (PermissionError, OSError, UnicodeDecodeError):
        pass

    return matches


def scan_directory_for_keywords(directory_path, keywords, patterns, deep_scan=False):
    """
    Scan a directory for keywords and patterns.
    Returns search results.
    """
    results = {
        'directory': directory_path,
        'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'duration': 0,
        'total_files_scanned': 0,
        'total_files_skipped': 0,
        'total_matches': 0,
        'matches_by_type': {},
        'matches': [],
        'warnings': []
    }

    start_time = datetime.now()

    # Validate directory
    if not os.path.isdir(directory_path):
        results['warnings'].append(f"Invalid directory path: {directory_path}")
        return results

    # Parse keywords
    keyword_list = [k.strip() for k in keywords.split(',') if k.strip()] if keywords else []

    # Get files to scan
    files_to_scan = []

    try:
        if deep_scan:
            for root, dirs, files in os.walk(directory_path):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    files_to_scan.append(filepath)
                    if len(files_to_scan) >= 300:
                        results['warnings'].append("File limit (300) reached - some files were not scanned")
                        break
                if len(files_to_scan) >= 300:
                    break
        else:
            for filename in os.listdir(directory_path):
                filepath = os.path.join(directory_path, filename)
                if os.path.isfile(filepath):
                    files_to_scan.append(filepath)
    except PermissionError as e:
        results['warnings'].append(f"Permission denied: {str(e)}")
        return results
    except OSError as e:
        results['warnings'].append(f"Directory access error: {str(e)}")
        return results

    # Scan each file
    for filepath in files_to_scan:
        if len(results['matches']) >= 1000:
            results['warnings'].append("Match limit (1000) reached - search stopped early")
            break

        # Check file extension
        if not is_text_file(filepath):
            results['total_files_skipped'] += 1
            continue

        # Check file size
        try:
            file_size = os.path.getsize(filepath)
            if file_size > MAX_FILE_SIZE:
                results['total_files_skipped'] += 1
                results['warnings'].append(f"File too large (>10MB): {os.path.basename(filepath)}")
                continue
        except OSError:
            results['total_files_skipped'] += 1
            continue

        results['total_files_scanned'] += 1

        # Search keywords
        if keyword_list:
            keyword_matches = search_keywords(filepath, keyword_list)
            for match in keyword_matches:
                if len(results['matches']) >= 1000:
                    break
                results['matches'].append(match)
                match_type = match['match_type']
                results['matches_by_type'][match_type] = results['matches_by_type'].get(match_type, 0) + 1

        # Search patterns
        if patterns:
            pattern_matches = search_patterns(filepath, patterns)
            for match in pattern_matches:
                if len(results['matches']) >= 1000:
                    break
                results['matches'].append(match)
                match_type = match['match_type']
                results['matches_by_type'][match_type] = results['matches_by_type'].get(match_type, 0) + 1

    # Calculate duration
    end_time = datetime.now()
    results['duration'] = (end_time - start_time).total_seconds()
    results['total_matches'] = len(results['matches'])

    return results


# ============================================================
# ROUTES
# ============================================================

@app.route('/')
def index():
    """Dashboard / Landing Page"""
    return render_template('index.html')


@app.route('/integrity', methods=['GET', 'POST'])
def integrity():
    """
    File Integrity & Signature Analysis Module

    GET: Display the upload form
    POST: Analyze uploaded file and return results
    """
    results = None
    error = None

    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            error = 'No file uploaded'
        else:
            file = request.files['file']

            if file.filename == '':
                error = 'No file selected'
            else:
                # Save file temporarily
                filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                try:
                    # Perform analysis
                    results = analyze_file_integrity(filepath, filename)
                except Exception as e:
                    error = f'Analysis error: {str(e)}'
                finally:
                    # Clean up - delete the uploaded file
                    if os.path.exists(filepath):
                        os.remove(filepath)

    return render_template('integrity.html', results=results, error=error)


@app.route('/image-forensics', methods=['GET', 'POST'])
def image_forensics():
    """Image Forensic Analysis Module (Steganography & EXIF)"""
    results = None
    error = None

    if request.method == 'POST':
        if 'file' not in request.files:
            error = 'No file uploaded'
        else:
            file = request.files['file']

            if file.filename == '':
                error = 'No file selected'
            else:
                # Save file temporarily
                filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                try:
                    # Perform image forensics analysis
                    results = analyze_image_forensics(filepath, filename)
                except Exception as e:
                    error = f'Analysis error: {str(e)}'
                finally:
                    # Clean up - delete the uploaded file
                    if os.path.exists(filepath):
                        os.remove(filepath)

    return render_template('image_forensics.html', results=results, error=error)


@app.route('/hex-viewer', methods=['GET', 'POST'])
def hex_viewer():
    """Low-Level Hex Dump Viewer Module"""
    results = None
    error = None

    if request.method == 'POST':
        if 'file' not in request.files:
            error = 'No file uploaded'
        else:
            file = request.files['file']

            if file.filename == '':
                error = 'No file selected'
            else:
                # Save file temporarily
                filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                try:
                    # Perform hex viewer analysis
                    results = analyze_hex_viewer(filepath, filename)
                except Exception as e:
                    error = f'Analysis error: {str(e)}'
                finally:
                    # Clean up - delete the uploaded file
                    if os.path.exists(filepath):
                        os.remove(filepath)

    return render_template('hex_viewer.html', results=results, error=error)


@app.route('/artifact-scanner', methods=['GET', 'POST'])
def artifact_scanner():
    """System Artifact Scanner Module"""
    results = None
    error = None

    if request.method == 'POST':
        directory_path = request.form.get('directory_path', '')
        deep_scan = request.form.get('deep_scan') == 'on'

        if not directory_path:
            error = 'No directory path provided'
        elif not os.path.exists(directory_path):
            error = f"Directory does not exist: {directory_path}"
        else:
            try:
                # Perform directory scan
                results = scan_directory(directory_path, deep_scan=deep_scan)
            except Exception as e:
                error = f'Scan error: {str(e)}'

    return render_template('artifact_scanner.html', results=results, error=error)


@app.route('/keyword-search', methods=['GET', 'POST'])
def keyword_search():
    """Keyword & Pattern Search Module"""
    results = None
    error = None

    if request.method == 'POST':
        directory_path = request.form.get('directory', '')
        keywords = request.form.get('keywords', '')
        deep_scan = request.form.get('deep_scan') == 'on'

        # Get selected patterns from checkboxes
        selected_patterns = {}
        for pattern_name in PRESET_PATTERNS.keys():
            if request.form.get(f'pattern_{pattern_name}') == 'on':
                selected_patterns[pattern_name] = PRESET_PATTERNS[pattern_name]

        if not directory_path:
            error = 'No directory path provided'
        elif not os.path.exists(directory_path):
            error = f"Directory does not exist: {directory_path}"
        else:
            try:
                # Perform keyword and pattern search
                results = scan_directory_for_keywords(
                    directory_path, keywords, selected_patterns, deep_scan=deep_scan
                )
            except Exception as e:
                error = f'Search error: {str(e)}'

    return render_template('keyword_search.html', results=results, error=error, stats=None, match_counts=None, warnings=None)


@app.route('/report')
def report():
    """Automated Report Generator Module"""
    return render_template('report.html')


@app.route('/generate_report', methods=['POST'])
def generate_report():
    """
    Generate PDF report from collected module findings.
    Receives JSON with case info and module data.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Extract case information
        case_id = data.get('case_id', 'UNKNOWN')
        investigator = data.get('investigator', 'Unknown')
        institution = data.get('institution', 'JNN Institute of Engineering')
        notes = data.get('notes', '')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Create PDF buffer
        buffer = BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=0.75*inch,
            leftMargin=0.75*inch,
            topMargin=1*inch,
            bottomMargin=0.75*inch
        )

        # Styles
        styles = getSampleStyleSheet()

        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=HexColor('#0a0e17'),
            spaceAfter=30,
            alignment=1  # Center
        )

        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#00ff9f'),
            spaceAfter=20,
            alignment=1
        )

        header_style = ParagraphStyle(
            'SectionHeader',
            parent=styles['Heading2'],
            fontSize=14,
            textColor=HexColor('#ffffff'),
            spaceAfter=12,
            spaceBefore=12,
            backColor=HexColor('#0a0e17'),
            borderPadding=8
        )

        normal_style = ParagraphStyle(
            'CustomNormal',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#333333'),
            spaceAfter=8
        )

        # Build document elements
        elements = []

        # =====================
        # PAGE 1 - COVER PAGE
        # =====================

        # Title
        elements.append(Spacer(1, 1.5*inch))
        elements.append(Paragraph("CYBER FORENSIC INVESTIGATION REPORT", title_style))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph("CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY", subtitle_style))
        elements.append(Spacer(1, 1*inch))

        # Logo placeholder
        logo_data = [
            [Paragraph("<font size='20' color='#00ff9f'>⬡</font>", normal_style)],
            [Paragraph("<font size='16' color='#0a0e17'><b>CYFOR</b></font>", normal_style)]
        ]
        logo_table = Table(logo_data, colWidths=[2*inch])
        logo_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BACKGROUND', (0, 0), (-1, -1), HexColor('#0a0e17')),
            ('BOX', (0, 0), (-1, -1), 2, HexColor('#00ff9f')),
        ]))
        elements.append(logo_table)
        elements.append(Spacer(1, 1*inch))

        # Case details table
        case_data = [
            ['Case ID:', case_id],
            ['Investigator Name:', investigator],
            ['Institution:', institution],
            ['Date & Time Generated:', timestamp],
            ['Tool Version:', 'CYFOR v1.0']
        ]

        case_table = Table(case_data, colWidths=[2*inch, 3.5*inch])
        case_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 11),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#0a0e17')),
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('LINEABOVE', (0, 0), (-1, 0), 1, HexColor('#0a0e17')),
            ('LINEBELOW', (0, -1), (-1, -1), 1, HexColor('#0a0e17')),
        ]))
        elements.append(case_table)
        elements.append(Spacer(1, 0.5*inch))

        # Horizontal divider
        elements.append(HRFlowable(width="100%", thickness=2, color=HexColor('#00ff9f')))
        elements.append(Spacer(1, 0.3*inch))

        # Executive Summary
        elements.append(Paragraph("EXECUTIVE SUMMARY", header_style))
        elements.append(Spacer(1, 0.2*inch))

        if notes:
            elements.append(Paragraph(notes.replace('\n', '<br/>'), normal_style))
        else:
            elements.append(Paragraph("No investigator notes provided.", normal_style))

        elements.append(PageBreak())

        # =====================
        # MODULE SECTIONS
        # =====================

        # Integrity Module Section
        if data.get('include_integrity') and data.get('integrity_data'):
            integrity = data['integrity_data']
            elements.append(Paragraph("FILE INTEGRITY ANALYSIS", header_style))
            elements.append(Spacer(1, 0.2*inch))

            if integrity:
                # File info
                info_data = [
                    ['File Name:', integrity.get('filename', 'N/A')],
                    ['File Size:', f"{integrity.get('size_kb', 0)} KB ({integrity.get('size_mb', 0)} MB)"],
                    ['Timestamp:', integrity.get('timestamp', 'N/A')]
                ]
                info_table = Table(info_data, colWidths=[1.5*inch, 4*inch])
                info_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(info_table)
                elements.append(Spacer(1, 0.2*inch))

                # Hash table
                hash_data = [['Algorithm', 'Hash Value', 'Strength']]
                hash_data.append(['MD5', integrity.get('md5', 'N/A'), 'WEAK'])
                hash_data.append(['SHA-1', integrity.get('sha1', 'N/A'), 'MODERATE'])
                hash_data.append(['SHA-256', integrity.get('sha256', 'N/A'), 'STRONG'])

                hash_table = Table(hash_data, colWidths=[1.2*inch, 3.8*inch, 1*inch])
                hash_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                    ('TOPPADDING', (0, 0), (-1, -1), 8),
                ]))
                elements.append(hash_table)
                elements.append(Spacer(1, 0.2*inch))

                # MIME validation
                mime_data = [
                    ['Declared Extension:', f".{integrity.get('declared_ext', 'none')}"],
                    ['Actual Extension:', f".{integrity.get('actual_ext', 'unknown')}"],
                    ['Actual MIME Type:', integrity.get('actual_mime', 'unknown')],
                    ['Status:', integrity.get('mime_status', 'UNKNOWN')],
                    ['Risk Level:', integrity.get('risk_level', 'UNKNOWN')]
                ]
                mime_table = Table(mime_data, colWidths=[1.5*inch, 4*inch])
                mime_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(mime_table)
                elements.append(Spacer(1, 0.3*inch))

        # Image Forensics Section
        if data.get('include_image') and data.get('image_data'):
            image = data['image_data']
            elements.append(Paragraph("IMAGE FORENSICS ANALYSIS", header_style))
            elements.append(Spacer(1, 0.2*inch))

            if image:
                exif = image.get('exif_data', {})
                lsb = image.get('lsb_analysis', {})

                # Image info
                file_info = exif.get('file_info', {})
                img_info = [
                    ['Filename:', file_info.get('filename', 'N/A')],
                    ['Dimensions:', file_info.get('dimensions', 'N/A')],
                    ['Color Mode:', file_info.get('mode', 'N/A')],
                    ['File Size:', f"{(file_info.get('size', 0) / 1024):.2f} KB"]
                ]
                img_table = Table(img_info, colWidths=[1.5*inch, 4*inch])
                img_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(img_table)
                elements.append(Spacer(1, 0.2*inch))

                # LSB Analysis
                lsb_data = [
                    ['LSB Verdict:', lsb.get('verdict', 'N/A')],
                    ['Confidence:', lsb.get('confidence', 'N/A')],
                    ['Zeros Ratio:', f"{lsb.get('zeros_ratio', 0)}%"],
                    ['Ones Ratio:', f"{lsb.get('ones_ratio', 0)}%"]
                ]
                lsb_table = Table(lsb_data, colWidths=[1.5*inch, 4*inch])
                lsb_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(lsb_table)
                elements.append(Spacer(1, 0.2*inch))

                # EXIF Metadata
                if exif.get('device') or exif.get('capture'):
                    exif_data = [['Property', 'Value']]
                    for key, value in exif.get('device', {}).items():
                        exif_data.append([key, str(value)])
                    for key, value in exif.get('capture', {}).items():
                        exif_data.append([key, str(value)])

                    if len(exif_data) > 1:
                        exif_table = Table(exif_data, colWidths=[2*inch, 3.5*inch])
                        exif_table.setStyle(TableStyle([
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                            ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                            ('FONTSIZE', (0, 0), (-1, -1), 8),
                            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ]))
                        elements.append(exif_table)

                elements.append(Spacer(1, 0.3*inch))

        # Hex Viewer Section
        if data.get('include_hex') and data.get('hex_data'):
            hex_data = data['hex_data']
            elements.append(Paragraph("HEX DUMP ANALYSIS", header_style))
            elements.append(Spacer(1, 0.2*inch))

            if hex_data:
                # File info
                hex_info = [
                    ['File Name:', hex_data.get('filename', 'N/A')],
                    ['File Size:', f"{(hex_data.get('file_size', 0) / 1024):.2f} KB"],
                    ['File Type:', hex_data.get('file_type', 'Unknown')],
                    ['Magic Bytes:', hex_data.get('file_magic', 'N/A')]
                ]
                hex_table = Table(hex_info, colWidths=[1.5*inch, 4*inch])
                hex_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTNAME', (1, 3), (1, 3), 'Courier'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(hex_table)
                elements.append(Spacer(1, 0.2*inch))

                # Hex dump (first 8 rows)
                hex_rows = hex_data.get('hex_rows', [])
                if hex_rows:
                    hex_dump_data = [['Offset', 'Hex (00-07)', 'Hex (08-0F)', 'ASCII']]
                    for i, row in enumerate(hex_rows[:8]):
                        hex_str = row.get('hex', '')
                        hex_part1 = hex_str[:23] if len(hex_str) > 23 else hex_str
                        hex_part2 = hex_str[24:47] if len(hex_str) > 47 else hex_str[24:] if len(hex_str) > 24 else ''
                        hex_dump_data.append([
                            row.get('offset', ''),
                            hex_part1,
                            hex_part2,
                            row.get('ascii', '')
                        ])

                    hex_dump_table = Table(hex_dump_data, colWidths=[0.8*inch, 2*inch, 2*inch, 1.2*inch])
                    hex_dump_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                        ('FONTSIZE', (0, 0), (-1, -1), 7),
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ]))
                    elements.append(hex_dump_table)
                    elements.append(Spacer(1, 0.2*inch))

                # Interesting strings
                interesting = hex_data.get('interesting_strings', [])
                if interesting:
                    elements.append(Paragraph("Interesting Strings Found:", ParagraphStyle('SubHeader', parent=styles['Heading3'], fontSize=10, textColor=HexColor('#0a0e17'))))
                    str_data = [['String', 'Reason']]
                    for item in interesting[:10]:  # Limit to 10
                        str_data.append([item.get('value', '')[:50], item.get('reason', '')])

                    str_table = Table(str_data, colWidths=[3*inch, 2.5*inch])
                    str_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTNAME', (0, 1), (0, -1), 'Courier'),
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ]))
                    elements.append(str_table)

                elements.append(Spacer(1, 0.3*inch))

        # Artifact Scanner Section
        if data.get('include_artifact') and data.get('artifact_data'):
            artifact = data['artifact_data']
            elements.append(Paragraph("ARTIFACT SCANNER RESULTS", header_style))
            elements.append(Spacer(1, 0.2*inch))

            if artifact:
                # Scan info
                art_info = [
                    ['Directory Scanned:', artifact.get('directory', 'N/A')],
                    ['Scan Time:', artifact.get('scan_time', 'N/A')],
                    ['Total Files:', str(artifact.get('total_files', 0))],
                    ['Hidden Files:', str(artifact.get('hidden_count', 0))],
                    ['Extension Mismatches:', str(artifact.get('mismatch_count', 0))]
                ]
                art_table = Table(art_info, colWidths=[1.8*inch, 3.7*inch])
                art_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(art_table)
                elements.append(Spacer(1, 0.2*inch))

                # Summary stats
                stats_data = [
                    ['Risk Level', 'Count'],
                    ['HIGH', str(artifact.get('high_risk', 0))],
                    ['MEDIUM', str(artifact.get('medium_risk', 0))],
                    ['LOW', str(artifact.get('low_risk', 0))]
                ]
                stats_table = Table(stats_data, colWidths=[2*inch, 2*inch])
                stats_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                    ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                ]))
                elements.append(stats_table)
                elements.append(Spacer(1, 0.2*inch))

                # High risk files
                files = artifact.get('files', [])
                high_risk = [f for f in files if f.get('risk_level') == 'HIGH'][:10]
                if high_risk:
                    elements.append(Paragraph("HIGH Risk Files:", ParagraphStyle('SubHeader', parent=styles['Heading3'], fontSize=10, textColor=HexColor('#0a0e17'))))
                    file_data = [['Filename', 'Extension', 'Actual Type', 'Risk']]
                    for f in high_risk:
                        file_data.append([
                            f.get('name', '')[:30],
                            f.get('extension', ''),
                            f.get('actual_type', ''),
                            f.get('risk_level', '')
                        ])

                    file_table = Table(file_data, colWidths=[2*inch, 0.8*inch, 1.5*inch, 0.7*inch])
                    file_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#ff4d6d')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ]))
                    elements.append(file_table)

                elements.append(Spacer(1, 0.3*inch))

        # Keyword Search Section
        if data.get('include_keyword') and data.get('keyword_data'):
            keyword = data['keyword_data']
            elements.append(Paragraph("KEYWORD & PATTERN SEARCH", header_style))
            elements.append(Spacer(1, 0.2*inch))

            if keyword:
                # Search info
                kw_info = [
                    ['Directory:', keyword.get('directory', 'N/A')],
                    ['Scan Time:', keyword.get('scan_time', 'N/A')],
                    ['Duration:', f"{keyword.get('duration', 0):.2f} seconds"],
                    ['Files Scanned:', str(keyword.get('total_files_scanned', 0))],
                    ['Files Skipped:', str(keyword.get('total_files_skipped', 0))],
                    ['Total Matches:', str(keyword.get('total_matches', 0))]
                ]
                kw_table = Table(kw_info, colWidths=[1.5*inch, 4*inch])
                kw_table.setStyle(TableStyle([
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ]))
                elements.append(kw_table)
                elements.append(Spacer(1, 0.2*inch))

                # Matches by type
                by_type = keyword.get('matches_by_type', {})
                if by_type:
                    type_data = [['Pattern Type', 'Count']]
                    for ptype, count in by_type.items():
                        type_data.append([ptype, str(count)])

                    type_table = Table(type_data, colWidths=[3*inch, 1.5*inch])
                    type_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                        ('FONTSIZE', (0, 0), (-1, -1), 9),
                    ]))
                    elements.append(type_table)
                    elements.append(Spacer(1, 0.2*inch))

                # Top matches
                matches = keyword.get('matches', [])
                if matches:
                    elements.append(Paragraph("Top 20 Matches:", ParagraphStyle('SubHeader', parent=styles['Heading3'], fontSize=10, textColor=HexColor('#0a0e17'))))
                    match_data = [['File', 'Line', 'Type', 'Preview']]
                    for m in matches[:20]:
                        match_data.append([
                            m.get('filename', '')[:20],
                            str(m.get('line_number', 'N/A')),
                            m.get('match_type', '')[:25],
                            (m.get('line_content', '')[:40] + '...') if len(m.get('line_content', '')) > 40 else m.get('line_content', '')
                        ])

                    match_table = Table(match_data, colWidths=[1.5*inch, 0.5*inch, 1.5*inch, 2.5*inch])
                    match_table.setStyle(TableStyle([
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#0a0e17')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#cccccc')),
                        ('FONTSIZE', (0, 0), (-1, -1), 7),
                        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ]))
                    elements.append(match_table)

                elements.append(Spacer(1, 0.3*inch))

        # =====================
        # FINAL PAGE - DISCLAIMER
        # =====================
        elements.append(PageBreak())
        elements.append(Spacer(1, 2*inch))

        disclaimer_style = ParagraphStyle(
            'Disclaimer',
            parent=styles['Normal'],
            fontSize=10,
            textColor=HexColor('#666666'),
            alignment=1,  # Center
            spaceAfter=12
        )

        elements.append(Paragraph("DISCLAIMER", ParagraphStyle('DisclaimerTitle', parent=styles['Heading2'], fontSize=16, textColor=HexColor('#0a0e17'), alignment=1)))
        elements.append(Spacer(1, 0.5*inch))
        elements.append(Paragraph("This report was generated by CYFOR Forensic Tool", disclaimer_style))
        elements.append(Paragraph("JNN Institute of Engineering — Cybersecurity Department", disclaimer_style))
        elements.append(Paragraph("For academic and authorized investigative purposes only", disclaimer_style))
        elements.append(Spacer(1, 0.3*inch))
        elements.append(Paragraph(f"Generated: {timestamp}", disclaimer_style))

        # Build PDF
        doc.build(elements)
        buffer.seek(0)

        # Generate filename
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_filename = f"CYFOR_Report_{case_id}_{timestamp_str}.pdf"
        pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)

        # Save to uploads folder
        with open(pdf_path, 'wb') as f:
            f.write(buffer.getvalue())

        # Create response with cleanup
        @after_this_request
        def cleanup(response):
            try:
                if os.path.exists(pdf_path):
                    os.remove(pdf_path)
            except Exception:
                pass
            return response

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype='application/pdf'
        )

    except Exception as e:
        app.logger.error(f"Report generation error: {str(e)}")
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500


# ============================================================
# MAIN ENTRY POINT
# ============================================================

if __name__ == '__main__':
    # Run in debug mode for development
    app.run(debug=True, host='0.0.0.0', port=5000)
