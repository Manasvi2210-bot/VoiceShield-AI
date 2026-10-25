"""
upload_security.py – Audio upload validation, signature verification, and secure path handling.

This module provides multi-layer verification for audio uploads:
1. Extension allowlist check against permitted formats.
2. File size boundary enforcement (rejection of 0-byte empty files and oversized streams).
3. Binary container signature (magic byte) inspection.
4. Cryptographically randomized storage names (UUIDv4) decoupling original filenames from disk paths.

LIMITATION NOTE:
Binary signature inspection verifies container magic bytes at the byte level. Complete bitstream
and codec validation requires an audio decoder (e.g. ffmpeg/libsndfile). Decode verification
is performed during acoustic feature extraction.
"""

import os
import uuid
from typing import Tuple, Dict, Any
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

ALLOWED_EXTENSIONS = {"wav", "mp3", "ogg", "flac", "m4a", "webm"}


def _check_signature(ext: str, header: bytes) -> bool:
    """Verify leading magic bytes match claimed audio container extension."""
    if ext == "wav":
        # RIFF header with WAVE format descriptor at offset 8
        return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE"

    elif ext == "mp3":
        # ID3v2 container tag OR raw MPEG Audio Layer III sync word (11 bits set: 0xFF followed by 0b111xxxxx)
        if header.startswith(b"ID3"):
            return True
        if len(header) >= 2 and header[0] == 0xFF:
            second_byte = header[1]
            # MPEG frame sync: 11 bits set (first byte 0xFF, top 3 bits of second byte 0b111)
            # layer check: bits 1-2 must not be 0b00 (reserved)
            is_sync = (second_byte & 0xE0) == 0xE0
            is_valid_layer = ((second_byte >> 1) & 0x03) != 0
            return is_sync and is_valid_layer
        return False

    elif ext == "ogg":
        # Ogg container capture pattern: 'OggS'
        return header.startswith(b"OggS")

    elif ext == "flac":
        # Free Lossless Audio Codec stream marker: 'fLaC'
        return header.startswith(b"fLaC")

    elif ext == "m4a":
        # ISO Base Media File Format box structure: size (4 bytes) + 'ftyp' (4 bytes)
        return len(header) >= 8 and header[4:8] == b"ftyp"

    elif ext == "webm":
        # Matroska / EBML header ID: 0x1A 0x45 0xDF 0xA3
        return header.startswith(b"\x1a\x45\xdf\xa3")

    return False


def validate_audio_upload(
    file_storage: FileStorage,
    max_size_bytes: int = 50 * 1024 * 1024,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Perform deep validation of an uploaded audio file.

    Returns:
        (is_valid: bool, error_message_or_ok: str, metadata: dict)
    """
    if file_storage is None or not file_storage.filename:
        return False, "No file was selected for upload.", {}

    filename = file_storage.filename.strip()
    if "." not in filename:
        return False, "File name must include a valid audio extension.", {}

    ext = filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        allowed_list = ", ".join(sorted(ALLOWED_EXTENSIONS))
        return False, f"Unsupported file extension '.{ext}'. Allowed formats: {allowed_list}", {}

    # File size validation via stream seeking
    stream = file_storage.stream
    try:
        stream.seek(0, os.SEEK_END)
        file_size = stream.tell()
        stream.seek(0)
    except Exception as exc:
        return False, f"Unable to determine upload file size: {exc}", {}

    if file_size == 0:
        return False, "The uploaded audio file is empty (0 bytes). Please upload a valid recording.", {}

    if file_size > max_size_bytes:
        max_mb = max_size_bytes // (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        return False, f"File exceeds maximum size limit of {max_mb} MB (received {actual_mb:.2f} MB).", {}

    # Read leading header bytes for magic signature inspection
    try:
        header = stream.read(64)
        stream.seek(0)  # Always reset stream pointer for subsequent saving
    except Exception as exc:
        return False, f"Unable to read file header: {exc}", {}

    if len(header) < 4:
        return False, "File header is corrupted or too short to identify as valid audio.", {}

    if not _check_signature(ext, header):
        return (
            False,
            f"File content signature does not match claimed format '.{ext}' (corrupted, empty, or disguised non-audio file).",
            {"claimed_extension": ext, "file_size": file_size},
        )

    metadata = {
        "extension": ext,
        "file_size": file_size,
        "original_display_name": secure_filename(filename) or f"recording.{ext}",
    }
    return True, "File signature and headers validated successfully.", metadata


def generate_secure_storage_name(original_filename: str) -> Tuple[str, str]:
    """
    Generate an unguessable storage name and sanitized display name.

    Returns:
        (disk_filename: str, display_name: str)
    """
    ext = original_filename.rsplit(".", 1)[-1].lower() if "." in original_filename else "bin"
    disk_filename = f"{uuid.uuid4().hex}.{ext}"
    display_name = secure_filename(original_filename) or f"recording.{ext}"
    return disk_filename, display_name
