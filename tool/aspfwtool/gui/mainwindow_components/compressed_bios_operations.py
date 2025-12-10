# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
compressed bios (TypeId 0x62) operations

"""


from __future__ import annotations

import re
import zlib
from math import gcd
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Tuple
from uuid import UUID

from ...agesa.directory import list_entry_ranges
from ...utils.debug_logger import get_logger

from .qt import (
    QFileDialog,
    QMessageBox,
)

from ...uefi import (
    FirmwareMutationError,
    insert_ffs_file,
    replace_ffs_file,
    remove_ffs_file,
    scan_firmware_volumes,
    enumerate_volumes,
    lookup_guid_name,
)

if TYPE_CHECKING:
    from .controller import MainWindow
    from .models import LoadedImage


# Alignment enum -> byte alignment table from FFS spec
ALIGN_TABLE = {
    0: 1,  # no special requirement
    1: 16,
    2: 128,
    3: 512,
    4: 1024,
    5: 4096,
    6: 32768,
    7: 65536,
}

PAD_GUID = UUID("ffffffff-ffff-ffff-ffff-ffffffffffff")
SEC_CORE_GUID = UUID("1ba0062e-c779-4582-8566-336ae8f78f09")


class CompressedBiosOperationsMixin:
    """Mixin providing compressed BIOS entry (type 0x62) operations."""

    def _is_compressed_bios_edit(self: "MainWindow", payload: dict) -> bool:
        """Check if a payload targets a compressed BIOS entry (0x62) via PSP tab.

        Returns True only if:
        1. The item has compressed_bios_info (it's inside a 0x62 entry)
        2. The operation was initiated from the PSP tab (context_tag == "psp")

        This distinction is important because items inside 0x62 can appear in both tabs,
        but only PSP tab edits should bypass the soft lock (since that's the correct workflow).
        """
        if not payload.get("compressed_bios_info"):
            return False
        # Must be from PSP tab to count as a proper compressed BIOS edit
        return payload.get("context_tag") == "psp"

    def _capture_0x62_original_state(
        self: "MainWindow",
        image: "LoadedImage",
        bios_info: dict,
    ) -> dict:
        """
        Capture the original state of a 0x62 BIOS entry for undo support.

        This saves all the data needed to restore the entry to its original state:
        - The compressed blob (or uncompressed blob if not compressed)
        - Directory entry bytes
        - Header and metadata

        Args:
            image: LoadedImage containing the firmware
            bios_info: Compressed BIOS info dict from payload

        Returns:
            Dict containing original state for undo
        """
        source_offset = bios_info.get("source_offset", 0)
        entry_offset = bios_info.get("entry_offset")
        compressed_size = bios_info.get("compressed_size", 0)
        decompressed_size = bios_info.get("decompressed_size", 0)
        destination = bios_info.get("destination", 0)
        zlib_offset = bios_info.get("zlib_offset", 0x100)

        # Determine actual size to capture
        is_compressed = compressed_size > 0
        if is_compressed:
            # For compressed entries, we need to capture the actual compressed blob
            # Use _decompress_bios_entry_ex to get the actual size
            decompress_result = self._decompress_bios_entry_ex(image.data, bios_info)
            if decompress_result:
                _, actual_compressed_size, actual_zlib_offset = decompress_result
                blob_size = actual_compressed_size
            else:
                blob_size = compressed_size
        else:
            blob_size = decompressed_size

        # Capture the compressed/uncompressed blob
        original_blob = (
            bytes(image.data[source_offset : source_offset + blob_size])
            if blob_size > 0
            else b""
        )

        # Capture the directory entry (24 bytes for BHD/BL2)
        original_entry_bytes = b""
        if entry_offset is not None:
            original_entry_bytes = bytes(image.data[entry_offset : entry_offset + 24])

        return {
            "source_offset": source_offset,
            "entry_offset": entry_offset,
            "compressed_size": compressed_size,
            "actual_blob_size": blob_size,
            "decompressed_size": decompressed_size,
            "destination": destination,
            "zlib_offset": zlib_offset,
            "original_blob": original_blob,
            "original_entry_bytes": original_entry_bytes,
            "is_compressed": is_compressed,
        }

    def _queue_0x62_action(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        bios_info: dict,
        action_type: str,
        original_state: dict,
        change_desc: str,
        *,
        file_guid: Optional[UUID] = None,
        relocated: bool = False,
        new_source_offset: Optional[int] = None,
        new_compressed_size: int = 0,
        target_file_index: Optional[int] = None,
        target_offset: Optional[int] = None,
        removed_file_context: Optional[dict] = None,
    ) -> None:
        """Queue a 0x62 BIOS entry action for undo support.

        Args:
            image: LoadedImage containing the firmware
            image_idx: Index of the image
            bios_info: Compressed BIOS info dict
            action_type: Type of action ("replace", "insert", "remove")
            original_state: Dict from _capture_0x62_original_state
            change_desc: Description of the change
            file_guid: GUID of the file being modified (optional)
            relocated: Whether the entry was relocated
            new_source_offset: New source offset if relocated
            new_compressed_size: New compressed size after modification
        """
        directory_index = bios_info.get("directory_index", -1)
        entry_index = bios_info.get("entry_index", -1)

        logger = get_logger()
        logger.debug(
            f"_queue_0x62_action: dir={directory_index}, entry={entry_index}, action={action_type}"
        )
        logger.debug(f"  bios_info keys: {list(bios_info.keys())}")

        if directory_index < 0 or entry_index < 0:
            logger.debug(
                f"  SKIPPING: invalid indices (dir={directory_index}, entry={entry_index})"
            )
            return

        action_id = self._allocate_action_id()
        key = (directory_index, entry_index)

        # Check if there's already a pending action for this entry
        # If so, preserve the ORIGINAL original_state (for proper undo to initial state)
        # and accumulate change descriptions
        existing_action = image.pending_entry_actions.get(key)
        if existing_action and existing_action.get("is_0x62_edit"):
            # Keep the first original_state so undo restores to initial state
            preserved_original_state = existing_action.get(
                "original_state", original_state
            )
            # Accumulate change descriptions
            existing_desc = existing_action.get("change_desc", "")
            accumulated_desc = (
                f"{existing_desc}; {change_desc}" if existing_desc else change_desc
            )
            # Track all actions for display
            action_count = existing_action.get("action_count", 1) + 1
            combined_action_text = f"Modify ({action_count})"
            logger.debug(f"  Merging with existing action: count={action_count}")
        else:
            preserved_original_state = original_state
            accumulated_desc = change_desc
            action_count = 1
            combined_action_text = action_type.capitalize()

        pending_action = {
            "action": action_type,
            "action_id": action_id,
            "image_index": image_idx,
            "directory_index": directory_index,
            "entry_index": entry_index,
            "is_0x62_edit": True,
            "bios_info": bios_info.copy(),
            "original_state": preserved_original_state,  # Use preserved state for undo
            "relocated": relocated,
            "new_source_offset": new_source_offset,
            "new_compressed_size": new_compressed_size,
            "change_desc": accumulated_desc,
            "action_text": combined_action_text,
            "action_count": action_count,
            "file_guid": str(file_guid) if file_guid else None,
            "target_file_index": target_file_index,
            "target_offset": target_offset,
            "removed_file_context": removed_file_context,
        }

        image.pending_entry_actions[key] = pending_action

        # Log the queued action
        self._append_console(f"Queued {action_type}: {change_desc}")
        logger.debug(f"  Added to pending_entry_actions: key={key}")
        logger.debug(
            f"  pending_entry_actions now has {len(image.pending_entry_actions)} entries"
        )

        # Update visual marker
        if hasattr(self, "psp_tab_controller"):
            self.psp_tab_controller.record_modification(
                image_idx,
                directory_index,
                entry_index,
                action_text=combined_action_text,
            )
            logger.debug("  Called record_modification")

    def _calculate_adjusted_bios_destination(
        self: "MainWindow",
        old_destination: int,
        old_decompressed_size: int,
        new_decompressed_size: int,
    ) -> int:
        """
        Calculate new destination address to keep reset vector fixed.

        For AMD Secured Boot entry 0x62 (reset_image=True):
            Reset Vector = destination + decompressed_size - 0x10

        When decompressed size changes, adjust destination so reset vector
        stays at the same address:
            new_destination = old_destination + old_size - new_size

        Args:
            old_destination: Original destination address from entry
            old_decompressed_size: Original decompressed size
            new_decompressed_size: New decompressed size after edit

        Returns:
            Adjusted destination address
        """
        # Reset vector address (must stay fixed)
        reset_vector = old_destination + old_decompressed_size - 0x10
        # New destination to keep reset vector at same address
        new_destination = reset_vector + 0x10 - new_decompressed_size
        return new_destination

    def _decompress_bios_entry(
        self: "MainWindow",
        image_data: bytearray,
        bios_info: dict,
    ) -> Optional[bytes]:
        """
        Decompress a compressed BIOS entry (type 0x62).

        Args:
            image_data: Full firmware image data
            bios_info: Compressed BIOS info dict from payload

        Returns:
            Decompressed data or None on failure
        """
        result = self._decompress_bios_entry_ex(image_data, bios_info)
        return result[0] if result else None

    def _decompress_bios_entry_ex(
        self: "MainWindow",
        image_data: bytearray,
        bios_info: dict,
    ) -> Optional[Tuple[bytes, int, int]]:
        """
        Decompress a compressed BIOS entry and return actual sizes.

        The 0x100-byte header has:
        - Offset 0x14: compressed size (4 bytes, little-endian) - zlib stream only
        - Offset 0x18: decompressed size (4 bytes, little-endian)

        Args:
            image_data: Full firmware image data
            bios_info: Compressed BIOS info dict from payload

        Returns:
            Tuple of (decompressed_data, actual_compressed_size, zlib_offset) or None
            The actual_compressed_size is the total blob size (header + zlib stream)
        """
        source_offset = bios_info.get("source_offset")
        zlib_offset = bios_info.get("zlib_offset", 0x100)

        if source_offset is None:
            return None
        if source_offset < 0 or source_offset >= len(image_data):
            return None

        # Read a large chunk to find the actual zlib stream size
        max_reasonable = min(len(image_data) - source_offset, 0x1000000)  # Max 16MB
        blob = bytes(image_data[source_offset : source_offset + max_reasonable])

        # Try decompression at various offsets
        for start in (zlib_offset, 0x100, 0x20, 0):
            if start >= len(blob):
                continue
            chunk = blob[start:]
            # Try with zlib header
            for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                try:
                    # Use decompressobj to get unconsumed_tail
                    dec = zlib.decompressobj(wbits)
                    decompressed = dec.decompress(chunk)
                    # Finish decompression (may have more data in buffer)
                    decompressed += dec.flush()

                    # Calculate actual compressed size:
                    # chunk_len - unconsumed_tail = bytes consumed by zlib
                    consumed = len(chunk) - len(dec.unconsumed_tail)

                    # Always use actual consumed bytes as the authoritative size.
                    # The header value at 0x14 may include padding or be slightly off.
                    actual_compressed_size = start + consumed

                    return (decompressed, actual_compressed_size, start)
                except zlib.error:
                    continue

        return None

    def _detect_zlib_settings(
        self: "MainWindow",
        compressed_data: bytes,
    ) -> Tuple[int, int]:
        """
        Detect compression level and window bits from zlib header.

        zlib header format (2 bytes):
        - Byte 0: CMF (Compression Method and Flags)
          - bits 0-3: CM (Compression Method, 8 = deflate)
          - bits 4-7: CINFO (window size = 2^(CINFO+8))
        - Byte 1: FLG (Flags)
          - bits 0-4: FCHECK (checksum)
          - bit 5: FDICT (preset dictionary)
          - bits 6-7: FLEVEL (compression level)
            - 0 = fastest
            - 1 = fast
            - 2 = default
            - 3 = maximum compression

        Returns:
            Tuple of (compression_level, wbits)
        """
        if len(compressed_data) < 2:
            return 9, zlib.MAX_WBITS  # Default to max compression

        cmf = compressed_data[0]
        flg = compressed_data[1]

        # Verify it's a valid zlib header
        if (cmf * 256 + flg) % 31 != 0:
            return 9, zlib.MAX_WBITS  # Invalid header, use defaults

        # Extract compression method (should be 8 for deflate)
        cm = cmf & 0x0F
        if cm != 8:
            return 9, zlib.MAX_WBITS  # Not deflate

        # Extract window size: CINFO = (cmf >> 4)
        # Window size = 2^(CINFO + 8), max is 32KB (CINFO=7)
        cinfo = (cmf >> 4) & 0x0F
        wbits = cinfo + 8
        if wbits > zlib.MAX_WBITS:
            wbits = zlib.MAX_WBITS

        # Extract compression level from FLEVEL
        flevel = (flg >> 6) & 0x03
        # Map FLEVEL to zlib compression level
        level_map = {
            0: 1,  # fastest
            1: 5,  # fast
            2: 6,  # default
            3: 9,  # maximum compression
        }
        level = level_map.get(flevel, 9)

        return level, wbits

    def _recompress_bios_entry(
        self: "MainWindow",
        decompressed: bytes,
        original_header: bytes,
        original_compressed: Optional[bytes] = None,
    ) -> bytes:
        """
        Recompress BIOS data and prepend original header.

        The 0x100-byte header has the following relevant fields:
        - Offset 0x14: compressed size (4 bytes, little-endian)
        - Offset 0x18: decompressed size (4 bytes, little-endian)

        Args:
            decompressed: Modified decompressed data
            original_header: Original bytes before zlib stream (e.g., 0x100 bytes)
            original_compressed: Original compressed data (to detect settings)

        Returns:
            New compressed blob with updated header
        """
        # Detect original compression settings
        level = 9
        wbits = zlib.MAX_WBITS

        if original_compressed and len(original_compressed) >= 2:
            level, wbits = self._detect_zlib_settings(original_compressed)

        # Create compressor with detected settings
        compressor = zlib.compressobj(level=level, wbits=wbits)
        compressed = compressor.compress(decompressed) + compressor.flush()

        # Update header with new sizes
        header = bytearray(original_header)
        if len(header) >= 0x1C:
            # Update compressed size at offset 0x14 (size of zlib stream only)
            compressed_size = len(compressed)
            header[0x14:0x18] = compressed_size.to_bytes(4, "little")
            # Update decompressed size at offset 0x18
            decompressed_size = len(decompressed)
            header[0x18:0x1C] = decompressed_size.to_bytes(4, "little")

        return bytes(header) + compressed

    def _update_ffs_wrapper_headers(
        self: "MainWindow",
        image_data: bytearray,
        source_offset: int,
        new_compressed_total_size: int,
    ) -> bool:
        """
        Update FFS file and GUID-defined section headers when compressed size changes.

        The 0x62 entry data is wrapped in UEFI structures:
        - FFS file header at source_offset - 0x30 (24 bytes)
        - GUID-defined section header at source_offset - 0x18 (24 bytes)
        - 0x100-byte AMD header + zlib data at source_offset

        The FFS file and section sizes must be updated when compressed data changes.

        Args:
            image_data: Firmware image to modify
            source_offset: Offset where the 0x100-byte header starts
            new_compressed_total_size: New size of header (0x100) + zlib data

        Returns:
            True if headers were updated, False if not found/invalid
        """
        # Expected structure:
        # [FFS header 0x18][Section header 0x18][0x100 header][zlib data]
        # FFS header is at source_offset - 0x30
        # Section header is at source_offset - 0x18

        ffs_offset = source_offset - 0x30
        section_offset = source_offset - 0x18

        if ffs_offset < 0 or section_offset < 0:
            return False

        # Verify FFS file header by checking for known GUID
        # AMD compressed BIOS FFS GUID: 3e3b6dc0-064d-4b01-9203-7836c9b498e7
        expected_ffs_guid = bytes.fromhex("c06d3b3e4d06014b92037836c9b498e7")
        ffs_guid = bytes(image_data[ffs_offset : ffs_offset + 16])

        if ffs_guid != expected_ffs_guid:
            # Not an FFS-wrapped entry, skip
            return False

        # Verify section is GUID-defined (type 0x02)
        section_type = image_data[section_offset + 3]
        if section_type != 0x02:
            return False

        # Calculate new sizes
        # Section size = section header (0x18) + data size
        new_section_size = 0x18 + new_compressed_total_size
        # FFS file size = FFS header (0x18) + section size
        new_ffs_size = 0x18 + new_section_size

        # Check if sizes fit in 3 bytes (max 0xFFFFFF)
        if new_ffs_size > 0xFFFFFF or new_section_size > 0xFFFFFF:
            # Would need extended headers, not supported
            return False

        # Update FFS file size at offset 0x14 (3 bytes)
        image_data[ffs_offset + 0x14 : ffs_offset + 0x17] = new_ffs_size.to_bytes(
            3, "little"
        )

        # Update section size at offset 0x00 (3 bytes)
        image_data[section_offset : section_offset + 3] = new_section_size.to_bytes(
            3, "little"
        )

        # Recalculate FFS header checksum
        # The checksum is stored in two parts at offset 0x10-0x11:
        # - Header checksum (byte 0x10): sum of header bytes 0x00-0x17 except 0x10-0x11 and 0x17
        # - File checksum (byte 0x11): for type 0x0B, this is 0xAA (FFS_FIXED_CHECKSUM)
        header_sum = 0
        for i in range(0x18):
            if i == 0x10 or i == 0x11 or i == 0x17:
                continue
            header_sum = (header_sum + image_data[ffs_offset + i]) & 0xFF
        header_checksum = (0x100 - header_sum) & 0xFF
        image_data[ffs_offset + 0x10] = header_checksum
        # File checksum is 0xAA for files with FFS_ATTRIB_CHECKSUM not set
        image_data[ffs_offset + 0x11] = 0xAA

        return True

    def _update_bios_entry_in_directory(
        self: "MainWindow",
        image_data: bytearray,
        bios_info: dict,
        new_decompressed_size: int,
        new_destination: int,
    ) -> bool:
        """
        Update a BIOS directory entry's size and destination fields.

        BHD/BL2 entry format (24 bytes):
            0x00: type_id (4 bytes)
            0x04: size (4 bytes) - for 0x62: decompressed blob size
            0x08: source (8 bytes) - flash offset (ptr64)
            0x10: destination (8 bytes) - memory load address

        For AMD Secured Boot 0x62 entries:
            - size = decompressed blob size (pre-FV header + FV data)
            - This is used for memory region window size and reset vector calc
            - Reset vector = destination + size - 0x10

        Args:
            image_data: Firmware image to modify
            bios_info: Compressed BIOS info dict
            new_decompressed_size: New decompressed blob size (pre-FV header + FV)
            new_destination: New destination address to write

        Returns:
            True on success
        """
        entry_offset = bios_info.get("entry_offset")
        if entry_offset is None:
            return False

        # Entry structure: type(4) + size(4) + source(8) + destination(8) = 24 bytes
        if entry_offset < 0 or entry_offset + 24 > len(image_data):
            return False

        # The directory size field stores the decompressed blob size
        # This is the size of the pre-FV header (0x20) + FV data
        # NOT the compressed size or the AMD header size
        directory_size = new_decompressed_size
        if directory_size < 0:
            directory_size = 0

        # Update size field at offset +4
        image_data[entry_offset + 4 : entry_offset + 8] = directory_size.to_bytes(
            4, "little"
        )

        # Update destination field at offset +16
        image_data[entry_offset + 16 : entry_offset + 24] = new_destination.to_bytes(
            8, "little"
        )

        return True

    def _update_bios_entry_source(
        self: "MainWindow",
        image_data: bytearray,
        entry_offset: int,
        new_source_offset: int,
        new_decompressed_size: int,
        new_destination: int,
    ) -> bool:
        """
        Update a BIOS directory entry's source, size, and destination fields.

        BHD/BL2 entry format (24 bytes):
            0x00: type_id (4 bytes)
            0x04: size (4 bytes) - for 0x62: decompressed blob size
            0x08: source/ptr64 (8 bytes) - flash offset
            0x10: destination (8 bytes) - memory address

        For AMD Secured Boot 0x62 entries:
            - size = decompressed blob size (pre-FV header + FV data)
            - Reset vector = destination + size - 0x10

        Args:
            image_data: Firmware image to modify
            entry_offset: Offset to entry in directory
            new_source_offset: New flash offset for the data
            new_decompressed_size: New decompressed blob size (pre-FV header + FV)
            new_destination: New destination address

        Returns:
            True on success
        """
        if entry_offset < 0 or entry_offset + 24 > len(image_data):
            return False

        # The directory size field stores the decompressed blob size
        # This is the size of the pre-FV header (0x20) + FV data
        directory_size = new_decompressed_size
        if directory_size < 0:
            directory_size = 0

        # Update size field at offset +4
        image_data[entry_offset + 4 : entry_offset + 8] = directory_size.to_bytes(
            4, "little"
        )

        # Update source/ptr64 field at offset +8
        # Use mode 1 (direct flash offset): bits 62-63 = 01
        new_ptr64 = (1 << 62) | new_source_offset
        image_data[entry_offset + 8 : entry_offset + 16] = new_ptr64.to_bytes(
            8, "little"
        )

        # Update destination field at offset +16
        image_data[entry_offset + 16 : entry_offset + 24] = new_destination.to_bytes(
            8, "little"
        )

        return True

    def _collect_used_ranges(
        self: "MainWindow",
        image: "LoadedImage",
    ) -> List[Tuple[int, int]]:
        """
        Collect all used byte ranges in the firmware image.

        This includes:
        - PSP/BIOS directory entries (using list_entry_ranges)
        - UEFI firmware volumes and files
        - EFS regions
        - Known headers and structures

        Returns:
            Sorted list of (start, end) tuples representing used ranges
        """
        used: List[Tuple[int, int]] = []
        data = image.data
        file_size = len(data)

        # Collect ranges from all PSP/BIOS directories
        for directory in image.directories:
            # Add all entry payloads
            for start, end in list_entry_ranges(bytes(data), directory):
                if 0 <= start < end <= file_size:
                    used.append((start, end))

        # Collect ranges from UEFI regions
        for root in image.uefi_roots:
            if root.offset is not None and root.size > 0:
                used.append((root.offset, root.offset + root.size))
            for volume in root.volumes:
                vol_off = volume.info.absolute_offset
                vol_size = volume.info.size
                if vol_off is not None and vol_size > 0:
                    used.append((vol_off, vol_off + vol_size))

        # Collect ranges from EFS (if any)
        for efs in image.efs_infos:
            efs_off = getattr(efs, "offset", None)
            efs_size = getattr(efs, "size", None)
            if efs_off is not None and efs_size is not None and efs_size > 0:
                used.append((efs_off, efs_off + efs_size))

        # Sort and merge overlapping ranges
        used.sort(key=lambda t: t[0])
        merged: List[Tuple[int, int]] = []
        for start, end in used:
            if not merged or start > merged[-1][1]:
                merged.append((start, end))
            else:
                # Extend the previous range if overlapping
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))

        return merged

    def _is_empty_region(
        self: "MainWindow",
        data: bytes,
        start: int,
        size: int,
    ) -> bool:
        """
        Check if a region contains only 0xFF bytes (empty flash).

        Args:
            data: Firmware image data
            start: Start offset
            size: Size to check

        Returns:
            True if all bytes are 0xFF
        """
        if start < 0 or start + size > len(data):
            return False
        region = data[start : start + size]
        # Check in chunks for efficiency
        return all(b == 0xFF for b in region)

    def _find_free_space_for_relocation(
        self: "MainWindow",
        image: "LoadedImage",
        required_size: int,
        alignment: int = 0x1000,
        exclude_start: int = 0,
        exclude_end: int = 0,
    ) -> Optional[int]:
        """
        Find a free region suitable for relocating a compressed BIOS entry.

        Searches for empty (0xFF) regions that:
        - Are NOT inside any PSP/BIOS entry
        - Are NOT inside any UEFI firmware volume
        - Have enough contiguous space for the required size
        - Are aligned to the specified alignment

        Args:
            image: LoadedImage with firmware data
            required_size: Minimum size needed (will be aligned up)
            alignment: Address alignment requirement (default 4KB)
            exclude_start: Original entry location start (to exclude from search)
            exclude_end: Original entry location end

        Returns:
            Flash offset where the entry can be relocated, or None if no space found
        """
        data = image.data
        file_size = len(data)

        # Align required size up
        aligned_size = ((required_size + alignment - 1) // alignment) * alignment

        # Get all used ranges
        used_ranges = self._collect_used_ranges(image)

        # Build list of gaps (potential free regions)
        gaps: List[Tuple[int, int]] = []
        prev_end = 0
        for start, end in used_ranges:
            if start > prev_end:
                gaps.append((prev_end, start))
            prev_end = max(prev_end, end)
        # Add final gap to end of file
        if prev_end < file_size:
            gaps.append((prev_end, file_size))

        # Search gaps for suitable free space
        candidates: List[Tuple[int, int]] = []  # (offset, size)

        for gap_start, gap_end in gaps:
            # Skip if this gap overlaps with the excluded region (original entry)
            if exclude_end > 0 and not (
                gap_end <= exclude_start or gap_start >= exclude_end
            ):
                continue

            # Align the start offset
            aligned_start = ((gap_start + alignment - 1) // alignment) * alignment
            if aligned_start >= gap_end:
                continue

            available = gap_end - aligned_start
            if available < aligned_size:
                continue

            # Verify the region is actually empty (all 0xFF)
            if not self._is_empty_region(bytes(data), aligned_start, aligned_size):
                # Region has data, try to find a subregion that's empty
                # Scan in alignment-sized chunks
                for offset in range(
                    aligned_start, gap_end - aligned_size + 1, alignment
                ):
                    if self._is_empty_region(bytes(data), offset, aligned_size):
                        candidates.append((offset, aligned_size))
                        break
            else:
                candidates.append((aligned_start, available))

        if not candidates:
            return None

        # Prefer the largest free region (more room for future resize)
        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[0][0]

    def _relocate_compressed_bios_entry(
        self: "MainWindow",
        image: "LoadedImage",
        bios_info: dict,
        new_compressed_data: bytes,
        new_decompressed_size: int,
        new_destination: int,
    ) -> Optional[int]:
        """
        Relocate a compressed BIOS entry to a new location.

        This function:
        1. Finds free space in the firmware image
        2. Writes the new compressed data to the free space
        3. Updates the directory entry's source pointer (ptr64)
        4. Updates the entry's size and destination
        5. Optionally fills the old location with 0xFF

        Args:
            image: LoadedImage with firmware data
            bios_info: Compressed BIOS info dict
            new_compressed_data: New compressed data to write
            new_decompressed_size: New decompressed blob size (including 0x100 header)
            new_destination: New destination address (for reset vector adjustment)

        Returns:
            New flash offset where data was written, or None on failure
        """
        old_offset = bios_info.get("source_offset", 0)
        old_size = bios_info.get("compressed_size", 0)
        new_compressed_size = len(new_compressed_data)

        # Find free space
        new_offset = self._find_free_space_for_relocation(
            image,
            new_compressed_size,
            alignment=0x1000,  # 4KB alignment
            exclude_start=old_offset,
            exclude_end=old_offset + old_size,
        )

        if new_offset is None:
            return None

        # Write new data to the new location
        image.data[new_offset : new_offset + new_compressed_size] = new_compressed_data

        # Fill old location with 0xFF
        image.data[old_offset : old_offset + old_size] = b"\xff" * old_size

        # Update directory entry
        entry_offset = bios_info.get("entry_offset")
        if entry_offset is not None:
            # The directory size field stores decompressed blob size
            # This is the size of the pre-FV header (0x20) + FV data
            directory_size = new_decompressed_size
            if directory_size < 0:
                directory_size = 0

            # Update size (offset +4, 4 bytes)
            image.data[entry_offset + 4 : entry_offset + 8] = directory_size.to_bytes(
                4, "little"
            )

            # Update source/ptr64 (offset +8, 8 bytes)
            # For mode 1 (direct flash offset), set bits 62-63 to 01 and offset in low bits
            new_ptr64 = (1 << 62) | new_offset  # Mode 1 = direct flash offset
            image.data[entry_offset + 8 : entry_offset + 16] = new_ptr64.to_bytes(
                8, "little"
            )

            # Update destination (offset +16, 8 bytes)
            image.data[entry_offset + 16 : entry_offset + 24] = (
                new_destination.to_bytes(8, "little")
            )

        return new_offset

    def _insert_pad_before_index(
        self: "MainWindow",
        blob: bytearray,
        volume,
        file_index: int,
        pad_size: int,
        *,
        state: int = 0xF8,
    ):
        """
        Insert a PAD FFS before volume.files[file_index].

        pad_size is the *total* FFS file size (header + body), already
        rounded to 8 bytes.
        """
        # Minimum FFS header size is 24 bytes
        if pad_size < 24:
            pad_size = 24

        body_size = max(pad_size - 24, 0)
        pad_body = b"\xff" * body_size

        new_volume = insert_ffs_file(
            blob,
            volume,
            file_index,
            pad_body,
            guid=PAD_GUID,
            file_type=0xF0,  # EFI_FV_FILETYPE_FFS_PAD
            attributes=0x00,  # pad file itself has no alignment requirement
            state=state,
        )
        return new_volume

    def _fix_file_alignment_in_volume(
        self: "MainWindow",
        blob: bytearray,
        volume,
        *,
        only_guid: Optional[UUID] = None,
    ):
        """
        Ensure that files with non-zero alignment requirements are actually aligned.

        If only_guid is given, only fix that file (e.g. SecCore VolumeTopFile).

        For SecCore_VolumeTopFile specifically, we insert any required padding
        *before* the preceding FFS_PAD file (the "Startup AP data padding file")
        so that the AP padding file and SecCore stay adjacent.
        """
        files = list(volume.files)
        i = 0
        while i < len(files):
            f = files[i]

            if only_guid is not None and getattr(f, "guid", None) != only_guid:
                i += 1
                continue

            attrs = int(getattr(f, "attributes", 0))
            align_enum = (attrs & 0x38) >> 3
            if align_enum == 0:
                i += 1
                continue

            required = ALIGN_TABLE.get(align_enum, 1)
            if required <= 1:
                i += 1
                continue

            # FFS alignment is relative to the start of the firmware volume
            # file_rel = offset from FV base to FFS header
            # header_size = FFS header size (24 bytes standard)
            # data_offset_in_fv = offset from FV base to file DATA
            file_rel = int(f.relative_offset)  # offset (from FV base) to FFS header
            header_size = 0x18  # assume standard 24-byte FFS header
            data_offset_in_fv = file_rel + header_size

            mis = data_offset_in_fv % required
            if mis == 0:
                i += 1
                continue  # already properly aligned

            # We want (data_offset + P) % required == 0
            needed = (required - mis) % required  # 0..required-1

            # Find pad file size P such that:
            #   P % required == needed, P % 8 == 0, P >= 24
            P: Optional[int] = None
            for k in range(0, 16):
                candidate = needed + k * required
                if candidate < 24:
                    continue
                if candidate % 8 != 0:
                    continue
                P = candidate
                break

            if P is None:
                # Fallback: use LCM(required, 8)
                step = (required * 8) // gcd(required, 8)
                P = max(24, ((needed + step - 1) // step) * step)

            # Decide where to insert the pad:
            # - In the general case, insert directly before this file.
            # - If this is SecCore, try to insert before the preceding FFS_PAD
            #   (Startup AP data padding file) so they stay together.
            insert_idx = i
            if getattr(f, "guid", None) == SEC_CORE_GUID:
                anchor_idx = None
                j = i - 1
                while j >= 0:
                    prev_f = files[j]
                    ftype = getattr(prev_f, "file_type", getattr(prev_f, "type", None))
                    if ftype == 0xF0:  # EFI_FV_FILETYPE_FFS_PAD
                        anchor_idx = j
                        j -= 1
                        continue
                    break
                if anchor_idx is not None:
                    insert_idx = anchor_idx

            volume = self._insert_pad_before_index(blob, volume, insert_idx, P)
            # Refresh file list after insertion (offsets changed)
            files = list(volume.files)
            # Restart scan so offsets/indices are always consistent
            i = 0
            continue

        return volume

    # ----------------------------------------------------------------------

    def _insert_uefi_file_compressed_bios_from_payload(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        payload: dict,
        insert_before: bool,
    ) -> None:
        """Handle insertion of a file into compressed BIOS (0x62) from payload.

        This shows the file selection dialog and then calls the insertion function.
        """
        base_dir = image.path.parent if image.path else Path.cwd()
        open_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select firmware file to insert",
            str(base_dir),
            "FFS files (*.ffs *.bin);;All files (*)",
        )
        if not open_path:
            return

        try:
            blob = Path(open_path).read_bytes()
        except Exception as exc:
            QMessageBox.critical(
                self, "Read failed", f"Unable to read the firmware file: {exc}"
            )
            return

        payload_bytes, parsed_info = self._interpret_uefi_file_blob(blob)

        # Use parsed info or default values
        if parsed_info:
            guid_value = parsed_info.guid
            type_value = parsed_info.type
            attributes_value = parsed_info.attributes
            state_value = parsed_info.state
        else:
            # Generate a random GUID for new file if not parsed
            import uuid

            guid_value = uuid.uuid4()
            type_value = 0x07  # EFI_FV_FILETYPE_DRIVER
            attributes_value = 0x00
            state_value = 0xF8

        if not isinstance(guid_value, UUID):
            guid_value = UUID(str(guid_value))

        self._insert_uefi_file_compressed_bios(
            image,
            image_idx,
            payload,
            payload_bytes,
            guid_value,
            int(type_value),
            int(attributes_value),
            int(state_value),
            insert_before,
        )

    def _insert_uefi_file_compressed_bios(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        payload: dict,
        payload_bytes: bytes,
        guid_value: UUID,
        type_value: int,
        attributes_value: int,
        state_value: int,
        insert_before: bool,
    ) -> None:
        """Insert a file into a compressed BIOS entry (type 0x62).

        Similar to _replace_uefi_file_compressed_bios but inserts a new file.
        """
        bios_info = payload.get("compressed_bios_info")
        if not bios_info:
            QMessageBox.critical(self, "Error", "Missing compressed BIOS info")
            return

        # Capture original state for undo support
        original_state = self._capture_0x62_original_state(image, bios_info)

        target_offset = payload.get("offset")
        file_index = payload.get("file_index")

        # Check if entry is compressed (compressed_size > 0 indicates zlib compression)
        is_compressed = bios_info.get("compressed_size", 0) > 0

        if is_compressed:
            # Decompress the BIOS entry and get actual compressed size
            decompress_result = self._decompress_bios_entry_ex(image.data, bios_info)
            if decompress_result is None:
                QMessageBox.critical(
                    self, "Decompression failed", "Unable to decompress the BIOS entry."
                )
                return
            decompressed, actual_compressed_size, actual_zlib_offset = decompress_result
        else:
            # Uncompressed - read directly from ROM
            source_offset = bios_info.get("source_offset", 0)
            data_size = bios_info.get("decompressed_size", 0)
            if source_offset < 0 or source_offset + data_size > len(image.data):
                QMessageBox.critical(
                    self,
                    "Read failed",
                    f"Invalid data range: offset=0x{source_offset:X}, size=0x{data_size:X}",
                )
                return
            decompressed = bytes(image.data[source_offset : source_offset + data_size])
            actual_compressed_size = 0
            actual_zlib_offset = 0

        old_decompressed_size = len(decompressed)

        # Scan for volumes
        try:
            volumes = scan_firmware_volumes(decompressed, 0, len(decompressed))
        except Exception as exc:
            QMessageBox.critical(
                self, "Parse failed", f"Unable to parse UEFI content: {exc}"
            )
            return

        if not volumes:
            QMessageBox.critical(self, "Parse failed", "No firmware volumes found")
            return

        enumerated, _, _ = enumerate_volumes(volumes)

        # Find the target volume and file position
        source_offset = bios_info.get("source_offset", 0)
        relative_target = (target_offset - source_offset) if target_offset else None

        target_volume = None
        insert_idx = 0

        for vol in enumerated:
            for idx, f in enumerate(vol.info.files):
                if f.relative_offset == relative_target or (
                    file_index is not None and idx == file_index
                ):
                    target_volume = vol.info
                    insert_idx = idx if insert_before else idx + 1
                    break
                if payload.get("guid") and f.guid == payload.get("guid"):
                    target_volume = vol.info
                    insert_idx = idx if insert_before else idx + 1
                    break
            if target_volume:
                break

        if target_volume is None:
            # Default to first volume, append at end
            if enumerated:
                target_volume = enumerated[0].info
                insert_idx = len(target_volume.files)
            else:
                QMessageBox.critical(self, "Not found", "No target volume found")
                return

        # Insert into decompressed data
        blob = bytearray(decompressed)
        try:
            target_volume = insert_ffs_file(
                blob,
                target_volume,
                insert_idx,
                payload_bytes,
                guid=guid_value,
                file_type=type_value,
                attributes=attributes_value,
                state=state_value,
            )
        except FirmwareMutationError as exc:
            # Check if it's a space issue - if so, try to resize the FV
            error_msg = str(exc)
            if "not enough free space" in error_msg:
                # Parse the shortage amount from the error message
                match = re.search(r"short by 0x([0-9A-Fa-f]+)", error_msg)
                shortage = int(match.group(1), 16) if match else 0x10000

                # Resize by the shortage plus alignment padding to ensure files stay aligned
                # Add 8 bytes for alignment safety margin
                extra_needed = shortage + 8

                # Try to resize the FV
                grown_volume = self._grow_firmware_volume_in_blob(
                    blob, target_volume, extra_needed
                )
                if grown_volume is None:
                    QMessageBox.critical(
                        self,
                        "Insertion failed",
                        f"Cannot resize firmware volume to make room for insertion.\n\n{exc}",
                    )
                    return

                logger = get_logger()
                logger.debug(
                    f"After FV resize: volume has {len(grown_volume.files)} files"
                )

                # Insert the user's blob directly
                try:
                    target_volume = insert_ffs_file(
                        blob,
                        grown_volume,
                        insert_idx,
                        payload_bytes,
                        guid=guid_value,
                        file_type=type_value,
                        attributes=attributes_value,
                        state=state_value,
                    )
                    logger.debug(
                        f"After user insertion: {len(target_volume.files)} files"
                    )
                except FirmwareMutationError as exc2:
                    QMessageBox.critical(self, "Insertion failed", str(exc2))
                    return

                # Log any remaining free space
                vol_size = int(target_volume.size)
                if target_volume.files:
                    last_file = target_volume.files[-1]
                    last_end = int(last_file.relative_offset) + int(last_file.size)
                    last_end_aligned = ((last_end + 7) // 8) * 8
                    free_space = vol_size - last_end_aligned
                    if free_space > 0:
                        logger.debug(f"Remaining free space: 0x{free_space:X} bytes")

                self._append_console(
                    f"Grew firmware volume by 0x{extra_needed:X} bytes to accommodate insertion."
                )
            else:
                QMessageBox.critical(self, "Insertion failed", str(exc))
                return

        # ---- NEW: fix SecCore alignment (or other aligned files) in this FV ----
        target_volume = self._fix_file_alignment_in_volume(
            blob,
            target_volume,
            only_guid=SEC_CORE_GUID,
        )
        # ------------------------------------------------------------------------

        new_decompressed_size = len(blob)

        # Calculate new destination
        old_destination = bios_info.get("destination", 0)
        new_destination = self._calculate_adjusted_bios_destination(
            old_destination, old_decompressed_size, new_decompressed_size
        )

        source_offset = bios_info.get("source_offset", 0)
        relocated = False
        new_source_offset = source_offset

        if is_compressed:
            # Recompress using actual compressed size from decompression
            old_compressed_size = actual_compressed_size
            original_header = bytes(
                image.data[source_offset : source_offset + actual_zlib_offset]
            )
            # Get original zlib stream to detect compression settings
            original_zlib = bytes(
                image.data[
                    source_offset + actual_zlib_offset : source_offset
                    + old_compressed_size
                ]
            )
            new_compressed = self._recompress_bios_entry(
                bytes(blob), original_header, original_zlib
            )
            new_compressed_size = len(new_compressed)
        else:
            # Uncompressed - the modified blob is the new data
            old_compressed_size = old_decompressed_size
            new_compressed = bytes(blob)
            new_compressed_size = new_decompressed_size

        if new_compressed_size > old_compressed_size:
            size_diff = new_compressed_size - old_compressed_size

            # Try to find free space for relocation
            new_location = self._find_free_space_for_relocation(
                image,
                new_compressed_size,
                alignment=0x1000,
                exclude_start=source_offset,
                exclude_end=source_offset + old_compressed_size,
            )

            if new_location is None:
                QMessageBox.critical(
                    self,
                    "Size overflow - No free space",
                    f"The recompressed BIOS image is 0x{size_diff:X} bytes larger.\n\n"
                    f"Original compressed: 0x{old_compressed_size:X}\n"
                    f"New compressed: 0x{new_compressed_size:X}\n\n"
                    f"No suitable empty region (0xFF bytes) found for relocation.\n"
                    f"Consider removing unused files first.",
                )
                return

            # Confirm relocation with user
            reply = QMessageBox.question(
                self,
                "Relocation Required",
                f"The modified BIOS image is 0x{size_diff:X} bytes larger.\n\n"
                f"Original location: 0x{source_offset:X} (size: 0x{old_compressed_size:X})\n"
                f"New location found: 0x{new_location:X} (size: 0x{new_compressed_size:X})\n\n"
                f"The entry will be relocated to empty flash space.\n"
                f"Original location will be filled with 0xFF.\n\n"
                f"Proceed with relocation?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )

            if reply != QMessageBox.StandardButton.Yes:
                return

            relocated = True
            new_source_offset = new_location

            # Write new data to new location
            image.data[new_location : new_location + new_compressed_size] = (
                new_compressed
            )

            # Fill old location with 0xFF (including old FFS wrapper)
            old_ffs_start = source_offset - 0x30
            old_total_size = old_compressed_size + 0x30
            if old_ffs_start >= 0:
                image.data[old_ffs_start : old_ffs_start + old_total_size] = (
                    b"\xff" * old_total_size
                )
            else:
                image.data[source_offset : source_offset + old_compressed_size] = (
                    b"\xff" * old_compressed_size
                )

            # Update directory entry with new source, size, and destination
            entry_offset = bios_info.get("entry_offset")
            if entry_offset is not None:
                self._update_bios_entry_source(
                    image.data,
                    entry_offset,
                    new_location,
                    new_decompressed_size,
                    new_destination,
                )
        else:
            # Fits in original space - pad and write in place
            if new_compressed_size < old_compressed_size:
                new_compressed = new_compressed + (
                    b"\xff" * (old_compressed_size - new_compressed_size)
                )

            image.data[source_offset : source_offset + old_compressed_size] = (
                new_compressed
            )

            # Update FFS wrapper headers
            self._update_ffs_wrapper_headers(
                image.data, source_offset, new_compressed_size
            )

            # Always update directory entry to ensure size and destination are correct
            # Even if sizes match, we should update to ensure consistency
            self._update_bios_entry_in_directory(
                image.data, bios_info, new_decompressed_size, new_destination
            )

        # Finalize
        guid_text = str(guid_value) if guid_value else "file"

        # Calculate reset vector addresses for verification
        old_reset_vector = old_destination + old_decompressed_size - 0x10
        new_reset_vector = new_destination + new_decompressed_size - 0x10

        if relocated:
            self._record_modified_range(image_idx, source_offset, old_compressed_size)
            self._record_modified_range(
                image_idx, new_source_offset, new_compressed_size
            )

            image.change_log.append(
                f"UEFI: inserted {guid_text} in compressed BIOS 0x62, "
                f"relocated 0x{source_offset:X} \u2192 0x{new_source_offset:X}"
            )

            logger = get_logger()
            logger.debug(
                f"Inserted {guid_text} in compressed BIOS entry (RELOCATED).\n"
                f"  Old location: 0x{source_offset:X} (now 0xFF filled)\n"
                f"  New location: 0x{new_source_offset:X}\n"
                f"  Decompressed size: 0x{old_decompressed_size:X} \u2192 0x{new_decompressed_size:X}\n"
                f"  Destination: 0x{old_destination:X} \u2192 0x{new_destination:X}\n"
                f"  Reset vector: 0x{old_reset_vector:X} \u2192 0x{new_reset_vector:X} (should be equal)\n"
                f"  Compressed size: 0x{old_compressed_size:X} \u2192 0x{new_compressed_size:X}"
            )
            change_desc = (
                f"UEFI: inserted {guid_text} in compressed BIOS 0x62, "
                f"relocated 0x{source_offset:X} \u2192 0x{new_source_offset:X}"
            )
        else:
            self._record_modified_range(image_idx, source_offset, old_compressed_size)

            image.change_log.append(
                f"UEFI: inserted {guid_text} in compressed BIOS 0x62"
            )

            logger = get_logger()
            logger.debug(
                f"Inserted {guid_text} in compressed BIOS entry.\n"
                f"  Decompressed size: 0x{old_decompressed_size:X} \u2192 0x{new_decompressed_size:X}\n"
                f"  Destination: 0x{old_destination:X} \u2192 0x{new_destination:X}\n"
                f"  Reset vector: 0x{old_reset_vector:X} \u2192 0x{new_reset_vector:X} (should be equal)"
            )
            change_desc = f"UEFI: inserted {guid_text} in compressed BIOS 0x62"

        # Queue the action for undo support
        self._queue_0x62_action(
            image,
            image_idx,
            bios_info,
            "insert",
            original_state,
            change_desc,
            file_guid=guid_value,
            relocated=relocated,
            new_source_offset=new_source_offset if relocated else None,
            new_compressed_size=new_compressed_size,
            target_file_index=insert_idx,
        )

        self._mark_image_dirty(image_idx)
        self._status_message(f"Queued insertion of {guid_text} in compressed BIOS 0x62")

        # Re-parse the image to pick up the modified directories
        self._reprocess_image(image_idx)
        self._rebuild_from_loaded_images()

    def _replace_uefi_file_compressed_bios_from_payload(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        payload: dict,
    ) -> None:
        """
        Handle replacement of a file inside compressed BIOS (0x62) from payload.

        This shows the file selection dialog and then calls the replacement function.
        """
        # Get file info from payload for default values
        file_guid = payload.get("guid")

        base_dir = image.path.parent if image.path else Path.cwd()
        open_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select replacement firmware file",
            str(base_dir),
            "FFS files (*.ffs *.bin);;All files (*)",
        )
        if not open_path:
            return

        try:
            blob = Path(open_path).read_bytes()
        except Exception as exc:
            QMessageBox.critical(
                self, "Read failed", f"Unable to read the firmware file: {exc}"
            )
            return

        payload_bytes, parsed_info = self._interpret_uefi_file_blob(blob)

        # Use parsed info or fall back to payload defaults
        if parsed_info:
            guid_value = parsed_info.guid
            type_value = parsed_info.type
            attributes_value = parsed_info.attributes
            state_value = parsed_info.state
        else:
            guid_value = (
                file_guid
                if isinstance(file_guid, UUID)
                else UUID(str(file_guid))
                if file_guid
                else None
            )
            type_value = 0x07  # EFI_FV_FILETYPE_DRIVER
            attributes_value = 0x00
            state_value = 0xF8

        if guid_value is None:
            QMessageBox.critical(
                self,
                "Invalid file",
                "Unable to determine GUID for the replacement file.",
            )
            return

        if not isinstance(guid_value, UUID):
            guid_value = UUID(str(guid_value))

        self._replace_uefi_file_compressed_bios(
            image,
            image_idx,
            payload,
            payload_bytes,
            guid_value,
            int(type_value),
            int(attributes_value),
            int(state_value),
        )

    def _replace_uefi_file_compressed_bios(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        payload: dict,
        payload_bytes: bytes,
        guid_value: UUID,
        type_value: int,
        attributes_value: int,
        state_value: int,
    ) -> None:
        """
        Replace a file inside a compressed BIOS entry (type 0x62).

        This handles the AMD Secured Boot case where the entire UEFI image
        is zlib-compressed inside a PSP BIOS directory entry.
        """
        bios_info = payload.get("compressed_bios_info")
        if not bios_info:
            QMessageBox.critical(self, "Error", "Missing compressed BIOS info")
            return

        # Capture original state for undo support
        original_state = self._capture_0x62_original_state(image, bios_info)

        target_offset = payload.get("offset")
        file_index = payload.get("file_index")

        # Check if entry is compressed
        is_compressed = bios_info.get("compressed_size", 0) > 0

        if is_compressed:
            decompress_result = self._decompress_bios_entry_ex(image.data, bios_info)
            if decompress_result is None:
                QMessageBox.critical(
                    self,
                    "Decompression failed",
                    "Unable to decompress the BIOS entry. The data may be corrupted.",
                )
                return
            decompressed, actual_compressed_size, actual_zlib_offset = decompress_result
        else:
            source_offset = bios_info.get("source_offset", 0)
            data_size = bios_info.get("decompressed_size", 0)
            if source_offset < 0 or source_offset + data_size > len(image.data):
                QMessageBox.critical(
                    self,
                    "Read failed",
                    f"Invalid data range: offset=0x{source_offset:X}, size=0x{data_size:X}",
                )
                return
            decompressed = bytes(image.data[source_offset : source_offset + data_size])
            actual_compressed_size = 0
            actual_zlib_offset = 0

        old_decompressed_size = len(decompressed)

        # Scan for volumes in decompressed data
        try:
            volumes = scan_firmware_volumes(decompressed, 0, len(decompressed))
        except Exception as exc:
            QMessageBox.critical(
                self, "Parse failed", f"Unable to parse UEFI content: {exc}"
            )
            return

        if not volumes:
            QMessageBox.critical(
                self, "Parse failed", "No firmware volumes found in decompressed data"
            )
            return

        enumerated, _, _ = enumerate_volumes(volumes)

        # Find the target file
        source_offset = bios_info.get("source_offset", 0)
        relative_target = (target_offset - source_offset) if target_offset else None

        target_volume = None
        target_file_idx = None

        for vol in enumerated:
            for idx, f in enumerate(vol.info.files):
                if f.relative_offset == relative_target or (
                    file_index is not None and idx == file_index
                ):
                    target_volume = vol.info
                    target_file_idx = idx
                    break
                if payload.get("guid") and f.guid == payload.get("guid"):
                    target_volume = vol.info
                    target_file_idx = idx
                    break
            if target_volume:
                break

        if target_volume is None or target_file_idx is None:
            QMessageBox.critical(
                self,
                "Not found",
                "Unable to locate the target file in the decompressed BIOS data.",
            )
            return

        # Modify the decompressed data
        blob = bytearray(decompressed)
        try:
            target_volume = replace_ffs_file(
                blob,
                target_volume,
                target_file_idx,
                payload_bytes,
                guid=guid_value,
                file_type=type_value,
                attributes=attributes_value,
                state=state_value,
            )
        except FirmwareMutationError as exc:
            error_msg = str(exc)
            if (
                "cannot resize file" in error_msg
                or "not erased" in error_msg
                or "not enough free space" in error_msg
            ):
                match = re.search(r"short by 0x([0-9A-Fa-f]+)", error_msg)
                if match:
                    shortage = int(match.group(1), 16)
                else:
                    old_file = target_volume.files[target_file_idx]
                    old_size = ((old_file.size + 7) // 8) * 8
                    new_size = ((len(payload_bytes) + 24 + 7) // 8) * 8
                    shortage = max(new_size - old_size, 0x1000)
                extra_needed = shortage + 0x1000

                grown_volume = self._grow_firmware_volume_in_blob(
                    blob, target_volume, extra_needed
                )
                if grown_volume is None:
                    QMessageBox.critical(
                        self,
                        "Replacement failed",
                        f"Cannot resize firmware volume to accommodate larger file.\n\n{exc}",
                    )
                    return

                try:
                    target_volume = replace_ffs_file(
                        blob,
                        grown_volume,
                        target_file_idx,
                        payload_bytes,
                        guid=guid_value,
                        file_type=type_value,
                        attributes=attributes_value,
                        state=state_value,
                    )
                    self._append_console(
                        f"Resized firmware volume by 0x{extra_needed:X} bytes to accommodate larger file."
                    )
                except FirmwareMutationError as exc2:
                    QMessageBox.critical(self, "Replacement failed", str(exc2))
                    return
            else:
                QMessageBox.critical(self, "Replacement failed", str(exc))
                return

        new_decompressed_size = len(blob)

        # Calculate new destination to keep reset vector fixed
        old_destination = bios_info.get("destination", 0)
        new_destination = self._calculate_adjusted_bios_destination(
            old_destination, old_decompressed_size, new_decompressed_size
        )

        source_offset = bios_info.get("source_offset", 0)
        relocated = False
        new_source_offset = source_offset

        if is_compressed:
            old_compressed_size = actual_compressed_size
            original_header = bytes(
                image.data[source_offset : source_offset + actual_zlib_offset]
            )
            original_zlib = bytes(
                image.data[
                    source_offset + actual_zlib_offset : source_offset
                    + old_compressed_size
                ]
            )
            new_compressed = self._recompress_bios_entry(
                bytes(blob), original_header, original_zlib
            )
            new_compressed_size = len(new_compressed)
        else:
            old_compressed_size = old_decompressed_size
            new_compressed = bytes(blob)
            new_compressed_size = new_decompressed_size

        # Check if new compressed blob fits in original space
        if new_compressed_size > old_compressed_size:
            size_diff = new_compressed_size - old_compressed_size

            new_location = self._find_free_space_for_relocation(
                image,
                new_compressed_size,
                alignment=0x1000,
                exclude_start=source_offset,
                exclude_end=source_offset + old_compressed_size,
            )

            if new_location is None:
                QMessageBox.critical(
                    self,
                    "Size overflow - No free space",
                    f"The recompressed BIOS image is 0x{size_diff:X} bytes larger.\n\n"
                    f"Original compressed: 0x{old_compressed_size:X}\n"
                    f"New compressed: 0x{new_compressed_size:X}\n\n"
                    f"No suitable empty region (0xFF bytes) found for relocation.\n"
                    f"Consider removing unused files first.",
                )
                return

            reply = QMessageBox.question(
                self,
                "Relocation Required",
                f"The recompressed BIOS image is 0x{size_diff:X} bytes larger.\n\n"
                f"Original location: 0x{source_offset:X} (size: 0x{old_compressed_size:X})\n"
                f"New location found: 0x{new_location:X} (size: 0x{new_compressed_size:X})\n\n"
                f"The entry will be relocated to empty flash space.\n"
                f"Original location will be filled with 0xFF.\n\n"
                f"Proceed with relocation?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )

            if reply != QMessageBox.StandardButton.Yes:
                return

            relocated = True
            new_source_offset = new_location

            image.data[new_location : new_location + new_compressed_size] = (
                new_compressed
            )

            old_ffs_start = source_offset - 0x30
            old_total_size = old_compressed_size + 0x30
            if old_ffs_start >= 0:
                image.data[old_ffs_start : old_ffs_start + old_total_size] = (
                    b"\xff" * old_total_size
                )
            else:
                image.data[source_offset : source_offset + old_compressed_size] = (
                    b"\xff" * old_compressed_size
                )

            entry_offset = bios_info.get("entry_offset")
            if entry_offset is not None:
                if not self._update_bios_entry_source(
                    image.data,
                    entry_offset,
                    new_location,
                    new_decompressed_size,
                    new_destination,
                ):
                    self._append_console(
                        "Warning: Could not update BIOS directory entry pointer."
                    )
        else:
            if new_compressed_size < old_compressed_size:
                padding = old_compressed_size - new_compressed_size
                new_compressed = new_compressed + (b"\xff" * padding)

            image.data[source_offset : source_offset + old_compressed_size] = (
                new_compressed
            )

            self._update_ffs_wrapper_headers(
                image.data, source_offset, new_compressed_size
            )

            # Always update directory entry to ensure size and destination are correct
            if not self._update_bios_entry_in_directory(
                image.data, bios_info, new_decompressed_size, new_destination
            ):
                self._append_console(
                    "Warning: Could not update BIOS directory entry. "
                    "Destination may be incorrect."
                )

        # Finalize
        guid_text = str(guid_value) if guid_value else "file"

        # Calculate reset vector addresses for verification
        old_reset_vector = old_destination + old_decompressed_size - 0x10
        new_reset_vector = new_destination + new_decompressed_size - 0x10

        if relocated:
            self._record_modified_range(image_idx, source_offset, old_compressed_size)
            self._record_modified_range(
                image_idx, new_source_offset, new_compressed_size
            )

            image.change_log.append(
                f"UEFI: replaced {guid_text} in compressed BIOS 0x62, "
                f"relocated 0x{source_offset:X} \u2192 0x{new_source_offset:X}"
            )

            logger = get_logger()
            logger.debug(
                f"Replaced {guid_text} in compressed BIOS entry (RELOCATED).\n"
                f"  Old location: 0x{source_offset:X} (now 0xFF filled)\n"
                f"  New location: 0x{new_source_offset:X}\n"
                f"  Decompressed size: 0x{old_decompressed_size:X} \u2192 0x{new_decompressed_size:X}\n"
                f"  Destination: 0x{old_destination:X} \u2192 0x{new_destination:X}\n"
                f"  Reset vector: 0x{old_reset_vector:X} \u2192 0x{new_reset_vector:X} (should be equal)\n"
                f"  Compressed size: 0x{old_compressed_size:X} \u2192 0x{new_compressed_size:X}"
            )
            change_desc = (
                f"UEFI: replaced {guid_text} in compressed BIOS 0x62, "
                f"relocated 0x{source_offset:X} \u2192 0x{new_source_offset:X}"
            )
        else:
            self._record_modified_range(image_idx, source_offset, old_compressed_size)

            image.change_log.append(
                f"UEFI: replaced {guid_text} in compressed BIOS 0x62 at 0x{source_offset:X}"
            )

            logger = get_logger()
            logger.debug(
                f"Replaced {guid_text} in compressed BIOS entry.\n"
                f"  Decompressed size: 0x{old_decompressed_size:X} \u2192 0x{new_decompressed_size:X}\n"
                f"  Destination: 0x{old_destination:X} \u2192 0x{new_destination:X}\n"
                f"  Reset vector: 0x{old_reset_vector:X} \u2192 0x{new_reset_vector:X} (should be equal)\n"
                f"  Compressed size: 0x{old_compressed_size:X} \u2192 0x{new_compressed_size:X} (padded to original)"
            )
            change_desc = f"UEFI: replaced {guid_text} in compressed BIOS 0x62 at 0x{source_offset:X}"

        # Queue the action for undo support
        self._queue_0x62_action(
            image,
            image_idx,
            bios_info,
            "replace",
            original_state,
            change_desc,
            file_guid=guid_value,
            relocated=relocated,
            new_source_offset=new_source_offset if relocated else None,
            new_compressed_size=new_compressed_size,
            target_file_index=target_file_idx,
        )

        self._mark_image_dirty(image_idx)
        self._status_message(
            f"Queued replacement of {guid_text} in compressed BIOS 0x62"
        )

        self._reprocess_image(image_idx)
        self._rebuild_from_loaded_images()

    def _remove_uefi_file_compressed_bios(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        payload: dict,
    ) -> None:
        """Remove a file from a compressed BIOS entry (type 0x62).

        This handles removing files from the zlib-compressed BIOS content.
        """
        bios_info = payload.get("compressed_bios_info")
        if not bios_info:
            QMessageBox.critical(self, "Error", "Missing compressed BIOS info")
            return

        # Capture original state for undo support
        original_state = self._capture_0x62_original_state(image, bios_info)

        target_offset = payload.get("offset")
        file_guid = payload.get("guid")
        file_index = payload.get("file_index")

        # Confirm removal
        guid_text = str(file_guid) if file_guid else "unknown"
        reply = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Remove file {guid_text} from compressed BIOS entry?\n\n"
            "This will recompress the BIOS image.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        # Check if entry is compressed
        is_compressed = bios_info.get("compressed_size", 0) > 0

        if is_compressed:
            decompress_result = self._decompress_bios_entry_ex(image.data, bios_info)
            if decompress_result is None:
                QMessageBox.critical(
                    self, "Decompression failed", "Unable to decompress the BIOS entry."
                )
                return
            decompressed, actual_compressed_size, actual_zlib_offset = decompress_result
        else:
            source_offset = bios_info.get("source_offset", 0)
            data_size = bios_info.get("decompressed_size", 0)
            if source_offset < 0 or source_offset + data_size > len(image.data):
                QMessageBox.critical(
                    self,
                    "Read failed",
                    f"Invalid data range: offset=0x{source_offset:X}, size=0x{data_size:X}",
                )
                return
            decompressed = bytes(image.data[source_offset : source_offset + data_size])
            actual_compressed_size = 0
            actual_zlib_offset = 0

        old_decompressed_size = len(decompressed)
        source_offset = bios_info.get("source_offset", 0)

        # Scan for volumes
        try:
            volumes = scan_firmware_volumes(decompressed, 0, len(decompressed))
        except Exception as exc:
            QMessageBox.critical(
                self, "Parse failed", f"Unable to parse UEFI content: {exc}"
            )
            return

        if not volumes:
            QMessageBox.critical(self, "Parse failed", "No firmware volumes found")
            return

        enumerated, _, _ = enumerate_volumes(volumes)

        # Find the target file
        relative_target = (target_offset - source_offset) if target_offset else None

        target_volume = None
        remove_idx = None
        removed_file_context = None

        for vol in enumerated:
            for idx, f in enumerate(vol.info.files):
                if f.relative_offset == relative_target or (
                    file_index is not None and idx == file_index
                ):
                    target_volume = vol.info
                    remove_idx = idx
                    removed_file = vol.info.files[idx]
                    removed_file_context = {
                        "guid": str(getattr(removed_file, "guid", "") or ""),
                        "name": getattr(removed_file, "display_name", None)
                        or lookup_guid_name(getattr(removed_file, "guid", None))
                        or str(getattr(removed_file, "guid", "") or "unknown"),
                        "type_name": removed_file.type_name,
                        "size": int(getattr(removed_file, "size", 0) or 0),
                        "relative_offset": int(
                            getattr(removed_file, "relative_offset", 0) or 0
                        ),
                        "absolute_offset": int(
                            getattr(removed_file, "absolute_offset", 0) or 0
                        )
                        if getattr(removed_file, "absolute_offset", None) is not None
                        else None,
                        "file_index": idx,
                        "volume_index": getattr(vol, "index", None),
                        "volume_guid": str(
                            getattr(vol.info, "filesystem_guid", "") or ""
                        ),
                    }
                    break
                if file_guid and f.guid == file_guid:
                    target_volume = vol.info
                    remove_idx = idx
                    removed_file = vol.info.files[idx]
                    removed_file_context = {
                        "guid": str(getattr(removed_file, "guid", "") or ""),
                        "name": getattr(removed_file, "display_name", None)
                        or lookup_guid_name(getattr(removed_file, "guid", None))
                        or str(getattr(removed_file, "guid", "") or "unknown"),
                        "type_name": removed_file.type_name,
                        "size": int(getattr(removed_file, "size", 0) or 0),
                        "relative_offset": int(
                            getattr(removed_file, "relative_offset", 0) or 0
                        ),
                        "absolute_offset": int(
                            getattr(removed_file, "absolute_offset", 0) or 0
                        )
                        if getattr(removed_file, "absolute_offset", None) is not None
                        else None,
                        "file_index": idx,
                        "volume_index": getattr(vol, "index", None),
                        "volume_guid": str(
                            getattr(vol.info, "filesystem_guid", "") or ""
                        ),
                    }
                    break
            if target_volume:
                break

        if target_volume is None or remove_idx is None:
            QMessageBox.critical(
                self,
                "Not found",
                "Unable to locate the target file in the decompressed BIOS data.",
            )
            return

        # Remove from decompressed data
        blob = bytearray(decompressed)
        try:
            remove_ffs_file(blob, target_volume, remove_idx)
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Removal failed", str(exc))
            return

        new_decompressed_size = len(blob)

        # Calculate new destination
        old_destination = bios_info.get("destination", 0)
        new_destination = self._calculate_adjusted_bios_destination(
            old_destination, old_decompressed_size, new_decompressed_size
        )

        if is_compressed:
            old_compressed_size = actual_compressed_size
            original_header = bytes(
                image.data[source_offset : source_offset + actual_zlib_offset]
            )
            original_zlib = bytes(
                image.data[
                    source_offset + actual_zlib_offset : source_offset
                    + old_compressed_size
                ]
            )
            new_compressed = self._recompress_bios_entry(
                bytes(blob), original_header, original_zlib
            )
            new_compressed_size = len(new_compressed)
        else:
            old_compressed_size = old_decompressed_size
            new_compressed = bytes(blob)
            new_compressed_size = new_decompressed_size

        # Removal should always shrink or maintain size
        if new_compressed_size > old_compressed_size:
            size_diff = new_compressed_size - old_compressed_size
            QMessageBox.warning(
                self,
                "Size warning",
                f"Unexpectedly, the recompressed BIOS is 0x{size_diff:X} bytes larger.\n"
                "This may indicate compression inefficiency. Proceeding anyway.",
            )

        # Pad and write back
        if new_compressed_size < old_compressed_size:
            new_compressed = new_compressed + (
                b"\xff" * (old_compressed_size - new_compressed_size)
            )
        elif new_compressed_size > old_compressed_size:
            new_compressed = new_compressed[:old_compressed_size]

        image.data[source_offset : source_offset + old_compressed_size] = new_compressed

        # Update FFS wrapper headers
        self._update_ffs_wrapper_headers(image.data, source_offset, new_compressed_size)

        # Always update directory entry to ensure size and destination are correct
        self._update_bios_entry_in_directory(
            image.data, bios_info, new_decompressed_size, new_destination
        )

        # Finalize
        self._record_modified_range(image_idx, source_offset, old_compressed_size)

        change_desc = f"UEFI: removed {guid_text} from compressed BIOS 0x62"
        image.change_log.append(change_desc)

        # Queue the action for undo support
        self._queue_0x62_action(
            image,
            image_idx,
            bios_info,
            "remove",
            original_state,
            change_desc,
            file_guid=file_guid if isinstance(file_guid, UUID) else None,
            new_compressed_size=new_compressed_size,
            target_file_index=remove_idx,
            target_offset=target_offset,
            removed_file_context=removed_file_context,
        )

        self._mark_image_dirty(image_idx)

        # Calculate reset vector addresses for verification
        old_reset_vector = old_destination + old_decompressed_size - 0x10
        new_reset_vector = new_destination + new_decompressed_size - 0x10

        logger = get_logger()
        logger.debug(
            f"Removed {guid_text} from compressed BIOS entry.\n"
            f"  Compressed size: 0x{old_compressed_size:X} \u2192 0x{new_compressed_size:X}\n"
            f"  Decompressed size: 0x{old_decompressed_size:X} \u2192 0x{new_decompressed_size:X}\n"
            f"  Destination: 0x{old_destination:X} \u2192 0x{new_destination:X}\n"
            f"  Reset vector: 0x{old_reset_vector:X} \u2192 0x{new_reset_vector:X} (should be equal)"
        )
        self._status_message(f"Queued removal of {guid_text} from compressed BIOS 0x62")

        self._reprocess_image(image_idx)
        self._rebuild_from_loaded_images()
