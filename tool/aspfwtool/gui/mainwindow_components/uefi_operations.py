# Copyright (C) 2025 kolabo.dev / ReisWeirdStuff <https://kolabo.dev/>
"""
UEFI firmware file operation mixin for MainWindow.

This module provides:
    - Compressed section editing and recompression
    - File insertion, replacement, and removal
    - Volume and file context resolution
    - Section navigation and extraction

For compressed BIOS entry (0x62) handling for AMD Secured Boot,
see compressed_bios_operations.py.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Dict, Iterable, Optional, Sequence, Tuple
from uuid import UUID

from ...utils.debug_logger import get_logger

from .qt import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    Qt,
)
from .common import (
    SUPPORTED_UEFI_COMPRESSION_TYPES,
    UEFI_SECTION_ALIGNMENT,
    _align_up,
    _sanitize_filename,
)
from .models import UefiFileContextInfo, UefiVolumeContextInfo
from .compressed_bios_operations import CompressedBiosOperationsMixin

from ...uefi import (
    EnumeratedFirmwareFile,
    EnumeratedFirmwareSection,
    EnumeratedFirmwareVolume,
    EFI_SECTION_COMPRESSION,
    EFI_FV_FILETYPE_SECURITY_CORE,
    FirmwareFileInfo,
    FirmwareVolumeInfo,
    FirmwareMutationError,
    PAD_FILE_GUID,
    VTF_FILE_GUID,
    build_compression_section,
    decompress_compression_section,
    insert_ffs_file,
    replace_ffs_file,
    remove_ffs_file,
    parse_ffs_file_bytes,
    scan_firmware_volumes,
    enumerate_volumes,
)

if TYPE_CHECKING:
    from .controller import MainWindow
    from .models import LoadedImage


class UefiOperationsMixin(CompressedBiosOperationsMixin):
    """Mixin providing UEFI firmware file operations."""

    def _is_soft_locked_by_0x62(self: "MainWindow", payload: dict) -> bool:
        """Check if a UEFI entry is soft-locked because it's referenced by a 0x62 PSP entry.
        
        UEFI entries (volumes, files, sections) that are pointed to by 0x62 BIOS entries
        contain calculated offsets (reset vector, zlib header) that would be corrupted
        if the UEFI structure is edited. This method checks if editing should be blocked.
        
        This also detects "virtual" volumes/files inside decompressed 0x62 regions by
        checking if the item's compressed_bios_info is set or if its offset falls within
        a cached 0x62 region.
        
        Returns:
            True if editing should be blocked (entry is inside 0x62 protected area)
        """
        # Direct flag from tree payload
        bios_refs = payload.get("bios_entry_refs")
        if bios_refs:
            return True
        
        # Check if this is content from inside a compressed BIOS entry (virtual)
        # The compressed_bios_info is set by tree_builder for items inside 0x62 entries
        if payload.get("compressed_bios_info"):
            return True
        
        # Check if offset falls within any cached 0x62 BIOS entry region
        image_index = payload.get("image_index")
        if image_index is None or not (0 <= image_index < len(self.loaded_images)):
            return False
        
        image = self.loaded_images[image_index]
        bios_entry_refs = getattr(image, "bios_entry_refs", None)
        if not bios_entry_refs:
            return False
        
        # Check if the payload's offset/size overlaps with any 0x62 region
        offset = payload.get("offset")
        size = payload.get("size", 0)
        if offset is None:
            return False
        
        try:
            start = int(offset)
            end = start + int(size) if size else start + 1
        except (TypeError, ValueError):
            return False
        
        for ref in bios_entry_refs:
            ref_start = ref.source_offset
            ref_end = ref_start + ref.size
            # Check for overlap
            if start < ref_end and end > ref_start:
                return True
        
        return False
    
    def _show_soft_lock_warning(self: "MainWindow", payload: dict) -> bool:
        """Show a warning dialog explaining why editing is blocked for 0x62-referenced entries.
        
        Returns:
            True if user chose to override (proceed anyway), False to cancel
        """
        bios_refs = payload.get("bios_entry_refs", [])
        ref_strs = [f"D{r.directory_index}E{r.entry_index}" for r in bios_refs]
        refs_text = ", ".join(ref_strs) if ref_strs else "0x62 PSP entry"
        
        # Check if this is from compressed_bios_info (virtual content)
        cbi = payload.get("compressed_bios_info")
        if cbi and not bios_refs:
            dir_idx = cbi.get("directory_index", -1)
            entry_idx = cbi.get("entry_index", -1)
            if dir_idx >= 0 and entry_idx >= 0:
                refs_text = f"D{dir_idx}E{entry_idx}"
        
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Protected Entry")
        box.setText(
            f"This UEFI entry referenced a PSP TypeId 0x62 (UEFI Binary & RTM) pointer ({refs_text}).\n\n"
            "Editing via the UEFI tab would corrupt PSP firmware pointers\n\n"
            "(PSB signing, x86 reset vector, zlib header, directory pointer, etc...)\n\n"
            "To \"safely\" modify this content, use the PSP tab to edit the 0x62 entry directly."
        )
        box.setInformativeText("Override to edit anyway, or Cancel to abort.")
        box.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        box.setDefaultButton(QMessageBox.Cancel)
        box.button(QMessageBox.Yes).setText("Override")
        
        result = box.exec()
        return result == QMessageBox.Yes

    def _calculate_volume_free_space(
        self: "MainWindow",
        volume_info: FirmwareVolumeInfo,
    ) -> int:
        """Calculate the free space available at the end of a firmware volume."""
        if not volume_info.files:
            return int(volume_info.size) - int(volume_info.header_length)
        last_file = volume_info.files[-1]
        # Calculate aligned end of last file
        last_file_end = ((last_file.relative_offset + last_file.size + 7) // 8) * 8
        return max(0, int(volume_info.size) - last_file_end)

    def _grow_firmware_volume_in_blob(
        self: "MainWindow",
        blob: bytearray,
        volume_info: FirmwareVolumeInfo,
        extra_bytes: int,
    ) -> Optional[FirmwareVolumeInfo]:
        """
        Resize a firmware volume by appending free space at the END.
        
        Appends 0xFF padding at the end of the FV, extending the total blob size.
        This approach keeps existing files at their original offsets, preserving
        file indices for subsequent insert operations.
        
        Resizes by N*0x1000 (4 KiB blocks) to satisfy the requested size.
        
        Args:
            blob: Decompressed BIOS data (will be modified in place)
            volume_info: Volume to resize
            extra_bytes: Number of bytes needed (will be rounded up to 0x1000 boundary)
            
        Returns:
            Updated FirmwareVolumeInfo or None on failure
        """
        logger = get_logger()
        
        # Round up to nearest 4 KiB boundary (minimum one block)
        if extra_bytes <= 0:
            extra_bytes = 0x1000
        else:
            extra_bytes = ((extra_bytes + 0xFFF) // 0x1000) * 0x1000
        
        # Find the actual FV header location by searching for _FVH signature
        # The signature is at offset 0x28 within the FV header
        fvh_sig = b'_FVH'
        vol_start = int(volume_info.relative_offset or 0)
        
        # Search for _FVH near the expected location
        search_start = max(0, vol_start)
        search_end = min(len(blob), vol_start + 0x100)
        fvh_pos = blob.find(fvh_sig, search_start, search_end)
        
        if fvh_pos == -1:
            # Try searching from the beginning
            fvh_pos = blob.find(fvh_sig, 0, min(len(blob), 0x1000))
        
        if fvh_pos == -1:
            return None
        
        # FV header starts 0x28 bytes before _FVH
        actual_vol_start = fvh_pos - 0x28
        if actual_vol_start < 0:
            return None
        
        vol_size = int(volume_info.size)
        header_length = int(volume_info.header_length)
        
        # Read the original block size from block map at FV+0x38
        blockmap_offset = actual_vol_start + 0x38
        original_block_size = 0x1000  # Default to 4KB
        if blockmap_offset + 8 <= len(blob):
            original_block_size = int.from_bytes(blob[blockmap_offset + 4:blockmap_offset + 8], "little")
            if original_block_size <= 0:
                original_block_size = 0x1000
        
        logger.debug(f"FV grow: start=0x{actual_vol_start:X}, size=0x{vol_size:X}, block_size=0x{original_block_size:X}")
        
        # Insert 0xFF padding at the END of the FV
        # This extends the tail free space region where insert_ffs_file places new files
        # Existing files remain at their current offsets, preserving file indices
        fv_end = actual_vol_start + vol_size
        padding = bytes([0xFF]) * extra_bytes
        blob[fv_end:fv_end] = padding
        
        # Calculate new size
        new_size = vol_size + extra_bytes
        
        # Update FV header size field (at offset 0x20 in FV header, 8 bytes)
        size_field_offset = actual_vol_start + 0x20
        if size_field_offset + 8 <= len(blob):
            blob[size_field_offset:size_field_offset + 8] = new_size.to_bytes(8, "little")
            
            # Update the block map at FV+0x38 to match new size
            # Keep the original block size, update num_blocks
            if blockmap_offset + 8 <= len(blob):
                new_num_blocks = new_size // original_block_size
                blob[blockmap_offset:blockmap_offset + 4] = new_num_blocks.to_bytes(4, "little")
                # block_size stays the same
            
            # Recalculate FV header checksum (at offset 0x32, 2 bytes)
            checksum_offset = actual_vol_start + 0x32
            if actual_vol_start + header_length <= len(blob):
                blob[checksum_offset:checksum_offset + 2] = b'\x00\x00'
                checksum = 0
                for i in range(0, header_length, 2):
                    word = int.from_bytes(blob[actual_vol_start + i:actual_vol_start + i + 2], "little")
                    checksum = (checksum + word) & 0xFFFF
                checksum = (0x10000 - checksum) & 0xFFFF
                blob[checksum_offset:checksum_offset + 2] = checksum.to_bytes(2, "little")
        
        # Update wrapper section header (type 0x17 = EFI_SECTION_FIRMWARE_VOLUME_IMAGE)
        section_hdr_offset = actual_vol_start - 4
        if section_hdr_offset >= 0:
            section_type = blob[section_hdr_offset + 3]
            if section_type == 0x17:
                new_section_size = new_size + 4
                if new_section_size <= 0xFFFFFF:
                    blob[section_hdr_offset:section_hdr_offset + 3] = new_section_size.to_bytes(3, "little")
        
        logger.debug(f"FV grow: new_size=0x{new_size:X}, new_num_blocks={new_size // original_block_size}")
        
        # Re-parse the volume to get updated info
        try:
            volumes = scan_firmware_volumes(bytes(blob), actual_vol_start, new_size)
            if volumes:
                return volumes[0]
        except Exception:
            pass
        
        return None

    def _is_reset_vector_protected_pad(
        self: "MainWindow",
        volume_info: FirmwareVolumeInfo,
        pad_index: int,
    ) -> bool:
        """
        Check if a padding file protects the reset vector area.
        
        Returns True if the padding file should NOT be shrunk because:
        - It's in a PHYSICAL volume and shrinking would move VTF/SecCore
        
        For VIRTUAL volumes (inside compressed sections), positions don't
        affect the reset vector since it points to physical addresses.
        Startup AP data padding files in virtual volumes can be safely shrunk.
        """
        total = len(volume_info.files)
        if pad_index < 0 or pad_index >= total:
            return False
        
        pad_file = volume_info.files[pad_index]
        is_startup_ap = getattr(pad_file, "display_name", None) == "Startup AP data padding file"
        
        # Virtual volumes (no absolute_offset) - Startup AP can be shrunk
        if volume_info.absolute_offset is None and is_startup_ap:
            return False
        
        # Check the file immediately after this padding
        if pad_index + 1 < total:
            next_file = volume_info.files[pad_index + 1]
            next_guid = getattr(next_file, "guid", None)
            next_type = int(getattr(next_file, "type", 0))
            
            # VTF file or SEC_CORE - must stay at fixed location
            if next_guid == VTF_FILE_GUID or next_type == EFI_FV_FILETYPE_SECURITY_CORE:
                if volume_info.absolute_offset is None and is_startup_ap:
                    return False
                return True
        
        # Check if this is second-to-last and last is VTF/SEC
        if pad_index == total - 2 and total >= 2:
            last_file = volume_info.files[total - 1]
            last_guid = getattr(last_file, "guid", None)
            last_type = int(getattr(last_file, "type", 0))
            if last_guid == VTF_FILE_GUID or last_type == EFI_FV_FILETYPE_SECURITY_CORE:
                if volume_info.absolute_offset is None and is_startup_ap:
                    return False
                return True
        
        # Last padding file - check if it's a Startup AP data padding file
        if pad_index == total - 1:
            if is_startup_ap:
                return False
            return True
        
        return False

    def _calculate_reclaimable_padding(
        self: "MainWindow",
        volume_info: FirmwareVolumeInfo,
        image_data: bytearray,
    ) -> int:
        """
        Calculate how much space can be reclaimed from padding files in a volume.
        
        Excludes padding files that protect the reset vector area.
        For Startup AP data padding files in virtual volumes, includes
        both leading and trailing free space.
        """
        reclaimable = 0
        vol_start = int(volume_info.absolute_offset or 0)
        is_virtual = volume_info.absolute_offset is None
        
        for idx, file_info in enumerate(volume_info.files):
            # Check if it's a padding file (type 0xF0, GUID all FF)
            if int(getattr(file_info, "type", 0)) != 0xF0:
                continue
            guid = getattr(file_info, "guid", None)
            if guid != PAD_FILE_GUID:
                continue
            
            # Skip padding files that protect reset vector
            if self._is_reset_vector_protected_pad(volume_info, idx):
                continue
            
            # Calculate shrinkable content (FF-filled tail and lead)
            header_len = int(getattr(file_info, "header_length", 0) or 24)
            file_size = int(file_info.size)
            if file_size <= header_len:
                continue
            
            # Check how much of the payload is FF (can be reclaimed)
            is_startup_ap = getattr(file_info, "display_name", None) == "Startup AP data padding file"
            
            # For virtual files, use raw_data if available
            if is_virtual and file_info.raw_data:
                payload = file_info.raw_data[header_len:]
            else:
                file_start = vol_start + int(file_info.relative_offset)
                payload_start = file_start + header_len
                payload_end = file_start + file_size
                if payload_end > len(image_data):
                    continue
                payload = image_data[payload_start:payload_end]
            
            # Count trailing FF bytes
            tail_ff = 0
            for i in range(len(payload) - 1, -1, -1):
                if payload[i] == 0xFF:
                    tail_ff += 1
                else:
                    break
            
            # For Startup AP files in virtual volumes, also count leading FF
            lead_ff = 0
            if is_startup_ap and is_virtual:
                for i in range(len(payload)):
                    if payload[i] == 0xFF:
                        lead_ff += 1
                    else:
                        break
            
            # Can reclaim the FF portion (aligned to 8 bytes)
            total_ff = tail_ff + lead_ff
            reclaimable += (total_ff // 8) * 8
        
        return reclaimable

    def _format_compressed_section_error(
        self: "MainWindow",
        original_error: str,
        original_section_size: int,
        new_section_size: int,
        volume_free_space: int = 0,
        reclaimable_padding: int = 0,
    ) -> str:
        """Format an error message for compressed section operations with size context."""
        size_diff = new_section_size - original_section_size
        if size_diff > 0:
            msg = (
                f"{original_error}\n\n"
                f"The compressed section grew from 0x{original_section_size:X} to 0x{new_section_size:X} bytes "
                f"(+0x{size_diff:X} bytes).\n"
            )
            if volume_free_space > 0 or reclaimable_padding > 0:
                total_available = volume_free_space + reclaimable_padding
                msg += (
                    f"\nParent volume space:\n"
                    f"  - Free space: 0x{volume_free_space:X} bytes\n"
                    f"  - Reclaimable from padding: 0x{reclaimable_padding:X} bytes\n"
                    f"  - Total available: 0x{total_available:X} bytes\n"
                )
                if total_available < size_diff:
                    msg += f"  - Still short by: 0x{size_diff - total_available:X} bytes"
            else:
                msg += "The parent volume has no free space or reclaimable padding."
            return msg
        return original_error

    def _iter_enumerated_volumes(
        self: "MainWindow",
        volumes: Sequence[EnumeratedFirmwareVolume],
    ) -> Iterable[EnumeratedFirmwareVolume]:
        """Recursively yield all enumerated volumes including nested ones."""
        for volume in volumes:
            yield volume
            for file_enum in volume.files:
                for section in file_enum.sections:
                    if section.volumes:
                        yield from self._iter_enumerated_volumes(section.volumes)

    def _locate_uefi_section_context(
        self: "MainWindow",
        image: "LoadedImage",
        absolute_offset: int,
    ) -> Optional[
        Tuple[
            EnumeratedFirmwareVolume,
            EnumeratedFirmwareFile,
            EnumeratedFirmwareSection,
            int,
        ]
    ]:
        """Locate the UEFI section context for a given absolute offset."""
        for root in image.uefi_roots:
            for volume in self._iter_enumerated_volumes(root.volumes):
                for file_enum in volume.files:
                    for idx, section in enumerate(file_enum.sections):
                        sec_off = section.info.absolute_offset
                        if sec_off is None:
                            continue
                        if int(sec_off) == absolute_offset:
                            return (volume, file_enum, section, idx)
        return None

    def _locate_uefi_volume_context(
        self: "MainWindow",
        image: "LoadedImage",
        absolute_offset: int,
    ) -> Optional[EnumeratedFirmwareVolume]:
        """Locate the UEFI volume context for a given absolute offset."""
        for root in image.uefi_roots:
            for volume in self._iter_enumerated_volumes(root.volumes):
                vol_off = volume.info.absolute_offset
                if vol_off is None:
                    continue
                try:
                    if int(vol_off) == absolute_offset:
                        return volume
                except Exception:
                    continue
        return None

    def _locate_uefi_file_context(
        self: "MainWindow",
        image: "LoadedImage",
        absolute_offset: int,
    ) -> Optional[Tuple[EnumeratedFirmwareVolume, int, EnumeratedFirmwareFile]]:
        """Locate the UEFI file context for a given absolute offset."""
        for root in image.uefi_roots:
            for volume in self._iter_enumerated_volumes(root.volumes):
                for idx, file_enum in enumerate(volume.files):
                    file_off = file_enum.info.absolute_offset
                    if file_off is None:
                        continue
                    try:
                        if int(file_off) == absolute_offset:
                            return (volume, idx, file_enum)
                    except Exception:
                        continue
        return None

    def _resolve_uefi_file_context_from_payload(
        self: "MainWindow",
        payload: dict,
    ) -> Optional[UefiFileContextInfo]:
        """Resolve UEFI file context from a payload dictionary."""
        image_index = payload.get("image_index")
        if image_index is None:
            return None
        try:
            idx = int(image_index)
        except Exception:
            return None
        if not (0 <= idx < len(self.loaded_images)):
            return None
        image = self.loaded_images[idx]

        uefi_kind = payload.get("uefi_kind")
        if uefi_kind != "file":
            return None

        virtual = payload.get("virtual", False)
        offset = payload.get("offset")
        
        # Get chain information from payload
        volume_chain = payload.get("uefi_volume_chain") or []
        file_chain = payload.get("uefi_file_chain") or []
        section_chain = payload.get("uefi_section_chain") or []
        section_path = payload.get("uefi_section_path") or []

        # For virtual files, we must use chain info since offset is None
        if virtual or offset is None:
            if not volume_chain or not file_chain:
                return None
            
            # The payload contains stale EnumeratedFirmware* objects from when tree was built.
            # We need to re-locate the root volume/file from current uefi_roots using their
            # identifying information (GUID, offset) to get fresh objects with correct offsets.
            
            # Get identifying info from the stale root objects
            stale_root_volume = volume_chain[0]
            stale_root_file = file_chain[0]
            stale_target_volume = volume_chain[-1]
            stale_target_file = file_chain[-1]
            
            if not all([stale_root_volume, stale_root_file, stale_target_volume, stale_target_file]):
                return None
            
            # Try to find the root volume by its offset in current uefi_roots
            root_volume_offset = stale_root_volume.info.absolute_offset
            if root_volume_offset is None:
                return None
            
            fresh_root_volume = self._locate_uefi_volume_context(image, int(root_volume_offset))
            if fresh_root_volume is None:
                return None
            
            # Find the root file within the fresh volume by GUID or offset
            root_file_guid = stale_root_file.info.guid
            root_file_offset = stale_root_file.info.absolute_offset
            fresh_root_file = None
            
            # Try matching by GUID first
            for f in fresh_root_volume.files:
                if f.info.guid == root_file_guid:
                    fresh_root_file = f
                    break
            
            # Fallback: try matching by offset
            if fresh_root_file is None and root_file_offset is not None:
                for f in fresh_root_volume.files:
                    if f.info.absolute_offset == root_file_offset:
                        fresh_root_file = f
                        break
            
            # Fallback: try matching by file index if available
            if fresh_root_file is None:
                stale_file_index = getattr(stale_root_file, 'index', None)
                if stale_file_index is not None:
                    for f in fresh_root_volume.files:
                        if f.index == stale_file_index:
                            fresh_root_file = f
                            break
            
            if fresh_root_file is None:
                return None
            
            # For target volume/file inside compressed section, we keep the stale references
            # since they represent virtual structures that will be re-parsed during the operation.
            # The section_path is still valid as an index into root_file's sections.
            
            # Get file index within target volume
            file_index = payload.get("file_index")
            
            # Build fresh chain with the root objects refreshed
            fresh_volume_chain = [fresh_root_volume] + list(volume_chain[1:])
            fresh_file_chain = [fresh_root_file] + list(file_chain[1:])
            
            return UefiFileContextInfo(
                image_index=idx,
                image=image,
                volume_chain=fresh_volume_chain,
                file_chain=fresh_file_chain,
                section_chain=section_chain,
                section_path=section_path,
                root_volume=fresh_root_volume,
                target_volume=stale_target_volume,  # Target is virtual, will be re-parsed
                root_file=fresh_root_file,
                target_file=stale_target_file,  # Target is virtual, will be re-parsed
                file_index=file_index,
                virtual=True,
            )
        
        # Non-virtual file with real offset
        try:
            target_offset = int(offset)
        except Exception:
            return None

        context = self._locate_uefi_file_context(image, target_offset)
        if context is None:
            return None

        volume_enum, file_index, file_enum = context
        
        return UefiFileContextInfo(
            image_index=idx,
            image=image,
            volume_chain=[volume_enum],
            file_chain=[file_enum],
            section_chain=[],
            section_path=[],
            root_volume=volume_enum,
            target_volume=volume_enum,
            root_file=file_enum,
            target_file=file_enum,
            file_index=file_index,
            virtual=False,
        )

    def _resolve_uefi_volume_context_from_payload(
        self: "MainWindow",
        payload: dict,
    ) -> Optional[UefiVolumeContextInfo]:
        """Resolve UEFI volume context from a payload dictionary."""
        image_index = payload.get("image_index")
        if image_index is None:
            return None
        try:
            idx = int(image_index)
        except Exception:
            return None
        if not (0 <= idx < len(self.loaded_images)):
            return None
        image = self.loaded_images[idx]

        uefi_kind = payload.get("uefi_kind")
        if uefi_kind != "volume":
            return None

        virtual = payload.get("virtual", False)
        offset = payload.get("offset")
        
        # Get chain information from payload
        volume_chain = payload.get("uefi_volume_chain") or []
        file_chain = payload.get("uefi_file_chain") or []
        section_chain = payload.get("uefi_section_chain") or []
        section_path = payload.get("uefi_section_path") or []

        # For virtual volumes, we must use chain info since offset is None
        if virtual or offset is None:
            if not volume_chain:
                return None
            # Root volume is the first in chain (the one with real offset)
            root_volume = volume_chain[0] if volume_chain else None
            # Target volume is the last in chain (the virtual one)
            target_volume = volume_chain[-1] if volume_chain else None
            
            if not all([root_volume, target_volume]):
                return None
            
            # Get root file (the file containing the compressed section)
            root_file = file_chain[0] if file_chain else None
            
            return UefiVolumeContextInfo(
                image_index=idx,
                image=image,
                volume_chain=volume_chain,
                file_chain=file_chain,
                section_chain=section_chain,
                section_path=section_path,
                root_volume=root_volume,
                target_volume=target_volume,
                root_file=root_file,
                virtual=True,
            )

        # Non-virtual volume with real offset
        try:
            target_offset = int(offset)
        except Exception:
            return None

        volume_enum = self._locate_uefi_volume_context(image, target_offset)
        if volume_enum is None:
            return None

        return UefiVolumeContextInfo(
            image_index=idx,
            image=image,
            volume_chain=[volume_enum],
            file_chain=[],
            section_chain=[],
            section_path=[],
            root_volume=volume_enum,
            target_volume=volume_enum,
            root_file=None,
            virtual=False,
        )

    def _find_matching_volume(
        self: "MainWindow",
        volumes: Sequence[FirmwareVolumeInfo],
        target: FirmwareVolumeInfo,
    ) -> Optional[FirmwareVolumeInfo]:
        """Find a matching volume in the list by offset or GUID."""
        target_off = target.absolute_offset
        target_guid = target.filesystem_guid
        for vol in volumes:
            if target_off is not None and vol.absolute_offset == target_off:
                return vol
            if target_guid and vol.filesystem_guid == target_guid:
                return vol
        return None

    def _find_matching_file_index(
        self: "MainWindow",
        files: Sequence[FirmwareFileInfo],
        target: FirmwareFileInfo,
    ) -> Optional[int]:
        """Find the index of a matching file in the list."""
        target_off = target.absolute_offset
        target_guid = target.guid
        for idx, file_info in enumerate(files):
            if target_off is not None and file_info.absolute_offset == target_off:
                return idx
            if target_guid and file_info.guid == target_guid:
                return idx
        return None

    def _assemble_ffs_payload_with_section(
        self: "MainWindow",
        data: bytearray,
        file_info: FirmwareFileInfo,
        section_index: int,
        new_section_bytes: bytes,
    ) -> Optional[bytes]:
        """Assemble a firmware file payload with a replaced section."""
        sections = list(getattr(file_info, "sections", []))
        if not sections or not (0 <= section_index < len(sections)):
            return None
        payload = bytearray()
        for idx, section_info in enumerate(sections):
            sec_start = section_info.absolute_offset
            if sec_start is None or section_info.size <= 0:
                continue
            try:
                sec_start_int = int(sec_start)
                sec_size_int = int(section_info.size)
            except Exception:
                return None
            if idx == section_index:
                section_bytes = bytes(new_section_bytes)
            else:
                section_bytes = bytes(data[sec_start_int : sec_start_int + sec_size_int])
            payload.extend(section_bytes)
            pad_len = _align_up(len(section_bytes), UEFI_SECTION_ALIGNMENT) - len(
                section_bytes
            )
            if pad_len > 0:
                if idx == section_index:
                    payload.extend(bytes([0xFF]) * pad_len)
                else:
                    pad_start = sec_start_int + sec_size_int
                    pad_end = pad_start + pad_len
                    file_limit = (
                        int(file_info.absolute_offset or 0) + int(file_info.size)
                    )
                    pad_end = min(pad_end, file_limit)
                    padding = bytes(data[pad_start:pad_end])
                    if len(padding) < pad_len:
                        padding += bytes([0xFF]) * (pad_len - len(padding))
                    payload.extend(padding)
        return bytes(payload)

    def _interpret_uefi_file_blob(
        self: "MainWindow",
        blob: bytes,
    ) -> Tuple[bytes, Optional[FirmwareFileInfo]]:
        """Interpret a blob as a UEFI firmware file, extracting metadata."""
        try:
            parsed = parse_ffs_file_bytes(blob)
            if parsed is not None:
                # Extract payload (body after header)
                header_len = parsed.header_length or 24
                if header_len > 0 and header_len < len(blob):
                    return (blob[header_len:], parsed)
                return (blob, parsed)
        except Exception:
            pass
        return (blob, None)

    def _rebuild_compressed_section(
        self: "MainWindow",
        section_bytes: bytes,
        ctx: UefiFileContextInfo,
        *,
        action: str,
        insert_before: bool = False,
        payload_bytes: Optional[bytes] = None,
        guid: Optional[UUID] = None,
        file_type: Optional[int] = None,
        attributes: Optional[int] = None,
        state: Optional[int] = None,
    ) -> bytes:
        """Rebuild a compressed section after mutation."""
        from ...uefi import decompress_compression_section, build_compression_section
        from ...uefi.ffs import (
            EFI_SECTION_COMPRESSION,
            EFI_SECTION_GUID_DEFINED,
            _uuid_from_bytes_le,
            EFI_CUSTOM_COMPRESSION_LZMA,
            EFI_CUSTOM_COMPRESSION_AMD_DEFLATE,
            EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1,
        )
        from ...uefi.guids import (
            EFI_GUIDED_SECTION_LZMA,
            EFI_GUIDED_SECTION_LZMA_HP,
            EFI_GUIDED_SECTION_LZMA_MS,
            EFI_GUIDED_SECTION_LZMAF86,
            EFI_GUIDED_SECTION_ZLIB_AMD,
            EFI_GUIDED_SECTION_ZLIB_AMD2,
        )
        from ...uefi.decompressor import decompress_guid_defined

        # Mapping from section GUID to compression type constant
        GUID_TO_COMPRESSION_TYPE: Dict[UUID, int] = {
            EFI_GUIDED_SECTION_LZMA: EFI_CUSTOM_COMPRESSION_LZMA,
            EFI_GUIDED_SECTION_LZMA_HP: EFI_CUSTOM_COMPRESSION_LZMA,
            EFI_GUIDED_SECTION_LZMA_MS: EFI_CUSTOM_COMPRESSION_LZMA,
            EFI_GUIDED_SECTION_LZMAF86: EFI_CUSTOM_COMPRESSION_LZMA,
            EFI_GUIDED_SECTION_ZLIB_AMD: EFI_CUSTOM_COMPRESSION_AMD_DEFLATE,
            EFI_GUIDED_SECTION_ZLIB_AMD2: EFI_CUSTOM_COMPRESSION_AMD_DEFLATE1,
        }

        if len(section_bytes) < 4:
            raise FirmwareMutationError("Section too small")

        # Determine section type from header
        section_type = section_bytes[3]
        
        header_len = 4
        size_field = int.from_bytes(section_bytes[:3], "little")
        if size_field == 0xFFFFFF and len(section_bytes) >= 8:
            header_len = 8

        decompressed: bytes
        compression_type: int = 0
        section_guid: Optional[UUID] = None

        try:
            if section_type == EFI_SECTION_COMPRESSION:
                # Standard compression section (type 0x01)
                decompressed, compression_type, _, _ = decompress_compression_section(section_bytes)
            elif section_type == EFI_SECTION_GUID_DEFINED:
                # GUID-defined section (type 0x02) - usually LZMA or AMD ZLIB
                if len(section_bytes) < header_len + 20:
                    raise FirmwareMutationError("GUID-defined section too small")
                guid_offset = header_len
                section_guid = _uuid_from_bytes_le(bytes(section_bytes[guid_offset:guid_offset+16]))
                data_offset = int.from_bytes(section_bytes[guid_offset+16:guid_offset+18], "little")
                # attributes at guid_offset+18:guid_offset+20
                
                # Adjust data_offset relative to section start (it's relative to GUID start)
                abs_data_offset = header_len + data_offset
                if abs_data_offset > len(section_bytes):
                    raise FirmwareMutationError("Invalid data offset in GUID-defined section")
                
                preamble = section_bytes[header_len+20:abs_data_offset]
                body = section_bytes[abs_data_offset:]
                
                result = decompress_guid_defined(section_guid, bytes(preamble), bytes(body))
                if result is None:
                    raise FirmwareMutationError(f"No decompression handler for GUID {section_guid}")
                decompressed = result
                # Map section GUID to proper compression type for rebuild
                compression_type = GUID_TO_COMPRESSION_TYPE.get(
                    section_guid, EFI_CUSTOM_COMPRESSION_LZMA
                )
            else:
                raise FirmwareMutationError(f"Unsupported section type 0x{section_type:02X}")
        except FirmwareMutationError:
            raise
        except Exception as exc:
            raise FirmwareMutationError(
                "Failed to decompress section. If you just performed another operation, "
                "please re-select the item from the tree and try again."
            ) from exc

        # Scan for firmware volumes in the decompressed blob
        parsed_volumes = scan_firmware_volumes(decompressed, 0, len(decompressed))
        if not parsed_volumes:
            raise FirmwareMutationError("No firmware volumes found inside compressed section")
        enumerated_volumes, _, _ = enumerate_volumes(parsed_volumes, fv_start=0, ffs_start=0)

        target_vol = ctx.target_volume.info
        matched_vol = self._find_matching_volume(
            [vol.info for vol in enumerated_volumes],
            target_vol,
        )
        if matched_vol is None:
            raise FirmwareMutationError("Unable to locate target volume in decompressed data")

        # ctx.file_index is the global enumeration index, not the position within volume.files
        # We must find the actual position by looking up the file in matched_vol's files list
        file_idx = self._find_matching_file_index(matched_vol.files, ctx.target_file.info)
        if file_idx is None:
            raise FirmwareMutationError("Unable to locate target file in decompressed volume")

        blob = bytearray(decompressed)
        if action == "insert":
            if payload_bytes is None:
                raise FirmwareMutationError("Insert requires payload bytes")
            insert_idx = file_idx if insert_before else file_idx + 1
            try:
                insert_ffs_file(
                    blob,
                    matched_vol,
                    insert_idx,
                    payload_bytes,
                    guid=guid,
                    file_type=int(file_type) if file_type is not None else 0,
                    attributes=int(attributes) if attributes is not None else 0,
                    state=int(state) if state is not None else 0,
                )
            except FirmwareMutationError as exc:
                # Check if it's a space issue - if so, try to grow the FV
                error_msg = str(exc)
                if "not enough free space" in error_msg:
                    import re
                    match = re.search(r"short by 0x([0-9A-Fa-f]+)", error_msg)
                    shortage = int(match.group(1), 16) if match else 0x10000
                    extra_needed = shortage + 0x1000  # Add padding for alignment
                    
                    # Try to resize the FV
                    grown_volume = self._grow_firmware_volume_in_blob(blob, matched_vol, extra_needed)
                    if grown_volume is None:
                        raise FirmwareMutationError(
                            f"Cannot resize firmware volume to make room for insertion.\n\n{exc}"
                        ) from exc
                    
                    # Retry insertion with resized volume
                    insert_ffs_file(
                        blob,
                        grown_volume,
                        insert_idx,
                        payload_bytes,
                        guid=guid,
                        file_type=int(file_type) if file_type is not None else 0,
                        attributes=int(attributes) if attributes is not None else 0,
                        state=int(state) if state is not None else 0,
                    )
                else:
                    raise
        elif action == "replace":
            if payload_bytes is None:
                raise FirmwareMutationError("Replace requires payload bytes")
            try:
                replace_ffs_file(
                    blob,
                    matched_vol,
                    file_idx,
                    payload_bytes,
                    guid=guid if guid is not None else ctx.target_file.info.guid,
                    file_type=int(file_type) if file_type is not None else int(ctx.target_file.info.type),
                    attributes=int(attributes) if attributes is not None else int(ctx.target_file.info.attributes),
                    state=int(state) if state is not None else int(ctx.target_file.info.state),
                )
            except FirmwareMutationError as exc:
                # Check if it's a space issue - if so, try to grow the FV
                error_msg = str(exc)
                if "not enough free space" in error_msg:
                    import re
                    match = re.search(r"short by 0x([0-9A-Fa-f]+)", error_msg)
                    shortage = int(match.group(1), 16) if match else 0x10000
                    extra_needed = shortage + 0x1000  # Add padding for alignment
                    
                    # Try to grow the FV
                    grown_volume = self._grow_firmware_volume_in_blob(blob, matched_vol, extra_needed)
                    if grown_volume is None:
                        raise FirmwareMutationError(
                            f"Cannot grow firmware volume to make room for replacement.\n\n{exc}"
                        ) from exc
                    
                    # Retry replacement with grown volume
                    replace_ffs_file(
                        blob,
                        grown_volume,
                        file_idx,
                        payload_bytes,
                        guid=guid if guid is not None else ctx.target_file.info.guid,
                        file_type=int(file_type) if file_type is not None else int(ctx.target_file.info.type),
                        attributes=int(attributes) if attributes is not None else int(ctx.target_file.info.attributes),
                        state=int(state) if state is not None else int(ctx.target_file.info.state),
                    )
                else:
                    raise
        elif action == "remove":
            remove_ffs_file(
                blob,
                matched_vol,
                file_idx,
            )
        else:
            raise ValueError("unsupported compressed section mutation")
        
        # Rebuild the section with the appropriate format
        return build_compression_section(
            bytes(blob),
            compression_type=compression_type,
            original_header_length=header_len,
            original_section_bytes=section_bytes,  # Pass original for format detection
        )

    def _edit_uefi_compressed_section(self: "MainWindow", payload: dict) -> None:
        """Open a dialog to edit a compressed UEFI section."""
        # Check if entry is soft-locked (referenced by 0x62 PSP entry)
        # Skip this check for compressed BIOS edits (PSP tab workflow is the correct way)
        if not self._is_compressed_bios_edit(payload) and self._is_soft_locked_by_0x62(payload):
            if not self._show_soft_lock_warning(payload):
                return
        
        image_index = payload.get("image_index")
        offset = payload.get("offset")
        if image_index is None or offset is None:
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Image index or offset is missing.",
            )
            return
        try:
            idx = int(image_index)
            section_offset = int(offset)
        except Exception:
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Unable to parse image index or offset.",
            )
            return
        if not (0 <= idx < len(self.loaded_images)):
            QMessageBox.warning(
                self, "Invalid selection", "Image index is out of range."
            )
            return
        image = self.loaded_images[idx]
        context = self._locate_uefi_section_context(image, section_offset)
        if context is None:
            QMessageBox.warning(
                self,
                "Not found",
                "Unable to locate the selected compression section.",
            )
            return
        volume, file_enum, section_enum, section_idx = context
        file_offset = payload.get("file_offset")
        if file_offset is None:
            file_offset = file_enum.info.absolute_offset
        section_info = section_enum.info
        if section_info.type != EFI_SECTION_COMPRESSION:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "The selected section is not a compression section.",
            )
            return
        if section_info.compression_type not in SUPPORTED_UEFI_COMPRESSION_TYPES:
            QMessageBox.warning(
                self,
                "Unsupported compression",
                f"Compression type {section_info.compression_type} is not supported.",
            )
            return
        if section_info.absolute_offset is None or section_info.size <= 0:
            QMessageBox.warning(
                self,
                "Incomplete metadata",
                "Section offset or size is not available.",
            )
            return
        start = int(section_info.absolute_offset)
        end = start + int(section_info.size)
        if not (0 <= start < end <= len(image.data)):
            QMessageBox.warning(
                self,
                "Invalid range",
                "Section range exceeds image boundaries.",
            )
            return
        section_bytes = bytes(image.data[start:end])
        try:
            decompressed = decompress_compression_section(section_bytes)
            decompressed_size = len(decompressed)
        except Exception as exc:
            QMessageBox.critical(
                self,
                "Decompression failed",
                f"Unable to decompress the section: {exc}",
            )
            return
        label = payload.get("label") or section_info.type_name or "section"
        safe_label = re.sub(r"[^A-Za-z0-9_.-]", "_", str(label)) or "section"

        base_dir = image.path.parent if image.path else Path.cwd()
        default_path = base_dir / f"{safe_label}_decompressed.bin"

        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Compressed Section - {label}")
        dialog.setAttribute(Qt.WA_DeleteOnClose, True)

        # Build UI in Python
        wrapper = QVBoxLayout(dialog)
        wrapper.setContentsMargins(12, 12, 12, 12)
        wrapper.setSpacing(10)

        description_label = QLabel(
            "Export the decompressed section, edit the file externally, then select the modified data to recompress and queue in the firmware image.",
            dialog
        )
        description_label.setObjectName("description_label")
        description_label.setWordWrap(True)
        wrapper.addWidget(description_label)

        # Export row
        export_layout = QHBoxLayout()
        export_edit = QLineEdit(dialog)
        export_edit.setObjectName("export_path_edit")
        export_edit.setPlaceholderText("Export path…")
        export_layout.addWidget(export_edit)
        export_button = QPushButton("Export…", dialog)
        export_button.setObjectName("export_browse_button")
        export_layout.addWidget(export_button)
        wrapper.addLayout(export_layout)

        # Import row
        import_layout = QHBoxLayout()
        import_edit = QLineEdit(dialog)
        import_edit.setObjectName("import_path_edit")
        import_edit.setPlaceholderText("Modified data path…")
        import_layout.addWidget(import_edit)
        import_button = QPushButton("Browse…", dialog)
        import_button.setObjectName("import_browse_button")
        import_layout.addWidget(import_button)
        wrapper.addLayout(import_layout)

        status_label = QLabel("", dialog)
        status_label.setObjectName("status_label")
        status_label.setWordWrap(True)
        wrapper.addWidget(status_label)

        button_box = QDialogButtonBox(
            QDialogButtonBox.Cancel | QDialogButtonBox.Ok, dialog
        )
        button_box.setObjectName("button_box")
        wrapper.addWidget(button_box)

        export_edit.setText(str(default_path))
        if status_label:
            status_label.setText(
                f"Decompressed size: {decompressed_size:,} bytes"
            )

        def browse_export():
            path, _ = QFileDialog.getSaveFileName(
                dialog,
                "Export decompressed section",
                export_edit.text() or str(default_path),
                "Binary files (*.bin);;All files (*)",
            )
            if path:
                export_edit.setText(path)

        def browse_import():
            path, _ = QFileDialog.getOpenFileName(
                dialog,
                "Import modified section",
                import_edit.text() or str(base_dir),
                "Binary files (*.bin);;All files (*)",
            )
            if path:
                import_edit.setText(path)

        def do_export():
            path = export_edit.text().strip()
            if not path:
                QMessageBox.warning(dialog, "No path", "Please specify an export path.")
                return
            try:
                Path(path).write_bytes(decompressed)
                if status_label:
                    status_label.setText(f"Exported {decompressed_size:,} bytes to {Path(path).name}")
            except Exception as exc:
                QMessageBox.critical(dialog, "Export failed", str(exc))

        def do_import():
            path = import_edit.text().strip()
            if not path:
                QMessageBox.warning(dialog, "No path", "Please specify an import path.")
                return
            try:
                new_data = Path(path).read_bytes()
            except Exception as exc:
                QMessageBox.critical(dialog, "Import failed", str(exc))
                return
            try:
                new_section = build_compression_section(
                    new_data,
                    compression_type=section_info.compression_type,
                )
            except Exception as exc:
                QMessageBox.critical(dialog, "Compression failed", str(exc))
                return
            if len(new_section) > section_info.size:
                result = QMessageBox.question(
                    dialog,
                    "Size mismatch",
                    f"Compressed section is larger than original "
                    f"({len(new_section)} vs {section_info.size}). Continue?",
                )
                if result != QMessageBox.Yes:
                    return
            image.data[start : start + len(new_section)] = new_section
            if len(new_section) < section_info.size:
                pad_start = start + len(new_section)
                pad_end = start + int(section_info.size)
                image.data[pad_start:pad_end] = b"\xFF" * (pad_end - pad_start)
            self._record_modified_range(idx, start, int(section_info.size))
            image.needs_reparse = True
            self._mark_image_dirty(idx)
            image.change_log.append(
                f"UEFI: replaced compressed section at 0x{start:X}"
            )
            if status_label:
                status_label.setText(f"Imported and compressed {len(new_data):,} bytes")
            self._status_message(f"Replaced compressed section at 0x{start:X}")

        if export_button:
            export_button.clicked.connect(browse_export)
        if import_button:
            import_button.clicked.connect(browse_import)

        apply_btn = button_box.button(QDialogButtonBox.Apply)
        if apply_btn:
            apply_btn.clicked.connect(do_export)

        save_btn = button_box.button(QDialogButtonBox.Save)
        if save_btn:
            save_btn.clicked.connect(do_import)

        button_box.rejected.connect(dialog.reject)
        dialog.resize(600, 200)
        dialog.exec()

    def _insert_uefi_file(self: "MainWindow", payload: dict, *, insert_before: bool) -> None:
        """Insert a new UEFI firmware file."""
        # Check for compressed BIOS edit FIRST (before trying to locate in uefi_roots)
        if self._is_compressed_bios_edit(payload):
            image_index = payload.get("image_index")
            if image_index is None or not (0 <= image_index < len(self.loaded_images)):
                QMessageBox.warning(
                    self, "Invalid selection",
                    "Unable to determine the image for compressed BIOS edit.",
                )
                return
            image = self.loaded_images[int(image_index)]
            self._insert_uefi_file_compressed_bios_from_payload(
                image, int(image_index), payload, insert_before
            )
            return
        
        # Check if entry is soft-locked (referenced by 0x62 PSP entry)
        # Only for non-compressed BIOS edits (UEFI tab access to protected region)
        if self._is_soft_locked_by_0x62(payload):
            if not self._show_soft_lock_warning(payload):
                return
        
        image_index = payload.get("image_index")
        ctx_file = self._resolve_uefi_file_context_from_payload(payload)
        ctx_volume = (
            self._resolve_uefi_volume_context_from_payload(payload)
            if ctx_file is None
            else None
        )
        image_idx: Optional[int] = None
        if ctx_file is not None:
            image_idx = ctx_file.image_index
        elif ctx_volume is not None:
            image_idx = ctx_volume.image_index
        elif image_index is not None:
            try:
                image_idx = int(image_index)
            except Exception:
                image_idx = None
        if image_idx is None or not (0 <= image_idx < len(self.loaded_images)):
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Unable to determine the selected firmware volume.",
            )
            return
        image = self.loaded_images[image_idx]
        offset_value = payload.get("offset")
        try:
            target_offset = int(offset_value) if offset_value is not None else None
        except Exception:
            target_offset = None

        uefi_kind = payload.get("uefi_kind")
        volume_info = None
        insert_index = 0
        volume_offset = None

        if uefi_kind == "file":
            if ctx_file is None:
                if target_offset is None:
                    QMessageBox.warning(
                        self,
                        "Invalid selection",
                        "Unable to determine the selected firmware file.",
                    )
                    return
                context = self._locate_uefi_file_context(image, target_offset)
                if context is None:
                    QMessageBox.warning(
                        self,
                        "Not found",
                        "Unable to locate metadata for the selected firmware file.",
                    )
                    return
                volume_enum, _local_idx, file_enum = context
                volume_info = volume_enum.info
                try:
                    insert_index = volume_info.files.index(file_enum.info)
                except ValueError:
                    insert_index = len(volume_info.files)
                if not insert_before:
                    insert_index += 1
                volume_offset = volume_info.absolute_offset
            else:
                volume_info = ctx_file.target_volume.info
                file_enum = ctx_file.target_file
                # ctx_file.file_index is the global enumeration index, not the position within volume.files
                # We must find the actual position by looking up the file in the volume's files list
                try:
                    insert_index = volume_info.files.index(file_enum.info)
                except ValueError:
                    # Fallback: match by offset or guid
                    found_idx = self._find_matching_file_index(volume_info.files, file_enum.info)
                    insert_index = found_idx if found_idx is not None else len(volume_info.files)
                if not insert_before:
                    insert_index += 1
                volume_offset = volume_info.absolute_offset
        elif uefi_kind == "volume":
            if ctx_volume is None:
                if target_offset is not None:
                    volume_enum = self._locate_uefi_volume_context(image, target_offset)
                    if volume_enum:
                        volume_info = volume_enum.info
                        insert_index = len(volume_info.files)
                        volume_offset = volume_info.absolute_offset
            else:
                if ctx_volume.virtual:
                    QMessageBox.warning(
                        self,
                        "Unsupported selection",
                        "Insertions must target a specific file inside compressed volumes.",
                    )
                    return
                volume_info = ctx_volume.target_volume.info
                insert_index = len(volume_info.files)
                volume_offset = volume_info.absolute_offset
        else:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Firmware files can only be inserted from a volume or file item.",
            )
            return

        if volume_info is None:
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Unable to resolve the target firmware volume.",
            )
            return

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
        guid_value = parsed_info.guid if parsed_info and parsed_info.guid else None
        type_value = parsed_info.type if parsed_info else None
        attributes_value = parsed_info.attributes if parsed_info else None
        state_value = parsed_info.state if parsed_info else None

        if (
            guid_value is None
            or type_value is None
            or attributes_value is None
            or state_value is None
        ):
            metadata = self._prompt_uefi_file_metadata(
                title="Insert Firmware File",
                default_guid=guid_value,
                default_type=type_value,
                default_attributes=attributes_value,
                default_state=state_value,
            )
            if metadata is None:
                return
            guid_value, type_value, attributes_value, state_value = metadata
        else:
            if not isinstance(guid_value, UUID):
                guid_value = UUID(str(guid_value))
            type_value = int(type_value) & 0xFF
            attributes_value = int(attributes_value) & 0xFF
            state_value = int(state_value) & 0xFF

        # Handle compressed BIOS entry (type 0x62)
        if self._is_compressed_bios_edit(payload):
            self._insert_uefi_file_compressed_bios(
                image, image_idx, payload, payload_bytes,
                guid_value, type_value, attributes_value, state_value,
                insert_before,
            )
            return

        # Handle virtual (compressed section) context
        if ctx_file and ctx_file.virtual:
            self._insert_uefi_file_virtual(
                image, image_idx, ctx_file, payload_bytes,
                guid_value, type_value, attributes_value, state_value,
                insert_before, payload,
            )
            return

        try:
            insert_ffs_file(
                image.data,
                volume_info,
                insert_index,
                payload_bytes,
                guid=guid_value,
                file_type=int(type_value),
                attributes=int(attributes_value),
                state=int(state_value),
            )
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Insertion failed", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Insertion failed", str(exc))
            return

        volume_base = int(volume_offset) if volume_offset is not None else 0
        volume_span = int(volume_info.size) if volume_info.size else 0

        self._finalize_uefi_mutation(
            image, image_idx, str(guid_value), volume_info,
            volume_base, volume_span, "insert", payload,
        )

    def _insert_uefi_file_virtual(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        ctx_file: UefiFileContextInfo,
        payload_bytes: bytes,
        guid_value: UUID,
        type_value: int,
        attributes_value: int,
        state_value: int,
        insert_before: bool,
        payload: dict,
    ) -> None:
        """Handle insertion into a virtual (compressed) UEFI volume."""
        root_volume = ctx_file.root_volume.info
        root_file = ctx_file.root_file.info
        try:
            root_file_index = root_volume.files.index(root_file)
        except ValueError:
            root_file_index = None
            for candidate_index, candidate in enumerate(root_volume.files):
                if candidate.absolute_offset == root_file.absolute_offset:
                    root_file_index = candidate_index
                    break
        if root_file_index is None or not ctx_file.section_path:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Unable to determine the parent file for insertion.",
            )
            return
        section_idx = ctx_file.section_path[0]
        section_info = root_file.sections[section_idx]
        sec_offset = section_info.absolute_offset
        sec_size = section_info.size
        if sec_offset is None or sec_size <= 0:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Compressed section metadata is incomplete.",
            )
            return
        sec_start = int(sec_offset)
        sec_end = sec_start + int(sec_size)
        section_bytes = bytes(image.data[sec_start:sec_end])
        original_section_size = len(section_bytes)
        try:
            new_section_bytes = self._rebuild_compressed_section(
                section_bytes,
                ctx_file,
                action="insert",
                insert_before=insert_before,
                payload_bytes=payload_bytes,
                guid=guid_value,
                file_type=int(type_value),
                attributes=int(attributes_value),
                state=int(state_value),
            )
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Insertion failed", str(exc))
            return
        except Exception as exc:
            QMessageBox.critical(self, "Insertion failed", str(exc))
            return
        assembled = self._assemble_ffs_payload_with_section(
            image.data, root_file, section_idx, new_section_bytes
        )
        if assembled is None:
            QMessageBox.critical(
                self,
                "Insertion failed",
                "Unable to rebuild the parent firmware file payload.",
            )
            return
        try:
            replace_ffs_file(
                image.data,
                root_volume,
                root_file_index,
                assembled,
                guid=root_file.guid,
                file_type=int(root_file.type),
                attributes=int(root_file.attributes),
                state=int(root_file.state),
            )
        except FirmwareMutationError as exc:
            # Calculate available space for better error message
            volume_free = self._calculate_volume_free_space(root_volume)
            reclaimable = self._calculate_reclaimable_padding(root_volume, image.data)
            error_msg = self._format_compressed_section_error(
                str(exc), original_section_size, len(new_section_bytes),
                volume_free, reclaimable
            )
            QMessageBox.critical(self, "Insertion failed", error_msg)
            return

        volume_base = int(root_volume.absolute_offset or 0)
        volume_span = int(root_volume.size) if root_volume.size else 0

        self._finalize_uefi_mutation(
            image, image_idx, str(guid_value), root_volume,
            volume_base, volume_span, "insert", payload,
        )

    def _replace_uefi_file(self: "MainWindow", payload: dict) -> None:
        """Replace an existing UEFI firmware file."""
        # Check for compressed BIOS edit FIRST (before trying to locate in uefi_roots)
        if self._is_compressed_bios_edit(payload):
            image_index = payload.get("image_index")
            if image_index is None or not (0 <= image_index < len(self.loaded_images)):
                QMessageBox.warning(
                    self, "Invalid selection",
                    "Unable to determine the image for compressed BIOS edit.",
                )
                return
            image = self.loaded_images[int(image_index)]
            self._replace_uefi_file_compressed_bios_from_payload(image, int(image_index), payload)
            return
        
        # Check if entry is soft-locked (referenced by 0x62 PSP entry)
        # Only for non-compressed BIOS edits (UEFI tab access to protected region)
        if self._is_soft_locked_by_0x62(payload):
            if not self._show_soft_lock_warning(payload):
                return
        
        image_index = payload.get("image_index")
        ctx = self._resolve_uefi_file_context_from_payload(payload)
        image_idx: Optional[int] = None
        if ctx is not None:
            image_idx = ctx.image_index
        elif image_index is not None:
            try:
                image_idx = int(image_index)
            except Exception:
                image_idx = None
        if image_idx is None or not (0 <= image_idx < len(self.loaded_images)):
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Unable to determine the selected firmware file.",
            )
            return
        image = self.loaded_images[image_idx]

        if ctx is None:
            offset = payload.get("offset")
            if offset is None:
                QMessageBox.warning(
                    self, "Invalid selection", "File offset is missing."
                )
                return
            context = self._locate_uefi_file_context(image, int(offset))
            if context is None:
                QMessageBox.warning(
                    self, "Not found", "Unable to locate the selected firmware file."
                )
                return
            volume_enum, file_index, file_enum = context
            volume_info = volume_enum.info
        else:
            volume_info = ctx.target_volume.info
            file_enum = ctx.target_file
            # ctx.file_index is the global enumeration index, not the position within volume.files
            # We must find the actual position by looking up the file in the volume's files list
            try:
                file_index = volume_info.files.index(file_enum.info)
            except ValueError:
                # Fallback: match by offset or guid
                file_index = self._find_matching_file_index(volume_info.files, file_enum.info)
                if file_index is None:
                    file_index = 0

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
        guid_value = parsed_info.guid if parsed_info else file_enum.info.guid
        type_value = parsed_info.type if parsed_info else file_enum.info.type
        attributes_value = parsed_info.attributes if parsed_info else file_enum.info.attributes
        state_value = parsed_info.state if parsed_info else file_enum.info.state

        if not isinstance(guid_value, UUID):
            guid_value = UUID(str(guid_value)) if guid_value else file_enum.info.guid

        # Handle virtual (compressed section) context
        if ctx and ctx.virtual:
            self._replace_uefi_file_virtual(
                image, image_idx, ctx, payload_bytes,
                guid_value, int(type_value), int(attributes_value), int(state_value),
                payload,
            )
            return

        try:
            replace_ffs_file(
                image.data,
                volume_info,
                file_index,
                payload_bytes,
                guid=guid_value,
                file_type=int(type_value),
                attributes=int(attributes_value),
                state=int(state_value),
            )
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Replacement failed", str(exc))
            return

        volume_base = int(volume_info.absolute_offset or 0)
        volume_span = int(volume_info.size) if volume_info.size else 0

        self._finalize_uefi_mutation(
            image, image_idx, str(guid_value), volume_info,
            volume_base, volume_span, "replaced", payload,
        )

    def _replace_uefi_file_virtual(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        ctx: UefiFileContextInfo,
        payload_bytes: bytes,
        guid_value: UUID,
        type_value: int,
        attributes_value: int,
        state_value: int,
        payload: dict,
    ) -> None:
        """Handle replacement in a virtual (compressed) UEFI volume."""
        root_volume = ctx.root_volume.info
        root_file = ctx.root_file.info
        
        try:
            root_file_index = root_volume.files.index(root_file)
        except ValueError:
            root_file_index = None
            for idx, candidate in enumerate(root_volume.files):
                if candidate.absolute_offset == root_file.absolute_offset:
                    root_file_index = idx
                    break
        if root_file_index is None or not ctx.section_path:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Unable to determine the parent file for replacement.",
            )
            return
        section_idx = ctx.section_path[0]
        section_info = root_file.sections[section_idx]
        sec_offset = section_info.absolute_offset
        sec_size = section_info.size
        
        if sec_offset is None or sec_size <= 0:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Compressed section metadata is incomplete.",
            )
            return
        sec_start = int(sec_offset)
        sec_end = sec_start + int(sec_size)
        section_bytes = bytes(image.data[sec_start:sec_end])
        original_section_size = len(section_bytes)
        try:
            new_section_bytes = self._rebuild_compressed_section(
                section_bytes,
                ctx,
                action="replace",
                payload_bytes=payload_bytes,
                guid=guid_value,
                file_type=type_value,
                attributes=attributes_value,
                state=state_value,
            )
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Replacement failed", str(exc))
            return
        assembled = self._assemble_ffs_payload_with_section(
            image.data, root_file, section_idx, new_section_bytes
        )
        if assembled is None:
            QMessageBox.critical(
                self,
                "Replacement failed",
                "Unable to rebuild the parent firmware file payload.",
            )
            return
        try:
            replace_ffs_file(
                image.data,
                root_volume,
                root_file_index,
                assembled,
                guid=root_file.guid,
                file_type=int(root_file.type),
                attributes=int(root_file.attributes),
                state=int(root_file.state),
            )
        except FirmwareMutationError as exc:
            # Calculate available space for better error message
            volume_free = self._calculate_volume_free_space(root_volume)
            reclaimable = self._calculate_reclaimable_padding(root_volume, image.data)
            error_msg = self._format_compressed_section_error(
                str(exc), original_section_size, len(new_section_bytes),
                volume_free, reclaimable
            )
            QMessageBox.critical(self, "Replacement failed", error_msg)
            return

        volume_base = int(root_volume.absolute_offset or 0)
        volume_span = int(root_volume.size) if root_volume.size else 0

        self._finalize_uefi_mutation(
            image, image_idx, str(guid_value), root_volume,
            volume_base, volume_span, "replaced", payload,
        )

    def _remove_uefi_file(self: "MainWindow", payload: dict) -> None:
        """Mark a UEFI firmware file for removal (staged, not immediate)."""
        # Check for compressed BIOS edit FIRST (before trying to locate in uefi_roots)
        if self._is_compressed_bios_edit(payload):
            image_index = payload.get("image_index")
            if image_index is None or not (0 <= image_index < len(self.loaded_images)):
                QMessageBox.warning(
                    self, "Invalid selection",
                    "Unable to determine the image for compressed BIOS edit.",
                )
                return
            image = self.loaded_images[int(image_index)]
            self._remove_uefi_file_compressed_bios(image, int(image_index), payload)
            return
        
        # Check if entry is soft-locked (referenced by 0x62 PSP entry)
        # Only for non-compressed BIOS edits (UEFI tab access to protected region)
        if self._is_soft_locked_by_0x62(payload):
            if not self._show_soft_lock_warning(payload):
                return
        
        image_index = payload.get("image_index")
        ctx = self._resolve_uefi_file_context_from_payload(payload)
        image_idx: Optional[int] = None
        if ctx is not None:
            image_idx = ctx.image_index
        elif image_index is not None:
            try:
                image_idx = int(image_index)
            except Exception:
                image_idx = None
        if image_idx is None or not (0 <= image_idx < len(self.loaded_images)):
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Unable to determine the selected firmware file.",
            )
            return
        image = self.loaded_images[image_idx]

        if ctx is None:
            offset = payload.get("offset")
            if offset is None:
                QMessageBox.warning(
                    self, "Invalid selection", "File offset is missing."
                )
                return
            context = self._locate_uefi_file_context(image, int(offset))
            if context is None:
                QMessageBox.warning(
                    self, "Not found", "Unable to locate the selected firmware file."
                )
                return
            volume_enum, file_index, file_enum = context
            volume_info = volume_enum.info
        else:
            volume_info = ctx.target_volume.info
            file_enum = ctx.target_file
            # ctx.file_index is the global enumeration index, not the position within volume.files
            # We must find the actual position by looking up the file in the volume's files list
            try:
                file_index = volume_info.files.index(file_enum.info)
            except ValueError:
                # Fallback: match by offset or guid
                file_index = self._find_matching_file_index(volume_info.files, file_enum.info)
                if file_index is None:
                    file_index = 0

        guid_text = str(file_enum.info.guid) if file_enum.info.guid else "unknown"

        # Build action key for pending actions
        # Use the root volume for virtual files, otherwise the direct volume
        if ctx and ctx.virtual and ctx.root_volume:
            root_vol_info = ctx.root_volume.info
            volume_base = int(root_vol_info.absolute_offset or 0)
        else:
            volume_base = int(volume_info.absolute_offset or 0)
        
        guid_upper = guid_text.upper() if guid_text else ""
        file_idx_from_payload = payload.get("file_index")
        file_idx_str = str(file_idx_from_payload) if file_idx_from_payload is not None else str(file_enum.index) if file_enum.index is not None else "?"
        action_key = f"{image_idx}:{volume_base:X}:{guid_upper}:{file_idx_str}"

        # Check if already marked for removal - if so, this is a toggle to undo
        existing_action = image.pending_uefi_actions.get(action_key)
        if existing_action and existing_action.get("action") == "remove" and existing_action.get("staged"):
            # Undo the pending removal
            del image.pending_uefi_actions[action_key]
            self._append_console(f"Cancelled removal of UEFI file {guid_text}")
            self._status_message(f"Cancelled removal of {guid_text}")
            self._rebuild_from_loaded_images()
            return

        result = QMessageBox.question(
            self,
            "Mark for removal",
            f"Mark firmware file {guid_text} for removal?\n\nThe file will be removed when changes are applied.",
        )
        if result != QMessageBox.Yes:
            return

        # Store pending removal action (don't actually remove yet)
        label = payload.get("label") or getattr(volume_info, "filesystem_guid", None) or "FV"
        safe_label = _sanitize_filename(str(label), "fv")
        
        image.pending_uefi_actions[action_key] = {
            "action": "remove",
            "action_text": "Remove",
            "staged": True,  # Indicates this is a staged action, not yet applied
            "guid": guid_text,
            "volume_base": volume_base,
            "volume_offset": int(volume_info.absolute_offset or 0),
            "file_index": file_index,
            "label": safe_label,
            "image_index": image_idx,
            "virtual": ctx.virtual if ctx else False,
            "payload": payload,  # Store original payload for later execution
        }
        
        self._mark_image_dirty(image_idx)
        self._append_console(f"Marked UEFI file {guid_text} for removal")
        self._status_message(f"Marked {guid_text} for removal")
        self._rebuild_from_loaded_images()

    def _execute_uefi_removal(self: "MainWindow", action: dict) -> bool:
        """Actually execute a staged UEFI file removal. Returns True on success."""
        image_index = action.get("image_index")
        if image_index is None or not (0 <= image_index < len(self.loaded_images)):
            return False
        image = self.loaded_images[image_index]
        
        guid_text = action.get("guid", "unknown")
        
        # Handle virtual (compressed) files
        if action.get("virtual"):
            payload = action.get("payload")
            if not payload:
                self._append_console(f"Missing payload for virtual file removal of {guid_text}")
                return False
            
            # Resolve context from stored payload
            ctx = self._resolve_uefi_file_context_from_payload(payload)
            if ctx is None:
                self._append_console(f"Could not resolve context for virtual file removal of {guid_text}")
                return False
            
            return self._execute_uefi_removal_virtual(image, image_index, ctx, payload)
        
        # Use the stored volume offset to locate the volume
        volume_offset = action.get("volume_offset")
        file_index = action.get("file_index")
        
        if volume_offset is None:
            self._append_console(f"Missing volume offset for staged removal of {guid_text}")
            return False
        
        # Find the volume at this offset - search through uefi_roots
        volume_info = None
        
        def find_volume_recursive(volumes):
            """Search for volume by offset in a list of EnumeratedFirmwareVolume."""
            for vol in volumes:
                if vol.info.absolute_offset == volume_offset:
                    return vol.info
                # Search nested volumes in files->sections
                for f in vol.files:
                    for sec in f.sections:
                        if sec.volumes:
                            found = find_volume_recursive(sec.volumes)
                            if found:
                                return found
            return None
        
        uefi_roots = getattr(image, "uefi_roots", [])
        # UefiRoot objects have a 'volumes' attribute containing EnumeratedFirmwareVolume
        for root in uefi_roots:
            if hasattr(root, "volumes"):
                volume_info = find_volume_recursive(root.volumes)
                if volume_info is not None:
                    break
        
        if volume_info is None:
            self._append_console(f"Could not locate volume at 0x{volume_offset:X} for removal of {guid_text}")
            return False
        
        # Verify file_index is valid
        if file_index is None or file_index < 0 or file_index >= len(volume_info.files):
            # Try to find by GUID
            found_idx = None
            for idx, f in enumerate(volume_info.files):
                if str(f.guid).upper() == guid_text.upper():
                    found_idx = idx
                    break
            if found_idx is None:
                self._append_console(f"Could not locate file {guid_text} in volume for removal")
                return False
            file_index = found_idx
        
        try:
            remove_ffs_file(image.data, volume_info, file_index)
        except FirmwareMutationError as exc:
            self._append_console(f"Failed to remove {guid_text}: {exc}")
            return False

        volume_base = int(volume_info.absolute_offset or 0)
        volume_span = int(volume_info.size) if volume_info.size else 0
        if volume_span > 0:
            self._record_modified_range(image_index, volume_base, volume_span)
        
        image.change_log.append(f"UEFI: removed {guid_text} at 0x{volume_base:X}")
        return True

    def _execute_uefi_removal_virtual(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        ctx: UefiFileContextInfo,
        payload: dict,
    ) -> bool:
        """Execute removal from a virtual (compressed) UEFI volume. Returns True on success."""
        root_volume = ctx.root_volume.info
        root_file = ctx.root_file.info
        try:
            root_file_index = root_volume.files.index(root_file)
        except ValueError:
            root_file_index = None
            for idx, candidate in enumerate(root_volume.files):
                if candidate.absolute_offset == root_file.absolute_offset:
                    root_file_index = idx
                    break
        if root_file_index is None or not ctx.section_path:
            self._append_console("Unable to determine parent file for virtual removal")
            return False

        section_idx = ctx.section_path[0]
        section_info = root_file.sections[section_idx]
        sec_offset = section_info.absolute_offset
        sec_size = section_info.size

        if sec_offset is None or sec_size <= 0:
            self._append_console("Compressed section metadata is incomplete for virtual removal")
            return False
        
        sec_start = int(sec_offset)
        sec_end = sec_start + int(sec_size)
        section_bytes = bytes(image.data[sec_start:sec_end])

        guid_text = str(ctx.target_file.info.guid) if ctx.target_file.info.guid else "unknown"

        try:
            new_section_bytes = self._rebuild_compressed_section(
                section_bytes,
                ctx,
                action="remove",
            )
        except FirmwareMutationError as exc:
            self._append_console(f"Failed to rebuild compressed section for removal of {guid_text}: {exc}")
            return False
        
        assembled = self._assemble_ffs_payload_with_section(
            image.data, root_file, section_idx, new_section_bytes
        )
        if assembled is None:
            self._append_console(f"Failed to rebuild parent file payload for removal of {guid_text}")
            return False
        
        try:
            replace_ffs_file(
                image.data,
                root_volume,
                root_file_index,
                assembled,
                guid=root_file.guid,
                file_type=int(root_file.type),
                attributes=int(root_file.attributes),
                state=int(root_file.state),
            )
        except FirmwareMutationError as exc:
            self._append_console(f"Failed to replace parent file for removal of {guid_text}: {exc}")
            return False

        volume_base = int(root_volume.absolute_offset or 0)
        volume_span = int(root_volume.size) if root_volume.size else 0
        if volume_span > 0:
            self._record_modified_range(image_idx, volume_base, volume_span)

        image.change_log.append(f"UEFI: removed {guid_text} (virtual) at 0x{volume_base:X}")
        return True

    def _remove_uefi_file_immediate(self: "MainWindow", payload: dict) -> None:
        """Remove a UEFI firmware file immediately (legacy behavior)."""
        image_index = payload.get("image_index")
        ctx = self._resolve_uefi_file_context_from_payload(payload)
        image_idx: Optional[int] = None
        if ctx is not None:
            image_idx = ctx.image_index
        elif image_index is not None:
            try:
                image_idx = int(image_index)
            except Exception:
                image_idx = None
        if image_idx is None or not (0 <= image_idx < len(self.loaded_images)):
            QMessageBox.warning(
                self,
                "Invalid selection",
                "Unable to determine the selected firmware file.",
            )
            return
        image = self.loaded_images[image_idx]

        if ctx is None:
            offset = payload.get("offset")
            if offset is None:
                QMessageBox.warning(
                    self, "Invalid selection", "File offset is missing."
                )
                return
            context = self._locate_uefi_file_context(image, int(offset))
            if context is None:
                QMessageBox.warning(
                    self, "Not found", "Unable to locate the selected firmware file."
                )
                return
            volume_enum, file_index, file_enum = context
            volume_info = volume_enum.info
        else:
            volume_info = ctx.target_volume.info
            file_enum = ctx.target_file
            try:
                file_index = volume_info.files.index(file_enum.info)
            except ValueError:
                file_index = self._find_matching_file_index(volume_info.files, file_enum.info)
                if file_index is None:
                    file_index = 0

        guid_text = str(file_enum.info.guid) if file_enum.info.guid else "unknown"

        # Handle virtual (compressed) context
        if ctx and ctx.virtual:
            self._remove_uefi_file_virtual(image, image_idx, ctx, payload)
            return

        try:
            remove_ffs_file(image.data, volume_info, file_index)
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Removal failed", str(exc))
            return

        volume_base = int(volume_info.absolute_offset or 0)
        volume_span = int(volume_info.size) if volume_info.size else 0

        self._finalize_uefi_mutation(
            image, image_idx, guid_text, volume_info,
            volume_base, volume_span, "removed", payload,
        )

    def _remove_uefi_file_virtual(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        ctx: UefiFileContextInfo,
        payload: dict,
    ) -> None:
        """Handle removal from a virtual (compressed) UEFI volume."""
        root_volume = ctx.root_volume.info
        root_file = ctx.root_file.info
        try:
            root_file_index = root_volume.files.index(root_file)
        except ValueError:
            root_file_index = None
            for idx, candidate in enumerate(root_volume.files):
                if candidate.absolute_offset == root_file.absolute_offset:
                    root_file_index = idx
                    break
        if root_file_index is None or not ctx.section_path:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Unable to determine the parent file for removal.",
            )
            return
        section_idx = ctx.section_path[0]
        section_info = root_file.sections[section_idx]
        sec_offset = section_info.absolute_offset
        sec_size = section_info.size
        
        if sec_offset is None or sec_size <= 0:
            QMessageBox.warning(
                self,
                "Unsupported selection",
                "Compressed section metadata is incomplete.",
            )
            return
        sec_start = int(sec_offset)
        sec_end = sec_start + int(sec_size)
        section_bytes = bytes(image.data[sec_start:sec_end])

        guid_text = str(ctx.target_file.info.guid) if ctx.target_file.info.guid else "unknown"

        try:
            new_section_bytes = self._rebuild_compressed_section(
                section_bytes,
                ctx,
                action="remove",
            )
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Removal failed", str(exc))
            return
        assembled = self._assemble_ffs_payload_with_section(
            image.data, root_file, section_idx, new_section_bytes
        )
        if assembled is None:
            QMessageBox.critical(
                self,
                "Removal failed",
                "Unable to rebuild the parent firmware file payload.",
            )
            return
        try:
            replace_ffs_file(
                image.data,
                root_volume,
                root_file_index,
                assembled,
                guid=root_file.guid,
                file_type=int(root_file.type),
                attributes=int(root_file.attributes),
                state=int(root_file.state),
            )
        except FirmwareMutationError as exc:
            QMessageBox.critical(self, "Removal failed", str(exc))
            return

        volume_base = int(root_volume.absolute_offset or 0)
        volume_span = int(root_volume.size) if root_volume.size else 0

        self._finalize_uefi_mutation(
            image, image_idx, guid_text, root_volume,
            volume_base, volume_span, "removed", payload,
        )

    def _finalize_uefi_mutation(
        self: "MainWindow",
        image: "LoadedImage",
        image_idx: int,
        guid_text: str,
        volume_info,
        volume_base: int,
        volume_span: int,
        action: str,
        payload: dict,
    ) -> None:
        """Finalize a UEFI mutation by updating state and rebuilding."""
        label = payload.get("label") or getattr(volume_info, "filesystem_guid", None) or "FV"
        safe_label = _sanitize_filename(str(label), "fv")

        if volume_span > 0:
            self._record_modified_range(image_idx, volume_base, volume_span)

        image.change_log.append(
            f"UEFI: {action} {guid_text} in {safe_label} at 0x{volume_base:X}"
        )
        image.needs_reparse = True
        self._mark_image_dirty(image_idx)

        # Store action info for tree display after rebuild
        # Key includes volume_base and file_index to handle duplicate GUIDs
        guid_upper = guid_text.upper() if guid_text else ""
        file_index = payload.get("file_index")
        file_idx_str = str(file_index) if file_index is not None else "?"
        action_key = f"{image_idx}:{volume_base:X}:{guid_upper}:{file_idx_str}"
        image.pending_uefi_actions[action_key] = {
            "action": action,
            "action_text": action.capitalize(),
            "guid": guid_text,
            "volume_base": volume_base,
            "volume_span": volume_span,
            "label": safe_label,
            "image_index": image_idx,
        }

        try:
            image.uefi_roots = self._builder._collect_uefi_roots(
                image_idx, bytes(image.data)
            )
        except Exception:
            image.uefi_roots = []
        self._append_console(
            f"UEFI: {action} {guid_text} in {safe_label} at 0x{volume_base:X}"
        )
        self._status_message(
            f"{action.capitalize()} firmware file {guid_text} at 0x{volume_base:X}"
        )
        self._rebuild_from_loaded_images()

    def _undo_uefi_staged_action(self: "MainWindow", action: dict) -> None:
        """Undo a staged UEFI action (like a pending removal)."""
        image_idx = action.get("image_index")
        if image_idx is None or not (0 <= image_idx < len(self.loaded_images)):
            raise ValueError("Invalid image index for undo")
        
        image = self.loaded_images[image_idx]
        guid_text = action.get("guid", "unknown")
        volume_base = action.get("volume_base", 0)
        
        # Find and remove the action from pending_uefi_actions
        action_key_to_remove = None
        for key, stored_action in image.pending_uefi_actions.items():
            if stored_action is action or (
                stored_action.get("guid") == guid_text and 
                stored_action.get("volume_base") == volume_base and
                stored_action.get("staged")
            ):
                action_key_to_remove = key
                break
        
        if action_key_to_remove is None:
            raise ValueError("Could not find staged action to undo")
        
        del image.pending_uefi_actions[action_key_to_remove]
        
        # Check if image is still dirty (has other pending actions)
        has_pending = (
            bool(image.pending_uefi_actions) or 
            bool(getattr(image, "pending_entry_actions", {}))
        )
        if not has_pending and not image.change_log:
            self._mark_image_dirty(image_idx, False)
        
        self._append_console(f"Cancelled staged removal of UEFI file {guid_text}")
        self._status_message(f"Cancelled removal of {guid_text}")
        self._rebuild_from_loaded_images()
