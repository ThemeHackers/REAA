import struct
import logging
import structlog
from pathlib import Path
from typing import Optional, Dict, Any
from enum import Enum

log = structlog.get_logger()


class BinaryType(Enum):
    PE = "pe"         
    ELF = "elf"         
    MACHO = "macho"    
    UNKNOWN = "unknown"


class FileTypeDetector:
    """Detect binary file types (PE, ELF, Mach-O) by reading magic bytes"""

    MAGIC_BYTES = {
        b'MZ': BinaryType.PE,           
        b'\x7fELF': BinaryType.ELF,  
    }


    MACHO_MAGICS = {
        0xfeedface, 
        0xcefaedfe,  
        0xfeedfacf,  
        0xcffaedfe, 
        0xcafebabe,  
        0xbebafeca,  
    }

    @classmethod
    def detect(cls, file_path: str) -> BinaryType:
        """Detect binary type from file path

        Args:
            file_path: Path to the binary file

        Returns:
            BinaryType enum value
        """
        try:
            path = Path(file_path)
            if not path.exists():
                log.warning(f"File not found: {file_path}")
                return BinaryType.UNKNOWN

            with open(path, 'rb') as f:
                header = f.read(4)

            if len(header) < 2:
                return BinaryType.UNKNOWN


            if header[:2] == b'MZ':
                try:
                    with open(path, 'rb') as f:
                        f.seek(0x3C)
                        pe_offset_bytes = f.read(4)
                        if len(pe_offset_bytes) == 4:
                            pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                            f.seek(pe_offset)
                            pe_sig = f.read(4)
                            if pe_sig == b'PE\x00\x00':
                                return BinaryType.PE
                except Exception:
                    pass
                return BinaryType.PE

            if header[:4] == b'\x7fELF':
                return BinaryType.ELF

            if len(header) == 4:
                magic_be = struct.unpack('>I', header)[0]  # Big-endian
                magic_le = struct.unpack('<I', header)[0]   # Little-endian

                if magic_be in cls.MACHO_MAGICS or magic_le in cls.MACHO_MAGICS:
                    return BinaryType.MACHO

            return BinaryType.UNKNOWN

        except Exception as e:
            log.error(f"Failed to detect file type for {file_path}: {e}", exc_info=True)
            return BinaryType.UNKNOWN

    @classmethod
    def get_file_info(cls, file_path: str) -> Dict[str, Any]:
        """Get comprehensive file information

        Args:
            file_path: Path to the binary file

        Returns:
            Dictionary with file type info, architecture, etc.
        """
        binary_type = cls.detect(file_path)

        info = {
            "path": file_path,
            "type": binary_type.value,
            "is_windows": binary_type == BinaryType.PE,
            "is_linux": binary_type == BinaryType.ELF,
            "is_macos": binary_type == BinaryType.MACHO,
            "requires_wine": binary_type == BinaryType.PE,
        }

       
        if binary_type == BinaryType.ELF:
            try:
                with open(file_path, 'rb') as f:
                    f.seek(4)  
                    ei_class = f.read(1)
                    if ei_class == b'\x01':
                        info["architecture"] = "32-bit"
                    elif ei_class == b'\x02':
                        info["architecture"] = "64-bit"
                    else:
                        info["architecture"] = "unknown"
            except Exception:
                info["architecture"] = "unknown"

      
        elif binary_type == BinaryType.PE:
            try:
                with open(file_path, 'rb') as f:
                    f.seek(0x3C)
                    pe_offset_bytes = f.read(4)
                    pe_offset = struct.unpack('<I', pe_offset_bytes)[0]
                    f.seek(pe_offset + 4)  
                    machine_type = f.read(2)
                    machine_val = struct.unpack('<H', machine_type)[0]

                    arch_map = {
                        0x014c: "x86 (32-bit)",
                        0x8664: "x64 (64-bit)",
                        0x01c0: "ARM",
                        0xaa64: "ARM64",
                    }
                    info["architecture"] = arch_map.get(machine_val, f"unknown (0x{machine_val:04x})")
            except Exception:
                info["architecture"] = "unknown"

        return info


def detect_binary_type(file_path: str) -> str:
    """Simple function to detect binary type as string"""
    return FileTypeDetector.detect(file_path).value


def get_binary_info(file_path: str) -> Dict[str, Any]:
    """Get full binary information"""
    return FileTypeDetector.get_file_info(file_path)
