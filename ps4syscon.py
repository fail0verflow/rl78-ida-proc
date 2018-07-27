import struct
import idaapi, idc, ida_auto, ida_kernwin

MAGIC_PATCH = b'PTCH'
MAGIC_BLANK = b'BLNK'
MAGIC_BASE = b'BASE'
MAGIC_SYSTEM = b'SYST'
MAGICS = (MAGIC_PATCH, MAGIC_BLANK, MAGIC_BASE, MAGIC_SYSTEM)

class FupdBlockDesc:
    def __init__(s, buf, magic):
        is_patch = magic == MAGIC_PATCH
        s.offset, s.size, s.flash_addr = struct.unpack('<HHH', buf.read(2 * 3))
        s.offset <<= 8
        s.offset += 0x400 if is_patch else 0x110
        s.size <<= 8
        s.flash_addr <<= 8
        if is_patch and s.flash_addr == 0: s.flash_addr = 0x1000

class FupdFile:
    def __init__(s, buf):
        buf.seek(0)
        s.mac = buf.read(0x10)
        s.magic = buf.read(4)
        s.version, s.num_blocks, s.patch_version = struct.unpack('<BBB', buf.read(3))
        s.parse_blocks(buf)
    def parse_blocks(s, buf):
        s.block_descs = []
        s.blocks = []
        for i in range(s.num_blocks):
            buf.seek(0x10 + 0x10 + 8 * i)
            desc = FupdBlockDesc(buf, s.magic)
            s.block_descs.append(desc)
            buf.seek(desc.offset)
            s.blocks.append(buf.read(desc.size))
            print('%d %x %x %x' % (i, desc.offset, desc.size, desc.flash_addr))
    def iter_blocks(s):
        for desc, block in zip(s.block_descs, s.blocks):
            yield desc, block

def accept_file(li, n):
    try:
        li.seek(0x10)
        magic = li.read(4)
        if magic in MAGICS:
            return 'ps4 syscon fupd file loader'
    except:
        pass
    return 0

def make_seg(start, size):
    seg = idaapi.segment_t()
    seg.bitness = 1 # 32bit
    seg.startEA = start
    seg.endEA = start + size
    seg.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE | idaapi.SEGPERM_EXEC
    # NOTE: we have no real way to determine what is code or not. for example, 40010001 kinda looks
    # like it begins with code, but really the entire thing is data.
    seg.type = idaapi.SEG_CODE
    # they never seem to use dflash anyways
    idaapi.add_segm_ex(seg, 'cflash' if start < 0x80000 else 'dflash', 'CODE', 0)

def load_file(li, neflags, fmt):
    idaapi.set_processor_type('rl78', idaapi.SETPROC_ALL | idaapi.SETPROC_FATAL)
    f = FupdFile(li)
    if f.magic != MAGIC_PATCH:
        make_seg(0xf0000, 0x10000)
    for desc, block in f.iter_blocks():
        make_seg(desc.flash_addr, desc.size)
        idaapi.put_many_bytes(desc.flash_addr, block)
    return 1
