#!/usr/bin/env python3
import ctypes
import os
import platform
import ipaddress
from typing import Dict

# 1. Architecture-specific syscall detection
arch = platform.machine().lower()
if "x86_64" in arch or "amd64" in arch:
    SYS_BPF = 321
elif "aarch64" in arch or "arm64" in arch:
    SYS_BPF = 280
else:
    # Fallback to standard x86_64
    SYS_BPF = 321

libc = ctypes.CDLL("libc.so.6", use_errno=True)

class bpf_attr(ctypes.Union):
    class map_elem(ctypes.Structure):
        _fields_ = [
            ("map_fd", ctypes.c_uint32),
            ("key", ctypes.c_uint64),
            ("value", ctypes.c_uint64),
            ("flags", ctypes.c_uint64),
        ]
    class obj_get(ctypes.Structure):
        _fields_ = [
            ("pathname", ctypes.c_uint64),
            ("bpf_fd", ctypes.c_uint32),
            ("file_flags", ctypes.c_uint32),
        ]
    _fields_ = [("elem", map_elem), ("obj_get", obj_get)]

def bpf_syscall(cmd: int, attr: bpf_attr) -> int:
    res = libc.syscall(SYS_BPF, cmd, ctypes.byref(attr), ctypes.sizeof(attr))
    if res < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return res

def bpf_obj_get(path: str) -> int:
    attr = bpf_attr()
    # Keep the path buffer alive in a local until the syscall returns. A bare
    # c_char_p(path.encode()) creates a temporary bytes object that Python may
    # free before syscall() runs, leaving pathname pointing at garbage -> ENOENT.
    path_buf = ctypes.create_string_buffer(path.encode())
    attr.obj_get.pathname = ctypes.cast(path_buf, ctypes.c_void_p).value
    return bpf_syscall(7, attr)

# 2. Dynamic CPU core scaling for PERCPU arrays
num_cpus = os.cpu_count() or 1

class PercpuValue(ctypes.Structure):
    _fields_ = [("vals", ctypes.c_uint64 * num_cpus)]

# 3. IPv4 Map Structs and Helpers
class BpfKey(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_uint8 * 4)]

class BpfValue(ctypes.Structure):
    _fields_ = [("val", ctypes.c_uint32)]

class ProtoKey(ctypes.Structure):
    _fields_ = [("val", ctypes.c_uint8)]

def key_to_ip(k: BpfKey) -> str:
    return str(ipaddress.IPv4Address(bytes(k.bytes)))

def ip_to_key(ip_str: str) -> BpfKey:
    k = BpfKey()
    k.bytes = (ctypes.c_uint8 * 4)(*ipaddress.IPv4Address(ip_str).packed)
    return k

def dump_map_u32(fd: int) -> Dict[str, int]:
    res = {}
    first_key = BpfKey()
    current_key = BpfKey()
    next_key = BpfKey()
    value = BpfValue()
    
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = 0
    attr.elem.value = ctypes.addressof(first_key)
    
    try:
        bpf_syscall(4, attr)
    except OSError as e:
        if e.errno == 2:
            return res
        raise
        
    ctypes.memmove(ctypes.addressof(current_key), ctypes.addressof(first_key), ctypes.sizeof(BpfKey))

    while True:
        attr_lookup = bpf_attr()
        attr_lookup.elem.map_fd = fd
        attr_lookup.elem.key = ctypes.addressof(current_key)
        attr_lookup.elem.value = ctypes.addressof(value)
        try:
            bpf_syscall(1, attr_lookup)
            res[key_to_ip(current_key)] = value.val
        except OSError:
            pass
            
        attr_next = bpf_attr()
        attr_next.elem.map_fd = fd
        attr_next.elem.key = ctypes.addressof(current_key)
        attr_next.elem.value = ctypes.addressof(next_key)
        try:
            bpf_syscall(4, attr_next)
            ctypes.memmove(ctypes.addressof(current_key), ctypes.addressof(next_key), ctypes.sizeof(BpfKey))
        except OSError as e:
            break
            
    return res

def set_map_u32(fd: int, ip_str: str, val: int) -> None:
    k = ip_to_key(ip_str)
    v = BpfValue()
    v.val = val
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    attr.elem.value = ctypes.addressof(v)
    attr.elem.flags = 0
    bpf_syscall(2, attr)

def del_map_u32(fd: int, ip_str: str) -> None:
    k = ip_to_key(ip_str)
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    bpf_syscall(3, attr)

# 4. IPv6 Map Structs and Helpers
class BpfKeyV6(ctypes.Structure):
    _fields_ = [("bytes", ctypes.c_uint8 * 16)]

def key_to_ip_v6(k: BpfKeyV6) -> str:
    return str(ipaddress.IPv6Address(bytes(k.bytes)))

def ip_to_key_v6(ip_str: str) -> BpfKeyV6:
    k = BpfKeyV6()
    k.bytes = (ctypes.c_uint8 * 16)(*ipaddress.IPv6Address(ip_str).packed)
    return k

def dump_map_u32_v6(fd: int) -> Dict[str, int]:
    res = {}
    first_key = BpfKeyV6()
    current_key = BpfKeyV6()
    next_key = BpfKeyV6()
    value = BpfValue()
    
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = 0
    attr.elem.value = ctypes.addressof(first_key)
    
    try:
        bpf_syscall(4, attr)
    except OSError as e:
        if e.errno == 2:
            return res
        raise
        
    ctypes.memmove(ctypes.addressof(current_key), ctypes.addressof(first_key), ctypes.sizeof(BpfKeyV6))

    while True:
        attr_lookup = bpf_attr()
        attr_lookup.elem.map_fd = fd
        attr_lookup.elem.key = ctypes.addressof(current_key)
        attr_lookup.elem.value = ctypes.addressof(value)
        try:
            bpf_syscall(1, attr_lookup)
            res[key_to_ip_v6(current_key)] = value.val
        except OSError:
            pass
            
        attr_next = bpf_attr()
        attr_next.elem.map_fd = fd
        attr_next.elem.key = ctypes.addressof(current_key)
        attr_next.elem.value = ctypes.addressof(next_key)
        try:
            bpf_syscall(4, attr_next)
            ctypes.memmove(ctypes.addressof(current_key), ctypes.addressof(next_key), ctypes.sizeof(BpfKeyV6))
        except OSError as e:
            break
            
    return res

def set_map_u32_v6(fd: int, ip_str: str, val: int) -> None:
    k = ip_to_key_v6(ip_str)
    v = BpfValue()
    v.val = val
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    attr.elem.value = ctypes.addressof(v)
    attr.elem.flags = 0
    bpf_syscall(2, attr)

def del_map_u32_v6(fd: int, ip_str: str) -> None:
    k = ip_to_key_v6(ip_str)
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    bpf_syscall(3, attr)

# 5. Other map operations
def set_proto_filter(fd: int, proto: int, action: int) -> None:
    k = ProtoKey()
    k.val = proto
    v = BpfValue()
    v.val = action
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    attr.elem.value = ctypes.addressof(v)
    attr.elem.flags = 0
    bpf_syscall(2, attr)

def get_global_counter(fd: int) -> int:
    k = BpfValue()
    k.val = 0
    v = PercpuValue()
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    attr.elem.value = ctypes.addressof(v)
    try:
        bpf_syscall(1, attr)
        return sum(v.vals[i] for i in range(num_cpus))
    except OSError:
        return 0

def get_global_tokens(fd: int) -> int:
    class TokenBucket(ctypes.Structure):
        _fields_ = [("last_time", ctypes.c_uint64), ("tokens", ctypes.c_int64)]
    k = BpfValue()
    k.val = 0
    v = TokenBucket()
    attr = bpf_attr()
    attr.elem.map_fd = fd
    attr.elem.key = ctypes.addressof(k)
    attr.elem.value = ctypes.addressof(v)
    try:
        bpf_syscall(1, attr)
        return v.tokens
    except OSError:
        return 0
