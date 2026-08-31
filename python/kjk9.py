# -*- coding: utf-8 -*-
"""KJKv9 二进制包格式 + 大文件多线程调度框架。

格式布局 (小端):
    [定长头 64B][数据块区域...][目录密文 blob][空洞...]
    定长头: magic'KJK9' ver u16 flags u16 kdf_iter u32 dir_offset u64
            dir_len u32 salt 16B dir_nonce 12B 保留 12B
    数据块: [nonce 12B][密文][tag 16B], 独立 AES-256-GCM, 可随机访问
    目录:   明文 JSON(AES-GCM 加密) {files:[{p,s,m,b}], free:[[off,len]], ...}

多线程调度:
    分页 = 调度单位, 页内由 4MB 块组成。线程安全队列派发, 预扩展目标文件,
    按固定偏移直写, 全程零临时文件。
    数据通路全 C (kjkfast-10500.dll): 每页一次调用, DLL 内完成
    定位读取→分块 AES-GCM→定位写入, Python 侧无文件 I/O、无 GIL 争用;
    C 内部按块流式, 每线程内存恒为 2×块大小(约 8MB), 与分页大小无关。
    分页大小自适应(总量/1000, ≥4MB): 进度粒度 ≤0.1%, 断点重算量小。
    看门狗: 单页心跳超时重新入队由其他线程接管。
    断点续传: <目标>.kjkprog 记录已完成页, 中断后重启续跑。

KDF: PBKDF2-HMAC-SHA256(600000, salt16) → 32B 主密钥 (与网页版 WebCrypto 一致)。
"""

import ctypes
import json
import os
import queue
import secrets
import struct
import sys
import threading
import time

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    import msvcrt
except ImportError:  # 非 Windows
    msvcrt = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import engine  # noqa: E402  复用其 DLL 加载器 (kjkfast-10500.dll 优先)

__all__ = [
    'KJK9Error', 'KJK9AuthError', 'KJK9Cancel', 'KJK9Package',
    'encrypt_paths_to_kjk9', 'encrypt_entries_to_kjk9', 'plan_params',
    'is_kjk9', 'peek_info', 'BLOCK_SIZE',
]

MAGIC = b'KJK9'
VERSION = 9
HEADER_SIZE = 64
BLOCK_SIZE = 4 * 1024 * 1024
KDF_ITER = 600000
_FLAG_HAS_PASSWORD = 1
_NONCE_SIZE = 12
_TAG_SIZE = 16

_HDR = struct.Struct('<4sHHIQI16s12s12x')  # 共 64 字节


class KJK9Error(Exception):
    pass


class KJK9AuthError(KJK9Error):
    """密码错误或数据被篡改。"""


class KJK9Cancel(KJK9Error):
    """用户取消。"""


# ============================================================
# AES-256-GCM: C 引擎优先(kjkfast-10500.dll, CNG), 回退 cryptography
# ============================================================

_C = engine._KJKFAST
_HAS_C = _C is not None and hasattr(_C, 'kjk_aesgcm_open')
if _HAS_C:
    try:
        _C.kjk_aesgcm_open.restype = ctypes.c_long
        _C.kjk_aesgcm_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_void_p)]
        _C.kjk_aesgcm_close.restype = ctypes.c_long
        _C.kjk_aesgcm_close.argtypes = [ctypes.c_void_p]
        _C.kjk_aesgcm_encrypt.restype = ctypes.c_long
        _C.kjk_aesgcm_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                           ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
        _C.kjk_aesgcm_decrypt.restype = ctypes.c_long
        _C.kjk_aesgcm_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                           ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
        _C.kjk_sha256.restype = ctypes.c_long
        _C.kjk_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        _C.kjk_block_encrypt.restype = ctypes.c_long
        _C.kjk_block_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                         ctypes.c_size_t, ctypes.c_char_p]
        _C.kjk_block_decrypt.restype = ctypes.c_long
        _C.kjk_block_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                         ctypes.c_size_t, ctypes.c_char_p]
        _C.kjk_page_encrypt.restype = ctypes.c_long
        _C.kjk_page_encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t]
        _C.kjk_page_decrypt.restype = ctypes.c_long
        _C.kjk_page_decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                                        ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t]
        _C.kjk_run_encrypt_io.restype = ctypes.c_long
        _C.kjk_run_encrypt_io.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                                          ctypes.c_void_p, ctypes.c_uint64,
                                          ctypes.c_size_t, ctypes.c_size_t]
        _C.kjk_run_decrypt_io.restype = ctypes.c_long
        _C.kjk_run_decrypt_io.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                                          ctypes.c_void_p, ctypes.c_uint64,
                                          ctypes.c_size_t, ctypes.c_size_t]
        _C.kjk_run_rekey_io.restype = ctypes.c_long
        _C.kjk_run_rekey_io.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                        ctypes.c_uint64, ctypes.c_uint64,
                                        ctypes.c_size_t, ctypes.c_size_t]
    except Exception:
        _HAS_C = False

# 数据通路全 C: 读→加/解密→写 在 DLL 内一次完成(内部按块流式, 每线程内存恒 2×块大小),
# Python 侧每页仅一次 ctypes 调用, 无 Python I/O、无 GIL 争用。
_HAS_C_IO = (_HAS_C and msvcrt is not None
             and hasattr(_C, 'kjk_run_encrypt_io')
             and hasattr(_C, 'kjk_run_decrypt_io')
             and hasattr(_C, 'kjk_run_rekey_io'))

# 调度器全 C: 线程池/原子认领/看门狗重派/OVERLAPPED 读写/进度回调都在 DLL 内,
# Python 一次调用提交全部分页, 数据通路零 Python 参与。
if _HAS_C and hasattr(_C, 'kjk_run_jobs'):
    class _CJobS(ctypes.Structure):
        _fields_ = [('inOff', ctypes.c_uint64), ('outOff', ctypes.c_uint64),
                    ('n', ctypes.c_uint64), ('weight', ctypes.c_uint64),
                    ('inIdx', ctypes.c_uint32), ('outIdx', ctypes.c_uint32)]

    _PROG_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_double,
                               ctypes.c_uint32, ctypes.c_uint32)
    try:
        _C.kjk_run_jobs.restype = ctypes.c_long
        _C.kjk_run_jobs.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                                    ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_uint32,
                                    ctypes.POINTER(ctypes.c_wchar_p), ctypes.c_uint32,
                                    ctypes.c_int,
                                    ctypes.POINTER(_CJobS), ctypes.c_uint32,
                                    ctypes.c_uint32, ctypes.c_int,
                                    ctypes.POINTER(ctypes.c_uint32),
                                    ctypes.POINTER(ctypes.c_long),
                                    _PROG_CB, ctypes.c_void_p]
        _HAS_C_SCHED = True
    except Exception:
        _HAS_C_SCHED = False
else:
    _HAS_C_SCHED = False

# Win32 直调: 稀疏预扩展用。NTFS 普通扩展会同步清零新增区域(实测 4GB 要 10s+);
# FSCTL_SET_SPARSE 后 SetEndOfFile 为纯元数据操作(0ms), 页写入时才真正分配簇。
_K32 = None
if msvcrt is not None:
    try:
        _K32 = ctypes.WinDLL('kernel32', use_last_error=True)
        _K32.DeviceIoControl.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                         ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        _K32.DeviceIoControl.restype = ctypes.c_int
        _K32.SetFilePointerEx.argtypes = [ctypes.c_void_p, ctypes.c_longlong,
                                          ctypes.c_void_p, ctypes.c_uint32]
        _K32.SetFilePointerEx.restype = ctypes.c_int
        _K32.SetEndOfFile.argtypes = [ctypes.c_void_p]
        _K32.SetEndOfFile.restype = ctypes.c_int
    except Exception:
        _K32 = None

_FSCTL_SET_SPARSE = 0x000900C4


def _sparse_extend(path, final_size):
    """把目标文件稀疏化并扩展到 final_size(只增不减)。失败回退普通 truncate。"""
    try:
        if os.path.getsize(path) >= final_size:
            return
    except OSError:
        pass
    if _K32 is None:
        with open(path, 'r+b') as f:
            f.truncate(final_size)
        return
    f = open(path, 'r+b', buffering=0)
    try:
        h = msvcrt.get_osfhandle(f.fileno())
        got = ctypes.c_uint32(0)
        _K32.DeviceIoControl(h, _FSCTL_SET_SPARSE, None, 0, None, 0,
                             ctypes.byref(got), None)
        if not (_K32.SetFilePointerEx(h, final_size, None, 0)
                and _K32.SetEndOfFile(h)):
            raise KJK9Error('预扩展目标文件失败 (Win32)')
    finally:
        f.close()

_tls = threading.local()


def _touch(path, mtime):
    """设置文件修改时间(恢复原时间戳), 失败忽略。"""
    if mtime:
        try:
            os.utime(path, (mtime, mtime))
        except OSError:
            pass


def _cp(x):
    """bytes / ctypes 缓冲区 → c_char_p 兼容实参(零拷贝)。"""
    if isinstance(x, bytes):
        return x
    return ctypes.cast(x, ctypes.c_char_p)


def _tls_buf(name, cap):
    """线程本地复用缓冲(只增不减), 避免每页重复大分配。"""
    b = getattr(_tls, name, None)
    if b is None or ctypes.sizeof(b) < cap:
        b = ctypes.create_string_buffer(cap)
        setattr(_tls, name, b)
    return b


def _tls_release():
    """释放本线程的 C 密码上下文、大缓冲与文件句柄。"""
    for slot in (0, 1):
        c = getattr(_tls, 'cipher%d' % slot, None)
        if c is not None and c[0] == 'c':
            try:
                _C.kjk_aesgcm_close(c[1])
            except Exception:
                pass
        setattr(_tls, 'cipher%d' % slot, None)
        setattr(_tls, 'key%d' % slot, None)
    _tls.rb = None
    _tls.ob = None
    for attr in ('rdh', 'wrh', 'wh_r', 'wh_w', 'wh_rw'):
        h = getattr(_tls, attr, None)
        if h is not None:
            try:
                h[1].close()
            except OSError:
                pass
            setattr(_tls, attr, None)


def _tls_whandle(name, path, mode):
    """线程持久化 Win32 句柄(buffering=0), 供 C 引擎 SetFilePointerEx+Read/WriteFile 直读直写。

    返回 int 句柄; 同一路径跨页复用, 免去每页开关文件。"""
    h = getattr(_tls, name, None)
    if h is not None and h[0] == path:
        return h[2]
    if h is not None:
        try:
            h[1].close()
        except OSError:
            pass
    f = open(path, mode, buffering=0)
    fh = msvcrt.get_osfhandle(f.fileno())
    setattr(_tls, name, (path, f, fh))
    return fh


def _tls_reader(path):
    """线程持久化读句柄: 同一源文件跨页复用, 免去每页开关文件。"""
    h = getattr(_tls, 'rdh', None)
    if h is not None and h[0] == path:
        return h[1]
    if h is not None:
        try:
            h[1].close()
        except OSError:
            pass
    f = open(path, 'rb')
    _tls.rdh = (path, f)
    return f


def _tls_writer(path):
    """线程持久化写句柄(r+b, 按偏移写)。"""
    h = getattr(_tls, 'wrh', None)
    if h is not None and h[0] == path:
        return h[1]
    if h is not None:
        try:
            h[1].close()
        except OSError:
            pass
    f = open(path, 'r+b')
    _tls.wrh = (path, f)
    return f


def _py_aesgcm(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key)


def _thread_cipher(key, slot=0):
    """线程本地密码上下文。slot 0 常规, slot 1 换密时的新密钥(与旧上下文共存)。"""
    ca, ka = 'cipher%d' % slot, 'key%d' % slot
    c = getattr(_tls, ca, None)
    k = getattr(_tls, ka, None)
    if c is not None and k == key:
        return c
    if c is not None and c[0] == 'c':
        try:
            _C.kjk_aesgcm_close(c[1])
        except Exception:
            pass
    if _HAS_C:
        ctx = ctypes.c_void_p()
        if _C.kjk_aesgcm_open(key, ctypes.byref(ctx)) == 0 and ctx.value:
            c = ('c', ctx)
            setattr(_tls, ca, c)
            setattr(_tls, ka, key)
            return c
    c = ('py', _py_aesgcm(key))
    setattr(_tls, ca, c)
    setattr(_tls, ka, key)
    return c


def _cipher_ctx(key):
    """C 引擎上下文(c_void_p), 不可用时返回 None(调用方走 Python 回退)。"""
    c = _thread_cipher(key)
    return c[1] if c[0] == 'c' else None


def _aes_seal(key, data):
    """加密 → [nonce|ct|tag] 完整块。"""
    nonce = os.urandom(_NONCE_SIZE)
    c = _thread_cipher(key)
    if c[0] == 'c':
        n = len(data)
        out = ctypes.create_string_buffer(n + 1)
        tag = ctypes.create_string_buffer(16)
        rc = _C.kjk_aesgcm_encrypt(c[1], nonce, data if n else b'', n, out, tag)
        if rc != 0:
            raise KJK9Error(f'AES 加密失败 rc={rc}')
        return nonce + out.raw[:n] + tag.raw[:16]
    return nonce + c[1].encrypt(nonce, data, None)


def _aes_open(key, blob):
    """解密 [nonce|ct|tag] 完整块。校验失败抛 KJK9AuthError。"""
    if len(blob) < _NONCE_SIZE + _TAG_SIZE:
        raise KJK9AuthError('数据块不完整')
    nonce = blob[:_NONCE_SIZE]
    ct = blob[_NONCE_SIZE:-_TAG_SIZE]
    tag = blob[-_TAG_SIZE:]
    c = _thread_cipher(key)
    if c[0] == 'c':
        n = len(ct)
        out = ctypes.create_string_buffer(n + 1)
        rc = _C.kjk_aesgcm_decrypt(c[1], nonce, ct if n else b'', n, tag, out)
        if rc != 0:
            raise KJK9AuthError('密码错误或数据已损坏')
        return out.raw[:n]
    try:
        return c[1].decrypt(nonce, ct + tag, None)
    except Exception:
        raise KJK9AuthError('密码错误或数据已损坏')


def _page_runs(blocks):
    """[(off, 密文总长, 明文总长)] 把连续块合并为段(增量分配后块未必连续)。"""
    runs = []
    for off, size in blocks:
        off, size = int(off), int(size)
        if runs and runs[-1][0] + runs[-1][1] == off:
            runs[-1][1] += size
            runs[-1][2] += size - _NONCE_SIZE - _TAG_SIZE
        else:
            runs.append([off, size, size - _NONCE_SIZE - _TAG_SIZE])
    return runs


def _page_runs_idx(blocks):
    """[(起始块索引, off, 密文总长, 明文总长)] 同 _page_runs 但记录块索引(换密映射用)。"""
    runs = []
    for i, (off, size) in enumerate(blocks):
        off, size = int(off), int(size)
        if runs and runs[-1][1] + runs[-1][2] == off:
            runs[-1][2] += size
            runs[-1][3] += size - _NONCE_SIZE - _TAG_SIZE
        else:
            runs.append([i, off, size, size - _NONCE_SIZE - _TAG_SIZE])
    return runs


def _page_timeout(n_bytes):
    """单页看门狗超时(秒): 覆盖整页读+写+加密, 极慢磁盘也不误判重派。"""
    return max(120.0, 2.5 * (n_bytes / (1024.0 * 1024.0)))


def _seg(buf, off, n):
    """ctypes 缓冲零拷贝切片(同一段内存, 偏移视图)。"""
    return (ctypes.c_char * n).from_address(ctypes.addressof(buf) + off)


def _page_seal(key, in_buf, in_n, out_buf, out_cap):
    """整页加密: in_buf 前 in_n 字节明文 → out_buf, 返回密文长度。

    C 路径单次调用处理整页(释放 GIL), 输出布局 [nonce|ct|tag]* 与逐块一致。"""
    c = _thread_cipher(key)
    if c[0] == 'c':
        rc = _C.kjk_page_encrypt(c[1], _cp(in_buf), in_n, _cp(out_buf),
                                 out_cap, BLOCK_SIZE)
        if rc < 0:
            raise KJK9Error(f'页加密失败 rc={rc}')
        return rc
    mv = memoryview(out_buf).cast('B')
    pos = 0
    for i in range(0, in_n, BLOCK_SIZE):
        chunk = in_buf[i:i + BLOCK_SIZE] if isinstance(in_buf, bytes) \
            else memoryview(in_buf).cast('B')[i:i + BLOCK_SIZE].tobytes()
        nonce = os.urandom(_NONCE_SIZE)
        blob = nonce + c[1].encrypt(nonce, chunk, None)
        mv[pos:pos + len(blob)] = blob
        pos += len(blob)
    return pos


def _page_open(key, in_buf, in_n, out_buf, out_cap):
    """整页解密: in_buf 前 in_n 字节密文 → out_buf, 返回明文长度。"""
    c = _thread_cipher(key)
    if c[0] == 'c':
        rc = _C.kjk_page_decrypt(c[1], _cp(in_buf), in_n, _cp(out_buf),
                                 out_cap, BLOCK_SIZE)
        if rc < 0:
            raise KJK9AuthError('密码错误或数据已损坏')
        return rc
    plain = bytearray()
    pos = 0
    src = in_buf if isinstance(in_buf, bytes) else memoryview(in_buf).cast('B')
    while pos < in_n:
        rem = in_n - pos
        take = BLOCK_SIZE if rem >= BLOCK_SIZE + _NONCE_SIZE + _TAG_SIZE \
            else rem - _NONCE_SIZE - _TAG_SIZE
        plain += _aes_open(key, bytes(src[pos:pos + take + _NONCE_SIZE + _TAG_SIZE]))
        pos += take + _NONCE_SIZE + _TAG_SIZE
    memoryview(out_buf).cast('B')[:len(plain)] = plain
    return len(plain)


def _derive_key(password, salt, iterations=KDF_ITER):
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=iterations).derive((password or '').encode('utf-8'))


def _sha256_hex(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def is_kjk9(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4) == MAGIC
    except OSError:
        return False


def peek_info(path):
    """快速探测包信息(不派生密钥, 毫秒级): (是否 KJKv9, 是否有密码)。

    非 v9 文件返回 (False, None), 由调用方走旧格式链路。"""
    try:
        hdr = _read_header(path)
    except Exception:
        return False, None
    return True, bool(hdr['flags'] & _FLAG_HAS_PASSWORD)


# ============================================================
# 资源规划: 线程数 / 分页大小
# ============================================================

class SchedParams(object):
    __slots__ = ('threads', 'page_bytes', 'watch_base', 'reserve_cores', 'mem_frac')

    def __init__(self, threads, page_bytes, reserve_cores=1, mem_frac=0.55):
        self.threads = threads
        self.page_bytes = page_bytes
        self.reserve_cores = reserve_cores
        self.mem_frac = mem_frac


def plan_params(cfg=None, reserve_cores=None, mem_frac=None):
    """根据 CPU 核心数与可用内存计算线程数与分页大小。

    原则: 预留至少 1 核给主程序与系统; 每线程峰值内存 ≈ 页大小 + 单块,
    总占用 ≤ 可用内存的 mem_frac (默认 55%)。
    可被 config (v9_threads / v9_page_mb / v9_reserve_cores) 覆盖。
    """
    cores = os.cpu_count() or 4
    if cfg is None:
        try:
            import config
            cfg = config.load_config()
        except Exception:
            cfg = {}
    reserve = cfg.get('v9_reserve_cores', reserve_cores if reserve_cores is not None else 1)
    reserve = max(0, int(reserve))
    frac = float(cfg.get('v9_mem_frac', mem_frac if mem_frac is not None else 0.55))

    threads = max(1, cores - reserve)
    if psutil is not None:
        try:
            budget = psutil.virtual_memory().available * min(max(frac, 0.1), 0.9)
        except Exception:
            budget = 1 << 30
    else:
        budget = 1 << 30

    user_threads = cfg.get('v9_threads')
    if user_threads:
        threads = max(1, min(int(user_threads), cores * 2))

    page = int(budget // max(1, threads))
    page = max(BLOCK_SIZE, (page // BLOCK_SIZE) * BLOCK_SIZE)
    page = min(page, 256 * 1024 * 1024)

    user_page = cfg.get('v9_page_mb')
    if user_page:
        page = max(BLOCK_SIZE, (int(user_page) * 1024 * 1024 // BLOCK_SIZE) * BLOCK_SIZE)

    return SchedParams(threads, page, reserve, frac)


def _set_thread_priority_below_normal():
    """工作线程降到略低优先级, 为系统与其他程序预留性能。"""
    if os.name != 'nt':
        return
    try:
        k32 = ctypes.windll.kernel32
        k32.SetThreadPriority(k32.GetCurrentThread(), -1)  # THREAD_PRIORITY_BELOW_NORMAL
    except Exception:
        pass


# ============================================================
# 断点续传
# ============================================================

class _Checkpoint(object):
    """进度文件: 记录已完成分页, 中断后可续跑。完成后自动删除。"""

    def __init__(self, target_path, sig, total):
        self.path = target_path + '.kjkprog'
        self.sig = sig
        self.total = total
        self.done = [False] * total
        self._lock = threading.Lock()
        self._last_flush = 0.0
        if os.path.exists(self.path):
            try:
                with open(self.path, 'r', encoding='utf-8') as f:
                    d = json.load(f)
                if d.get('sig') == sig and d.get('n') == total:
                    done = d.get('done') or []
                    self.done = [bool(x) for x in done[:total]]
                    if len(self.done) < total:
                        self.done += [False] * (total - len(self.done))
            except Exception:
                self.done = [False] * total

    def count(self):
        with self._lock:
            return sum(1 for x in self.done if x)

    def mark(self, idx):
        with self._lock:
            first = not self.done[idx]
            self.done[idx] = True
        if first:
            now = time.time()
            if now - self._last_flush >= 1.0:
                self._last_flush = now
                self._flush()

    def flush(self):
        """立即落盘当前进度(出错/取消路径调用)。"""
        self._last_flush = time.time()
        self._flush()

    def _flush(self):
        tmp = self.path + '.tmp'
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                json.dump({'sig': self.sig, 'n': self.total, 'done': self.done}, f)
            os.replace(tmp, self.path)
        except OSError:
            pass

    def finish(self):
        try:
            if os.path.exists(self.path):
                os.remove(self.path)
        except OSError:
            pass


# ============================================================
# 分页调度器: 队列派发 + 看门狗重派
# ============================================================

class _Job(object):
    __slots__ = ('idx', 'gen', 'done', 'deadline', 'hb', 'lock')

    def __init__(self, idx):
        self.idx = idx
        self.gen = 0        # 代际: 看门狗重派 +1, 旧线程据此作废
        self.done = False
        self.deadline = 0.0
        self.hb = 0.0
        self.lock = threading.Lock()

    def beat(self, gen, base_timeout):
        with self.lock:
            if self.gen != gen or self.done:
                return False
            self.hb = time.time()
            self.deadline = self.hb + base_timeout
            return True


def run_paged(page_count, page_fn, params, progress=None, cancel=None,
              checkpoint=None, label='处理', weight=None):
    """通用分页调度器。

    page_fn(job, wid, gen, beat) 在工作线程执行整页:
        - 每处理一块前调用 beat(gen, timeout) 维持心跳, 返回 False 表示已被
          看门狗重派(旧代际), 应立即放弃当前页。
        - 正常完成时返回; 抛异常则整页失败。
    weight: 每页权重(默认 1), 用于进度聚合。
    返回完成页数。
    """
    if page_count == 0:
        if progress:
            progress(1.0, label + '完成')
        return 0

    jobs = [_Job(i) for i in range(page_count)]
    weights = list(weight) if weight else [1.0] * page_count
    total_w = float(sum(weights)) or 1.0
    done_w = [0.0]
    done_count = [0]
    q = queue.SimpleQueue()
    for j in jobs:
        if not (checkpoint and checkpoint.done[j.idx]):
            q.put(j)
        else:
            j.done = True
            done_w[0] += weights[j.idx]
            done_count[0] += 1

    base_timeout = max(120.0, params.page_bytes * 2.5 / (1024.0 * 1024.0))
    stop = threading.Event()
    done_evt = threading.Event()  # 最后一页完成即触发, 看门狗免空转等待
    err = []
    err_lock = threading.Lock()
    progress_lock = threading.Lock()

    def report(frac, text):
        if progress:
            with progress_lock:
                try:
                    progress(frac, text)
                except Exception:
                    pass

    def worker(wid):
        _set_thread_priority_below_normal()
        try:
            while not stop.is_set():
                if cancel is not None and cancel.is_set():
                    stop.set()
                    return
                try:
                    job = q.get_nowait()
                except queue.Empty:
                    return
                if job is None or job.done:
                    continue
                with job.lock:
                    if job.done:
                        continue
                    gen = job.gen
                    job.hb = time.time()
                    job.deadline = job.hb + base_timeout
                try:
                    page_fn(job, wid, gen,
                            lambda g, t=base_timeout: job.beat(g, t))
                except KJK9Cancel:
                    stop.set()
                    continue
                except Exception as e:
                    with err_lock:
                        if not err:
                            err.append(e)
                    stop.set()
                    return
                with job.lock:
                    already = job.done
                    ok = (job.gen == gen)
                    if ok:
                        job.done = True
                if ok and not already:
                    done_count[0] += 1
                    done_w[0] += weights[job.idx]
                    if checkpoint:
                        checkpoint.mark(job.idx)
                    if done_count[0] >= page_count:
                        done_evt.set()
                    report(min(done_w[0] / total_w, 1.0),
                           f'{label} {done_count[0]}/{page_count}')
        finally:
            _tls_release()

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(max(1, min(params.threads, page_count)))]
    for t in threads:
        t.start()

    # 看门狗: 心跳超时 → 代际+1 重新入队, 其他线程接管
    requeued = 0
    try:
        while done_count[0] < page_count:
            if all(not t.is_alive() for t in threads):
                break
            if cancel is not None and cancel.is_set():
                stop.set()
                break
            if done_evt.wait(timeout=0.2):
                break
            now = time.time()
            for j in jobs:
                if j.done:
                    continue
                with j.lock:
                    if not j.done and j.deadline and now > j.deadline:
                        j.gen += 1
                        j.deadline = now + base_timeout
                        requeued += 1
                        q.put(j)
    finally:
        stop.set()
        for t in threads:
            t.join(timeout=5.0)
        if checkpoint:
            checkpoint.flush()

    if err:
        raise err[0]
    if cancel is not None and cancel.is_set() and done_count[0] < page_count:
        raise KJK9Cancel('已取消')
    if done_count[0] < page_count and not err:
        # 看门狗也无法推进(如全部线程死亡)
        raise KJK9Error(f'{label}未完成 ({done_count[0]}/{page_count})')
    report(1.0, label + '完成')
    return done_count[0]


# 测试钩子(仅 _t_*.py 使用, 正常为 None):
#   _TEST_FAIL_AFTER: 完成第 N 页后模拟中途故障(取消调度并抛 KJK9Error, 保留进度文件)
#   _TEST_COUNT: dict, 记录本次实际提交给 C 调度器的页数(断点续传计数用)
_TEST_FAIL_AFTER = None
_TEST_COUNT = None


def _c_run_jobs(mode, key, key2, ins, outs, jobs, threads,
                out_truncate=False, progress=None, cancel=None,
                label='处理', names=None, checkpoint=None, cp_map=None,
                frac_scale=1.0, frac_ofs=0.0):
    """全 C 多线程分页调度: 线程池/看门狗/OVERLAPPED 读写全在 DLL 内,
    Python 一次调用提交所有任务, 数据通路零 Python 参与。

    jobs: [(inIdx, inOff, outIdx, outOff, n, weight)]
    names: 每任务显示名; cp_map: 任务索引 → 检查点页索引(断点续传)
    出错抛异常, 取消抛 KJK9Cancel。"""
    n_jobs = len(jobs)
    if n_jobs == 0:
        return
    arr = (_CJobS * n_jobs)()
    for i, (ii, io_, oi, oo, n, w) in enumerate(jobs):
        r = arr[i]
        r.inOff, r.outOff, r.n, r.weight = io_, oo, n, w
        r.inIdx, r.outIdx = ii, oi
    ins_a = (ctypes.c_wchar_p * len(ins))(*ins)
    outs_a = (ctypes.c_wchar_p * len(outs))(*outs)
    bits = (ctypes.c_uint32 * ((n_jobs + 31) // 32))()
    errinfo = (ctypes.c_long * 1)()
    st = {'cb': 0.0, 'cp': 0.0}

    def _sync_cp():
        if checkpoint is None or not cp_map:
            return
        for i in range(n_jobs):
            if bits[i >> 5] >> (i & 31) & 1:
                checkpoint.mark(cp_map[i])

    def on_prog(_ud, frac, done, total):
        try:
            if _TEST_COUNT is not None and total > st.get('tot', 0):
                st['tot'] = total
            if _TEST_FAIL_AFTER is not None and done >= _TEST_FAIL_AFTER:
                st['fail'] = True
                return 1
            now = time.time()
            if now - st['cb'] >= 0.1 or done >= total:
                st['cb'] = now
                if progress:
                    txt = f'{label} {done}/{total}'
                    if names and 0 < done <= len(names):
                        txt = f'{label} {names[done - 1]} ({done}/{total})'
                    progress(min(frac_ofs + frac_scale * frac, 1.0), txt)
            if now - st['cp'] >= 1.0:
                st['cp'] = now
                _sync_cp()
            if cancel is not None and cancel.is_set():
                return 1
        except Exception:
            pass
        return 0

    cb = _PROG_CB(on_prog)  # 持引用防 GC
    rc = _C.kjk_run_jobs(key, key2, ins_a, len(ins), outs_a, len(outs),
                         1 if out_truncate else 0, arr, n_jobs,
                         max(1, min(int(threads), 64)), mode, bits, errinfo,
                         cb, None)
    if checkpoint is not None and cp_map:
        _sync_cp()
    if _TEST_COUNT is not None:
        _TEST_COUNT['n'] = st.get('tot', 0)
    if rc == 0:
        return
    if st.get('fail'):
        raise KJK9Error('模拟中途故障')
    if rc == 1:
        raise KJK9Cancel('已取消')
    info = errinfo[0]
    cls, idx = (info // 1000000, info % 1000000) if info >= 0 else (0, 0)
    if cls == 1:
        raise KJK9AuthError('数据已损坏(校验失败)')
    if cls == 2:
        j = jobs[idx][0] if 0 <= idx < n_jobs else 0
        raise KJK9Error(f'读取失败: {ins[j] if j < len(ins) else "?"}')
    if cls == 3:
        j = jobs[idx][1] if 0 <= idx < n_jobs else 0
        raise KJK9Error(f'写入失败: {outs[j] if j < len(outs) else "?"}')
    if cls == 4:
        raise KJK9Error(f'无法打开文件: {ins[idx] if idx < len(ins) else "?"}')
    if cls == 5:
        raise KJK9Error(f'无法创建文件: {outs[idx] if idx < len(outs) else "?"}')
    if cls == 6:
        raise KJK9Error('内存不足 (C 引擎)')
    if cls == 9:
        raise KJK9Error(f'{label}未完成')
    raise KJK9Error(f'C 引擎调度失败 rc={rc} info={info}')


# ============================================================
# 打包: 路径列表 → KJKv9
# ============================================================

def _collect_entries(paths):
    """展开文件/目录 → [(relpath, abspath, size, mtime)]"""
    out = []
    seen = set()

    def add_file(rel, abspath):
        rel = rel.replace('\\', '/').lstrip('/')
        if not rel or rel in seen:
            return
        seen.add(rel)
        try:
            st = os.stat(abspath)
        except OSError:
            return
        out.append({'p': rel, 'src': abspath, 's': st.st_size, 'm': st.st_mtime})

    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            top = os.path.basename(p.rstrip('\\/')) or 'folder'
            for root, dirs, files in os.walk(p):
                for fn in sorted(files):
                    full = os.path.join(root, fn)
                    rel = top + '/' + os.path.relpath(full, p).replace('\\', '/')
                    add_file(rel, full)
        elif os.path.isfile(p):
            add_file(os.path.basename(p), p)
    out.sort(key=lambda e: e['p'])
    return out


def _blocks_of(size, start_off):
    """文件 → [(offset, csize)] 块布局, 顺序连续。"""
    blocks = []
    off = start_off
    remaining = size
    while remaining > 0:
        n = min(BLOCK_SIZE, remaining)
        blocks.append([off, n + _NONCE_SIZE + _TAG_SIZE])
        off += n + _NONCE_SIZE + _TAG_SIZE
        remaining -= n
    return blocks


def _total_csize(size):
    nblocks = (size + BLOCK_SIZE - 1) // BLOCK_SIZE if size else 0
    if not nblocks:
        return 0
    last = size - (nblocks - 1) * BLOCK_SIZE
    return size + nblocks * (_NONCE_SIZE + _TAG_SIZE)


def _pages_for(entries, layout, page_bytes):
    """按页聚合 (文件连续块): [(entry_idx, src_off, length, first_block, block_count, weight)]"""
    pages = []
    for ei, ent in enumerate(entries):
        blocks = layout[ei]
        if not blocks:
            continue
        src_off = 0
        bi = 0
        while bi < len(blocks):
            take = []
            nbytes = 0
            while bi < len(blocks) and nbytes < page_bytes:
                take.append(blocks[bi])
                nbytes += take[-1][1] - _NONCE_SIZE - _TAG_SIZE
                bi += 1
            pages.append({
                'ei': ei, 'src': ent['src'], 'src_off': src_off, 'len': nbytes,
                'blocks': take, 'weight': nbytes,
            })
            src_off += nbytes
    return pages


def _write_header(path, salt, kdf_iter, has_password, dir_offset=0, dir_len=0,
                  dir_nonce=b'', sync=True):
    with open(path, 'r+b') as f:
        f.seek(0)
        f.write(_HDR.pack(MAGIC, VERSION,
                          _FLAG_HAS_PASSWORD if has_password else 0,
                          kdf_iter, dir_offset, dir_len, salt,
                          dir_nonce or os.urandom(_NONCE_SIZE)))
        f.flush()
        if sync:
            os.fsync(f.fileno())


def _read_header(path):
    with open(path, 'rb') as f:
        raw = f.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        raise KJK9Error('文件头不完整')
    magic, ver, flags, kdf_iter, dir_off, dir_len, salt, nonce = _HDR.unpack(raw)
    if magic != MAGIC:
        raise KJK9Error('不是 KJKv9 包')
    if ver != VERSION:
        raise KJK9Error(f'不支持的版本 v{ver}')
    fsize = os.path.getsize(path)
    if dir_len and (dir_off < HEADER_SIZE or dir_off + dir_len > fsize):
        raise KJK9Error('包目录指针越界, 文件可能已损坏')
    return {'flags': flags, 'iter': kdf_iter, 'dir_off': dir_off,
            'dir_len': dir_len, 'salt': salt, 'nonce': nonce}


def _seal_dir(key, directory):
    return _aes_seal(key, json.dumps(directory, ensure_ascii=False,
                                      separators=(',', ':')).encode('utf-8'))


def _open_dir(key, blob):
    try:
        return json.loads(_aes_open(key, blob).decode('utf-8'))
    except KJK9AuthError:
        raise
    except Exception:
        raise KJK9Error('包目录数据损坏')


def encrypt_entries_to_kjk9(entries, out_path, password, progress=None, cancel=None,
                            params=None, use_checkpoint=True):
    """将显式条目打包为 KJKv9 二进制包(多线程直写, 零临时文件, 支持断点续传)。

    entries: [{'p': 包内相对路径, 'src': 源文件绝对路径, 's': 大小, 'm': mtime}]
    相对路径原样保留(可含目录层级), 供旧格式升级等需要保持路径的场景。
    返回 KJK9Package。"""
    params = params or plan_params()
    if not entries:
        raise KJK9Error('没有可打包的文件')

    # ---- 布局 ----
    layout = []
    off = HEADER_SIZE
    for ent in entries:
        blocks = _blocks_of(ent['s'], off)
        layout.append(blocks)
        if blocks:
            off = blocks[-1][0] + blocks[-1][1]
    data_end = off
    # 分页: C 引擎逐块流式, 页大小与内存无关(每线程恒 2×块大小);
    # 自适应缩页 → ≥1000 页, 进度粒度 ≤0.1%, 断点续传重算量也更小
    page_bytes = params.page_bytes
    total_plain = sum(e['s'] for e in entries)
    if _HAS_C_IO:
        want = max(BLOCK_SIZE, (total_plain + 999) // 1000)
        want = (want + BLOCK_SIZE - 1) // BLOCK_SIZE * BLOCK_SIZE
        page_bytes = max(BLOCK_SIZE, min(page_bytes, want))
    pages = _pages_for(entries, layout, page_bytes)
    total_blocks = sum(len(b) for b in layout)

    sig = _sha256_hex((out_path + '|' + str(data_end) + '|' + str(total_blocks)).encode('utf-8'))
    cp = _Checkpoint(out_path, sig, len(pages)) if use_checkpoint else None

    # ---- 头部先行(含 salt), 断点续跑时沿用同一 salt/key ----
    fresh = True
    if cp is not None and cp.count() > 0 and os.path.exists(out_path):
        try:
            hdr = _read_header(out_path)
            salt = hdr['salt']
            fresh = False
        except Exception:
            fresh = True
    if fresh:
        salt = os.urandom(16)
        # 先写真实头部(含 salt)并落盘(仅 64B, 快), 再稀疏预扩展: NTFS 普通扩展会
        # 同步清零整个目标区域(4GB 级要 10s+), 稀疏化为 0ms, 簇由页写入按需分配。
        # 顺序保证: 任何分页写入前 salt 已持久化 → 断点续传密钥一致。
        with open(out_path, 'wb') as f:
            f.write(_HDR.pack(MAGIC, VERSION,
                              _FLAG_HAS_PASSWORD if password or '' else 0,
                              KDF_ITER, 0, 0, salt, os.urandom(_NONCE_SIZE)))
            f.flush()
            os.fsync(f.fileno())
        _sparse_extend(out_path, data_end)
    else:
        _sparse_extend(out_path, data_end)  # 续跑: 补齐被截断的预扩展(幂等)
    key = _derive_key(password, salt, KDF_ITER)

    def page_fn(job, wid, gen, beat):
        pg = pages[job.idx]
        ent = entries[pg['ei']]
        n = pg['len']
        if not beat(gen, _page_timeout(n)):
            return  # 被看门狗重派, 放弃本页
        ctx = _cipher_ctx(key) if _HAS_C_IO else None
        if ctx is not None:
            # 全 C: 读取→分块加密→定位直写, 单次调用完成整页
            hsrc = _tls_whandle('wh_r', ent['src'], 'rb')
            hout = _tls_whandle('wh_w', out_path, 'r+b')
            rc = _C.kjk_run_encrypt_io(ctx, hsrc, pg['src_off'],
                                       hout, pg['blocks'][0][0], n, BLOCK_SIZE)
            if rc < 0:
                raise KJK9Error(f'页加密失败 rc={rc} (C 引擎)')
            return
        # 回退: Python 读 → C 整页 → Python 写
        cap = n + 28 * len(pg['blocks']) + 16
        rb = _tls_buf('rb', n)
        rf = _tls_reader(ent['src'])
        rf.seek(pg['src_off'])
        got = rf.readinto(memoryview(rb).cast('B')[:n])
        if got != n:
            raise KJK9Error(f'源文件读取不完整: {ent["src"]}')
        if not beat(gen, _page_timeout(n)):
            return
        ob = _tls_buf('ob', cap)
        out = _tls_writer(out_path)
        pos = 0
        for run_off, run_c, run_p in _page_runs(pg['blocks']):
            if not beat(gen, _page_timeout(n)):
                return
            rc = _page_seal(key, _seg(rb, pos, run_p), run_p, ob, cap)
            out.seek(run_off)
            out.write(memoryview(ob).cast('B')[:rc])
            pos += run_p

    if progress:
        progress(0.0, f'准备加密 {len(entries)} 个文件 / {total_blocks} 块')

    if _HAS_C_SCHED:
        # 调度全 C: 线程池+看门狗+OVERLAPPED 读写都在 DLL 内
        src_idx = {}
        ins = []
        jobs = []
        names = []
        cp_map = []
        for pi, pg in enumerate(pages):
            if cp is not None and cp.done[pi]:
                continue
            ent = entries[pg['ei']]
            sp = ent['src']
            ii = src_idx.get(sp)
            if ii is None:
                ii = len(ins)
                src_idx[sp] = ii
                ins.append(sp)
            jobs.append((ii, pg['src_off'], 0, pg['blocks'][0][0],
                         pg['len'], pg['len']))
            names.append(ent['p'])
            cp_map.append(pi)
        _c_run_jobs(0, key, None, ins, [out_path], jobs, params.threads,
                    progress=progress, cancel=cancel, label='加密',
                    names=names, checkpoint=cp, cp_map=cp_map)
    else:
        run_paged(len(pages), page_fn, params, progress=progress, cancel=cancel,
                  checkpoint=cp, label='加密',
                  weight=[p['weight'] for p in pages])

    # ---- 目录 + 头部指针 ----
    directory = {
        'v': VERSION,
        'files': [{'p': e['p'], 's': e['s'], 'm': e['m'], 'b': layout[i]}
                  for i, e in enumerate(entries)],
        'free': [],
        'app': 'KJK-Encryptor',
        'iter': KDF_ITER,
    }
    blob = _seal_dir(key, directory)
    with open(out_path, 'r+b') as f:
        f.seek(data_end)
        f.write(blob)
        f.truncate(data_end + len(blob))
    _write_header(out_path, salt, KDF_ITER, bool(password or ''),
                  dir_offset=data_end, dir_len=len(blob))
    if cp:
        cp.finish()
    return KJK9Package.open(out_path, password)


def encrypt_paths_to_kjk9(paths, out_path, password, progress=None, cancel=None,
                          params=None, use_checkpoint=True, base_dir=None):
    """将多个文件/目录打包为 KJKv9 二进制包(目录按 basename/子路径展开)。

    返回 KJK9Package。"""
    entries = _collect_entries(paths)
    if not entries:
        raise KJK9Error('没有可打包的文件')
    return encrypt_entries_to_kjk9(entries, out_path, password, progress=progress,
                                   cancel=cancel, params=params,
                                   use_checkpoint=use_checkpoint)


# ============================================================
# 包对象: 只读打开 / 按需解密 / 增量编辑
# ============================================================

class KJK9Package(object):
    def __init__(self, path, password, header, directory, key):
        self.path = os.path.abspath(path)
        self.password = password
        self.header = header
        self.key = key
        self.directory = directory
        self._files = {f['p']: f for f in directory.get('files', [])}
        self._free = [[int(o), int(l)] for o, l in directory.get('free', [])]
        self._eof = None
        self._dirty = False
        # 编辑暂存
        self._pending_add = {}     # relpath -> {'src','s','m'}
        self._pending_rename = {}  # old -> new
        self._pending_delete = set()

    # ---------- 打开 ----------
    @classmethod
    def open(cls, path, password):
        hdr = _read_header(path)
        key = _derive_key(password, hdr['salt'], hdr['iter'])
        with open(path, 'rb') as f:
            f.seek(hdr['dir_off'])
            blob = f.read(hdr['dir_len'])
        if len(blob) != hdr['dir_len']:
            raise KJK9Error('目录数据不完整')
        try:
            directory = _open_dir(key, blob)
        except KJK9AuthError:
            raise KJK9AuthError('密码错误或包已损坏')
        return cls(path, password, hdr, directory, key)

    # ---------- 基础 ----------
    @property
    def files(self):
        """dict relpath -> {p,s,m,b}"""
        return self._files

    def file_list(self):
        return sorted(self._files.values(), key=lambda f: f['p'])

    def is_dirty(self):
        return self._dirty

    def _live_size(self):
        return sum(int(f.get('s', 0)) for f in self._files.values()) \
            + sum(int(f['s']) for f in self._pending_add.values())

    def _hole_size(self):
        live_end = HEADER_SIZE
        for f in self._files.values():
            for off, size in f.get('b', []):
                live_end = max(live_end, off + size)
        for meta in self._pending_add.values():
            live_end += _total_csize(int(meta['s']))
        return max(0, self._file_end() - live_end)

    def _file_end(self):
        if self._eof is None:
            self._eof = os.path.getsize(self.path)
        return self._eof

    # ---------- 按需解密 ----------
    @staticmethod
    def _safe_join(dest_dir, rel):
        """包内相对路径 → 目标路径, 阻止目录穿越。"""
        raw = str(rel).replace('\\', '/').split('/')
        if any(p == '..' for p in raw):
            raise KJK9Error(f'非法路径: {rel}')
        parts = [p for p in raw if p not in ('', '.')]
        if not parts:
            raise KJK9Error(f'非法路径: {rel}')
        bad = [p for p in parts if ':' in p or '\x00' in p or p[0] in '<>|']
        if bad:
            raise KJK9Error(f'非法路径: {rel}')
        return os.path.join(dest_dir, *parts)

    def extract_files(self, dest_dir, relpaths=None, progress=None, cancel=None,
                      params=None, overwrite=True):
        """只解密指定文件(或全部)涉及的块, 多线程流式写盘。返回提取的文件数。"""
        params = params or plan_params()
        if relpaths is None:
            targets = self.file_list()
        else:
            targets = [self._files[p] for p in relpaths if p in self._files]
        targets = [t for t in targets if t['p'] not in self._pending_delete]
        if not targets:
            if progress:
                progress(1.0, '无文件')
            return 0

        total_bytes = sum(int(t.get('s', 0)) for t in targets) or 1
        if progress:
            progress(0.0, f'准备解密 {len(targets)} 个文件')

        if _HAS_C_SCHED:
            # 调度全 C: 线程池+看门狗+OVERLAPPED 读写都在 DLL 内
            full = BLOCK_SIZE + _NONCE_SIZE + _TAG_SIZE
            total_ct = 0
            for t in targets:
                for _o, c, _p in _page_runs(t.get('b', [])):
                    total_ct += c
            # 分块粒度对齐 总量/1000 → 进度精确到 0.1%
            want = max(full, (total_ct + 999) // 1000)
            chunk = max(1, (want + full - 1) // full) * full
            outs = []
            jobs = []
            job_names = []
            written_pairs = []
            done_files = 0
            for ent in targets:
                dest = self._safe_join(dest_dir, ent['p'])
                ddir = os.path.dirname(dest)
                if ddir:
                    os.makedirs(ddir, exist_ok=True)
                if os.path.exists(dest) and not overwrite:
                    done_files += 1
                    continue
                runs = _page_runs(ent.get('b', []))
                if not runs:
                    with open(dest, 'wb'):
                        pass
                    _touch(dest, ent.get('m'))
                    done_files += 1
                    continue
                oi = len(outs)
                outs.append(dest)
                written_pairs.append((dest, ent))
                ppos = 0
                for run_off, run_c, run_p in runs:
                    pos = 0
                    while pos < run_c:
                        take = min(run_c - pos, chunk)
                        fb = take // full
                        tail = take - fb * full
                        # 明文长度: 整块 -28/块, 尾块(若有)再 -28
                        plain = take - (fb + 1) * 28 if tail else take - fb * 28
                        jobs.append((0, run_off + pos, oi, ppos, take, plain))
                        job_names.append(ent['p'])
                        ppos += plain
                        pos += take
            if jobs:
                _c_run_jobs(1, self.key, None, [self.path], outs, jobs,
                            params.threads, out_truncate=True,
                            progress=progress, cancel=cancel, label='解密',
                            names=job_names)
            for dest, ent in written_pairs:
                _touch(dest, ent.get('m'))
                done_files += 1
            if progress:
                progress(1.0, '解密完成')
            return done_files

        written = [0]
        done_files = [0]
        lock = threading.Lock()
        err = []
        stop = threading.Event()
        tq = queue.SimpleQueue()
        for t in targets:
            tq.put(t)

        def report(frac, text):
            if progress:
                with lock:
                    try:
                        progress(frac, text)
                    except Exception:
                        pass

        def one(ent):
            if stop.is_set():
                return
            dest = self._safe_join(dest_dir, ent['p'])
            ddir = os.path.dirname(dest)
            if ddir:
                os.makedirs(ddir, exist_ok=True)
            if os.path.exists(dest) and not overwrite:
                with lock:
                    written[0] += int(ent.get('s', 0))
                    done_files[0] += 1
                    report(min(written[0] / total_bytes, 1.0),
                           f'跳过已存在: {ent["p"]}')
                return
            runs = _page_runs(ent.get('b', []))
            ctx = _cipher_ctx(self.key) if _HAS_C_IO else None
            if ctx is not None and runs:
                # 全 C: 包文件→解密→目标文件定位直写。
                # 分块粒度对齐 总量/1000 → 进度精确到 0.1%
                full = BLOCK_SIZE + _NONCE_SIZE + _TAG_SIZE
                want = max(full, (total_bytes + 999) // 1000)
                nblk = max(1, (want + full - 1) // full)
                hp = _tls_whandle('wh_r', self.path, 'rb')
                with open(dest, 'wb', buffering=0) as wf:
                    hw = msvcrt.get_osfhandle(wf.fileno())
                    ppos = 0
                    for run_off, run_c, run_p in runs:
                        pos = 0
                        while pos < run_c:
                            if cancel is not None and cancel.is_set():
                                stop.set()
                                return
                            take = min(run_c - pos, nblk * full)
                            rc = _C.kjk_run_decrypt_io(ctx, hp, run_off + pos,
                                                       hw, ppos, take, BLOCK_SIZE)
                            if rc < 0:
                                if rc in (-4, -5):
                                    raise KJK9Error(f'读写失败 rc={rc}: {ent["p"]}')
                                raise KJK9AuthError('数据已损坏(校验失败)')
                            ppos += rc
                            pos += take
                            with lock:
                                written[0] += rc
                                report(min(written[0] / total_bytes, 1.0),
                                       f'解密 {ent["p"]}')
            else:
                # 回退: Python 读 → C 整页解密 → Python 写
                chunk_lim = max(params.page_bytes, BLOCK_SIZE)
                full = BLOCK_SIZE + _NONCE_SIZE + _TAG_SIZE
                with open(self.path, 'rb') as rf, open(dest, 'wb') as wf:
                    for run_off, run_c, run_p in runs:
                        pos = 0
                        while pos < run_c:
                            if cancel is not None and cancel.is_set():
                                stop.set()
                                return
                            rem = run_c - pos
                            take = rem if rem <= chunk_lim + full \
                                else max(1, chunk_lim // full) * full
                            rb = _tls_buf('rb', take)
                            rf.seek(run_off + pos)
                            got = rf.readinto(memoryview(rb).cast('B')[:take])
                            if got != take:
                                raise KJK9Error(f'读取块失败: {ent["p"]}')
                            ob = _tls_buf('ob', take + 1)
                            pn = _page_open(self.key, rb, take, ob, take + 1)
                            wf.write(memoryview(ob).cast('B')[:pn])
                            pos += take
                            with lock:
                                written[0] += pn
                                report(min(written[0] / total_bytes, 1.0),
                                       f'解密 {ent["p"]}')
            try:
                os.utime(dest, (ent.get('m', time.time()), ent.get('m', time.time())))
            except OSError:
                pass
            with lock:
                done_files[0] += 1

        def worker():
            _set_thread_priority_below_normal()
            try:
                while not stop.is_set():
                    try:
                        ent = tq.get_nowait()
                    except queue.Empty:
                        return
                    try:
                        one(ent)
                    except KJK9Cancel:
                        stop.set()
                        return
                    except Exception as e:
                        with lock:
                            err.append(e)
                        stop.set()
                        return
            finally:
                _tls_release()

        nworkers = max(1, min(params.threads, len(targets)))
        threads = [threading.Thread(target=worker, daemon=True)
                   for _ in range(nworkers)]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        if err:
            raise err[0]
        if stop.is_set():
            raise KJK9Cancel('已取消')
        if progress:
            progress(1.0, '解密完成')
        return done_files[0]

    def read_file(self, relpath):
        """整文件读入内存(仅适合小文件, 如预览)。"""
        ent = self._files.get(relpath)
        if ent is None:
            raise KJK9Error(f'包内无此文件: {relpath}')
        parts = []
        with open(self.path, 'rb') as f:
            for run_off, run_c, run_p in _page_runs(ent.get('b', [])):
                rb = _tls_buf('rb', run_c)
                ob = _tls_buf('ob', run_c + 1)
                f.seek(run_off)
                got = f.readinto(memoryview(rb).cast('B')[:run_c])
                if got != run_c:
                    raise KJK9Error(f'读取块失败: {relpath}')
                pn = _page_open(self.key, rb, run_c, ob, run_c + 1)
                parts.append(memoryview(ob).cast('B')[:pn].tobytes())
        return b''.join(parts)

    # ---------- 增量编辑(内存暂存, save 落盘) ----------
    def stage_add(self, src_path, relpath=None):
        rel = (relpath or os.path.basename(src_path)).replace('\\', '/').lstrip('/')
        st = os.stat(src_path)
        if os.path.isdir(src_path):
            raise KJK9Error('请拖入文件而非文件夹(文件夹请用打包功能)')
        if rel in self._files or rel in self._pending_add:
            base, ext = os.path.splitext(rel)
            i = 1
            while f'{base} ({i}){ext}' in self._files or f'{base} ({i}){ext}' in self._pending_add:
                i += 1
            rel = f'{base} ({i}){ext}'
        self._pending_add[rel] = {'src': os.path.abspath(src_path),
                                   's': st.st_size, 'm': st.st_mtime}
        self._dirty = True
        return rel

    def stage_rename(self, old, new):
        if old not in self._files or old in self._pending_delete:
            raise KJK9Error(f'包内无此文件: {old}')
        new = new.replace('\\', '/').lstrip('/')
        if not new or new == old:
            return new
        if new in self._files or new in self._pending_add:
            raise KJK9Error('目标名称已存在')
        self._pending_rename[old] = new
        self._dirty = True
        return new

    def stage_delete(self, relpath):
        if relpath not in self._files:
            raise KJK9Error(f'包内无此文件: {relpath}')
        self._pending_delete.add(relpath)
        self._pending_rename.pop(relpath, None)
        self._pending_add.pop(relpath, None)
        self._dirty = True

    # ---------- 暂存查询/修正(浏览模式 UI 用) ----------

    def _recompute_dirty(self):
        self._dirty = bool(self._pending_add or self._pending_rename
                           or self._pending_delete)

    def pending_summary(self):
        """暂存修改统计 {add, rename, delete}。"""
        return {'add': len(self._pending_add),
                'rename': len(self._pending_rename),
                'delete': len(self._pending_delete)}

    def pending_add_info(self):
        """{relpath: {'src','s','m'}} — 未保存新增的源信息。"""
        return dict(self._pending_add)

    def drop_pending_add(self, relpath):
        """放弃某个未保存的新增。"""
        if self._pending_add.pop(relpath, None) is not None:
            self._recompute_dirty()

    def rename_pending_add(self, old, new):
        """重命名未保存的新增(仍留在暂存区)。"""
        if old not in self._pending_add:
            raise KJK9Error(f'暂存区无此文件: {old}')
        new = new.replace('\\', '/').lstrip('/')
        if not new or new == old:
            return new
        if new in self._files or new in self._pending_add:
            raise KJK9Error('目标名称已存在')
        self._pending_add[new] = self._pending_add.pop(old)
        return new

    def effective_files(self):
        """当前(含未保存修改)的文件视图: {relpath: {p,s,m,b|pending}}"""
        view = {}
        for p, f in self._files.items():
            if p in self._pending_delete:
                continue
            view[self._pending_rename.get(p, p)] = f
        for p, meta in self._pending_add.items():
            view[p] = {'p': p, 's': meta['s'], 'm': meta['m'], 'b': [],
                       '_pending': meta}
        return view

    # ---------- 空间分配 ----------
    def _alloc_region(self, size):
        """first-fit 分配空洞, 不够则追加到文件尾。返回 (offset, is_append)。"""
        for i, (off, length) in enumerate(self._free):
            if length >= size:
                rest = length - size
                if rest:
                    self._free[i] = [off + size, rest]
                else:
                    self._free.pop(i)
                return off, False
        off = self._file_end()
        self._eof = off + size
        return off, True

    # ---------- 保存(增量落盘) ----------
    def save(self, progress=None, cancel=None, params=None):
        """应用暂存修改: 新增追加块, 删除回收为空洞, 重命名只改目录。
        最后原子更新头部指针。失败回滚内存空间表。不改密码。"""
        if not self._dirty:
            if progress:
                progress(1.0, '无修改')
            return False
        params = params or plan_params()
        if progress:
            progress(0.0, '正在保存…')
        free_snapshot = [list(x) for x in self._free]
        try:
            return self._save_impl(progress, cancel, params)
        except Exception:
            self._free = free_snapshot
            self._eof = None
            raise

    def _save_impl(self, progress, cancel, params):
        # 1) 新增文件 → 整段连续分配(优先复用空洞, 否则追加文件尾),
        #    连续布局让保存路径也能整页批量加密
        add_files = []
        for rel, meta in sorted(self._pending_add.items()):
            try:
                st = os.stat(meta['src'])
                if st.st_size != meta['s']:
                    raise KJK9Error(f'源文件已变化: {meta["src"]}')
            except OSError:
                raise KJK9Error(f'源文件不可读: {meta["src"]}')
            total_c = _total_csize(meta['s'])
            if total_c:
                off, _ = self._alloc_region(total_c)
                blocks = _blocks_of(meta['s'], off)
            else:
                blocks = []
            add_files.append({'p': rel, 's': meta['s'], 'm': meta['m'],
                              'b': blocks, 'src': meta['src']})

        # 2) 删除的文件 → 空洞
        for rel in self._pending_delete:
            for off, size in self._files[rel].get('b', []):
                self._free.append([off, size])

        # 3) 写新增块(小文件单线程即写, 大文件走分页调度)
        big = [f for f in add_files if len(f['b']) > 4]
        small = [f for f in add_files if len(f['b']) <= 4]
        # 追加区域稀疏预扩展: 多线程散射写越过 EOF 会触发 NTFS 逐段同步清零
        need_end = 0
        for f in add_files:
            if f['b']:
                need_end = max(need_end, f['b'][-1][0] + f['b'][-1][1])
        if need_end:
            _sparse_extend(self.path, need_end)
        total_w = sum(f['s'] for f in add_files) or 1
        done_w = [0]
        wlock = threading.Lock()

        def _after(n):
            with wlock:
                done_w[0] += n
                if progress:
                    progress(min(0.6 * done_w[0] / total_w, 0.6),
                             f'写入新增文件 {done_w[0]}/{total_w} 字节')

        if _HAS_C_SCHED:
            # 调度全 C: 新增文件(大小不限)一次提交, 线程池+看门狗+读写都在 DLL 内
            ents_all = [{'p': f['p'], 'src': f['src'], 's': f['s'], 'm': f['m']}
                        for f in add_files if f['b']]
            layout_all = [f['b'] for f in add_files if f['b']]
            page_bytes = params.page_bytes
            total_add = sum(f['s'] for f in add_files if f['b'])
            want = max(BLOCK_SIZE, (total_add + 999) // 1000)
            want = (want + BLOCK_SIZE - 1) // BLOCK_SIZE * BLOCK_SIZE
            page_bytes = max(BLOCK_SIZE, min(page_bytes, want))
            pages = _pages_for(ents_all, layout_all, page_bytes)
            src_idx = {}
            ins = []
            jobs = []
            names = []
            for pg in pages:
                ent = ents_all[pg['ei']]
                sp = ent['src']
                ii = src_idx.get(sp)
                if ii is None:
                    ii = len(ins)
                    src_idx[sp] = ii
                    ins.append(sp)
                jobs.append((ii, pg['src_off'], 0, pg['blocks'][0][0],
                             pg['len'], pg['len']))
                names.append(ent['p'])
            if jobs:
                _c_run_jobs(0, self.key, None, ins, [self.path], jobs,
                            params.threads, progress=progress, cancel=cancel,
                            label='写入', names=names,
                            frac_scale=0.6, frac_ofs=0.0)
            for f in add_files:
                f.pop('src', None)
        else:
            for f in small:
                if cancel is not None and cancel.is_set():
                    raise KJK9Cancel('已取消')
                with open(f['src'], 'rb') as rf, open(self.path, 'r+b') as wf:
                    for off, csize in f['b']:
                        n = csize - _NONCE_SIZE - _TAG_SIZE
                        wf.seek(off)
                        wf.write(_aes_seal(self.key, rf.read(n)))
                _after(f['s'])
                f.pop('src', None)

            if big:
                layout = [f['b'] for f in big]
                ents = [{'p': f['p'], 'src': f['src'], 's': f['s'], 'm': f['m']}
                        for f in big]
                page_bytes = params.page_bytes
                if _HAS_C_IO:
                    total_add = sum(f['s'] for f in big)
                    want = max(BLOCK_SIZE, (total_add + 999) // 1000)
                    want = (want + BLOCK_SIZE - 1) // BLOCK_SIZE * BLOCK_SIZE
                    page_bytes = max(BLOCK_SIZE, min(page_bytes, want))
                pages = _pages_for(ents, layout, page_bytes)

                def page_fn(job, wid, gen, beat):
                    pg = pages[job.idx]
                    n = pg['len']
                    if not beat(gen, _page_timeout(n)):
                        return
                    ctx = _cipher_ctx(self.key) if _HAS_C_IO else None
                    if ctx is not None:
                        # 全 C: 源文件→加密→包内定位直写
                        hsrc = _tls_whandle('wh_r', pg['src'], 'rb')
                        hpkg = _tls_whandle('wh_w', self.path, 'r+b')
                        rc = _C.kjk_run_encrypt_io(ctx, hsrc, pg['src_off'],
                                                   hpkg, pg['blocks'][0][0],
                                                   n, BLOCK_SIZE)
                        if rc < 0:
                            raise KJK9Error(f'页加密失败 rc={rc} (C 引擎)')
                        _after(n)
                        return
                    # 回退: Python 读 → C 整页 → Python 写
                    cap = n + 28 * len(pg['blocks']) + 16
                    rb = _tls_buf('rb', n)
                    with open(pg['src'], 'rb') as rf:
                        rf.seek(pg['src_off'])
                        got = rf.readinto(memoryview(rb).cast('B')[:n])
                    if got != n:
                        raise KJK9Error(f'源文件读取不完整: {pg["src"]}')
                    if not beat(gen, _page_timeout(n)):
                        return
                    ob = _tls_buf('ob', cap)
                    with open(self.path, 'r+b') as wf:
                        pos = 0
                        for run_off, run_c, run_p in _page_runs(pg['blocks']):
                            if not beat(gen, _page_timeout(n)):
                                return
                            rc = _page_seal(self.key, _seg(rb, pos, run_p), run_p,
                                            ob, cap)
                            wf.seek(run_off)
                            wf.write(memoryview(ob).cast('B')[:rc])
                            pos += run_p
                    _after(pg['len'])

                run_paged(len(pages), page_fn, params, progress=None, cancel=cancel,
                          label='写入', weight=[p['weight'] for p in pages])
                for f in big:
                    f.pop('src', None)

        # 4) 重建目录
        if progress:
            progress(0.65, '更新目录…')
        # 旧目录区域回收为空洞
        if self.header.get('dir_len'):
            self._free.append([self.header['dir_off'], self.header['dir_len']])
        files = []
        for p, f in self._files.items():
            if p in self._pending_delete:
                continue
            files.append({'p': self._pending_rename.get(p, p), 's': f['s'],
                          'm': f['m'], 'b': f['b']})
        for f in add_files:
            files.append({'p': f['p'], 's': f['s'], 'm': f['m'], 'b': f['b']})
        files.sort(key=lambda x: x['p'])
        self._coalesce_free()
        directory = {'v': VERSION, 'files': files, 'free': self._free,
                     'app': 'KJK-Encryptor', 'iter': self.header['iter']}
        blob = _seal_dir(self.key, directory)
        off, _ = self._alloc_region(len(blob))
        with open(self.path, 'r+b') as f:
            f.seek(off)
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        if progress:
            progress(0.85, '更新文件头…')
        _write_header(self.path, self.header['salt'], self.header['iter'],
                      bool(self.password or ''), dir_offset=off, dir_len=len(blob))

        # 5) 提交内存状态
        self.directory = directory
        self.header['dir_off'] = off
        self.header['dir_len'] = len(blob)
        self._files = {f['p']: f for f in files}
        self._pending_add.clear()
        self._pending_rename.clear()
        self._pending_delete.clear()
        self._dirty = False
        self._eof = None
        if progress:
            progress(1.0, '保存完成')
        return True

    def _coalesce_free(self):
        """合并相邻空洞, 去重与排序。"""
        merged = []
        for off, size in sorted(self._free):
            if size <= 0:
                continue
            if merged and merged[-1][0] + merged[-1][1] >= off:
                merged[-1][1] = max(merged[-1][1], off + size - merged[-1][0])
            else:
                merged.append([off, size])
        self._free = merged

    # ---------- 整理(压实) ----------
    def compact(self, progress=None, cancel=None):
        """把存活块顺序搬移到文件前沿, 回收全部空洞(原地升序搬移, 无临时文件)。"""
        if self._pending_add:
            raise KJK9Error('请先保存新增文件再整理')
        files = [f for f in self.file_list()
                 if f['p'] not in self._pending_delete]
        blocks = []  # (old_off, csize)
        for f in files:
            for off, size in f.get('b', []):
                blocks.append((off, size))
        blocks.sort()
        total = len(blocks) or 1
        if progress:
            progress(0.0, f'整理 {total} 个数据块')
        with open(self.path, 'r+b') as f:
            target = HEADER_SIZE
            moved = []
            for i, (off, size) in enumerate(blocks):
                if cancel is not None and cancel.is_set():
                    raise KJK9Cancel('已取消')
                if off != target:
                    f.seek(off)
                    blob = f.read(size)
                    f.seek(target)
                    f.write(blob)
                moved.append((off, target, size))
                target += size
                if progress and (i % 16 == 0 or i == total - 1):
                    progress(0.9 * (i + 1) / total, f'整理 {i + 1}/{total}')
            # 新目录
            files2 = []
            it = iter(moved)
            by_old = {old: (new, size) for old, new, size in moved}
            for fn in files:
                nb = [list(by_old[off]) for off, _ in fn.get('b', [])]
                files2.append({'p': self._pending_rename.get(fn['p'], fn['p']),
                              's': fn['s'], 'm': fn['m'], 'b': nb})
            directory = {'v': VERSION, 'files': files2, 'free': [],
                         'app': 'KJK-Encryptor', 'iter': self.header['iter']}
            blob = _seal_dir(self.key, directory)
            f.seek(target)
            f.write(blob)
            f.truncate(target + len(blob))
            f.flush()
            os.fsync(f.fileno())
            dir_off = target
        if progress:
            progress(0.95, '更新文件头…')
        _write_header(self.path, self.header['salt'], self.header['iter'],
                      bool(self.password or ''), dir_offset=dir_off,
                      dir_len=len(blob))
        self.directory = directory
        self.header['dir_off'] = dir_off
        self.header['dir_len'] = len(blob)
        self._files = {f['p']: f for f in files2}
        self._free = []
        self._pending_add.clear()
        self._pending_rename.clear()
        self._pending_delete.clear()
        self._dirty = False
        self._eof = None
        if progress:
            progress(1.0, '整理完成')

    # ---------- 修改密码(追加式换密, 原子换头, 无临时文件) ----------
    def change_password(self, new_password, progress=None, cancel=None, params=None):
        """换密码: 在文件尾追加以新密钥重加密的块 → 新目录 → 原子换头。旧区域转为空洞。

        按页切分(读旧段→整页解密→整页再加密→写新段), 多线程负载均衡。"""
        if self._dirty:
            raise KJK9Error('请先保存修改, 再修改密码')
        params = params or plan_params()
        new_salt = os.urandom(16)
        new_key = _derive_key(new_password, new_salt, KDF_ITER)
        files = [f for f in self.file_list()
                 if f['p'] not in self._pending_delete]
        if progress:
            progress(0.0, f'换密码: 重加密 {len(files)} 个文件')

        # 新区域: 每文件整段连续分配在文件尾
        off = self._file_end()
        new_layout = []
        for f in files:
            blocks = _blocks_of(int(f['s']), off)
            new_layout.append(blocks)
            if blocks:
                off = blocks[-1][0] + blocks[-1][1]
        # 追加区域稀疏预扩展: 换密线程散射写越过 EOF 会触发 NTFS 同步清零
        if off > self._file_end():
            _sparse_extend(self.path, off)

        # 页: 每文件按 page_bytes 切块, 记录旧块段与新块段映射
        pages = []
        for i, f in enumerate(files):
            ob, nb = f.get('b', []), new_layout[i]
            if not ob:
                continue
            bi = 0
            while bi < len(ob):
                take_o, take_n, nbytes = [], [], 0
                while bi < len(ob) and nbytes < params.page_bytes:
                    take_o.append(ob[bi])
                    take_n.append(nb[bi])
                    nbytes += ob[bi][1] - _NONCE_SIZE - _TAG_SIZE
                    bi += 1
                pages.append({'ob': take_o, 'nb': take_n, 'weight': nbytes or 1})

        def page_fn(job, wid, gen, beat):
            pg = pages[job.idx]
            nbytes = sum(b[1] - _NONCE_SIZE - _TAG_SIZE for b in pg['ob'])
            if not beat(gen, _page_timeout(nbytes)):
                return
            ctx_o = _cipher_ctx(self.key) if _HAS_C_IO else None
            ctx_n = None
            if ctx_o is not None:
                nc = _thread_cipher(new_key, 1)
                ctx_n = nc[1] if nc[0] == 'c' else None
            if ctx_o is not None and ctx_n is not None:
                # 全 C: 同一文件内 旧密文→解密→新密钥加密→新区域定位直写
                h = _tls_whandle('wh_rw', self.path, 'r+b')
                nb = pg['nb']
                for bi, run_off, run_c, run_p in _page_runs_idx(pg['ob']):
                    if not beat(gen, _page_timeout(run_p)):
                        return
                    rc = _C.kjk_run_rekey_io(ctx_o, ctx_n, h, run_off,
                                             nb[bi][0], run_c, BLOCK_SIZE)
                    if rc < 0:
                        if rc in (-4, -5):
                            raise KJK9Error(f'读写失败 rc={rc} (C 引擎)')
                        raise KJK9AuthError('数据已损坏(校验失败)')
                return
            # 回退: Python 读 → C 整页解/加密 → Python 写
            with open(self.path, 'rb') as rf, open(self.path, 'r+b') as wf:
                for run_off, run_c, run_p in _page_runs(pg['ob']):
                    if not beat(gen, _page_timeout(run_p)):
                        return
                    rb = _tls_buf('rb', run_c)
                    rf.seek(run_off)
                    got = rf.readinto(memoryview(rb).cast('B')[:run_c])
                    if got != run_c:
                        raise KJK9Error('读取旧数据块失败')
                    ob = _tls_buf('ob', run_c + 16)
                    pn = _page_open(self.key, rb, run_c, ob, run_c + 16)
                    # 对应新块(整页再加密, 新块按段连续)
                    new_off = _new_off_of(pg, run_off)
                    tmp = _tls_buf('wb', run_c + 16)
                    rc = _page_seal(new_key, ob, pn, tmp, run_c + 16)
                    wf.seek(new_off)
                    wf.write(memoryview(tmp).cast('B')[:rc])

        def _new_off_of(pg, run_off):
            # run_off 是该页旧块某连续段的起始偏移, 新块同索引连续
            for k, (o, s) in enumerate(pg['ob']):
                if o == run_off:
                    return pg['nb'][k][0]
            raise KJK9Error('内部错误: 新旧块映射失败')

        if _HAS_C_SCHED:
            # 调度全 C: 线程池+看门狗+OVERLAPPED 读写都在 DLL 内。
            # 新旧块同大小同边界, 页内换密按块流式, in/out 偏移同步推进。
            full = BLOCK_SIZE + _NONCE_SIZE + _TAG_SIZE
            total_ct = 0
            for f in files:
                for _o, c, _p in _page_runs(f.get('b', [])):
                    total_ct += c
            want = max(full, (total_ct + 999) // 1000)
            chunk = max(1, (want + full - 1) // full) * full
            jobs = []
            job_names = []
            for i, f in enumerate(files):
                ob, nb = f.get('b', []), new_layout[i]
                if not ob:
                    continue
                for bi, run_off, run_c, run_p in _page_runs_idx(ob):
                    base = nb[bi][0]
                    pos = 0
                    while pos < run_c:
                        take = min(run_c - pos, chunk)
                        jobs.append((0, run_off + pos, 0, base + pos, take, take))
                        job_names.append(f['p'])
                        pos += take
            if jobs:
                _c_run_jobs(2, self.key, new_key, [self.path], [self.path],
                            jobs, params.threads, progress=progress,
                            cancel=cancel, label='重加密', names=job_names)
        else:
            run_paged(len(pages), page_fn, params, progress=progress, cancel=cancel,
                      label='重加密', weight=[p['weight'] for p in pages])

        # 新目录 + 原子换头
        if progress:
            progress(0.95, '更新文件头…')
        files2 = [{'p': f['p'], 's': f['s'], 'm': f['m'], 'b': new_layout[i]}
                  for i, f in enumerate(files)]
        old_regions = []
        for f in files:
            for o, s in f.get('b', []):
                old_regions.append([o, s])
        if self.header.get('dir_len'):
            old_regions.append([self.header['dir_off'], self.header['dir_len']])
        directory = {'v': VERSION, 'files': files2, 'free': old_regions,
                     'app': 'KJK-Encryptor', 'iter': KDF_ITER}
        blob = _seal_dir(new_key, directory)
        with open(self.path, 'r+b') as f:
            f.seek(off)
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        _write_header(self.path, new_salt, KDF_ITER, bool(new_password or ''),
                      dir_offset=off, dir_len=len(blob))
        self.password = new_password
        self.key = new_key
        self.header['salt'] = new_salt
        self.header['iter'] = KDF_ITER
        self.header['dir_off'] = off
        self.header['dir_len'] = len(blob)
        self.directory = directory
        self._files = {f['p']: f for f in files2}
        self._free = old_regions
        self._coalesce_free()
        self._eof = None
        if progress:
            progress(1.0, '换密码完成')
