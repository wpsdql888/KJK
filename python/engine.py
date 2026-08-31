# -*- coding: utf-8 -*-
"""KJK Encryptor - 核心加密引擎 v1.0.4 (AES-256-GCM + 密码头)

v7 设计 (新版):
  - 加密算法: AES-256-GCM (认证加密,防止篡改)
  - 密钥派生: HKDF-SHA256 (内容密钥), 从密码 + 密码头中的 salt 派生
  - 密码验证: PBKDF2-SHA256 600000 次迭代 (与 Web 版互通)
  - 输出格式仍保持 KJK token 外观 (base-20 字符集)
  - .kjk 文件头升级为 KJKv7

v6/v5 密码头 (旧版,仍可解密):
  - 密码头作为固定长度前缀或独立第一个条目,用空密码加密
  - 头内容: PWD:<salt_hex>:<hash_hex>
  - 旧版内容使用 SHA-256 计数器模式加密

v4 改进:
  - .kjk 文件内使用 gzip 压缩密文
  - 支持向已有 .kjk 文件追加新文件
"""

import hashlib
import zlib
import base64
import os
import secrets
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ======================== 可选依赖 ========================

try:
    import numpy as np
except ImportError:
    np = None

# ======================== C 加速引擎 (engine/ 插件目录) ========================
# 由 kjkfast.c 编译而来, 提供 token 编解码的 C 级实现。
# DLL 按版本化命名存放在安装目录的 engine/ 文件夹内 (kjkfast-10400.dll),
# 多代引擎可共存, 按版本号降序取最新可用者; 找不到 DLL 或调用失败时
# 自动回退 numpy / 纯 Python, 功能完全一致。

_KJKFAST = None
_KJKFAST_PATH = None
try:
    import ctypes as _ctypes
    import sys as _sys
    import re as _re

    def _kjkfast_candidates():
        """所有候选 DLL 路径, 插件目录版本降序优先。"""
        here = os.path.dirname(os.path.abspath(__file__))
        exe_dir = os.path.dirname(_sys.executable)
        meipass = getattr(_sys, '_MEIPASS', None)
        search = [d for d in (here, exe_dir, meipass) if d]

        versioned = []
        plain = []
        for d in search:
            ed = os.path.join(d, 'engine')
            if os.path.isdir(ed):
                for fn in os.listdir(ed):
                    m = _re.match(r'^kjkfast-(\d+)\.dll$', fn, _re.IGNORECASE)
                    if m:
                        versioned.append((int(m.group(1)), os.path.join(ed, fn)))
                    elif fn.lower() == 'kjkfast.dll':
                        plain.append(os.path.join(ed, fn))
        versioned.sort(key=lambda t: t[0], reverse=True)
        ordered = [p for _, p in versioned] + plain
        # 开发环境兼容: 同目录直接放 kjkfast.dll
        for d in search:
            p = os.path.join(d, 'kjkfast.dll')
            if p not in ordered:
                ordered.append(p)
        return ordered

    def _load_kjkfast():
        for path in _kjkfast_candidates():
            if os.path.isfile(path):
                try:
                    dll = _ctypes.CDLL(path)
                    dll.kjkfast_version.restype = _ctypes.c_long
                    if dll.kjkfast_version() < 10400:
                        continue
                    dll.kjk_bytes_to_tokens.restype = _ctypes.c_long
                    dll.kjk_bytes_to_tokens.argtypes = [
                        _ctypes.c_char_p, _ctypes.c_size_t,
                        _ctypes.c_char_p, _ctypes.c_size_t]
                    dll.kjk_tokens_to_bytes.restype = _ctypes.c_long
                    dll.kjk_tokens_to_bytes.argtypes = [
                        _ctypes.c_char_p, _ctypes.c_size_t,
                        _ctypes.c_char_p, _ctypes.c_size_t]
                    global _KJKFAST_PATH
                    _KJKFAST_PATH = path
                    return dll
                except OSError:
                    continue
        return None

    _KJKFAST = _load_kjkfast()
    del _load_kjkfast
except Exception:
    _KJKFAST = None


def engine_backend_name():
    """诊断用: 返回当前 token 编解码后端名称。"""
    if _KJKFAST is not None:
        return f'C ({os.path.basename(_KJKFAST_PATH)})' if _KJKFAST_PATH else 'C'
    if np is not None:
        return 'numpy'
    return 'python'


def _bytes_to_tokens_c(data: bytes) -> str:
    """C 引擎: 字节 → token 字符串。"""
    n = len(data)
    if n == 0:
        return ''
    cap = n * 6 + 1
    buf = _ctypes.create_string_buffer(cap)
    written = _KJKFAST.kjk_bytes_to_tokens(data, n, buf, cap)
    if written < 0:
        raise MemoryError('kjkfast 输出缓冲不足')
    return buf.raw[:written].decode('utf-8')


def _tokens_to_bytes_c(ciphertext: str) -> bytes:
    """C 引擎: token 字符串 → 字节(忽略空白)。"""
    raw = ciphertext.encode('utf-8')
    n = len(raw)
    if n == 0:
        return b''
    cap = n // 2 + 2
    buf = _ctypes.create_string_buffer(cap)
    written = _KJKFAST.kjk_tokens_to_bytes(raw, n, buf, cap)
    if written < 0:
        raise ValueError('无效的 token')
    return buf.raw[:written]


# ======================== Token 字符集 (base-20) ========================
TOKENS = '锟斤拷烫屯锘!+啊胩岐鑁歸鈪誷鷖竊蛦唄咚'
BASE = len(TOKENS)  # 20

_CHAR_TO_VAL = {ch: i for i, ch in enumerate(TOKENS)}
_BYTE_TO_DIGITS = None

# 字节 → 2 个 token 字符的查表,合并 _bytes_to_digits + _digits_to_tokens,提速并减少中间内存。
_BYTE_TO_TOKEN_PAIR = [''] * 256
_TOKEN_PAIR_TO_BYTE = {}
for _b in range(256):
    _d0 = _b % BASE
    _d1 = _b // BASE
    _pair = TOKENS[_d0] + TOKENS[_d1]
    _BYTE_TO_TOKEN_PAIR[_b] = _pair
    _TOKEN_PAIR_TO_BYTE[_pair] = _b

_STREAMING_THRESHOLD = 1024 * 1024  # 1 MB
_CHUNK_SIZE = 64 * 1024
_INTEGRITY_MARKER = '|INTEGRITY|'

# KJKv8 大文件分块: 超过该大小的文件拆分为多个独立加密的部分(part),
# 每个 part 单独 AES-GCM 加密 + gzip 压缩,限制单条 .kjk 行的内存占用。
_PART_PLAINTEXT_SIZE = 4 * 1024 * 1024  # 4 MB/part
_PART_MANIFEST_FLAG = 'M'
_PART_ENTRY_FLAG = '8'


def _init_tables():
    global _BYTE_TO_DIGITS
    if _BYTE_TO_DIGITS is None:
        _BYTE_TO_DIGITS = bytearray(512)
        for b in range(256):
            d0 = b % BASE
            d1 = b // BASE
            _BYTE_TO_DIGITS[b * 2] = d0
            _BYTE_TO_DIGITS[b * 2 + 1] = d1


def _bytes_to_digits(data: bytes) -> bytearray:
    """字节 → base-20 数字序列,带可选 numpy 加速。"""
    _init_tables()
    if np is not None and isinstance(data, (bytes, bytearray)):
        try:
            return _bytes_to_digits_np(data)
        except Exception:
            pass
    n = len(data)
    result = bytearray(n * 2)
    for i in range(n):
        b = data[i]
        result[i * 2] = _BYTE_TO_DIGITS[b * 2]
        result[i * 2 + 1] = _BYTE_TO_DIGITS[b * 2 + 1]
    return result


def _bytes_to_digits_np(data) -> bytearray:
    if np is None:
        raise ImportError('numpy 不可用')
    arr = np.frombuffer(bytes(data), dtype=np.uint8)
    out = np.empty(arr.size * 2, dtype=np.uint8)
    out[0::2] = arr % BASE
    out[1::2] = arr // BASE
    return bytearray(out)


def _digits_to_bytes(digits) -> bytes:
    """base-20 数字序列 → 字节,带可选 numpy 加速。"""
    if np is not None and isinstance(digits, (bytes, bytearray, list)):
        try:
            return _digits_to_bytes_np(digits)
        except Exception:
            pass
    n = len(digits)
    if n % 2 != 0:
        raise ValueError(f'数字长度无效: 期望偶数, 实际 {n}')
    result = bytearray(n // 2)
    for i in range(0, n, 2):
        result[i // 2] = (digits[i] + digits[i + 1] * BASE) % 256
    return bytes(result)


def _digits_to_bytes_np(digits) -> bytes:
    if np is None:
        raise ImportError('numpy 不可用')
    arr = np.frombuffer(bytes(digits), dtype=np.uint8).astype(np.uint16)
    if arr.size % 2 != 0:
        raise ValueError(f'数字长度无效: 期望偶数, 实际 {arr.size}')
    out = (arr[0::2] + arr[1::2] * BASE) % 256
    return bytes(out.astype(np.uint8))


def _digits_to_tokens(digits) -> str:
    if isinstance(digits, (bytes, bytearray)):
        return digits.decode('latin1').translate(_TOKENS_FROM_DIGIT)
    return ''.join(TOKENS[d] for d in digits)


def _tokens_to_digits(ciphertext: str) -> bytearray:
    s = ''.join(ciphertext.split())
    digits = s.translate(_TRANSLATE_TO_DIGIT)
    if np is not None:
        try:
            raw = digits.encode('latin1')
        except UnicodeEncodeError:
            raise ValueError('无效的 token')
        arr = np.frombuffer(raw, dtype=np.uint8)
        if np.any(arr >= BASE):
            bad = arr[arr >= BASE]
            raise ValueError(f'无效的 token: {chr(int(bad[0]))!r}')
        return bytearray(arr)
    result = bytearray()
    for ch in s:
        d = _TOKEN_TO_DIGIT.get(ch)
        if d is None:
            raise ValueError(f'无效的 token: {ch!r}')
        result.append(d)
    return result


_TOKEN_TO_DIGIT = {ch: i for i, ch in enumerate(TOKENS)}
_TRANSLATE_TO_DIGIT = str.maketrans({ch: chr(i) for i, ch in enumerate(TOKENS)})
_TOKENS_FROM_DIGIT = str.maketrans({chr(i): TOKENS[i] for i in range(BASE)})


def _bytes_to_tokens(data: bytes) -> str:
    """字节 → KJK token 字符串(C 引擎优先, 合并 digits + tokens 步骤)。"""
    if _KJKFAST is not None:
        try:
            return _bytes_to_tokens_c(data)
        except MemoryError:
            raise
        except Exception:
            pass
    return ''.join(map(_BYTE_TO_TOKEN_PAIR.__getitem__, data))


def _tokens_to_bytes(ciphertext: str) -> bytes:
    """KJK token 字符串 → 字节(C 引擎优先, 忽略空白字符)。"""
    if _KJKFAST is not None:
        try:
            return _tokens_to_bytes_c(ciphertext)
        except ValueError:
            raise
        except Exception:
            pass
    s = ''.join(ciphertext.split())  # 一次性去除所有空白(快于逐字符 isspace)
    n = len(s)
    if n % 2 != 0:
        raise ValueError(f'token 长度无效: 期望偶数, 实际 {n}')
    digits = s.translate(_TRANSLATE_TO_DIGIT)
    if np is not None:
        arr = np.frombuffer(digits.encode('latin1'), dtype=np.uint8)
        if np.any(arr >= BASE):
            bad = arr[arr >= BASE]
            raise ValueError(f'无效的 token: {chr(int(bad[0]))!r}')
        arr16 = arr.astype(np.uint16)
        out = (arr16[0::2] + arr16[1::2] * BASE) % 256
        return bytes(out.astype(np.uint8))
    result = bytearray(n // 2)
    for i in range(0, n, 2):
        result[i // 2] = (ord(digits[i]) + ord(digits[i + 1]) * BASE) % 256
    return bytes(result)


# ======================== 密码哈希 (PBKDF2-SHA256, 与 Web 互通) ========================

# 新版(v7)默认使用 PBKDF2-SHA256, 与 Web Crypto 互通
PBKDF2_ITERATIONS = 600000
PWD_HASH_LEN = 32        # 输出 256 位
PWD_SALT_LEN = 16        # 盐长度 16 字节

# 兼容旧版 Argon2id 密码头(仅用于解密旧文件)
_HAVE_ARGON2 = False
try:
    import argon2.low_level
    _HAVE_ARGON2 = True
except ImportError:
    pass

ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = PWD_HASH_LEN
ARGON2_SALT_LEN = PWD_SALT_LEN

# 密码头常量
PWD_CONTENT_PREFIX = 'PWD:'          # 头内容前缀
PWD_HEADER_SEPARATOR = ' '           # 密码头与内容的分隔符
PWD_HEADER_MARKER = 'kjk_pwd_hdr'   # 旧版头条目的文件名标记

# 密码头明文固定长度: PWD: + salt_hex(32) + : + hash_hex(64) = 101 字节
PWD_HEADER_PLAINTEXT_LEN = len(PWD_CONTENT_PREFIX) + PWD_SALT_LEN * 2 + 1 + PWD_HASH_LEN * 2
# 密码头密文固定长度: 101 字节 * 2 token/字节 = 202 字符
PWD_HEADER_CIPHER_LEN = PWD_HEADER_PLAINTEXT_LEN * 2


def _derive_password_hash(password: str, salt: bytes) -> bytes:
    """使用 PBKDF2-SHA256 计算密码哈希(v7 默认, 与 Web 版互通)。"""
    if not password or not password.strip():
        return b'\x00' * PWD_HASH_LEN
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PWD_HASH_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))


def _derive_password_hash_argon2(password: str, salt: bytes) -> bytes:
    """兼容旧版: 使用 Argon2id 计算密码哈希。"""
    if not password or not password.strip():
        return b'\x00' * ARGON2_HASH_LEN
    return argon2.low_level.hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=argon2.low_level.Type.ID,
    )


def _derive_aes_key(password: str, salt: bytes) -> bytes:
    """从密码和盐派生 AES-256-GCM 内容密钥。

    空密码使用全零密钥。有密码时使用 HKDF-SHA256 派生 256 位密钥。
    """
    if not password or not password.strip():
        return b'\x00' * 32
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'KJK-AES-GCM-v7',
    )
    return hkdf.derive(password.encode('utf-8'))


# ======================== 前缀式密码头系统 (v6/v7 共用) ========================
# 格式: [空密码加密的PWD:salt:hash(202字符)] [空格] [加密内容]
# 解密: 截取前202字符 → 检查空格 → 空密码解密头 → 验证密码 → 解密内容

# v7 中密码头本身也使用 AES-256-GCM(空密码/zero key)加密,保持固定长度。

def make_password_header(password: str):
    """生成密码头明文 PWD:salt:hash (固定101字节)。

    返回 (header_text, salt_bytes)
    """
    salt = secrets.token_bytes(PWD_SALT_LEN)
    h = _derive_password_hash(password, salt)
    return f'{PWD_CONTENT_PREFIX}{salt.hex()}:{h.hex()}', salt


def parse_password_header(header_text: str):
    """解析密码头明文,返回 (salt_hex, hash_hex) 或 None"""
    if not header_text.startswith(PWD_CONTENT_PREFIX):
        return None
    parts = header_text.split(':')
    if len(parts) < 3:
        return None
    salt_hex = parts[1]
    hash_hex = parts[2]
    if len(salt_hex) != PWD_SALT_LEN * 2 or len(hash_hex) != PWD_HASH_LEN * 2:
        return None
    return salt_hex, hash_hex


def has_password_prefix(content: str) -> bool:
    """检查内容开头是否有密码头前缀"""
    if len(content) < PWD_HEADER_CIPHER_LEN + 1:
        return False
    return content[PWD_HEADER_CIPHER_LEN] == PWD_HEADER_SEPARATOR


def detect_password_prefix(content: str) -> tuple:
    """检测内容开头的密码头前缀。

    返回 (has_pwd, salt_bytes, hash_hex, remaining_content)
    - has_pwd: 是否有密码头前缀
    - salt_bytes/hash_hex: 头中的盐和哈希
    - remaining_content: 去掉前缀后的内容
    """
    if not has_password_prefix(content):
        return False, None, None, content
    header_cipher = content[:PWD_HEADER_CIPHER_LEN]
    try:
        header_data = _decrypt_raw_legacy(header_cipher, '')
        header_text = header_data.decode('utf-8', errors='replace')
        parsed = parse_password_header(header_text)
        if parsed is None:
            return False, None, None, content
        salt_hex, hash_hex = parsed
        remaining = content[PWD_HEADER_CIPHER_LEN + 1:]
        return True, bytes.fromhex(salt_hex), hash_hex, remaining
    except Exception:
        return False, None, None, content


def add_password_prefix(content: str, password: str, salt: bytes = None) -> tuple:
    """在内容前添加密码头前缀。

    生成: [空密码加密的PWD:salt:hash(固定202字符)] [空格] [content]
    返回 (prefixed_content, salt_bytes)

    若传入 salt,则使用该 salt 生成密码头,确保与内部条目加密使用的 salt 一致。
    """
    if salt is None:
        header, salt = make_password_header(password)
    else:
        h = _derive_password_hash(password, salt)
        header = f'{PWD_CONTENT_PREFIX}{salt.hex()}:{h.hex()}'
    # 密码头必须使用旧版 SHA-256 计数器模式加密,才能保证长度固定为 202 token,
    # 便于后续检测和解析。
    header_cipher = _encrypt_raw_legacy(header.encode('utf-8'), '')
    return header_cipher + PWD_HEADER_SEPARATOR + content, salt


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    """验证密码是否正确。

    用用户输入的密码和头中的盐重新计算哈希,与头中的哈希比对。
    优先尝试新版 PBKDF2-SHA256(与 Web 互通),再尝试旧版 Argon2id。
    """
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
    except (ValueError, IndexError):
        return False

    # 新版 PBKDF2-SHA256
    computed = _derive_password_hash(password, salt)
    if computed == stored_hash:
        return True

    # 兼容旧版 Argon2id
    if _HAVE_ARGON2:
        try:
            computed_argon = _derive_password_hash_argon2(password, salt)
            if computed_argon == stored_hash:
                return True
        except Exception:
            pass

    return False


# ======================== 旧版密码头兼容 ========================
# 旧格式1: 独立条目 (KJKv5),用空密码加密,文件名解密为 PWD_HEADER_MARKER
# 旧格式2: pwd:<salt_hex>:<hash_hex>:<encrypted_filename> (pwd: 前缀)

def make_password_header_entry(password: str) -> dict:
    """旧版兼容: 生成密码头条目 (独立条目方式, v5)

    旧版使用 SHA-256 计数器模式加密,因此这里固定使用 legacy 算法,
    以便生成可被旧版逻辑识别的测试数据。
    """
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    h = _derive_password_hash(password, salt)
    header_content = f'{PWD_CONTENT_PREFIX}{salt.hex()}:{h.hex()}'
    header_bytes = header_content.encode('utf-8')
    return {
        'enc_name': _encrypt_raw_legacy(PWD_HEADER_MARKER.encode('utf-8'), ''),
        'ciphertext': _encrypt_raw_legacy(header_bytes, ''),
        'size': len(header_bytes),
        '_is_password_header': True,
    }


def _make_pwd_header(password: str) -> tuple:
    """旧版兼容: 生成 pwd: 前缀"""
    salt = secrets.token_bytes(ARGON2_SALT_LEN)
    h = _derive_password_hash(password, salt)
    return f'pwd:{salt.hex()}:{h.hex()}', salt


def _verify_password_header(header: str, password: str) -> tuple:
    """旧版兼容: 验证 pwd: 前缀"""
    if not header.startswith('pwd:'):
        return False, None
    parts = header.split(':', 3)
    if len(parts) < 4:
        return False, None
    salt_hex, hash_hex, remaining = parts[1], parts[2], parts[3]
    if len(salt_hex) != ARGON2_SALT_LEN * 2 or len(hash_hex) != ARGON2_HASH_LEN * 2:
        return False, None
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(hash_hex)
    except (ValueError, IndexError):
        return False, None
    computed_hash = _derive_password_hash(password, salt)
    if computed_hash == stored_hash:
        return True, remaining
    return False, None


def has_password_header(enc_name: str) -> bool:
    """旧版兼容: 检查 enc_name 是否包含 pwd: 前缀"""
    return enc_name.startswith('pwd:')


def strip_password_header(enc_name: str) -> tuple:
    """旧版兼容: 从 enc_name 中提取并移除 pwd: 前缀"""
    if not enc_name.startswith('pwd:'):
        return enc_name, False, None, None
    parts = enc_name.split(':', 3)
    if len(parts) < 4:
        return enc_name, False, None, None
    salt_hex, hash_hex, remaining = parts[1], parts[2], parts[3]
    if len(salt_hex) != ARGON2_SALT_LEN * 2 or len(hash_hex) != ARGON2_HASH_LEN * 2:
        return enc_name, False, None, None
    return remaining, True, salt_hex, hash_hex


# ======================== v7 AES-256-GCM 加解密 ========================

def _encrypt_raw_v7(data: bytes, key: bytes, callback=None) -> str:
    """使用 AES-256-GCM 加密并编码为 KJK token。"""
    if callback:
        callback(0.05)
    nonce = os.urandom(12)
    if callback:
        callback(0.25)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)  # ciphertext 含 16 字节 tag
    combined = nonce + ciphertext
    if callback:
        callback(0.6)
    result = _bytes_to_tokens(combined)
    if callback:
        callback(1.0)
    return result


def _decrypt_raw_v7(ciphertext: str, key: bytes, callback=None) -> bytes:
    """解码 KJK token 并使用 AES-256-GCM 解密。"""
    if callback:
        callback(0.1)
    combined = _tokens_to_bytes(ciphertext)
    if len(combined) < 12 + 16:
        raise ValueError('密文太短,无法解密')
    nonce = combined[:12]
    ct = combined[12:]
    if callback:
        callback(0.5)
    aesgcm = AESGCM(key)
    result = aesgcm.decrypt(nonce, ct, None)
    if callback:
        callback(1.0)
    return result


# ======================== 流式文件加解密 (大文件优化) ========================

def _encrypt_file_to_tokens(in_path: str, key: bytes, callback=None) -> str:
    """分块读取文件,使用 AES-256-GCM 流式加密并编码为 token。

    输出字节顺序与 AESGCM.encrypt 一致: nonce + ciphertext + tag。
    编码阶段使用查表一次生成 token,避免中间 digits 列表。
    """
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ct = bytearray()
    total_size = os.path.getsize(in_path)
    read_size = 0
    with open(in_path, 'rb') as fh:
        while True:
            chunk = fh.read(_CHUNK_SIZE)
            if not chunk:
                break
            ct.extend(encryptor.update(chunk))
            read_size += len(chunk)
            if callback and total_size:
                callback(min(read_size / total_size, 0.5))
    encryptor.finalize()  # 完成加密并生成 tag
    ct.extend(encryptor.tag)  # 追加 16 字节 tag
    combined = bytes(nonce) + bytes(ct)
    if callback:
        callback(0.6)
    result = _bytes_to_tokens(combined)
    if callback:
        callback(1.0)
    return result


def _decrypt_tokens_to_file(ciphertext_str: str, key: bytes, out_path: str, callback=None):
    """将 KJK token 密文流式解密并写入文件。

    字节顺序与 AESGCM.decrypt 一致: nonce + ciphertext + tag。
    解码阶段使用查表一次还原字节,避免中间 digits 列表。
    """
    combined = _tokens_to_bytes(ciphertext_str)
    if len(combined) < 12 + 16:
        raise ValueError('密文太短,无法解密')
    nonce = combined[:12]
    tag = combined[-16:]
    ct = combined[12:-16]
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    total = len(ct)
    processed = 0
    with open(out_path, 'wb') as fh:
        for i in range(0, len(ct), _CHUNK_SIZE):
            chunk = ct[i:i + _CHUNK_SIZE]
            fh.write(decryptor.update(chunk))
            processed += len(chunk)
            if callback and total:
                callback(min(processed / total, 0.9))
        decryptor.finalize()  # 验证 tag
    if callback:
        callback(1.0)


def decrypt_entry_to_file(item: dict, out_path: str, password: str = '', salt: bytes = None,
                          legacy: bool = False, progress_callback=None) -> None:
    """将一个条目(含 KJKv8 分块条目)流式解密并写入文件,避免整文件驻留内存。"""
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    parts = item.get('_chunked_parts')
    if parts:
        total = len(parts)
        for i, p in enumerate(parts):
            data = decrypt_raw(p['_ciphertext'], password, salt, legacy=legacy)
            mode = 'wb' if i == 0 else 'ab'
            with open(out_path, mode) as fh:
                fh.write(data)
            if progress_callback:
                progress_callback((i + 1) / total)
            time.sleep(0)  # 让出 GIL,保持 UI 响应
        return
    data = decrypt_raw(item['_ciphertext'], password, salt, legacy=legacy)
    with open(out_path, 'wb') as fh:
        fh.write(data)
    if progress_callback:
        progress_callback(1.0)


# ======================== v6/v5/v4/v3/v2/v1 旧版加解密 ========================

def _derive_keystream(password: str, length: int) -> bytes:
    if not password or not password.strip():
        return b'\x00' * length
    key = hashlib.sha256(password.encode('utf-8')).digest()
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        block = hashlib.sha256(key + counter.to_bytes(4, 'big')).digest()
        stream.extend(block)
        counter += 1
    return bytes(stream[:length])


def _mix_digits_inplace(digits: bytearray, keystream: bytes) -> None:
    if np is not None and len(keystream):
        n = len(digits)
        ks_len = len(keystream)
        arr = np.frombuffer(digits, dtype=np.uint8)
        ks = np.frombuffer(keystream, dtype=np.uint8)
        ks_full = np.resize(ks, n)
        out = (arr.astype(np.uint16) + ks_full) % BASE
        digits[:] = out.astype(np.uint8).tobytes()
        return
    ks_len = len(keystream)
    for i in range(len(digits)):
        digits[i] = (digits[i] + keystream[i % ks_len]) % BASE


def _unmix_digits_inplace(digits: bytearray, keystream: bytes) -> None:
    if np is not None and len(keystream):
        n = len(digits)
        ks_len = len(keystream)
        arr = np.frombuffer(digits, dtype=np.uint8)
        ks = np.frombuffer(keystream, dtype=np.uint8)
        ks_full = np.resize(ks, n)
        out = (arr.astype(np.int16) - ks_full) % BASE
        digits[:] = out.astype(np.uint8).tobytes()
        return
    ks_len = len(keystream)
    for i in range(len(digits)):
        digits[i] = (digits[i] - keystream[i % ks_len]) % BASE


def _encrypt_raw_legacy(data: bytes, password: str = '', callback=None) -> str:
    """旧版加密 (SHA-256 计数器模式)"""
    if callback:
        callback(0.05)
    digits = _bytes_to_digits(data)
    if callback:
        callback(0.35)
    if password and password.strip():
        keystream = _derive_keystream(password, len(digits))
        _mix_digits_inplace(digits, keystream)
    if callback:
        callback(0.75)
    result = _digits_to_tokens(digits)
    if callback:
        callback(1.0)
    return result


def _decrypt_raw_legacy(ciphertext: str, password: str = '', callback=None) -> bytes:
    """旧版解密 (SHA-256 计数器模式)"""
    if callback:
        callback(0.1)
    digits = _tokens_to_digits(ciphertext)
    if callback:
        callback(0.4)
    if password and password.strip():
        keystream = _derive_keystream(password, len(digits))
        _unmix_digits_inplace(digits, keystream)
    if callback:
        callback(0.85)
    result = _digits_to_bytes(digits)
    if callback:
        callback(1.0)
    return result


# ======================== 兼容接口 (不处理密码头) ========================

def encrypt_raw(data: bytes, password: str = '', salt: bytes = None, callback=None, legacy: bool = False) -> str:
    """加密 (不添加密码头前缀),用于 .kjk 条目和文件名。

    v7 默认使用 AES-256-GCM。salt 用于有密码时派生 AES 密钥。
    当 legacy=True 时使用旧版 SHA-256 计数器模式。
    """
    if legacy:
        return _encrypt_raw_legacy(data, password, callback)
    key = _derive_aes_key(password, salt or b'')
    return _encrypt_raw_v7(data, key, callback)


def decrypt_raw(ciphertext: str, password: str = '', salt: bytes = None, callback=None, legacy: bool = False) -> bytes:
    """解密 (不添加密码头前缀),用于 .kjk 条目和文件名。

    v7 默认使用 AES-256-GCM。salt 用于有密码时派生 AES 密钥。
    当 legacy=True 时使用旧版 SHA-256 计数器模式。
    """
    if legacy:
        return _decrypt_raw_legacy(ciphertext, password, callback)
    key = _derive_aes_key(password, salt or b'')
    return _decrypt_raw_v7(ciphertext, key, callback)


# ======================== 公开加解密 (带密码头前缀) ========================

def encrypt(data: bytes, password: str = '', callback=None) -> str:
    """加密,有密码时自动添加密码头前缀。

    输出格式(有密码): [密码头密文(202字符)] [空格] [内容密文]
    输出格式(无密码): [内容密文]

    用于纯文本加密。.kjk 条目加密请用 encrypt_raw()。
    """
    if password and password.strip():
        header_text, salt = make_password_header(password)
        content_cipher = encrypt_raw(data, password, salt, callback)
        header_cipher = _encrypt_raw_legacy(header_text.encode('utf-8'), '')
        return header_cipher + PWD_HEADER_SEPARATOR + content_cipher
    return encrypt_raw(data, '', None, callback)


def decrypt(ciphertext: str, password: str = '', callback=None) -> bytes:
    """解密,自动检测并处理密码头前缀。

    如果检测到密码头前缀:
    1. 用空密码解密头 → PWD:salt:hash
    2. 验证密码(用 salt 重新计算哈希,与 hash 比对)
    3. 密码正确则用密码派生 AES 密钥解密内容
    4. 密码错误抛出 ValueError

    无密码头前缀时先尝试 v7 AES-GCM(zero key)解密,失败则回退旧版。
    """
    if has_password_prefix(ciphertext):
        header_cipher = ciphertext[:PWD_HEADER_CIPHER_LEN]
        content_cipher = ciphertext[PWD_HEADER_CIPHER_LEN + 1:]
        header_data = _decrypt_raw_legacy(header_cipher, '')
        header_text = header_data.decode('utf-8', errors='replace')
        parsed = parse_password_header(header_text)
        if parsed is not None:
            salt_hex, hash_hex = parsed
            if not verify_password(password, salt_hex, hash_hex):
                raise ValueError('密码错误')
            salt = bytes.fromhex(salt_hex)
            # 有密码头时,先试 AES-GCM,失败则回退旧版(兼容新旧两种加密方式)
            try:
                return decrypt_raw(content_cipher, password, salt, callback)
            except Exception:
                return _decrypt_raw_legacy(content_cipher, password, callback)
        return _decrypt_raw_legacy(content_cipher, password, callback)
    # 无密码头: 先尝试 AES-GCM,失败则回退旧版(兼容新旧两种加密方式)
    try:
        return decrypt_raw(ciphertext, password, None, callback)
    except Exception:
        return _decrypt_raw_legacy(ciphertext, password, callback)


# ======================== 文件名加解密 ========================

def encrypt_filename(name: str, ext: str, password: str = '', salt: bytes = None, legacy: bool = False) -> str:
    """加密文件名 (不加密码头前缀)"""
    original = f"{name}.{ext}" if ext else name
    data = original.encode('utf-8')
    return encrypt_raw(data, password, salt, legacy=legacy)


def decrypt_filename(ciphertext: str, password: str = '', salt: bytes = None, legacy: bool = False) -> tuple:
    """解密文件名,返回 (name, ext)"""
    # 兼容旧版: 检测并移除 pwd: 前缀
    actual_enc, _, _, _ = strip_password_header(ciphertext)

    try:
        data = decrypt_raw(actual_enc, password, salt, legacy=legacy)
    except Exception:
        data = decrypt_raw(actual_enc, password, salt, legacy=not legacy)
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        text = data.decode('utf-8', errors='replace')
    if '.' in text:
        idx = text.rfind('.')
        return text[:idx], text[idx + 1:]
    return text, ''


def _filename_looks_valid(name: str) -> bool:
    """检查解密后的文件名是否像有效文件名(用于兼容旧版)"""
    if not name:
        return False
    if '\x00' in name:
        return False
    for ch in name:
        cat = ord(ch)
        if cat < 32 and ch not in '\t\n\r':
            return False
    if '.' not in name:
        return False
    idx = name.rfind('.')
    ext = name[idx + 1:]
    if not ext or len(ext) > 20:
        return False
    if not all(c.isalnum() or c == '_' for c in ext):
        return False
    name_part = name[:idx]
    if not name_part:
        return False
    return True


def try_decrypt_item(item: dict, password: str = '', salt: bytes = None, legacy: bool = False) -> tuple:
    """尝试用指定密码解密一个条目。

    返回 (success: bool, data: bytes|None, error: str|None)。
    兼容旧版 pwd: 前缀和新版前缀方式。
    """
    try:
        enc_name = item.get('enc_name', '')
        actual_enc = enc_name

        # 兼容旧版: 检测 pwd: 前缀
        if enc_name.startswith('pwd:'):
            is_valid, remaining = _verify_password_header(enc_name, password)
            if is_valid:
                actual_enc = remaining
                item['_password_verified'] = True
            else:
                return False, None, '密码错误'

        if actual_enc:
            name, ext = decrypt_filename(actual_enc, password, salt, legacy=legacy)
            full_name = f"{name}.{ext}" if ext else name
            # 旧版兼容: 无密码头时尝试文件名检测
            if legacy and not enc_name.startswith('pwd:') and not _filename_looks_valid(full_name):
                return False, None, '密码错误或文件损坏'
            item['name'] = name
            item['ext'] = ext
            item['originalName'] = full_name
        else:
            item['name'] = 'decrypted'
            item['ext'] = ''
            item['originalName'] = 'decrypted_text'

        # 先尝试指定算法,失败则回退另一种(兼容新旧文件)
        if item.get('_chunked_parts'):
            def _decrypt_all(leg):
                out = bytearray()
                for p in item['_chunked_parts']:
                    out.extend(decrypt_raw(p['_ciphertext'], password, salt, legacy=leg))
                return bytes(out)
            try:
                data = _decrypt_all(legacy)
            except Exception:
                try:
                    data = _decrypt_all(not legacy)
                except Exception:
                    return False, None, '密码错误或文件损坏(ALG)'
        else:
            try:
                data = decrypt_raw(item['_ciphertext'], password, salt, legacy=legacy)
            except Exception:
                try:
                    data = decrypt_raw(item['_ciphertext'], password, salt, legacy=not legacy)
                except Exception:
                    return False, None, '密码错误或文件损坏(ALG)'
        item['data'] = data
        item['_password_used'] = password
        return True, data, None
    except Exception as e:
        return False, None, str(e)


# ======================== 压缩/解压 ========================

def compress_ciphertext(text: str) -> str:
    raw = text.encode('utf-8')
    # 大段随机密文用 level 9 收益有限且极慢,level 1 速度提升数倍
    level = 1 if len(raw) > 1024 * 1024 else 9
    compressed = zlib.compress(raw, level=level)
    return base64.b64encode(compressed).decode('ascii')


def decompress_ciphertext(b64data: str) -> str:
    compressed = base64.b64decode(b64data.encode('ascii'))
    raw = zlib.decompress(compressed)
    return raw.decode('utf-8')


# ======================== 完整性校验辅助 ========================

def _strip_integrity_line(body: str) -> str:
    """移除 .kjk 主体末尾的完整性校验行。"""
    lines = body.split('\n')
    filtered = [ln for ln in lines if not ln.startswith(_INTEGRITY_MARKER)]
    return '\n'.join(filtered)


def add_integrity_hash(content: str) -> str:
    """在 .kjk 主体末尾追加完整性校验行 |INTEGRITY|<sha256_hex>。

    计算 body(不含已有校验行)的 SHA-256,重新添加密码头前缀。
    """
    if has_password_prefix(content):
        header_cipher = content[:PWD_HEADER_CIPHER_LEN]
        body = content[PWD_HEADER_CIPHER_LEN + 1:]
        prefix = header_cipher + PWD_HEADER_SEPARATOR
    else:
        prefix = ''
        body = content
    body = _strip_integrity_line(body).rstrip('\n')
    h = hashlib.sha256(body.encode('utf-8')).hexdigest()
    return prefix + body + '\n' + _INTEGRITY_MARKER + h


def verify_integrity_hash(content: str) -> tuple:
    """校验 .kjk 完整性。

    返回 (bool, reason)。无校验行时返回 (True, 'no hash')。
    """
    if has_password_prefix(content):
        body = content[PWD_HEADER_CIPHER_LEN + 1:]
    else:
        body = content
    lines = body.split('\n')
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].startswith(_INTEGRITY_MARKER):
            stored = lines[i][len(_INTEGRITY_MARKER):]
            body_lines = lines[:i] + lines[i + 1:]
            body_for_hash = '\n'.join(body_lines).rstrip('\n')
            computed = hashlib.sha256(body_for_hash.encode('utf-8')).hexdigest()
            if computed == stored:
                return True, 'ok'
            return False, 'integrity mismatch'
    return True, 'no hash'


# ======================== .kjk 文件格式 v6 ========================
# 新版格式 (有密码, v6 前缀式):
#   [空密码加密的PWD:salt:hash(202字符)] [空格] KJKv7
#   <N>
#   <密码加密的文件名1>|7|<size>|<压缩的密码加密密文1>
#   ...
#
# 新版格式 (无密码):
#   KJKv7
#   <N>
#   <加密的文件名1>|7|<size>|<压缩的密文1>
#   ...
#
# 旧版格式 (有密码, v5 独立条目,仍可解密):
#   KJKv5
#   <N+1>
#   <空密码加密的"pwd_header">|0|<size>|<压缩的空密码加密"PWD:salt:hash">
#   <密码加密的文件名1>|1|<size>|<压缩的密码加密密文1>
#   ...
#
# 旧版格式 (有密码, pwd: 前缀,仍可解密):
#   KJKv5
#   <N>
#   pwd:salt:hash:加密文件名1|0|<size>|<密文1>
#   ...

def pack_kjk(files: list, version: str = 'KJKv7') -> str:
    """打包为 .kjk 格式 (不含密码头前缀)

    files: list of dict {
        enc_name: 加密后的文件名,
        ciphertext: 文本格式密文,
        size: 原始文件大小,
        has_pwd: bool (可选,标记条目是否有密码,仅旧版使用),
        parts: list (可选,大文件分块,KJKv8),
    }
    version: 'KJKv7' 使用 AES-256-GCM, 'KJKv5' 保留旧版行为。
    当任一文件带 'parts' 时,自动升级为 KJKv8(manifest + part 行)。
    """
    has_parts = any('parts' in f for f in files)
    out_version = 'KJKv8' if has_parts else version
    lines = [out_version, str(len(files))]
    for f in files:
        sz = f.get('size', 0)
        enc_name = f.get('enc_name', '')
        parts = f.get('parts')
        if parts:
            lines.append(f'{enc_name}|{_PART_MANIFEST_FLAG}|{sz}|{len(parts)}|{_PART_PLAINTEXT_SIZE}|')
            for p in parts:
                psz = p.get('size', 0)
                pct = compress_ciphertext(p['ciphertext'])
                lines.append(f"{p.get('enc_name', enc_name)}|{_PART_ENTRY_FLAG}|{psz}|{pct}")
            continue
        if out_version == 'KJKv7':
            flag = '7'
        elif out_version == 'KJKv8':
            flag = _PART_ENTRY_FLAG
        else:
            flag = '1' if f.get('has_pwd') else '0'
        compressed = compress_ciphertext(f['ciphertext'])
        lines.append(f"{enc_name}|{flag}|{sz}|{compressed}")
    return '\n'.join(lines)


def pack_kjk_with_password(files: list, password: str = '', progress_callback=None, salt: bytes = None) -> str:
    """打包 .kjk 文件。有密码时自动添加密码头前缀，无密码时直接打包。

    files: list of dict {
        name: 原始文件名,
        ext: 扩展名,
        data: 原始文件内容(bytes),
        ciphertext: 已加密 token(大文件流式加密时使用),
        enc_name: 已加密文件名(可选),
        size: 原始大小(可选),
        callback: 单文件阶段回调(可选),
    }
    password: 用户密码
    progress_callback: 可选回调(current, total)
    salt: 可选指定 salt;用于外层已生成 salt 且条目已用该 salt 加密的情况。
    """
    has_pwd = password and password.strip()
    header_text = None
    if has_pwd:
        if salt is None:
            header_text, salt = make_password_header(password)
        else:
            h = _derive_password_hash(password, salt)
            header_text = f'{PWD_CONTENT_PREFIX}{salt.hex()}:{h.hex()}'

    total = len(files)
    encrypted_files = []
    has_chunked = False
    for i, f in enumerate(files):
        # 如果条目已经加密(大文件流式加密),直接使用其密文
        if 'ciphertext' in f:
            enc_name = f.get('enc_name') or encrypt_filename(
                f.get('name', 'untitled'), f.get('ext', ''), password, salt)
            encrypted_files.append({
                'enc_name': enc_name,
                'ciphertext': f['ciphertext'],
                'size': f.get('size', 0),
            })
        else:
            name = f.get('name', 'untitled')
            ext = f.get('ext', '')
            data = f.get('data', b'')
            enc_name = encrypt_filename(name, ext, password, salt)
            if len(data) > _PART_PLAINTEXT_SIZE:
                # 大文件分块: 每个 part 单独 AES-GCM 加密,避免超大单行
                has_chunked = True
                parts = []
                part_total = len(data)
                for start in range(0, part_total, _PART_PLAINTEXT_SIZE):
                    chunk = data[start:start + _PART_PLAINTEXT_SIZE]
                    cipher = encrypt_raw(chunk, password, salt, callback=f.get('callback'))
                    parts.append({'enc_name': enc_name, 'ciphertext': cipher, 'size': len(chunk)})
                encrypted_files.append({'enc_name': enc_name, 'size': len(data), 'parts': parts})
            else:
                cipher = encrypt_raw(data, password, salt, callback=f.get('callback'))
                encrypted_files.append({
                    'enc_name': enc_name,
                    'ciphertext': cipher,
                    'size': len(data),
                })
        if progress_callback:
            progress_callback(i + 1, total)

    # 打包为 KJKv7/KJKv8 (大文件分块时自动升级为 KJKv8)
    kjk_content = pack_kjk(encrypted_files, version='KJKv8' if has_chunked else 'KJKv7')

    # 有密码时添加密码头前缀(使用空密码旧版算法加密,保持固定长度202字符)
    if has_pwd and header_text:
        header_cipher = _encrypt_raw_legacy(header_text.encode('utf-8'), '')
        return header_cipher + PWD_HEADER_SEPARATOR + kjk_content
    return kjk_content


def _unpack_kjk_internal(content: str) -> list:
    """解析 .kjk 内容 (不含密码头前缀检测)

    支持格式: KJKv5/v4/v3/v2/v1 和纯密文
    """
    # 忽略末尾的完整性校验行,避免被当作条目解析
    content = _strip_integrity_line(content)
    # 兼容 Windows \r\n 换行(某些来源如二进制读取可能保留 \r)
    lines = content.replace('\r', '').strip().split('\n')
    if not lines:
        raise ValueError('输入为空')

    # ===== KJKv8 (大文件分块 AES-256-GCM) =====
    if lines[0] == 'KJKv8':
        count = int(lines[1])
        results = []
        i = 2
        parsed = 0
        while parsed < count and i < len(lines):
            line = lines[i]
            parts = line.split('|')
            if len(parts) < 4:
                i += 1
                continue
            enc_name = parts[0] if parts[0] else ''
            flag = parts[1]
            if flag == _PART_MANIFEST_FLAG and len(parts) >= 6:
                total_size = int(parts[2]) if parts[2] else 0
                part_count = int(parts[3]) if parts[3] else 0
                part_entries = []
                j = i + 1
                collected = 0
                while j < len(lines) and collected < part_count:
                    pl = lines[j].split('|')
                    if len(pl) >= 4 and pl[1] == _PART_ENTRY_FLAG:
                        psz = int(pl[2]) if pl[2] else 0
                        b64data = '|'.join(pl[3:])
                        try:
                            pct = decompress_ciphertext(b64data)
                        except Exception:
                            pct = b64data
                        part_entries.append({
                            'enc_name': pl[0], 'size': psz,
                            '_ciphertext': pct, '_compressed': b64data,
                        })
                        collected += 1
                    j += 1
                results.append({
                    'enc_name': enc_name,
                    'size': total_size,
                    '_needs_password': True,
                    '_kjkv7': True,
                    '_kjkv8': True,
                    '_chunked_parts': part_entries,
                })
                i = j
                parsed += 1
                continue
            # 普通单条条目 (flag '8')
            size = int(parts[2]) if parts[2] else 0
            b64data = '|'.join(parts[3:])
            try:
                ciphertext = decompress_ciphertext(b64data)
            except Exception:
                ciphertext = b64data
            results.append({
                'enc_name': enc_name,
                'size': size,
                '_ciphertext': ciphertext,
                '_compressed': b64data,
                '_needs_password': True,
                '_kjkv7': True,
                '_kjkv8': True,
            })
            i += 1
            parsed += 1
        return results

    # ===== KJKv7 (新版 AES-256-GCM) =====
    if lines[0] == 'KJKv7':
        count = int(lines[1])
        results = []
        for i in range(count):
            line = lines[i + 2]
            parts = line.split('|')
            if len(parts) < 4:
                continue
            enc_name = parts[0] if parts[0] else ''
            flag = parts[1] if len(parts) > 1 else '0'
            size = int(parts[2]) if len(parts[2]) > 0 else 0
            b64data = '|'.join(parts[3:])
            try:
                ciphertext = decompress_ciphertext(b64data)
            except Exception:
                ciphertext = b64data
            item = {
                'enc_name': enc_name,
                'size': size,
                '_ciphertext': ciphertext,
                '_compressed': b64data,
                '_needs_password': True,
                '_kjkv7': True,
            }
            results.append(item)
        return results

    # ===== KJKv5 (旧版 SHA-256 计数器模式) =====
    if lines[0] == 'KJKv5':
        count = int(lines[1])
        results = []
        for i in range(count):
            line = lines[i + 2]
            parts = line.split('|')
            if len(parts) < 4:
                continue
            enc_name = parts[0] if parts[0] else ''
            has_pwd_flag = parts[1] == '1' if len(parts) > 1 else False
            size = int(parts[2]) if len(parts[2]) > 0 else 0
            b64data = '|'.join(parts[3:])
            try:
                ciphertext = decompress_ciphertext(b64data)
            except Exception:
                ciphertext = b64data

            # 旧版: 检测 pwd: 前缀; 新版: part[1] 标记
            needs_pwd = enc_name.startswith('pwd:') or has_pwd_flag
            stripped_enc, _, _, _ = strip_password_header(enc_name)

            item = {
                'enc_name': enc_name,
                'size': size,
                '_ciphertext': ciphertext,
                '_compressed': b64data,
                '_needs_password': needs_pwd,
                '_kjkv5': True,
                '_has_pwd_flag': has_pwd_flag,
            }

            # 旧版密码头检测在 detect_password_header() 中处理
            if needs_pwd:
                item['_needs_password'] = True
            else:
                # 尝试用空密码解密,检测是否为旧版独立密码头条目
                success, _, _ = try_decrypt_item(item, '', legacy=True)
                try:
                    name_data = decrypt_raw(enc_name, '', legacy=True)
                    name_text = name_data.decode('utf-8', errors='replace')
                    if name_text == PWD_HEADER_MARKER:
                        item['_is_password_header'] = True
                        item['_needs_password'] = False  # 头本身不需要密码
                    else:
                        item['_needs_password'] = not success
                except Exception:
                    item['_needs_password'] = not success
            results.append(item)
        return results

    # ===== KJKv4 =====
    if lines[0] == 'KJKv4':
        count = int(lines[1])
        results = []
        for i in range(count):
            line = lines[i + 2]
            parts = line.split('|')
            if len(parts) < 4:
                continue
            enc_name = parts[0] if parts[0] else ''
            size = int(parts[2]) if len(parts[2]) > 0 else 0
            b64data = '|'.join(parts[3:])
            try:
                ciphertext = decompress_ciphertext(b64data)
            except Exception:
                ciphertext = b64data
            item = {
                'enc_name': enc_name,
                'size': size,
                '_ciphertext': ciphertext,
                '_compressed': b64data,
            }
            success, _, _ = try_decrypt_item(item, '', legacy=True)
            item['_needs_password'] = not success
            results.append(item)
        return results

    # ===== KJKv3/KJKv2 =====
    if lines[0] in ('KJKv3', 'KJKv2'):
        count = int(lines[1])
        results = []
        for i in range(count):
            line = lines[i + 2]
            parts = line.split('|')
            if len(parts) < 4:
                continue
            enc_name = parts[0] if parts[0] else ''
            size = int(parts[2]) if len(parts[2]) > 0 else 0
            ciphertext = '|'.join(parts[3:])
            item = {
                'enc_name': enc_name,
                'size': size,
                '_ciphertext': ciphertext,
            }
            success, _, _ = try_decrypt_item(item, '', legacy=True)
            item['_needs_password'] = not success
            results.append(item)
        return results

    # ===== KJKv1 =====
    if lines[0] == 'KJKv1':
        count = int(lines[1])
        results = []
        for i in range(count):
            line = lines[i + 2]
            parts = line.split('|')
            if len(parts) < 4:
                continue
            name, ext = parts[1], parts[2]
            has_pwd = False
            ciphertext = ''
            if len(parts) >= 5 and parts[3] in ('0', '1'):
                has_pwd = parts[3] == '1'
                ciphertext = '|'.join(parts[4:])
            elif len(parts) >= 4:
                ciphertext = '|'.join(parts[3:])
            orig_name = f"{name}.{ext}" if ext else name
            results.append({
                'enc_name': '', 'name': name, 'ext': ext,
                'originalName': orig_name, 'data': b'', 'has_pwd': has_pwd,
                'size': 0, '_ciphertext': ciphertext, '_legacy_v1': True,
            })
        return results

    # ===== 纯密文检测 =====
    token_set = set(TOKENS)
    stripped = content.strip()
    if ' ' in stripped:
        parts_list = [p for p in stripped.split() if p]
    else:
        parts_list = [ch for ch in stripped if not ch.isspace()]
    if not parts_list:
        raise ValueError('输入为空')
    matched = sum(1 for p in parts_list if p in token_set)
    ratio = matched / len(parts_list) if parts_list else 0
    if ratio > 0.7:
        item = {
            'enc_name': '',
            'size': 0,
            '_ciphertext': content,
        }
        # 检测是否有密码头前缀
        has_pwd_prefix, _, _, _ = detect_password_prefix(content)
        if has_pwd_prefix:
            item['_needs_password'] = True
        else:
            # 无密码头:仅尝试 AES-GCM 解密(零密钥)
            # 使用 decrypt_raw 直接调用,避免 try_decrypt_item 的内部 legacy 回退,
            # 因为 legacy 对空密码是无操作(token直接转字节),
            # 会错误地"成功"并存储错误的解密数据,导致外层不再重新解密
            try:
                data = decrypt_raw(content, '', None, legacy=False)
                item['data'] = data
                item['_needs_password'] = False
            except Exception:
                item['_needs_password'] = True
        return [item]
    raise ValueError('无效的输入: 无法识别为有效的密文')


def unpack_kjk(content: str) -> list:
    """解析 .kjk 文件或纯密文,自动检测密码头前缀。

    新版(v6): 内容开头有密码头前缀 → 去掉前缀,在 results 插入密码头标记
    旧版(v5): 独立条目方式 → results[0] 有 _is_password_header 标记
    旧版: pwd: 前缀 → results[0] 的 enc_name 以 pwd: 开头
    """
    # 检测密码头前缀(v6/v7 新版)
    has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(content)

    # 解析剩余内容
    results = _unpack_kjk_internal(remaining)

    # 如果有密码头前缀,在 results 开头插入密码头标记
    if has_pwd:
        header_item = {
            'enc_name': '',
            'size': 0,
            '_is_password_prefix_header': True,
            '_pwd_salt': salt_bytes.hex() if salt_bytes else None,
            '_pwd_hash': hash_hex,
            '_ciphertext': '',
        }
        results.insert(0, header_item)

    return results


def detect_password_header(results: list) -> tuple:
    """检测解析结果中是否有密码头。

    兼容三种格式:
    1. v6 前缀式: results[0] 有 _is_password_prefix_header 标记
    2. v5 独立条目: results[0] 有 _is_password_header 标记
    3. 旧版 pwd: 前缀: results[0] 的 enc_name 以 pwd: 开头

    返回 (has_pwd: bool, salt_hex: str|None, hash_hex: str|None, actual_files: list)
    """
    if not results:
        return False, None, None, results

    first = results[0]

    # v6 新版: 前缀式密码头
    if first.get('_is_password_prefix_header'):
        return True, first['_pwd_salt'], first['_pwd_hash'], results[1:]

    # v5 旧版: 独立条目式密码头
    if first.get('_is_password_header'):
        try:
            # 用空密码 + legacy 算法解密头内容 (v5 使用 SHA-256 计数器模式)
            cipher = first.get('_ciphertext', '')
            content_data = decrypt_raw(cipher, '', legacy=True)
            content_text = content_data.decode('utf-8', errors='replace')

            if content_text.startswith(PWD_CONTENT_PREFIX):
                parts = content_text.split(':')
                if len(parts) >= 3:
                    salt_hex = parts[1]
                    hash_hex = parts[2]
                    if len(salt_hex) == PWD_SALT_LEN * 2 and len(hash_hex) == PWD_HASH_LEN * 2:
                        return True, salt_hex, hash_hex, results[1:]
        except Exception:
            pass
        return True, None, None, results[1:]

    # 旧版: pwd: 前缀
    enc_name = first.get('enc_name', '')
    if enc_name.startswith('pwd:'):
        _, has_header, salt_hex, hash_hex = strip_password_header(enc_name)
        if has_header:
            return True, salt_hex, hash_hex, results

    return False, None, None, results


def re_decrypt(item: dict, password: str, salt: bytes = None, legacy: bool = False) -> bytes:
    """用密码重新解密,失败时抛出异常"""
    success, data, error = try_decrypt_item(item, password, salt, legacy=legacy)
    if not success:
        raise ValueError(error or '密码错误或文件损坏')
    return data


# ======================== 旧版文本格式流式提取 ========================
# 旧版(KJKv1/v2/v3/v4/v5/v7/v8)是逐行文本: enc|flag|size|b64。
# 整文件读入内存解析会占大量内存,这里提供逐行解析 + 逐条目解密直接落盘的
# 流式提取,每条目只短暂驻留内存,大包不再卡顿/爆内存。可选 callback 接收
# (bytes_done, bytes_total) 字节级进度用于 0.1% 精度的进度条。

def _decode_entry_ciphertext(b64data: str) -> str:
    """解压条目密文(base64→zlib→原始token密文),失败时返回原样。"""
    try:
        return decompress_ciphertext(b64data)
    except Exception:
        return b64data


def _entry_name_from_parts(parts, is_v1):
    """从条目的 parts 恢复 originalName。"""
    try:
        if is_v1:
            name, ext = parts[1], parts[2]
            return f"{name}.{ext}" if ext else name
        return ''
    except Exception:
        return ''


def _legacy_original_name(enc_name, password, salt):
    """从加密文件名恢复原始相对路径;失败返回 None。"""
    if not enc_name:
        return None
    if enc_name.startswith('pwd:'):
        is_valid, remaining = _verify_password_header(enc_name, password)
        if not is_valid:
            return None
        enc_name = remaining
    for legacy in (False, True):
        try:
            name, ext = decrypt_filename(enc_name, password, salt, legacy=legacy)
            full = f'{name}.{ext}' if ext else name
            if full:
                return full.replace('\\', '/')
        except Exception:
            continue
    return None


def _legacy_entry_plain(parts, is_v1, password, salt, legacy_alg):
    """解出一个旧版条目 → (original_relpath, content_bytes|None)。

    失败(密码错误/损坏)返回 (None, None)。文件名统一用 '/' 作目录分隔。
    """
    if is_v1:
        has_pwd = False
        ciphertext = ''
        if len(parts) >= 5 and parts[3] in ('0', '1'):
            has_pwd = parts[3] == '1'
            ciphertext = _decode_entry_ciphertext('|'.join(parts[4:]))
        elif len(parts) >= 4:
            ciphertext = _decode_entry_ciphertext('|'.join(parts[3:]))
        originalName = _entry_name_from_parts(parts, True) or 'decrypted'
        item = {
            'enc_name': '', 'size': 0, '_ciphertext': ciphertext,
            '_needs_password': has_pwd, 'data': None,
            'originalName': originalName, 'name': originalName, 'ext': '',
        }
        content = b''
        try:
            _, content, _ = try_decrypt_item(item, password, salt, legacy=True)
            if content is None:
                content = b''
        except Exception:
            content = b''
        return originalName.replace('\\', '/'), content

    enc_name = parts[0] if parts[0] else ''
    b64data = '|'.join(parts[3:])
    ciphertext = _decode_entry_ciphertext(b64data)
    has_pwd = enc_name.startswith('pwd:') or (len(parts) > 1 and parts[1] == '1')
    item = {
        'enc_name': enc_name, 'size': 0, '_ciphertext': ciphertext,
        '_needs_password': has_pwd, 'data': None,
    }
    success, content, _ = try_decrypt_item(item, password, salt, legacy=legacy_alg)
    if not success:
        success, content, _ = try_decrypt_item(item, password, salt, legacy=not legacy_alg)
    if not success:
        return None, None
    original = (item.get('originalName', '') or item.get('name', '') or 'decrypted').replace('\\', '/')
    return (original or 'decrypted'), content


def _write_legacy_entry(save_dir, original, content, path_safe=True):
    """将解出的条目写入 save_dir。返回是否写入了文件(目录项返回 False)。"""
    original = original if original else 'decrypted'
    if original.endswith('/'):
        os.makedirs(_safe_join(save_dir, original), exist_ok=True)
        return False
    if content is None:
        return False
    target = _safe_join(save_dir, original)
    d = os.path.dirname(target)
    if d:
        os.makedirs(d, exist_ok=True)
    CHUNK = 4 * 1024 * 1024
    with open(target, 'wb') as fw:
        for off in range(0, len(content), CHUNK):
            fw.write(content[off:off + CHUNK])
    return True


def _legacy_alg_for(fmt_header, salt):
    return not (bool(salt) or fmt_header == 'KJKv7' or fmt_header == 'KJKv8')


def _strip_password_prefix_first_line(line: str) -> str:
    """若行首为密码头前缀(固定长度密文+空格),去掉前缀。"""
    if len(line) > PWD_HEADER_CIPHER_LEN + 1 and \
            line[PWD_HEADER_CIPHER_LEN] == PWD_HEADER_SEPARATOR:
        return line[PWD_HEADER_CIPHER_LEN + 1:]
    return line


def extract_legacy_package_text(full_text: str, password: str, salt: bytes,
                                save_dir: str, callback=None,
                                path_safe: bool = True) -> int:
    """流式提取旧版文本 .kjk 到 save_dir,返回提取的文件数。

    - 逐行解析(不整文件 struct 化),逐条目解密并写盘,每条目完毕即释放内存。
    - callback(frac) 接收 0.0~1.0 进度,按已处理文本字节占总正文字节推进。
    - 文件名经 _safe_join 防路径穿越;目录项自动创建目录。
    """
    lines = full_text.replace('\r', '').strip().split('\n')
    if not lines:
        raise ValueError('输入为空')
    header = lines[0]
    if header == 'KJKv9':
        raise ValueError('KJKv9 为二进制格式,请用 kjk9 引擎')

    body = _strip_integrity_line(full_text)
    total_bytes = max(1, len(body))
    done_bytes = 0

    def _emit():
        nonlocal done_bytes
        if callback:
            callback(min(1.0, done_bytes / total_bytes))

    def _final():
        if callback:
            callback(1.0)

    extracted = 0
    legacy_alg = _legacy_alg_for(header, salt)

    try:
        count = int(lines[1])
        sidx = 2
        parsed = 0

        def _advance():
            nonlocal done_bytes
            done_bytes = min(total_bytes, done_bytes + len(lines[sidx]) + 1)
            _emit()

        while parsed < count and sidx < len(lines):
            line = lines[sidx]
            if not line.strip():
                _advance()
                sidx += 1
                continue
            parts = line.split('|')
            if len(parts) < 4:
                _advance()
                sidx += 1
                continue

            original, content = _legacy_entry_plain(parts, header == 'KJKv1',
                                                    password, salt, legacy_alg)
            if original is None:
                _advance()
                sidx += 1
                parsed += 1
                continue
            try:
                if _write_legacy_entry(save_dir, original, content, path_safe):
                    extracted += 1
            except (ValueError, OSError):
                pass
            _advance()
            sidx += 1
            parsed += 1

        _final()
        return extracted
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f'旧版格式解析失败: {e}')


def extract_legacy_package_file(filepath: str, password: str, salt: bytes,
                                save_dir: str, callback=None,
                                path_safe: bool = True) -> int:
    """从 .kjk 文件流式提取旧版文本格式到 save_dir,返回提取的文件数。

    相比 extract_legacy_package_text 的关键改进: 不整文件读入内存,
    逐行从磁盘读取、逐条目解密并直接落盘, 每条目处理完立即释放。
    callback(frac) 按已读文件字节/总文件字节推进(0.0~1.0,含密码头前缀)。
    自动处理开头密码头前缀(KJKv1/v5/v7/v8),文件名经 _safe_join 防穿越。
    """
    total_size = os.path.getsize(filepath)
    if total_size <= 0:
        raise ValueError('文件为空')
    done = [0]

    def _progress(min_frac, max_frac):
        if callback:
            callback(min(max_frac, max(min_frac, done[0] / max(1, total_size))))

    def _lines():
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for raw in f:
                done[0] += len(raw)
                line = raw.replace('\r', '').rstrip('\n')
                if line.strip():
                    yield line

    it = _lines()
    try:
        fmt_header = _strip_password_prefix_first_line(next(it)).strip()
    except StopIteration:
        raise ValueError('输入为空')

    if fmt_header == 'KJKv9':
        raise ValueError('KJKv9 为二进制格式,请用 kjk9 引擎')

    try:
        count = int(next(it))
    except StopIteration:
        raise ValueError('格式无效: 缺少条目数')
    except (ValueError, TypeError):
        raise ValueError('格式无效: 条目数不是数字')

    legacy_alg = _legacy_alg_for(fmt_header, salt)
    is_v1 = fmt_header == 'KJKv1'
    extracted = 0
    parsed = 0

    if fmt_header == 'KJKv8':
        # KJKv8 大文件分块: manifest 行 + 多个 part 行,逐 part 解密并增量落盘
        while parsed < count:
            try:
                line = next(it)
            except StopIteration:
                break
            _progress(done[0] / max(1, total_size), 0.999)
            if not line.strip():
                continue
            parts = line.split('|')
            if len(parts) < 4:
                continue
            enc_name = parts[0]
            if parts[1] == _PART_MANIFEST_FLAG and len(parts) >= 6:
                part_count = int(parts[3]) if parts[3] else 0
                original = _legacy_original_name(enc_name, password, salt)
                try:
                    if original is not None and not original.endswith('/'):
                        target = _safe_join(save_dir, original) if path_safe else os.path.join(save_dir, original.replace('/', os.sep))
                        d = os.path.dirname(target)
                        if d:
                            os.makedirs(d, exist_ok=True)
                        got_data = False
                        with open(target, 'wb') as fw:
                            for _ in range(part_count):
                                try:
                                    pl = next(it)
                                except StopIteration:
                                    break
                                done[0] += len(pl)
                                q = pl.split('|')
                                if len(q) >= 4 and q[1] == _PART_ENTRY_FLAG:
                                    try:
                                        tok = decompress_ciphertext('|'.join(q[3:]))
                                    except Exception:
                                        tok = '|'.join(q[3:])
                                    pitem = {'enc_name': enc_name, 'size': 0,
                                             '_ciphertext': tok, '_needs_password': True,
                                             '_kjkv7': True, 'data': None}
                                    ok, pdata, _ = try_decrypt_item(pitem, password, salt, legacy=False)
                                    if ok and pdata:
                                        fw.write(pdata)
                                        got_data = True
                        if got_data:
                            extracted += 1
                except (ValueError, OSError):
                    pass
            parsed += 1
        if callback:
            callback(1.0)
        return extracted

    for line in it:
        if parsed >= count:
            break
        _progress(done[0] / max(1, total_size), 0.999)  # 预留最终 100% 由 _final 置位
        if not line.strip():
            continue
        parts = line.split('|')
        if len(parts) < 4:
            continue

        original, content = _legacy_entry_plain(parts, is_v1, password, salt, legacy_alg)
        if original is None:
            parsed += 1
            continue
        try:
            if _write_legacy_entry(save_dir, original, content, path_safe):
                extracted += 1
        except (ValueError, OSError):
            pass
        parsed += 1

    if callback:
        callback(1.0)
    return extracted


def _safe_join(base: str, name: str) -> str:
    """防止路径穿越: 将 name 安全地拼接到 base 下。"""
    if os.name == 'nt':
        base_abs = os.path.abspath(base)
        norm = name.replace('/', '\\')
        if '..' in norm.split('\\'):
            raise ValueError('路径包含不可用字符')
        joined = os.path.normpath(os.path.join(base_abs, norm))
        if not joined.startswith(base_abs.rstrip('\\') + '\\'):
            raise ValueError('路径越界')
        return joined
    base_abs = os.path.abspath(base)
    joined = os.path.normpath(os.path.join(base_abs, name))
    if not joined.startswith(base_abs + os.sep):
        raise ValueError('路径越界')
    return joined


# ======================== 文件夹打包辅助 ========================

def _norm_rel_path(path: str, base: str) -> str:
    rel = os.path.relpath(path, base)
    return rel.replace('\\', '/')


def _split_name_ext(rel_path: str) -> tuple:
    """将相对路径拆分为 (name, ext),保留末尾的目录斜杠。"""
    if rel_path.endswith('/'):
        return rel_path, ''
    idx = rel_path.rfind('.')
    if idx > 0:
        return rel_path[:idx], rel_path[idx + 1:]
    return rel_path, ''


class _Entry(dict):
    """文件夹条目字典,支持大文件按需读取 data,同时保留流式加密的元数据。"""

    def __missing__(self, key):
        if key == 'data' and 'path' in self:
            with open(self['path'], 'rb') as fh:
                self['data'] = fh.read()
            return self['data']
        raise KeyError(key)


def collect_folder_entries(folder_path: str):
    """收集文件夹内所有文件与空目录。

    返回 (file_entries, empty_dir_paths), 其中:
    - file_entries: [{'rel_path': 完整相对路径(含顶层文件夹名), 'data': bytes|lazy, 'path': str(大文件), 'size': int}, ...]
    - empty_dir_paths: [完整相对目录路径(以 '/' 结尾,含顶层文件夹名), ...]

    小文件直接读入内存;大于 1 MB 的文件保留路径,由打包函数流式加密。
    """
    folder_path = os.path.abspath(folder_path)
    base = os.path.basename(folder_path.rstrip(os.sep))
    if not base:
        base = 'folder'

    file_entries = []
    dirs_with_files = set()

    for root, dirs, files in os.walk(folder_path):
        rel_root = _norm_rel_path(root, folder_path)
        if rel_root == '.':
            rel_root = ''
        if files:
            mark = rel_root
            while mark is not None:
                dirs_with_files.add(mark)
                mark = os.path.dirname(mark) if mark else None
        for f in files:
            full = os.path.join(root, f)
            rel = _norm_rel_path(full, folder_path)
            arcname = base + '/' + rel if rel else base
            size = os.path.getsize(full)
            if size > _STREAMING_THRESHOLD:
                # 大文件:保留路径,打包时流式加密
                file_entries.append(_Entry(rel_path=arcname, path=full, size=size))
            else:
                with open(full, 'rb') as fh:
                    data = fh.read()
                file_entries.append(_Entry(rel_path=arcname, data=data, size=len(data)))

    empty_dirs = []
    for root, dirs, _ in os.walk(folder_path):
        rel_root = _norm_rel_path(root, folder_path)
        if rel_root == '.':
            rel_root = ''
        if rel_root in dirs_with_files:
            continue
        arcname = base + '/' + rel_root if rel_root else base
        empty_dirs.append(arcname + '/')

    if not file_entries and not empty_dirs:
        empty_dirs.append(base + '/')

    return file_entries, empty_dirs


def pack_kjk_with_folder(folder_path: str, password: str = '', progress_callback=None) -> str:
    """将整个文件夹打包为单个 .kjk,保留目录层级与空目录,文件夹名也会加密。"""
    file_entries, empty_dirs = collect_folder_entries(folder_path)
    if not file_entries and not empty_dirs:
        raise ValueError('文件夹为空,无法打包。')

    has_pwd = password and password.strip()
    salt = None
    if has_pwd:
        _, salt = make_password_header(password)
    key = _derive_aes_key(password, salt or b'')

    files = []
    for e in file_entries:
        rel = e['rel_path']
        name, ext = _split_name_ext(rel)
        if 'path' in e:
            # 大文件流式加密
            ciphertext = _encrypt_file_to_tokens(e['path'], key)
            files.append({
                'enc_name': encrypt_filename(name, ext, password, salt),
                'ciphertext': ciphertext,
                'size': e['size'],
            })
        else:
            files.append({
                'name': name, 'ext': ext,
                'data': e['data'], 'size': e.get('size', len(e['data'])),
            })

    for d in empty_dirs:
        # 空目录以带斜杠的完整相对路径作为文件名保存
        name, ext = _split_name_ext(d)
        files.append({'name': name, 'ext': ext, 'data': b'', 'size': 0})

    return pack_kjk_with_password(files, password, progress_callback=progress_callback, salt=salt)


def pack_kjk_with_paths(paths: list, password: str = '', progress_callback=None, merge_name: str = None) -> str:
    """将多个文件或文件夹打包为一个 .kjk。

    每个顶层路径作为顶层条目;文件夹内容保持相对结构。
    空目录以名称末尾 '/'、数据 b'' 保存。
    若提供 merge_name,所有路径统一放到该名称的文件夹下。
    """
    if not paths:
        raise ValueError('paths 不能为空')

    has_pwd = password and password.strip()
    salt = None
    if has_pwd:
        _, salt = make_password_header(password)
    key = _derive_aes_key(password, salt or b'')

    files = []
    for p in paths:
        p = os.path.abspath(p)
        if not os.path.exists(p):
            raise FileNotFoundError(f'路径不存在: {p}')

        if os.path.isfile(p):
            size = os.path.getsize(p)
            arcname = os.path.basename(p)
            if merge_name:
                arcname = merge_name + '/' + arcname
            name, ext = _split_name_ext(arcname)
            if size > _STREAMING_THRESHOLD:
                ciphertext = _encrypt_file_to_tokens(p, key)
                files.append({
                    'enc_name': encrypt_filename(name, ext, password, salt),
                    'ciphertext': ciphertext,
                    'size': size,
                })
            else:
                with open(p, 'rb') as fh:
                    data = fh.read()
                files.append({'name': name, 'ext': ext, 'data': data, 'size': size})

        elif os.path.isdir(p):
            entries, empty_dirs = collect_folder_entries(p)
            for e in entries:
                rel = e['rel_path']
                if merge_name:
                    rel = merge_name + '/' + rel
                name, ext = _split_name_ext(rel)
                if 'path' in e:
                    ciphertext = _encrypt_file_to_tokens(e['path'], key)
                    files.append({
                        'enc_name': encrypt_filename(name, ext, password, salt),
                        'ciphertext': ciphertext,
                        'size': e['size'],
                    })
                else:
                    files.append({
                        'name': name, 'ext': ext,
                        'data': e['data'], 'size': e.get('size', len(e['data'])),
                    })
            for d in empty_dirs:
                if merge_name:
                    d = merge_name + '/' + d
                name, ext = _split_name_ext(d)
                files.append({'name': name, 'ext': ext, 'data': b'', 'size': 0})

    return pack_kjk_with_password(files, password, progress_callback=progress_callback, salt=salt)


def _fm_line_count(fm: dict) -> int:
    """估算一个文件元数据在 .kjk 中占据的行数 (manifest + parts 或单行)。"""
    size = fm.get('size', 0) or len(fm.get('data', b''))
    if size > _PART_PLAINTEXT_SIZE:
        return 1 + (size + _PART_PLAINTEXT_SIZE - 1) // _PART_PLAINTEXT_SIZE
    return 1


def _build_pack_lines(fm: dict, key: bytes, password: str, salt: bytes, progress_callback=None) -> list:
    """根据文件元数据生成 .kjk 条目行列表 (KJKv7 单行 或 KJKv8 manifest+parts)。"""
    def _inner_cb(ratio):
        if progress_callback:
            progress_callback(ratio)

    enc_name = encrypt_filename(fm['name'], fm['ext'], password, salt)
    if fm.get('path'):
        size = fm['size']
        if size > _PART_PLAINTEXT_SIZE:
            part_count = (size + _PART_PLAINTEXT_SIZE - 1) // _PART_PLAINTEXT_SIZE
            lines = [f'{enc_name}|{_PART_MANIFEST_FLAG}|{size}|{part_count}|{_PART_PLAINTEXT_SIZE}|']
            with open(fm['path'], 'rb') as fh:
                while True:
                    chunk = fh.read(_PART_PLAINTEXT_SIZE)
                    if not chunk:
                        break
                    ct = _encrypt_raw_v7(chunk, key, callback=_inner_cb)
                    lines.append(f'{enc_name}|{_PART_ENTRY_FLAG}|{len(chunk)}|{compress_ciphertext(ct)}')
                    time.sleep(0)  # 让出 GIL,保持 UI 响应
            return lines
        ciphertext = _encrypt_file_to_tokens(fm['path'], key, callback=_inner_cb)
    else:
        data = fm['data']
        if len(data) > _PART_PLAINTEXT_SIZE:
            part_count = (len(data) + _PART_PLAINTEXT_SIZE - 1) // _PART_PLAINTEXT_SIZE
            lines = [f'{enc_name}|{_PART_MANIFEST_FLAG}|{len(data)}|{part_count}|{_PART_PLAINTEXT_SIZE}|']
            for start in range(0, len(data), _PART_PLAINTEXT_SIZE):
                chunk = data[start:start + _PART_PLAINTEXT_SIZE]
                ct = _encrypt_raw_v7(chunk, key, callback=_inner_cb)
                lines.append(f'{enc_name}|{_PART_ENTRY_FLAG}|{len(chunk)}|{compress_ciphertext(ct)}')
                time.sleep(0)  # 让出 GIL,保持 UI 响应
            return lines
        ciphertext = _encrypt_raw_v7(data, key, callback=_inner_cb)
    return [f'{enc_name}|7|{fm["size"]}|{compress_ciphertext(ciphertext)}']


def _prepend_password_header_to_file(tmp_path: str, out_path: str, password: str, salt: bytes):
    """将密码头前缀写入最终文件,再流式复制 body 临时文件,避免一次性加载大文件。"""
    header_text = f'{PWD_CONTENT_PREFIX}{salt.hex()}:{_derive_password_hash(password, salt).hex()}'
    header_cipher = _encrypt_raw_legacy(header_text.encode('utf-8'), '')
    with open(out_path, 'w', encoding='utf-8') as out, open(tmp_path, 'r', encoding='utf-8') as src:
        out.write(header_cipher)
        out.write(PWD_HEADER_SEPARATOR)
        while True:
            chunk = src.read(_CHUNK_SIZE)
            if not chunk:
                break
            out.write(chunk)
    try:
        os.remove(tmp_path)
    except Exception:
        pass


def pack_kjk_with_paths_to_file(paths: list, out_path: str, password: str = '',
                                progress_callback=None, merge_name: str = None) -> None:
    """将多个文件/文件夹直接流式打包写入 .kjk 文件,避免内存爆炸。

    每个顶层路径作为顶层条目;文件夹内容保持相对结构。
    空目录以名称末尾 '/'、数据 b'' 保存。
    若提供 merge_name,所有路径统一放到该名称的文件夹下。
    """
    if not paths:
        raise ValueError('paths 不能为空')

    files_meta = []
    for p in paths:
        p = os.path.abspath(p)
        if not os.path.exists(p):
            raise FileNotFoundError(f'路径不存在: {p}')

        if os.path.isfile(p):
            size = os.path.getsize(p)
            arcname = os.path.basename(p)
            if merge_name:
                arcname = merge_name + '/' + arcname
            name, ext = _split_name_ext(arcname)
            if size > _STREAMING_THRESHOLD:
                files_meta.append({'path': p, 'name': name, 'ext': ext, 'size': size})
            else:
                with open(p, 'rb') as fh:
                    data = fh.read()
                files_meta.append({'name': name, 'ext': ext, 'data': data, 'size': size})

        elif os.path.isdir(p):
            entries, empty_dirs = collect_folder_entries(p)
            for e in entries:
                rel = e['rel_path']
                if merge_name:
                    rel = merge_name + '/' + rel
                name, ext = _split_name_ext(rel)
                if 'path' in e:
                    files_meta.append({'path': e['path'], 'name': name, 'ext': ext, 'size': e['size']})
                else:
                    files_meta.append({'name': name, 'ext': ext, 'data': e['data'], 'size': e.get('size', len(e['data']))})
            for d in empty_dirs:
                if merge_name:
                    d = merge_name + '/' + d
                name, ext = _split_name_ext(d)
                files_meta.append({'name': name, 'ext': ext, 'data': b'', 'size': 0})

    has_pwd = password and password.strip()
    salt = None
    if has_pwd:
        _, salt = make_password_header(password)
    key = _derive_aes_key(password, salt or b'')

    tmp_path = out_path + '.tmp'
    try:
        has_chunked = any(_fm_line_count(fm) > 1 for fm in files_meta)
        version = 'KJKv8' if has_chunked else 'KJKv7'
        total = len(files_meta)
        with open(tmp_path, 'w', encoding='utf-8') as out:
            out.write(version + '\n')
            out.write(str(total) + '\n')
            for i, fm in enumerate(files_meta):
                def _make_cb(idx):
                    if progress_callback is None:
                        return None
                    return lambda ratio: progress_callback(idx + ratio, total)

                for line in _build_pack_lines(fm, key, password, salt, progress_callback=_make_cb(i)):
                    out.write(line + '\n')
                if progress_callback:
                    progress_callback(i + 1, total)
        if has_pwd:
            _prepend_password_header_to_file(tmp_path, out_path, password, salt)
        else:
            if os.path.exists(out_path):
                os.remove(out_path)
            os.replace(tmp_path, out_path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass
        raise


# ======================== .kjk 内容管理 ========================
def append_to_kjk(kjk_content: str, new_files: list) -> str:
    """向已有 .kjk 内容追加新文件,保留密码头前缀。

    new_files: list of dict {
        enc_name: 加密后的文件名,
        ciphertext: 文本格式密文,
        size: 原始文件大小,
    }
    """
    # 先检测是否有密码头前缀;无前缀时不调用 detect_password_prefix 解析 salt/hash
    has_pwd = has_password_prefix(kjk_content)
    salt_bytes = None
    hash_hex = None
    remaining = kjk_content
    if has_pwd:
        has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(kjk_content)

    remaining = _strip_integrity_line(remaining)
    lines = remaining.strip().split('\n')
    version = lines[0]
    existing_count = int(lines[1])

    new_lines = []
    for f in new_files:
        sz = f.get('size', 0)
        compressed = compress_ciphertext(f['ciphertext'])
        flag = '7' if version == 'KJKv7' else '0'
        new_lines.append(f"{f.get('enc_name', '')}|{flag}|{sz}|{compressed}")

    all_lines = [version, str(existing_count + len(new_lines))]

    if version in ('KJKv7', 'KJKv5', 'KJKv4'):
        for i in range(existing_count):
            all_lines.append(lines[i + 2])
    else:
        old_results = _unpack_kjk_internal(remaining)
        for r in old_results:
            sz = r.get('size', 0)
            comp = compress_ciphertext(r['_ciphertext']) if not r.get('_legacy_v1') else r['_ciphertext']
            all_lines.append(f"{r.get('enc_name', '')}|0|{sz}|{comp}")

    all_lines.extend(new_lines)
    result = '\n'.join(all_lines)

    # 如果有密码头前缀,重新添加
    if has_pwd:
        header = f'{PWD_CONTENT_PREFIX}{salt_bytes.hex()}:{hash_hex}'
        header_cipher = _encrypt_raw_legacy(header.encode('utf-8'), '')
        result = header_cipher + PWD_HEADER_SEPARATOR + result

    return result


def change_password_kjk(content: str, old_password: str, new_password: str, progress_callback=None) -> str:
    """修改 .kjk 包密码:解密所有条目后用新密码重新加密并打包。"""
    has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(content)
    if has_pwd:
        if not verify_password(old_password, salt_bytes.hex(), hash_hex):
            raise ValueError('旧密码错误')

    remaining = _strip_integrity_line(remaining)
    results = _unpack_kjk_internal(remaining)
    files = [r for r in results if not r.get('_is_password_header') and not r.get('_is_password_prefix_header')]
    is_v7 = remaining.strip().split('\n')[0] == 'KJKv7' or all(r.get('_kjkv7') for r in files)

    total = len(files)
    new_files = []
    for i, r in enumerate(files):
        try:
            data = re_decrypt(r, old_password, salt_bytes, legacy=not is_v7)
        except Exception as e:
            raise ValueError(f'解密条目 {i} 失败: {e}')
        name = r.get('name', '')
        ext = r.get('ext', '')
        if not name:
            try:
                name, ext = decrypt_filename(r['enc_name'], old_password, salt_bytes, legacy=not is_v7)
            except Exception:
                name = f'entry_{i}'
        new_files.append({'name': name, 'ext': ext, 'data': data, 'size': len(data)})
        if progress_callback:
            progress_callback(i + 1, total)

    return pack_kjk_with_password(new_files, new_password, progress_callback=progress_callback)


def delete_entries_kjk(content: str, indices: list) -> str:
    """删除 .kjk 中指定索引(0-based,实际文件条目)的条目并重新打包。"""
    has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(content)
    remaining = _strip_integrity_line(remaining)
    results = _unpack_kjk_internal(remaining)
    files = [r for r in results if not r.get('_is_password_header') and not r.get('_is_password_prefix_header')]

    for idx in sorted(set(indices), reverse=True):
        if idx < 0 or idx >= len(files):
            raise IndexError(f'索引越界: {idx}')
        del files[idx]

    version = remaining.strip().split('\n')[0]
    lines = [version, str(len(files))]
    for r in files:
        sz = r.get('size', 0)
        comp = compress_ciphertext(r['_ciphertext']) if not r.get('_legacy_v1') else r['_ciphertext']
        if version == 'KJKv7':
            flag = '7'
        elif version == 'KJKv5':
            flag = '1' if r.get('_has_pwd_flag') else '0'
        else:
            flag = '0'
        lines.append(f"{r.get('enc_name', '')}|{flag}|{sz}|{comp}")
    result = '\n'.join(lines)

    if has_pwd:
        header = f'{PWD_CONTENT_PREFIX}{salt_bytes.hex()}:{hash_hex}'
        header_cipher = _encrypt_raw_legacy(header.encode('utf-8'), '')
        result = header_cipher + PWD_HEADER_SEPARATOR + result
    return result


def rename_entry_kjk(content: str, idx: int, new_name: str, new_ext: str = '', password: str = '') -> str:
    """重命名 .kjk 中指定索引的条目。

    支持无密码包与密码保护包:
      - 无密码包: 直接解密文件名→换名→重加密写入。
      - 密码保护包: 需提供正确 password, 否则抛 ValueError('密码错误')。
    密码包的 salt 来自密码头前缀,文件名与数据解密/重加密均使用该 salt。
    """
    has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(content)
    if has_pwd:
        if not verify_password(password, salt_bytes.hex(), hash_hex):
            raise ValueError('密码错误')

    remaining = _strip_integrity_line(remaining)
    results = _unpack_kjk_internal(remaining)
    files = [r for r in results if not r.get('_is_password_header') and not r.get('_is_password_prefix_header')]
    if idx < 0 or idx >= len(files):
        raise IndexError(f'索引越界: {idx}')

    item = files[idx]
    legacy = item.get('_kjkv5', False) or not item.get('_kjkv7', True)
    item['enc_name'] = encrypt_filename(new_name, new_ext, password, salt_bytes, legacy=legacy)

    version = remaining.strip().split('\n')[0]
    lines = [version, str(len(files))]
    for r in files:
        sz = r.get('size', 0)
        comp = compress_ciphertext(r['_ciphertext']) if not r.get('_legacy_v1') else r['_ciphertext']
        if version == 'KJKv7':
            flag = '7'
        elif version == 'KJKv5':
            flag = '1' if r.get('_has_pwd_flag') else '0'
        else:
            flag = '0'
        lines.append(f"{r.get('enc_name', '')}|{flag}|{sz}|{comp}")
    result = '\n'.join(lines)

    if has_pwd:
        header = f'{PWD_CONTENT_PREFIX}{salt_bytes.hex()}:{hash_hex}'
        header_cipher = _encrypt_raw_legacy(header.encode('utf-8'), '')
        result = header_cipher + PWD_HEADER_SEPARATOR + result
    return result


def extract_entry_to_path(content: str, idx: int, password: str, out_path: str, progress_callback=None) -> bool:
    """将 .kjk 中指定条目解密并写入磁盘,自动创建父目录。"""
    has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(content)
    if has_pwd:
        if not verify_password(password, salt_bytes.hex(), hash_hex):
            raise ValueError('密码错误')

    remaining = _strip_integrity_line(remaining)
    results = _unpack_kjk_internal(remaining)
    files = [r for r in results if not r.get('_is_password_header') and not r.get('_is_password_prefix_header')]
    if idx < 0 or idx >= len(files):
        raise IndexError(f'索引越界: {idx}')

    item = files[idx]
    is_v7 = remaining.strip().split('\n')[0] == 'KJKv7' or all(r.get('_kjkv7') for r in files)

    # 先解密文件名,避免后续找不到真实文件名
    enc_name = item.get('enc_name', '')
    if enc_name and not item.get('originalName'):
        try:
            name, ext = decrypt_filename(enc_name, password, salt_bytes, legacy=not is_v7)
            full = f"{name}.{ext}" if ext else name
            item['name'] = name
            item['ext'] = ext
            item['originalName'] = full
        except Exception:
            pass

    fname = item.get('originalName', item.get('name', f'entry_{idx}'))

    target = os.path.join(out_path, fname)
    if fname.endswith('/'):
        os.makedirs(target, exist_ok=True)
        return True

    out_dir = os.path.dirname(target)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # 大文件流式解密,避免内存爆炸
    if is_v7 and item.get('_ciphertext') and item.get('size', 0) > _STREAMING_THRESHOLD:
        key = _derive_aes_key(password, salt_bytes or b'')
        _decrypt_tokens_to_file(item['_ciphertext'], key, target, callback=progress_callback)
        return True

    data = re_decrypt(item, password, salt_bytes, legacy=not is_v7)
    with open(target, 'wb') as fh:
        fh.write(data)

    if progress_callback:
        progress_callback(1, 1)
    return True


def decrypt_kjk_to_dir(content: str, save_dir: str, password: str = '', progress_callback=None) -> int:
    """将整个 .kjk 内容流式解密到目录,保持目录层级,返回解密文件数。

    - 自动检测密码头(v7 前缀 / v5 独立条目 / pwd: 前缀)并验证密码
    - 支持 KJKv8 分块大文件流式解密,避免整文件驻留内存
    - 自动创建子目录;已存在文件自动加序号避免覆盖
    - progress_callback(current, total) 按条目回调(含当前文件内进度)
    """
    has_pwd, salt_bytes, hash_hex, actual = detect_password_prefix(content)
    results = unpack_kjk(content)
    if has_pwd:
        if not verify_password(password, salt_bytes.hex(), hash_hex):
            raise ValueError('密码错误')

    files = [r for r in results
             if not r.get('_is_password_header') and not r.get('_is_password_prefix_header')]
    if not files:
        return 0

    is_v7 = bool(salt_bytes) or all(r.get('_kjkv7') for r in files)
    total = len(files)
    decrypted = 0

    os.makedirs(save_dir, exist_ok=True)
    for i, r in enumerate(files):
        if not r.get('originalName') and r.get('enc_name'):
            try:
                name, ext = decrypt_filename(r['enc_name'], password, salt_bytes, legacy=not is_v7)
                r['originalName'] = f'{name}.{ext}' if ext else name
            except Exception:
                r['originalName'] = r.get('name', f'file_{i}')

        fname = r.get('originalName', r.get('name', f'file_{i}')).replace('\\', '/')
        if fname.endswith('/'):
            os.makedirs(os.path.join(save_dir, fname), exist_ok=True)
            if progress_callback:
                progress_callback(i + 1, total)
            continue

        target = os.path.join(save_dir, fname)
        if os.path.exists(target):
            base, ext = os.path.splitext(fname)
            n = 1
            while os.path.exists(target):
                target = os.path.join(save_dir, f'{base}_{n}{ext}')
                n += 1

        def _inner(ratio):
            if progress_callback:
                progress_callback(i + ratio, total)

        decrypt_entry_to_file(r, target, password, salt_bytes, legacy=not is_v7,
                              progress_callback=_inner)
        decrypted += 1
        time.sleep(0)

    if progress_callback:
        progress_callback(total, total)
    return decrypted


# ======================== 格式版本检测 ========================

# 兼容性映射: KJK格式版本 -> 应用版本
KJK_FORMAT_VERSION_MAP = {
    'KJKv8': '1.0.4',
    'KJKv7': '1.0.3',
    'KJKv5': '1.0.2',
    'KJKv4': '1.0.1',
    'KJKv3': '1.0.1',
    'KJKv2': '1.0.1',
    'KJKv1': '1.0.1',
}


def detect_kjk_format_version(content: str) -> str:
    """检测 .kjk 文件内容的格式版本,返回 'KJKv8', 'KJKv7', 'KJKv5' 等,或 'unknown'。

    先跳过密码头前缀 (v6/v7 格式),再检测第一行。
    """
    if not content or not content.strip():
        return 'unknown'

    # 跳过密码头前缀 (v6/v7 格式: 前缀 + 空格 + KJK内容)
    has_pwd, _, _, remaining = detect_password_prefix(content)
    if not remaining or not remaining.strip():
        return 'unknown'

    first_line = remaining.strip().split('\n')[0].strip()

    # 检查已知格式
    known_versions = ('KJKv8', 'KJKv7', 'KJKv5', 'KJKv4', 'KJKv3', 'KJKv2', 'KJKv1')
    for ver in known_versions:
        if first_line == ver:
            return ver

    # 纯密文格式 (无版本头)
    return 'plaintext'


def get_app_version_for_format(format_version: str) -> str:
    """获取指定格式版本对应的应用版本号。"""
    return KJK_FORMAT_VERSION_MAP.get(format_version, 'unknown')

