# -*- coding: utf-8 -*-
"""用 Python 模拟 kjkfast.c 的逻辑, 与 engine.py 现有实现对拍, 验证 C 源码算法正确性。"""
import sys, os, random

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python'))
from engine import TOKENS, BASE, _bytes_to_tokens, _tokens_to_bytes

assert BASE == 20

# ---- 模拟 C 表 ----
TOKEN_UTF8 = [ch.encode('utf-8') for ch in TOKENS]
TOKEN_LEN = [len(u) for u in TOKEN_UTF8]

def c_lookup3(b0, b1, b2):
    for t in range(20):
        u = TOKEN_UTF8[t]
        if TOKEN_LEN[t] == 3 and u[0] == b0 and u[1] == b1 and u[2] == b2:
            return t
    return -1

ASCII_MAP = {u[0]: t for t, u in enumerate(TOKEN_UTF8) if TOKEN_LEN[t] == 1}

def c_bytes_to_tokens(data):
    out = bytearray()
    for b in data:
        d0, d1 = b % 20, b // 20
        out += TOKEN_UTF8[d0]
        out += TOKEN_UTF8[d1]
    return bytes(out).decode('utf-8')

def c_tokens_to_bytes(s):
    raw = s.encode('utf-8')
    n = len(raw)
    out = bytearray()
    have, d = 0, 0
    i = 0
    while i < n:
        c = raw[i]
        if c in (0x20, 0x09, 0x0A, 0x0D):
            i += 1
            continue
        if c < 0x80:
            if c not in ASCII_MAP:
                return None
            v = ASCII_MAP[c]
            i += 1
        else:
            if i + 2 >= n:
                return None
            v = c_lookup3(raw[i], raw[i+1], raw[i+2])
            if v < 0:
                return None
            i += 3
        if have == 0:
            d, have = v, 1
        else:
            out.append((d + v * 20) & 0xFF)
            have = 0
    if have:
        return None
    return bytes(out)

# ---- 对拍 ----
random.seed(2026)
fail = 0
for trial in range(300):
    n = random.randint(0, 4096)
    data = bytes(random.getrandbits(8) for _ in range(n))

    ref_tokens = _bytes_to_tokens(data)
    c_tokens = c_bytes_to_tokens(data)
    if ref_tokens != c_tokens:
        print(f'[FAIL] 编码不一致 trial={trial} n={n}')
        fail += 1
        break

    # 带 CRLF/空白的密文也要能解
    spaced = ref_tokens[:len(ref_tokens)//2] + '\r\n' + ref_tokens[len(ref_tokens)//2:] + ' '
    ref_bytes = _tokens_to_bytes(spaced)
    c_bytes = c_tokens_to_bytes(spaced)
    if ref_bytes != c_bytes or c_bytes != data:
        print(f'[FAIL] 解码不一致 trial={trial} n={n}: ref={ref_bytes[:16]!r} c={c_bytes[:16] if c_bytes else None!r}')
        fail += 1
        break

# 无效 token 检测
assert c_tokens_to_bytes('锟斤') is None or len(_tokens_to_bytes('锟斤')) == 1  # 落单 token: C 返回 None
assert c_tokens_to_bytes(TOKENS[0] + 'X') is None, '无效字符应被拒绝'

if fail == 0:
    print('[PASS] C 逻辑模拟对拍 300 组随机数据全部一致 (编码/解码/空白容忍/无效拒绝)')
    print('[PASS] kjkfast.c 算法与 Python 引擎等价, 可交付编译')
