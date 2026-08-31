/* kjkfast.c — KJK Encryptor C 加速引擎 v10500
 *
 * 功能:
 *   1. token 编解码 (旧文本格式 KJKv1..v8 使用, 与 v10400 引擎二进制兼容)
 *   2. AES-256-GCM (KJKv9 二进制格式使用, Windows CNG/BCrypt 实现, 无 OpenSSL 依赖)
 *   3. SHA-256 摘要
 *   4. 多线程分页调度器 kjk_run_jobs: 大文件数据通路全 C 化
 *      (线程池 + 原子认领 + 心跳看门狗重派 + OVERLAPPED 定位读写 + 进度回调)
 *
 * 线程安全: AES 上下文按线程独立创建 (kjk_aesgcm_open/close), 无全局可变状态;
 *           token 表为只读静态表, 惰性初始化由一次性写入保证 (C11 保证静态初始化零值)。
 *
 * 编译: py -3 -m ziglang cc -O2 -shared -target x86_64-windows-gnu -lbcrypt -o kjkfast-10500.dll kjkfast.c
 *       (或 cl /O2 /LD kjkfast.c bcrypt.lib /Fe:kjkfast-10500.dll)
 * 接口由 python/engine.py (token) 与 python/kjk9.py (AES/SHA) 通过 ctypes 调用;
 * 缺失时自动回退 cryptography / numpy / 纯 Python 后端。
 *
 * 注意: token 表区域由 tools/gen_kjkfast.py 生成, 手改时勿整体重新生成本文件。
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

/* ==================================================================
 * 一、token 编解码 (旧文本格式, 与 v10400 引擎兼容)
 * ================================================================== */

/* 20 个 token 的 UTF-8 编码与字节长度 */
static const uint8_t TOKEN_UTF8[20][4] = {
    {0xE9, 0x94, 0x9F},
    {0xE6, 0x96, 0xA4},
    {0xE6, 0x8B, 0xB7},
    {0xE7, 0x83, 0xAB},
    {0xE5, 0xB1, 0xAF},
    {0xE9, 0x94, 0x98},
    {0x21},
    {0x2B},
    {0xE5, 0x95, 0x8A},
    {0xE8, 0x83, 0xA9},
    {0xE5, 0xB2, 0x90},
    {0xE9, 0x91, 0x81},
    {0xE6, 0xAD, 0xB8},
    {0xE9, 0x88, 0xAA},
    {0xE8, 0xAA, 0xB7},
    {0xE9, 0xB7, 0x96},
    {0xE7, 0xAB, 0x8A},
    {0xE8, 0x9B, 0xA6},
    {0xE5, 0x94, 0x84},
    {0xE5, 0x92, 0x9A},
};

static const uint8_t TOKEN_LEN[20] = {3, 3, 3, 3, 3, 3, 1, 1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};

/* 每个字节 → 2 个 token 的 UTF-8 序列(最长 6 字节)与总长度 */
static uint8_t PAIR_BYTES[256][6];
static uint8_t PAIR_LEN[256];

/* ASCII(1 字节) token → 序号, 0xFF 无效 */
static uint8_t ASCII_MAP[256];

/* 3 字节 UTF-8 直接查表: first byte ∈ {0xE5..0xE9} → [b0-0xE5][b1][b2] = token 序号, -1 无效 */
static int8_t MAP3[5][256][256];

static void kjk_init_tables(void)
{
    static volatile long inited = 0;
    if (inited) return;
    for (int i = 0; i < 256; i++) ASCII_MAP[i] = 0xFF;
    ASCII_MAP[0x21] = 6;
    ASCII_MAP[0x2B] = 7;
    memset(MAP3, 0xFF, sizeof(MAP3));
    for (int t = 0; t < 20; t++) {
        uint8_t b0 = TOKEN_UTF8[t][0];
        if (TOKEN_LEN[t] == 3 && b0 >= 0xE5 && b0 <= 0xE9)
            MAP3[b0 - 0xE5][TOKEN_UTF8[t][1]][TOKEN_UTF8[t][2]] = (int8_t)t;
    }
    for (int b = 0; b < 256; b++) {
        int d0 = b % 20, d1 = b / 20;
        int p = 0;
        for (int k = 0; k < TOKEN_LEN[d0]; k++) PAIR_BYTES[b][p++] = TOKEN_UTF8[d0][k];
        for (int k = 0; k < TOKEN_LEN[d1]; k++) PAIR_BYTES[b][p++] = TOKEN_UTF8[d1][k];
        PAIR_LEN[b] = (uint8_t)p;
    }
    inited = 1;
}

/* 3 字节 UTF-8 序列精确匹配 token 序号, 未命中返回 -1 */
static int kjk_lookup3(uint8_t b0, uint8_t b1, uint8_t b2)
{
    if (b0 < 0xE5 || b0 > 0xE9) return -1;
    return MAP3[b0 - 0xE5][b1][b2];
}

/* 字节 → token UTF-8 字符串。返回写入长度, 失败返回 -1。 */
__declspec(dllexport) long __cdecl kjk_bytes_to_tokens(const uint8_t *in, size_t n, uint8_t *out, size_t cap)
{
    kjk_init_tables();
    if (cap < n * 6) return -1;
    size_t p = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = in[i];
        const uint8_t *pair = PAIR_BYTES[b];
        uint8_t len = PAIR_LEN[b];
        for (uint8_t k = 0; k < len; k++) out[p++] = pair[k];
    }
    return (long)p;
}

/* token UTF-8 字符串 → 字节(忽略 ASCII 空白)。返回输出长度, 无效 token 返回 -1。 */
__declspec(dllexport) long __cdecl kjk_tokens_to_bytes(const uint8_t *in, size_t n, uint8_t *out, size_t cap)
{
    kjk_init_tables();
    if (cap < n / 2 + 1) return -1;
    size_t p = 0;
    int have = 0;
    int d = 0;
    size_t i = 0;
    while (i < n) {
        uint8_t c = in[i];
        if (c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D) { i++; continue; }
        int v;
        if (c < 0x80) {
            v = ASCII_MAP[c];
            if (v == 0xFF) return -1;
            i++;
        } else {
            if (i + 2 >= n) return -1;
            v = kjk_lookup3(c, in[i + 1], in[i + 2]);
            if (v < 0) return -1;
            i += 3;
        }
        if (have == 0) { d = v; have = 1; }
        else {
            out[p++] = (uint8_t)((d + v * 20) & 0xFF);
            have = 0;
        }
    }
    if (have != 0) return -1; /* 落单 token */
    return (long)p;
}

/* ==================================================================
 * 二、AES-256-GCM (KJKv9 二进制格式, Windows CNG/BCrypt)
 * ================================================================== */

#ifdef _WIN32

typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    uint8_t *buf[3];   /* 工作缓冲: 0=输入块 1=输出块 2=换密明文(惰性分配复用) */
    size_t cap[3];
} KJK_AES_CTX;

/* 线程私有工作缓冲: 按需增长, 跨调用复用。返回 NULL 表示内存不足。
 * 复用避免每页 2×4MB 的堆分配与需求零页清零(多线程下是主要开销)。 */
static uint8_t *kjk_ctx_buf(KJK_AES_CTX *ctx, int i, size_t need)
{
    if (ctx->cap[i] >= need) return ctx->buf[i];
    uint8_t *p = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, need);
    if (!p) return NULL;
    if (ctx->buf[i]) HeapFree(GetProcessHeap(), 0, ctx->buf[i]);
    ctx->buf[i] = p;
    ctx->cap[i] = need;
    return p;
}

/* 创建 AES-256-GCM 密钥上下文。每线程独立持有, 线程安全。
 * key: 32 字节主密钥。返回 0 成功。 */
__declspec(dllexport) long __cdecl kjk_aesgcm_open(const uint8_t *key, void **outCtx)
{
    if (!key || !outCtx) return -1;
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(KJK_AES_CTX));
    if (!ctx) return -2;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (st != 0) { HeapFree(GetProcessHeap(), 0, ctx); return (long)st; }
    st = BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE,
                           (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
        HeapFree(GetProcessHeap(), 0, ctx);
        return (long)st;
    }
    st = BCryptGenerateSymmetricKey(ctx->hAlg, &ctx->hKey, NULL, 0, (PUCHAR)key, 32, 0);
    if (st != 0) {
        BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
        HeapFree(GetProcessHeap(), 0, ctx);
        return (long)st;
    }
    *outCtx = ctx;
    return 0;
}

/* 释放 AES 上下文 */
__declspec(dllexport) long __cdecl kjk_aesgcm_close(void *p)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx) return 0;
    if (ctx->hKey) BCryptDestroyKey(ctx->hKey);
    if (ctx->hAlg) BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    for (int i = 0; i < 3; i++)
        if (ctx->buf[i]) HeapFree(GetProcessHeap(), 0, ctx->buf[i]);
    HeapFree(GetProcessHeap(), 0, ctx);
    return 0;
}

static long kjk_gcm_run(BCRYPT_KEY_HANDLE hKey, int enc,
                        const uint8_t *nonce, const uint8_t *in, size_t n,
                        uint8_t *out, uint8_t *tag)
{
    if (n > 0xFFFFFFFFu) return -3;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO ai;
    BCRYPT_INIT_AUTH_MODE_INFO(ai);
    ai.pbNonce = (PUCHAR)nonce;
    ai.cbNonce = 12;
    ai.pbTag = tag;
    ai.cbTag = 16;
    ULONG done = 0;
    NTSTATUS st;
    if (enc)
        st = BCryptEncrypt(hKey, (PUCHAR)in, (ULONG)n, &ai, NULL, 0,
                           out, (ULONG)n, &done, 0);
    else
        st = BCryptDecrypt(hKey, (PUCHAR)in, (ULONG)n, &ai, NULL, 0,
                           out, (ULONG)n, &done, 0);
    if (st != 0) return (long)st;      /* 校验失败等均返回非零 NTSTATUS */
    if (done != (ULONG)n) return -4;
    return 0;
}

/* AES-256-GCM 加密。nonce 12 字节, tag 输出 16 字节, out 容量须 ≥ n。返回 0 成功。 */
__declspec(dllexport) long __cdecl kjk_aesgcm_encrypt(void *p, const uint8_t *nonce,
                                                      const uint8_t *in, size_t n,
                                                      uint8_t *out, uint8_t *tag)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !nonce || (!in && n) || (!out && n) || !tag) return -1;
    return kjk_gcm_run(ctx->hKey, 1, nonce, in, n, out, tag);
}

/* AES-256-GCM 解密。tag 校验失败返回非零。返回 0 成功。 */
__declspec(dllexport) long __cdecl kjk_aesgcm_decrypt(void *p, const uint8_t *nonce,
                                                      const uint8_t *in, size_t n,
                                                      const uint8_t *tag, uint8_t *out)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !nonce || (!in && n) || (!out && n) || !tag) return -1;
    return kjk_gcm_run(ctx->hKey, 0, nonce, in, n, out, (uint8_t *)tag);
}

/* SHA-256 单次摘要。out32 输出 32 字节。返回 0 成功。 */
__declspec(dllexport) long __cdecl kjk_sha256(const uint8_t *in, size_t n, uint8_t *out32)
{
    if (!out32) return -1;
    if (!in && n) return -1;
    if (n > 0xFFFFFFFFu) return -3;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS st;
    ULONG objlen = 0, got = 0;
    PUCHAR obj = NULL;
    st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (st != 0) return (long)st;
    st = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                           (PUCHAR)&objlen, sizeof(objlen), &got, 0);
    if (st != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return (long)st; }
    obj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, objlen);
    if (!obj) { BCryptCloseAlgorithmProvider(hAlg, 0); return -2; }
    st = BCryptCreateHash(hAlg, &hHash, obj, objlen, NULL, 0, 0);
    if (st == 0 && n) st = BCryptHashData(hHash, (PUCHAR)in, (ULONG)n, 0);
    if (st == 0) st = BCryptFinishHash(hHash, out32, 32, 0);
    if (hHash) BCryptDestroyHash(hHash);
    HeapFree(GetProcessHeap(), 0, obj);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return (long)st;
}

/* 单块加密: in 明文 n 字节 → out=[nonce12|ct|tag16], 容量须 ≥ n+28。
 * nonce 在 C 内生成。返回 n+28, 负值为错误。 */
__declspec(dllexport) long __cdecl kjk_block_encrypt(void *p, const uint8_t *in, size_t n,
                                                     uint8_t *out)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !out || (!in && n)) return -1;
    NTSTATUS st = BCryptGenRandom(NULL, out, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) return (long)st;
    long rc = kjk_gcm_run(ctx->hKey, 1, out, in, n, out + 12, out + 12 + n);
    if (rc != 0) return rc;
    return (long)(n + 28);
}

/* 单块解密: in=[nonce12|ct|tag16] 共 n 字节 → out 明文, 容量须 ≥ n-28。
 * 返回明文长度, 负值为错误(tag 校验失败含在内)。 */
__declspec(dllexport) long __cdecl kjk_block_decrypt(void *p, const uint8_t *in, size_t n,
                                                     uint8_t *out)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !in || !out || n < 28) return -1;
    size_t ct = n - 28;
    long rc = kjk_gcm_run(ctx->hKey, 0, in, in + 12, ct, out, (uint8_t *)in + n - 16);
    if (rc != 0) return rc;
    return (long)ct;
}

/* 整页加密: in 明文 n 字节按 blocksz 分块 → out 顺序拼接 [nonce|ct|tag]*,
 * 容量须 ≥ n + ceil(n/blocksz)*28。返回输出总字节数, 负值为错误。
 * 整页一次 C 调用, 避免 Python 侧逐块拷贝占用 GIL。 */
__declspec(dllexport) long __cdecl kjk_page_encrypt(void *p, const uint8_t *in, size_t n,
                                                    uint8_t *out, size_t cap, size_t blocksz)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !out || (!in && n)) return -1;
    if (blocksz == 0) return -2;
    size_t nb = (n + blocksz - 1) / blocksz;
    if (nb > 0xFFFFFFFFu) return -3;
    if (cap < n + nb * 28) return -5;
    uint8_t *w = out;
    const uint8_t *r = in;
    size_t left = n;
    while (left > 0) {
        size_t take = left < blocksz ? left : blocksz;
        NTSTATUS st = BCryptGenRandom(NULL, w, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (st != 0) return (long)st;
        long rc = kjk_gcm_run(ctx->hKey, 1, w, r, take, w + 12, w + 12 + take);
        if (rc != 0) return rc;
        w += 12 + take + 16;
        r += take;
        left -= take;
    }
    return (long)(w - out);
}

/* 整页解密: in=[nonce|ct|tag]* 共 n 字节按 blocksz 还原 → out 明文,
 * 容量须 ≥ n - ceil(n/(blocksz+28))*28 之上限(传 n 即可)。
 * 返回明文总长度, 负值为错误。 */
__declspec(dllexport) long __cdecl kjk_page_decrypt(void *p, const uint8_t *in, size_t n,
                                                    uint8_t *out, size_t cap, size_t blocksz)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !out || !in) return -1;
    if (blocksz == 0) return -2;
    if (n > 0xFFFFFFFFu) return -3;
    const uint8_t *r = in;
    const uint8_t *end = in + n;
    uint8_t *w = out;
    while (r < end) {
        size_t rem = (size_t)(end - r);
        if (rem < 28) return -4;
        size_t take = rem >= blocksz + 28 ? blocksz : rem - 28;
        if ((size_t)(w - out) + take > cap) return -5;
        long rc = kjk_gcm_run(ctx->hKey, 0, r, r + 12, take, w, (uint8_t *)r + 12 + take);
        if (rc != 0) return rc;
        w += take;
        r += 12 + take + 16;
    }
    return (long)(w - out);
}

/* ---------- 数据通路全 C: 定位读写 ---------- */

static int kjk_seek(HANDLE h, uint64_t off)
{
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)off;
    return SetFilePointerEx(h, li, NULL, FILE_BEGIN) ? 0 : -1;
}

static int kjk_read_at(HANDLE h, uint64_t off, void *buf, size_t n)
{
    if (kjk_seek(h, off) != 0) return -1;
    uint8_t *w = (uint8_t *)buf;
    while (n > 0) {
        DWORD take = n > 0x40000000u ? 0x40000000u : (DWORD)n, got = 0;
        if (!ReadFile(h, w, take, &got, NULL) || got != take) return -2;
        w += got;
        n -= got;
    }
    return 0;
}

static int kjk_write_at(HANDLE h, uint64_t off, const void *buf, size_t n)
{
    if (kjk_seek(h, off) != 0) return -1;
    const uint8_t *r = (const uint8_t *)buf;
    while (n > 0) {
        DWORD take = n > 0x40000000u ? 0x40000000u : (DWORD)n, got = 0;
        if (!WriteFile(h, r, take, &got, NULL) || got != take) return -2;
        r += got;
        n -= got;
    }
    return 0;
}

/* 整页加密直写: 从 hIn 偏移 inOff 读 n 字节明文 → 按 blocksz 分块加密 →
 * 顺序写入 hOut 偏移 outOff ([nonce12|ct|tag16]* 布局)。
 * C 内部按块流式处理, 每线程内存恒为 2*(blocksz+28)。
 * 返回写入总字节数, 负值为错误。hIn/hOut 须为各线程私有句柄。 */
__declspec(dllexport) long __cdecl kjk_run_encrypt_io(void *p, void *hIn, uint64_t inOff,
                                                      void *hOut, uint64_t outOff,
                                                      size_t n, size_t blocksz)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !hIn || !hOut || blocksz == 0) return -1;
    if (n > 0xFFFFFFFFu) return -2;
    uint8_t *ib = kjk_ctx_buf(ctx, 0, blocksz);
    uint8_t *ob = kjk_ctx_buf(ctx, 1, blocksz + 28);
    if (!ib || !ob) return -3;
    uint64_t ip = inOff, op = outOff;
    size_t left = n;
    long written = 0;
    long rc = 0;
    while (left > 0) {
        size_t take = left < blocksz ? left : blocksz;
        if (kjk_read_at((HANDLE)hIn, ip, ib, take) != 0) { rc = -4; break; }
        long r = kjk_block_encrypt(ctx, ib, take, ob);
        if (r < 0) { rc = r; break; }
        if (kjk_write_at((HANDLE)hOut, op, ob, (size_t)r) != 0) { rc = -5; break; }
        ip += take;
        op += (uint64_t)r;
        left -= take;
        written += r;
    }
    return rc != 0 ? rc : written;
}

/* 整页解密直写: 从 hIn 偏移 inOff 读 n 字节密文([nonce12|ct|tag16]*, 须为整块数)
 * → 解密 → 顺序写入 hOut 偏移 outOff。返回写入明文总字节数, 负值为错误。 */
__declspec(dllexport) long __cdecl kjk_run_decrypt_io(void *p, void *hIn, uint64_t inOff,
                                                      void *hOut, uint64_t outOff,
                                                      size_t n, size_t blocksz)
{
    KJK_AES_CTX *ctx = (KJK_AES_CTX *)p;
    if (!ctx || !hIn || !hOut || blocksz == 0 || n == 0) return -1;
    if (n > 0xFFFFFFFFu) return -2;
    uint8_t *ib = kjk_ctx_buf(ctx, 0, blocksz + 28);
    uint8_t *ob = kjk_ctx_buf(ctx, 1, blocksz);
    if (!ib || !ob) return -3;
    uint64_t ip = inOff, op = outOff;
    size_t left = n;
    long written = 0;
    long rc = 0;
    while (left > 0) {
        size_t rem = left >= blocksz + 28 ? (size_t)blocksz + 28 : left;
        if (kjk_read_at((HANDLE)hIn, ip, ib, rem) != 0) { rc = -4; break; }
        long r = kjk_block_decrypt(ctx, ib, rem, ob);
        if (r < 0) { rc = r; break; }
        if (kjk_write_at((HANDLE)hOut, op, ob, (size_t)r) != 0) { rc = -5; break; }
        ip += rem;
        op += (uint64_t)r;
        left -= rem;
        written += r;
    }
    return rc != 0 ? rc : written;
}

/* 换密重加密直写: 同一文件内, 用旧密钥解密 inOff 处 n 字节密文,
 * 再以新密钥加密写入 outOff。返回写入密文总字节数, 负值为错误。
 * 两区域不得重叠。 */
__declspec(dllexport) long __cdecl kjk_run_rekey_io(void *pOld, void *pNew, void *h,
                                                    uint64_t inOff, uint64_t outOff,
                                                    size_t n, size_t blocksz)
{
    KJK_AES_CTX *old = (KJK_AES_CTX *)pOld;
    KJK_AES_CTX *neu = (KJK_AES_CTX *)pNew;
    if (!old || !neu || !h || blocksz == 0 || n == 0) return -1;
    if (n > 0xFFFFFFFFu) return -2;
    uint8_t *ib = kjk_ctx_buf(old, 0, blocksz + 28);
    uint8_t *ob = kjk_ctx_buf(old, 1, blocksz + 28);
    uint8_t *plain = kjk_ctx_buf(old, 2, blocksz);
    if (!ib || !ob || !plain) return -3;
    uint64_t ip = inOff, op = outOff;
    size_t left = n;
    long written = 0;
    long rc = 0;
    while (left > 0) {
        size_t rem = left >= blocksz + 28 ? (size_t)blocksz + 28 : left;
        if (kjk_read_at((HANDLE)h, ip, ib, rem) != 0) { rc = -4; break; }
        long pl = kjk_block_decrypt(old, ib, rem, plain);
        if (pl < 0) { rc = pl; break; }
        long cl = kjk_block_encrypt(neu, plain, (size_t)pl, ob);
        if (cl < 0) { rc = cl; break; }
        if (kjk_write_at((HANDLE)h, op, ob, (size_t)cl) != 0) { rc = -5; break; }
        ip += rem;
        op += (uint64_t)cl;
        left -= rem;
        written += cl;
    }
    return rc != 0 ? rc : written;
}

#endif /* _WIN32 */

/* ==================================================================
 * 四、多线程分页调度器 (大文件数据通路全 C 化)
 *
 * Python 一次 ctypes 调用提交全部分页任务, C 内部完成全部调度与 I/O:
 *   - 线程池(低优先级, 为系统预留性能): 每线程独立 AES 上下文与工作缓冲
 *   - 原子认领: CAS 状态机 PENDING→RUNNING→DONE, 自然负载均衡
 *   - 心跳看门狗: RUNNING 且心跳超时 → 重回队列由其他线程接管, 避免死等
 *   - OVERLAPPED 定位读写: 每文件仅开一个句柄, 全线程共享且无 seek 竞争
 *   - 进度回调仅在调用者线程执行(线程安全), 支持取消; 完成位图供断点续传
 * 每线程内存恒为 2~3 × 块大小(按块流式), 与页大小无关。
 * ================================================================== */

#ifdef _WIN32

#pragma pack(push, 8)
typedef struct {
    uint64_t inOff;   /* 输入偏移: 加密=明文源; 解密/换密=密文 */
    uint64_t outOff;  /* 输出偏移 */
    uint64_t n;       /* 本任务字节数(与 inOff 同侧语义) */
    uint64_t weight;  /* 进度权重(字节) */
    uint32_t inIdx;   /* ins[] 下标 */
    uint32_t outIdx;  /* outs[] 下标 */
} KJK_JOB;
#pragma pack(pop)

/* 进度回调: 仅在调用者线程执行。返回非 0 → 请求取消。 */
typedef int (__cdecl *KJK_PROG_CB)(void *ud, double frac, uint32_t done, uint32_t total);

/* 任务状态: 高 62 位 = 心跳毫秒值, 低 2 位 = 相位 */
#define JK_PENDING 0LL
#define JK_RUNNING 1LL
#define JK_DONE    2LL

/* 页处理返回: 0 成功; KJK_STOP=被取消/中止; 正数=错误类 */
#define KJK_STOP (-1000)
/* 错误类: 1=GCM校验失败 2=读失败 3=写失败 4=打开输入失败 5=打开输出失败
 *         6=内存/上下文 7=内部 8=参数 9=未完成 */

typedef struct {
    int mode;                        /* 0=加密 1=解密 2=换密 */
    const KJK_JOB *jobs;
    uint32_t nJobs;
    HANDLE *ins;
    uint32_t nIn;
    HANDLE *outs;
    uint32_t nOut;
    uint8_t key[32];
    uint8_t key2[32];
    size_t blocksz;
    uint32_t *doneBits;              /* 位图: 任务完成置位(断点续传用) */
    volatile LONG64 *st;             /* 每任务原子状态 */
    volatile LONG *fin;              /* 每任务完成标记(防重复计数) */
    volatile LONG nPending, nRunning, doneJobs, nAlive;
    volatile LONG64 doneWeight, totalWeight;
    volatile LONG stop, cancel, errCls, errIdx;
    HANDLE doneEvt;
    HANDLE *ths;
    uint32_t nThs;
} KJK_RUN;

typedef struct {
    KJK_RUN *g;
    HANDLE ev;                       /* 本线程 OVERLAPPED 等待事件 */
    KJK_AES_CTX *ctxA;               /* 主密钥 */
    KJK_AES_CTX *ctxB;               /* 换密: 新密钥 */
    uint32_t cursor;                 /* 认领扫描游标 */
} KJK_WORKER;

static void kjk_seterr(KJK_RUN *g, LONG cls, LONG idx)
{
    if (InterlockedCompareExchange(&g->errCls, cls, 0) == 0)
        InterlockedExchange(&g->errIdx, idx);
}

static void kjk_beat(KJK_RUN *g, uint32_t j)
{
    g->st[j] = ((LONG64)(int64_t)GetTickCount64() << 2) | JK_RUNNING;
}

/* OVERLAPPED 定位读写: 偏移在 OVERLAPPED 内, 句柄可全线程共享, 无 seek 竞争 */
static int kjk_ov(HANDLE h, uint64_t off, void *buf, size_t n, int wr, HANDLE ev)
{
    uint8_t *p = (uint8_t *)buf;
    while (n > 0) {
        DWORD take = n > 0x40000000u ? 0x40000000u : (DWORD)n, got = 0;
        OVERLAPPED ov;
        memset(&ov, 0, sizeof(ov));
        ov.Offset = (DWORD)(off & 0xFFFFFFFFULL);
        ov.OffsetHigh = (DWORD)(off >> 32);
        ov.hEvent = ev;
        BOOL ok = wr ? WriteFile(h, p, take, &got, &ov)
                     : ReadFile(h, p, take, &got, &ov);
        if (!ok) {
            if (GetLastError() != ERROR_IO_PENDING) return -1;
            if (!GetOverlappedResult(h, &ov, &got, TRUE)) return -1;
        }
        if (got != take) return -1;
        p += got;
        n -= got;
        off += got;
    }
    return 0;
}

static long kjk_claim(KJK_RUN *g, uint32_t *cursor)
{
    uint32_t n = g->nJobs, start = *cursor;
    for (uint32_t k = 0; k < n; k++) {
        uint32_t j = (start + k) % n;
        LONG64 s = g->st[j];
        if ((s & 3) != JK_PENDING) continue;
        LONG64 want = ((LONG64)(int64_t)GetTickCount64() << 2) | JK_RUNNING;
        if (InterlockedCompareExchange64(&g->st[j], want, s) == s) {
            InterlockedDecrement(&g->nPending);
            InterlockedIncrement(&g->nRunning);
            *cursor = j + 1;
            return (long)j;
        }
    }
    return -1;
}

static void kjk_finish_job(KJK_RUN *g, uint32_t j)
{
    LONG64 s = g->st[j];
    /* 尽力标记 DONE(可能已被看门狗重派, 失败无妨 — fin 防重复计数) */
    InterlockedCompareExchange64(&g->st[j], (s & ~3LL) | JK_DONE, s);
    InterlockedDecrement(&g->nRunning);
    if (InterlockedCompareExchange(&g->fin[j], 1, 0) == 0) {
        LONG d = InterlockedIncrement(&g->doneJobs);
        InterlockedAdd64(&g->doneWeight, (LONG64)g->jobs[j].weight);
        if (g->doneBits)
            InterlockedOr((volatile LONG *)&g->doneBits[j >> 5], 1L << (j & 31));
        if (d >= (LONG)g->nJobs) SetEvent(g->doneEvt);
    }
}

static void kjk_watchdog(KJK_RUN *g)
{
    ULONGLONG now = GetTickCount64();
    for (uint32_t j = 0; j < g->nJobs; j++) {
        LONG64 s = g->st[j];
        if ((s & 3) != JK_RUNNING) continue;
        uint64_t hb = (uint64_t)(s >> 2);
        if (hb == 0) continue;
        uint64_t to = 120000 + g->jobs[j].n * 2500 / 1048576; /* ≥120s + 2.5s/MB */
        if (now < hb + to) continue;
        LONG64 want = ((LONG64)(int64_t)now << 2) | JK_PENDING;
        if (InterlockedCompareExchange64(&g->st[j], want, s) == s) {
            InterlockedDecrement(&g->nRunning);
            InterlockedIncrement(&g->nPending);
        }
    }
}

/* 加密页: inOff 明文 → 按 blocksz 分块加密 → outOff ([nonce12|ct|tag16]*) */
static int kjk_page_enc_w(KJK_WORKER *w, const KJK_JOB *j, uint32_t idx)
{
    KJK_RUN *g = w->g;
    HANDLE hi = g->ins[j->inIdx], ho = g->outs[j->outIdx];
    size_t bs = g->blocksz;
    uint8_t *ib = kjk_ctx_buf(w->ctxA, 0, bs);
    uint8_t *ob = kjk_ctx_buf(w->ctxA, 1, bs + 28);
    if (!ib || !ob) return 6;
    uint64_t ip = j->inOff, op = j->outOff;
    size_t left = (size_t)j->n;
    while (left > 0) {
        if (g->stop) return KJK_STOP;
        size_t take = left < bs ? left : bs;
        if (kjk_ov(hi, ip, ib, take, 0, w->ev) != 0) return 2;
        long r = kjk_block_encrypt(w->ctxA, ib, take, ob);
        if (r < 0) return 1;
        if (kjk_ov(ho, op, ob, (size_t)r, 1, w->ev) != 0) return 3;
        ip += take;
        op += (uint64_t)r;
        left -= take;
        kjk_beat(g, idx);
    }
    return 0;
}

/* 解密页: inOff 密文([nonce|ct|tag]*, 整块数) → 解密 → outOff 明文 */
static int kjk_page_dec_w(KJK_WORKER *w, const KJK_JOB *j, uint32_t idx)
{
    KJK_RUN *g = w->g;
    HANDLE hi = g->ins[j->inIdx], ho = g->outs[j->outIdx];
    size_t bs = g->blocksz;
    uint8_t *ib = kjk_ctx_buf(w->ctxA, 0, bs + 28);
    uint8_t *ob = kjk_ctx_buf(w->ctxA, 1, bs);
    if (!ib || !ob) return 6;
    uint64_t ip = j->inOff, op = j->outOff;
    size_t left = (size_t)j->n;
    while (left > 0) {
        if (g->stop) return KJK_STOP;
        size_t rem = left >= bs + 28 ? bs + 28 : left;
        if (kjk_ov(hi, ip, ib, rem, 0, w->ev) != 0) return 2;
        long r = kjk_block_decrypt(w->ctxA, ib, rem, ob);
        if (r < 0) return 1;
        if (kjk_ov(ho, op, ob, (size_t)r, 1, w->ev) != 0) return 3;
        ip += rem;
        op += (uint64_t)r;
        left -= rem;
        kjk_beat(g, idx);
    }
    return 0;
}

/* 换密页: 旧密钥解密 inOff 处密文 → 新密钥加密 → 写入 outOff。
 * 两区域不重叠(换密写文件尾追加的新区域)。 */
static int kjk_page_rekey_w(KJK_WORKER *w, const KJK_JOB *j, uint32_t idx)
{
    KJK_RUN *g = w->g;
    HANDLE hi = g->ins[j->inIdx], ho = g->outs[j->outIdx];
    size_t bs = g->blocksz;
    uint8_t *ib = kjk_ctx_buf(w->ctxA, 0, bs + 28);
    uint8_t *ob = kjk_ctx_buf(w->ctxA, 1, bs + 28);
    uint8_t *pl = kjk_ctx_buf(w->ctxA, 2, bs);
    if (!ib || !ob || !pl) return 6;
    uint64_t ip = j->inOff, op = j->outOff;
    size_t left = (size_t)j->n;
    while (left > 0) {
        if (g->stop) return KJK_STOP;
        size_t rem = left >= bs + 28 ? bs + 28 : left;
        if (kjk_ov(hi, ip, ib, rem, 0, w->ev) != 0) return 2;
        long p = kjk_block_decrypt(w->ctxA, ib, rem, pl);
        if (p < 0) return 1;
        long c = kjk_block_encrypt(w->ctxB, pl, (size_t)p, ob);
        if (c < 0) return 1;
        if (kjk_ov(ho, op, ob, (size_t)c, 1, w->ev) != 0) return 3;
        ip += rem;
        op += (uint64_t)c;
        left -= rem;
        kjk_beat(g, idx);
    }
    return 0;
}

static DWORD WINAPI kjk_worker_proc(LPVOID param)
{
    KJK_WORKER *w = (KJK_WORKER *)param;
    KJK_RUN *g = w->g;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
    w->ev = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!w->ev) {
        kjk_seterr(g, 6, -1);
        g->stop = 1;
    } else if (kjk_aesgcm_open(g->key, (void **)&w->ctxA) != 0) {
        kjk_seterr(g, 6, -1);
        g->stop = 1;
    } else if (g->mode == 2 && kjk_aesgcm_open(g->key2, (void **)&w->ctxB) != 0) {
        kjk_seterr(g, 6, -1);
        g->stop = 1;
    }
    while (!g->stop) {
        long j = kjk_claim(g, &w->cursor);
        if (j < 0) {
            if (g->doneJobs >= (LONG)g->nJobs) break;
            if (g->nPending <= 0 && g->nRunning <= 0) break;
            Sleep(15);
            continue;
        }
        const KJK_JOB *job = &g->jobs[j];
        int rc;
        if (g->mode == 0)      rc = kjk_page_enc_w(w, job, (uint32_t)j);
        else if (g->mode == 1) rc = kjk_page_dec_w(w, job, (uint32_t)j);
        else                   rc = kjk_page_rekey_w(w, job, (uint32_t)j);
        if (rc == KJK_STOP) break;                 /* 取消/中止, 放弃本页 */
        if (rc != 0) { kjk_seterr(g, rc, j); g->stop = 1; break; }
        kjk_finish_job(g, (uint32_t)j);
    }
    if (w->ctxA) kjk_aesgcm_close(w->ctxA);
    if (w->ctxB) kjk_aesgcm_close(w->ctxB);
    if (w->ev) CloseHandle(w->ev);
    InterlockedDecrement(&g->nAlive);
    HeapFree(GetProcessHeap(), 0, w);
    return 0;
}

static void kjk_run_cleanup(KJK_RUN *g)
{
    if (g->ins) {
        for (uint32_t i = 0; i < g->nIn; i++)
            if (g->ins[i] && g->ins[i] != INVALID_HANDLE_VALUE) CloseHandle(g->ins[i]);
        HeapFree(GetProcessHeap(), 0, g->ins);
    }
    if (g->outs) {
        for (uint32_t i = 0; i < g->nOut; i++)
            if (g->outs[i] && g->outs[i] != INVALID_HANDLE_VALUE) CloseHandle(g->outs[i]);
        HeapFree(GetProcessHeap(), 0, g->outs);
    }
    if (g->ths) {
        for (uint32_t i = 0; i < g->nThs; i++)
            if (g->ths[i]) CloseHandle(g->ths[i]);
        HeapFree(GetProcessHeap(), 0, g->ths);
    }
    if (g->doneEvt) CloseHandle(g->doneEvt);
    if (g->st) HeapFree(GetProcessHeap(), 0, (void *)g->st);
    if (g->fin) HeapFree(GetProcessHeap(), 0, (void *)g->fin);
    HeapFree(GetProcessHeap(), 0, g);
}

/* 调度入口。返回: 0=成功 1=已取消 负值=错误(详情见 errInfo = 类*1000000+索引)。
 * key/key2: 32 字节主/新密钥; mode: 0=加密 1=解密 2=换密。
 * ins/outs: 输入(只读共享)/输出(写入)文件路径表; outTruncate: 输出是否截断重建。
 * jobs: 分页任务数组; doneBits: 完成位图(调用方分配并清零, 可为 NULL)。
 * cb: 进度回调(仅调用者线程, 返回非 0 取消); ud: 回调用户数据。 */
__declspec(dllexport) long __cdecl kjk_run_jobs(
    const uint8_t *key, const uint8_t *key2,
    const wchar_t **inPaths, uint32_t nIn,
    const wchar_t **outPaths, uint32_t nOut, int outTruncate,
    const KJK_JOB *jobs, uint32_t nJobs, uint32_t threads, int mode,
    uint32_t *doneBits, long *errInfo,
    KJK_PROG_CB cb, void *ud)
{
    if (errInfo) *errInfo = 0;
    if (!key || !inPaths || nIn == 0 || !outPaths || nOut == 0 || !jobs) {
        if (errInfo) *errInfo = 8000000;
        return -16;
    }
    if (nJobs == 0) {
        if (cb) cb(ud, 1.0, 0, 0);
        return 0;
    }
    if (mode < 0 || mode > 2 || (mode == 2 && !key2)) {
        if (errInfo) *errInfo = 8000001;
        return -16;
    }
    for (uint32_t j = 0; j < nJobs; j++) {
        if (jobs[j].inIdx >= nIn || jobs[j].outIdx >= nOut
                || jobs[j].n > 0xFFFFFFFFULL) {
            if (errInfo) *errInfo = 8000000 + j;
            return -16;
        }
    }

    HANDLE heap = GetProcessHeap();
    KJK_RUN *g = (KJK_RUN *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(KJK_RUN));
    if (!g) { if (errInfo) *errInfo = 6000000; return -15; }
    g->jobs = jobs;
    g->nJobs = nJobs;
    g->mode = mode;
    g->blocksz = 4u * 1024 * 1024;
    g->doneBits = doneBits;
    memcpy(g->key, key, 32);
    if (mode == 2) memcpy(g->key2, key2, 32);
    for (uint32_t j = 0; j < nJobs; j++)
        g->totalWeight += (LONG64)jobs[j].weight;

    g->ins = (HANDLE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(HANDLE) * nIn);
    g->outs = (HANDLE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(HANDLE) * nOut);
    g->st = (volatile LONG64 *)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                         sizeof(LONG64) * nJobs);
    g->fin = (volatile LONG *)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                        sizeof(LONG) * nJobs);
    if (!g->ins || !g->outs || !g->st || !g->fin) {
        kjk_run_cleanup(g);
        if (errInfo) *errInfo = 6000001;
        return -15;
    }
    g->nIn = nIn;   /* cleanup 需按已开数量关闭, 先行设置 */
    g->nOut = nOut;

    for (uint32_t i = 0; i < nIn; i++) {
        g->ins[i] = CreateFileW(inPaths[i], GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
        if (g->ins[i] == INVALID_HANDLE_VALUE) {
            kjk_seterr(g, 4, (LONG)i);
            if (errInfo) *errInfo = 4000000 + (LONG)i;
            kjk_run_cleanup(g);
            return -10;
        }
    }
    for (uint32_t i = 0; i < nOut; i++) {
        g->outs[i] = CreateFileW(outPaths[i], GENERIC_WRITE, FILE_SHARE_READ,
                                 NULL, outTruncate ? CREATE_ALWAYS : OPEN_ALWAYS,
                                 FILE_FLAG_OVERLAPPED, NULL);
        if (g->outs[i] == INVALID_HANDLE_VALUE) {
            kjk_seterr(g, 5, (LONG)i);
            if (errInfo) *errInfo = 5000000 + (LONG)i;
            kjk_run_cleanup(g);
            return -11;
        }
    }

    uint32_t nth = threads ? threads : 1;
    if (nth > 64) nth = 64;
    if (nth > nJobs) nth = nJobs;
    g->ths = (HANDLE *)HeapAlloc(heap, HEAP_ZERO_MEMORY, sizeof(HANDLE) * nth);
    g->doneEvt = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g->ths || !g->doneEvt) {
        kjk_run_cleanup(g);
        if (errInfo) *errInfo = 6000002;
        return -15;
    }
    g->nPending = (LONG)nJobs;
    g->errIdx = -1;
    g->nAlive = (LONG)nth;
    g->nThs = 0;
    for (uint32_t k = 0; k < nth; k++) {
        KJK_WORKER *w = (KJK_WORKER *)HeapAlloc(heap, HEAP_ZERO_MEMORY,
                                               sizeof(KJK_WORKER));
        if (!w) { InterlockedDecrement(&g->nAlive); continue; }
        w->g = g;
        HANDLE t = CreateThread(NULL, 0, kjk_worker_proc, w, 0, NULL);
        if (!t) {
            InterlockedDecrement(&g->nAlive);
            HeapFree(heap, 0, w);
            continue;
        }
        g->ths[g->nThs++] = t;
    }
    if (g->nThs == 0) {
        kjk_run_cleanup(g);
        if (errInfo) *errInfo = 7000000;
        return -17;
    }

    /* 调用者线程 = 看门狗 + 进度回调(唯一回调来源, 线程安全) */
    ULONGLONG lastCb = GetTickCount64();
    if (cb && cb(ud, 0.0, 0, nJobs)) {
        g->cancel = 1;
        g->stop = 1;
    }
    while (!g->stop) {
        if (g->doneJobs >= (LONG)nJobs) break;
        if (WaitForSingleObject(g->doneEvt, 20) == WAIT_OBJECT_0) break;
        kjk_watchdog(g);
        if (g->nAlive == 0) break;   /* 线程全退出(错误路径已设 stop) */
        if (cb) {
            ULONGLONG now = GetTickCount64();
            if (now - lastCb >= 100) {
                lastCb = now;
                double frac = g->totalWeight > 0
                    ? (double)(uint64_t)g->doneWeight / (double)(uint64_t)g->totalWeight
                    : 0.0;
                if (frac > 1.0) frac = 1.0;
                if (cb(ud, frac, (uint32_t)g->doneJobs, nJobs)) {
                    g->cancel = 1;
                    g->stop = 1;
                    break;
                }
            }
        }
    }

    /* 等工作线程退出; 卡死线程不关句柄直接泄漏, 避免竞态崩溃 */
    int joined = 1;
    for (uint32_t k = 0; k < g->nThs; k++) {
        if (WaitForSingleObject(g->ths[k], 15000) != WAIT_OBJECT_0) {
            joined = 0;
            break;
        }
    }

    long ret = 0;
    if (g->errCls) {
        if (errInfo) *errInfo = g->errCls * 1000000L + g->errIdx;
        ret = -30;
    } else if (g->cancel) {
        ret = 1;
    } else if (g->doneJobs < (LONG)nJobs) {
        if (errInfo) *errInfo = 9000000;
        ret = -31;
    } else if (!joined) {
        if (errInfo) *errInfo = 7000001;
        ret = -32;
    } else if (cb) {
        if (cb(ud, 1.0, nJobs, nJobs)) {
            /* 收尾回调要求取消(用户恰在最后一刻取消/测试故障注入):
             * 数据页已写完但调用方视为中断, 由其决定续传或放弃 */
            ret = 1;
        }
    }
    if (!joined) return ret;   /* 仍有线程在使用句柄, 泄漏以避免崩溃 */
    kjk_run_cleanup(g);
    return ret;
}

#endif /* _WIN32 */

/* 引擎版本号, 便于 Python 侧探测。10500 = v1.0.5(KJKv9 AES-GCM) */
__declspec(dllexport) long __cdecl kjkfast_version(void) { return 10500; }
