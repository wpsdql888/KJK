# -*- coding: utf-8 -*-
"""KJK-Encryptor - PyInstaller 打包脚本"""

import os
import re
import sys
import shutil
import subprocess
import time
import zipfile


def kjkfast_dll_name():
    """从 kjkfast.c 源码中的 kjkfast_version() 返回版本号, 生成版本化 DLL 名。
    例如版本 10500 → kjkfast-10500.dll, 与 engine.py 的版本降序选择逻辑对应。"""
    try:
        with open('kjkfast.c', encoding='utf-8') as f:
            m = re.search(r'kjkfast_version\s*\([^)]*\)\s*\{\s*return\s+(\d+)\s*;', f.read())
            if m:
                return f'kjkfast-{m.group(1)}.dll'
    except OSError:
        pass
    return 'kjkfast-10400.dll'


def png_to_ico(png_path, ico_path):
    """将 PNG 图标转换为 ICO 格式。"""
    try:
        from PIL import Image
        img = Image.open(png_path)
        sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        img.save(ico_path, format='ICO', sizes=sizes)
        return True
    except Exception as e:
        print(f'图标转换失败: {e}')
        return False


def build_kjkfast():
    """编译 C 加速引擎到 engine/ 插件目录, 版本化命名 kjkfast-<ver>.dll。

    多目录插件架构: 历代引擎 DLL 可共存于 engine/ 文件夹,
    运行时由 engine.py 按版本降序自动选择最新可用者。
    无编译器时回退: 复用已存在的引擎 DLL, 再不行用 numpy/纯 Python。"""
    src = 'kjkfast.c'
    if not os.path.exists(src):
        return None
    engine_dir = 'engine'
    os.makedirs(engine_dir, exist_ok=True)
    dll_name = kjkfast_dll_name()   # 与 kjkfast.c 内 kjkfast_version() 返回版本对应
    dll = os.path.join(engine_dir, dll_name)
    candidates = [
        ['gcc', '-O2', '-shared', '-o', dll, src],
        ['clang', '-O2', '-shared', '-o', dll, src],
        ['zig', 'cc', '-O2', '-shared', '-o', dll, src],
        ['tcc', '-shared', '-o', dll, src],
        ['py', '-3', '-m', 'ziglang', 'cc', '-O2', '-shared', '-o', dll, src],
    ]
    for cmd in candidates:
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=180)
            if r.returncode == 0 and os.path.exists(dll):
                print(f'C 加速引擎已编译: {dll} ({cmd[0]})')
                return dll
        except (OSError, subprocess.TimeoutExpired):
            continue
    if os.path.exists(dll):
        print(f'C 编译器不可用, 复用已有的 {dll}')
        return dll
    legacy = 'kjkfast.dll'
    if os.path.exists(legacy):
        import shutil
        shutil.copy2(legacy, dll)
        print(f'C 编译器不可用, 从 {legacy} 升级为插件 {dll}')
        return dll
    print('未检测到 C 编译器(gcc/clang/zig/tcc), 使用 numpy 向量化后端')
    return None


# 确保在脚本所在目录运行
os.chdir(os.path.dirname(os.path.abspath(__file__)))

kjkfast_dll = build_kjkfast()

# 图标处理
png_icon = os.path.join('icon', 'icon.png')
ico_icon = os.path.join('icon', 'icon.ico')

if os.path.exists(png_icon) and not os.path.exists(ico_icon):
    if png_to_ico(png_icon, ico_icon):
        print(f'已生成 ICO 图标: {ico_icon}')

icon_file = ico_icon if os.path.exists(ico_icon) else png_icon
icon_arg = f'--icon={icon_file}' if os.path.exists(icon_file) else ''

APP_NAME = 'KJK-Encryptor'

# 先清理旧的输出, 避免 PermissionError (onedir 结构清理整个应用目录)
app_out_dir = os.path.join('dist', APP_NAME)
exe_path = os.path.join(app_out_dir, f'{APP_NAME}.exe')
if os.path.exists(exe_path) or os.path.isdir(app_out_dir):
    print(f'正在删除旧的输出目录: {app_out_dir}')
    try:
        subprocess.run(['taskkill', '/F', '/IM', f'{APP_NAME}.exe'],
                      capture_output=True, timeout=5)
        time.sleep(1)
        if os.path.isdir(app_out_dir):
            shutil.rmtree(app_out_dir)
        elif os.path.exists(exe_path):
            os.remove(exe_path)
        print('旧文件已删除')
    except Exception as e:
        print(f'警告: 无法删除旧文件，请手动关闭正在运行的程序: {e}')
        sys.exit(1)
# 兼容清理 onefile 时代遗留的 dist 根 exe
legacy_exe = os.path.join('dist', f'{APP_NAME}.exe')
if os.path.exists(legacy_exe):
    try:
        os.remove(legacy_exe)
    except OSError:
        pass

# 打包源代码,供安装后本地获取与修改
source_files = [
    'engine.py', 'main.py', 'context_menu.py', 'kjk9.py', 'browse.py',
    'api_server.py', 'config.py', 'build.py', 'installer.py', 'uninstaller.py',
    'api_docs.html', 'kjkfast.c', 'README-LICENSE.txt', 'requirements.txt',
    '../LICENSE',
]
source_zip = 'source.zip'
print(f'正在打包源代码到 {source_zip}...')
try:
    with zipfile.ZipFile(source_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fname in source_files:
            if os.path.exists(fname):
                zf.write(fname, os.path.basename(fname))
        # 图标目录
        if os.path.isdir('icon'):
            for root, dirs, files in os.walk('icon'):
                for f in files:
                    full = os.path.join(root, f)
                    zf.write(full, full)
        # 网页版入口
        web_index = os.path.join('..', 'index.html')
        if os.path.exists(web_index):
            zf.write(web_index, 'index.html')
    print('源代码包已生成')
except Exception as e:
    print(f'生成 source.zip 失败: {e}')
    sys.exit(1)

# PyInstaller 命令 (onedir 多目录结构: 启动无需解压, engine/ 插件目录用户可见)
APP_VERSION = '1.1.0'
cmd = [
    'pyinstaller',
    f'--name={APP_NAME}',
    '--onedir',
    '--windowed',
]
if icon_arg:
    cmd.append(icon_arg)
cmd += [
    '--add-data=engine.py;.',
    '--add-data=api_server.py;.',
    '--add-data=context_menu.py;.',
    '--add-data=kjk9.py;.',
    '--add-data=browse.py;.',
    '--add-data=config.py;.',
    '--add-data=uninstaller.py;.',
    '--add-data=api_docs.html;.',
    '--add-data=source.zip;.',
    '--add-data=../LICENSE;LICENSE',
    '--add-data=README-LICENSE.txt;.',
]
cmd += [
    '--hidden-import=flask',
    '--hidden-import=PIL',
    '--hidden-import=requests',
    '--hidden-import=cryptography',
    '--hidden-import=cryptography.hazmat.primitives.ciphers.aead',
    '--hidden-import=cryptography.hazmat.primitives.kdf.hkdf',
    '--hidden-import=cryptography.hazmat.primitives.kdf.pbkdf2',
    '--hidden-import=cryptography.hazmat.primitives.hashes',
    '--hidden-import=kjk9',
    '--hidden-import=browse',
    '--hidden-import=config',
    '--clean',
    'main.py',
]

print('正在打包...')
print(' '.join(cmd))

result = subprocess.run(' '.join(cmd), shell=True)

if result.returncode != 0:
    print(f'打包失败，错误码: {result.returncode}')
    sys.exit(1)

# ---- onedir 后处理: engine/ 插件目录与版本文件 ----
import shutil
app_dir = os.path.join('dist', APP_NAME)

# C 引擎插件目录: 与 exe 平级, 安装后用户可见、可独立更新历代 DLL
if kjkfast_dll:
    dest_engine = os.path.join(app_dir, 'engine')
    os.makedirs(dest_engine, exist_ok=True)
    shutil.copy2(kjkfast_dll, os.path.join(dest_engine, os.path.basename(kjkfast_dll)))
    print(f'引擎插件已部署: {os.path.join(dest_engine, os.path.basename(kjkfast_dll))}')

# 版本文件: 安装器升级检测读取
with open(os.path.join(app_dir, 'version.txt'), 'w', encoding='utf-8') as f:
    f.write(APP_VERSION)
print(f'版本文件已写入: {APP_VERSION}')

print(f'打包成功！输出目录: {os.path.join(os.getcwd(), "dist", APP_NAME)}')
