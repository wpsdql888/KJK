# -*- coding: utf-8 -*-
"""KJK Encryptor - 打包脚本

自动打包 www.py 和 installer.py 为单文件 exe。
每次运行都会读取最新的源代码进行打包,无需手动修改。

installer.exe 内置:
  - www.py (注册表工具)
  - 主程序 dist 目录的所有文件 (自动打包)
  - icon.png (图标)

用法:
  python build.py              # 打包全部
  python build.py --www        # 仅打包 www.py
  python build.py --installer  # 仅打包 installer.py
"""

import os
import sys
import subprocess
import time
import zipfile
import shutil

# 切换到脚本所在目录
os.chdir(os.path.dirname(os.path.abspath(__file__)))

# 目录结构
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))          # v1.0/file
PYTHON_DIR = os.path.join(ROOT_DIR, '..', 'python')            # v1.0/python
MAIN_DIST_DIR = os.path.join(PYTHON_DIR, 'dist')               # v1.0/python/dist
ICON_DIR = os.path.join(PYTHON_DIR, 'icon')                    # v1.0/python/icon
OUTPUT_DIR = os.path.join(ROOT_DIR, 'dist')                    # v1.0/file/dist

os.makedirs(OUTPUT_DIR, exist_ok=True)


def kill_process(name):
    """尝试终止正在运行的进程。"""
    try:
        subprocess.run(['taskkill', '/F', '/IM', name],
                        capture_output=True, timeout=5)
        time.sleep(1)
    except Exception:
        pass


def remove_old_exe(path):
    """删除旧的 exe 文件。"""
    if os.path.exists(path):
        name = os.path.basename(path)
        print(f'  正在删除旧的 {name}...')
        kill_process(name)
        try:
            os.remove(path)
            print(f'  已删除: {path}')
        except Exception as e:
            print(f'  警告: 无法删除,请关闭正在运行的程序: {e}')
            return False
    return True


def png_to_ico(png_path, ico_path):
    """将 PNG 图标转换为 ICO 格式。"""
    try:
        from PIL import Image
        img = Image.open(png_path)
        # ICO 支持多种尺寸
        sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        img.save(ico_path, format='ICO', sizes=sizes)
        return True
    except Exception as e:
        print(f'  图标转换失败: {e}')
        return False


def get_ico_path():
    """获取 ICO 图标路径,如果不存在则从 PNG 转换。"""
    png_path = os.path.join(ICON_DIR, 'icon.png')
    ico_path = os.path.join(ICON_DIR, 'icon.ico')

    if os.path.exists(ico_path):
        return ico_path

    if os.path.exists(png_path):
        if png_to_ico(png_path, ico_path):
            print(f'  已生成 ICO 图标: {ico_path}')
            return ico_path

    return None


def create_main_dist_zip():
    """将主程序 onedir 应用目录打包为 zip,返回 zip 路径。

    v1.0.4 起主程序为 onedir 多目录结构 (dist/KJK-Encryptor/),
    zip 内不再包含顶层应用目录, 解压即得到 exe/_internal/engine 平级结构。"""
    zip_path = os.path.join(ROOT_DIR, 'main_dist.zip')

    # onedir 结构: 应用目录为 dist/KJK-Encryptor
    app_dir = os.path.join(MAIN_DIST_DIR, 'KJK-Encryptor')
    src_dir = app_dir if os.path.isdir(app_dir) else MAIN_DIST_DIR

    if not os.path.isdir(src_dir):
        print(f'  警告: 主程序应用目录不存在: {src_dir}')
        print(f'  请先运行 python/build.py 打包主程序。')
        return None

    print(f'  正在打包主程序应用目录...')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(src_dir):
            for f in files:
                full = os.path.join(root, f)
                arcname = os.path.relpath(full, src_dir)
                zf.write(full, arcname)

    size_mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f'  已打包: {zip_path} ({size_mb:.1f} MB)')
    return zip_path


def build_www():
    """打包 www.py 为单文件 exe。"""
    print('=' * 50)
    print('打包 www.py -> KJK-Registry.exe')
    print('=' * 50)

    exe_name = 'KJK-Registry.exe'
    exe_path = os.path.join(OUTPUT_DIR, exe_name)

    if not remove_old_exe(exe_path):
        return False

    www_src = os.path.join(ROOT_DIR, 'www.py')
    if not os.path.exists(www_src):
        print(f'  错误: 找不到 {www_src}')
        return False

    # 获取图标
    ico_path = get_ico_path()
    icon_arg = [f'--icon={ico_path}'] if ico_path else []

    cmd = [
        'pyinstaller',
        '--name=KJK-Registry',
        '--onefile',
        '--windowed',
        '--clean',
        '--distpath', OUTPUT_DIR,
        '--workpath', os.path.join(ROOT_DIR, 'build_www'),
        '--specpath', os.path.join(ROOT_DIR, 'build_www'),
    ] + icon_arg + [
        www_src,
    ]

    print(f'  命令: {" ".join(cmd)}')
    result = subprocess.run(' '.join(cmd), shell=True)

    if result.returncode == 0:
        print(f'  打包成功: {exe_path}')
        return True
    else:
        print(f'  打包失败,错误码: {result.returncode}')
        return False


def build_installer():
    """打包 installer.py 为单文件 exe,内置 www.py、主程序 dist 和卸载程序。"""
    print('=' * 50)
    print('打包 installer.py -> KJK-Installer.exe')
    print('=' * 50)

    exe_name = 'KJK-Installer.exe'
    exe_path = os.path.join(OUTPUT_DIR, exe_name)

    if not remove_old_exe(exe_path):
        return False

    installer_src = os.path.join(PYTHON_DIR, 'installer.py')
    www_src = os.path.join(ROOT_DIR, 'www.py')
    uninstaller_src = os.path.join(PYTHON_DIR, 'uninstaller.py')
    uninstaller_exe = os.path.join(OUTPUT_DIR, 'KJK-Uninstaller.exe')

    if not os.path.exists(installer_src):
        print(f'  错误: 找不到 {installer_src}')
        return False

    if not os.path.exists(www_src):
        print(f'  错误: 找不到 {www_src}')
        return False

    # 确保 KJK-Uninstaller.exe 存在（需要先运行 build_uninstaller）
    if not os.path.exists(uninstaller_exe):
        print(f'  警告: 找不到 {uninstaller_exe}，请先运行 build_uninstaller()')
        print(f'  正在自动打包 uninstaller...')
        if not build_uninstaller():
            print(f'  错误: 无法打包 uninstaller')
            return False

    # 打包主程序 dist 为 zip
    main_dist_zip = create_main_dist_zip()

    # 图标文件
    ico_path = get_ico_path()
    icon_src = os.path.join(PYTHON_DIR, 'icon', 'icon.png')

    # 构建 --add-data 参数
    add_data_args = [
        f'--add-data={www_src};.',
        f'--add-data={uninstaller_exe};.',  # 打包已编译的卸载程序exe
    ]
    if os.path.exists(uninstaller_src):
        add_data_args.append(f'--add-data={uninstaller_src};.')  # 同时保留源码作为备用
    if main_dist_zip:
        add_data_args.append(f'--add-data={main_dist_zip};.')
    readme_src = os.path.join(ROOT_DIR, '..', 'README.md')
    if os.path.exists(readme_src):
        add_data_args.append(f'--add-data={readme_src};.')
    if os.path.exists(icon_src):
        add_data_args.append(f'--add-data={icon_src};.')

    # 图标参数
    icon_arg = [f'--icon={ico_path}'] if ico_path else []

    cmd = [
        'pyinstaller',
        '--name=KJK-Installer',
        '--onefile',
        '--windowed',
        '--clean',
    ] + icon_arg + add_data_args + [
        '--distpath', OUTPUT_DIR,
        '--workpath', os.path.join(ROOT_DIR, 'build_installer'),
        '--specpath', os.path.join(ROOT_DIR, 'build_installer'),
        installer_src,
    ]

    print(f'  命令: {" ".join(cmd)}')
    result = subprocess.run(' '.join(cmd), shell=True)

    # 清理临时 zip
    if main_dist_zip and os.path.exists(main_dist_zip):
        os.remove(main_dist_zip)

    if result.returncode == 0:
        print(f'  打包成功: {exe_path}')
        return True
    else:
        print(f'  打包失败,错误码: {result.returncode}')
        return False


def build_uninstaller():
    """打包 uninstaller.py 为单文件 exe。"""
    print('=' * 50)
    print('打包 uninstaller.py -> KJK-Uninstaller.exe')
    print('=' * 50)

    exe_name = 'KJK-Uninstaller.exe'
    exe_path = os.path.join(OUTPUT_DIR, exe_name)

    if not remove_old_exe(exe_path):
        return False

    uninstaller_src = os.path.join(PYTHON_DIR, 'uninstaller.py')
    if not os.path.exists(uninstaller_src):
        print(f'  错误: 找不到 {uninstaller_src}')
        return False

    # 获取图标
    ico_path = get_ico_path()
    icon_arg = [f'--icon={ico_path}'] if ico_path else []

    cmd = [
        'pyinstaller',
        '--name=KJK-Uninstaller',
        '--onefile',
        '--windowed',
        '--clean',
        '--distpath', OUTPUT_DIR,
        '--workpath', os.path.join(ROOT_DIR, 'build_uninstaller'),
        '--specpath', os.path.join(ROOT_DIR, 'build_uninstaller'),
    ] + icon_arg + [
        uninstaller_src,
    ]

    print(f'  命令: {" ".join(cmd)}')
    result = subprocess.run(' '.join(cmd), shell=True)

    if result.returncode == 0:
        print(f'  打包成功: {exe_path}')
        return True
    else:
        print(f'  打包失败,错误码: {result.returncode}')
        return False


# ======================== 入口 ========================

if __name__ == '__main__':
    args = sys.argv[1:]

    if not args or '--all' in args:
        # 打包顺序: www -> uninstaller -> installer (installer需要uninstaller.exe)
        ok1 = build_www()
        print()
        ok2 = build_uninstaller()  # 先打包uninstaller
        print()
        ok3 = build_installer()    # installer依赖uninstaller.exe
        if ok1 and ok2 and ok3:
            print()
            print('全部打包完成!')
            print(f'输出目录: {OUTPUT_DIR}')
        else:
            print()
            print('部分打包失败,请检查错误信息。')
            sys.exit(1)
    elif '--www' in args:
        if build_www():
            print('打包完成!')
        else:
            sys.exit(1)
    elif '--installer' in args:
        # 单独打包installer时，确保uninstaller存在
        uninstaller_exe = os.path.join(OUTPUT_DIR, 'KJK-Uninstaller.exe')
        if not os.path.exists(uninstaller_exe):
            print('  正在先打包 uninstaller...')
            if not build_uninstaller():
                sys.exit(1)
            print()
        if build_installer():
            print('打包完成!')
        else:
            sys.exit(1)
    elif '--uninstaller' in args:
        if build_uninstaller():
            print('打包完成!')
        else:
            sys.exit(1)
    else:
        print('用法: python build.py [--all | --www | --installer | --uninstaller]')
        sys.exit(1)
