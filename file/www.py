# -*- coding: utf-8 -*-
"""KJK Encryptor - Windows 右键菜单注册/卸载工具

独立脚本,用于在安装或卸载时写入/删除注册表项。
支持管理员权限自动提权。

注册内容:
  1. 所有文件 (*) 的加密右键菜单 (encrypt_here, encrypt_to, pack_to)
  2. 桌面背景右键菜单
  3. .kjk 文件关联 (ProgID: KJKEncryptor.kjk)
  4. .kjk 文件的解密右键菜单 (decrypt_here, decrypt_to, add_to_kjk)
  5. .kjk 文件默认打开方式
"""

import winreg
import os
import sys
import ctypes


# ======================== 菜单项定义 ========================

MENU_NAME_KEY = 'menu_name'

# 所有文件的菜单项（加密相关）
MENU_ITEMS = [
    {'id': 'encrypt_here', 'label_key': 'menu_encrypt_here'},
    {'id': 'encrypt_to', 'label_key': 'menu_encrypt_to'},
    {'id': 'pack_to', 'label_key': 'menu_pack_to'},
]

# .kjk 文件的菜单项（解密相关 + 追加）
KJK_MENU_ITEMS = [
    {'id': 'decrypt_here', 'label_key': 'menu_decrypt_here'},
    {'id': 'decrypt_to', 'label_key': 'menu_decrypt_to'},
    {'id': 'add_to_kjk', 'label_key': 'menu_add_to_kjk'},
]

PROG_ID = 'KJKEncryptor.kjk'


# ======================== 国际化 ========================

I18N = {
    'menu_name': {
        'en': 'KJK Encryptor',
        'zh-HK': 'KJK Encryptor',
        'zh-CN': 'KJK Encryptor',
    },
    'menu_encrypt_here': {
        'en': 'Encrypt Here',
        'zh-HK': '加密到當前目錄',
        'zh-CN': '加密到当前目录',
    },
    'menu_encrypt_to': {
        'en': 'Encrypt To...',
        'zh-HK': '加密到...',
        'zh-CN': '加密到...',
    },
    'menu_pack_to': {
        'en': 'Pack To...',
        'zh-HK': '打包到...',
        'zh-CN': '打包到...',
    },
    'menu_decrypt_here': {
        'en': 'Decrypt to Here',
        'zh-HK': '解密到當前位置',
        'zh-CN': '解密到当前位置',
    },
    'menu_decrypt_to': {
        'en': 'Decrypt to...',
        'zh-HK': '解密到...',
        'zh-CN': '解密到...',
    },
    'menu_add_to_kjk': {
        'en': 'Add to KJK Package...',
        'zh-HK': '添加到KJK包...',
        'zh-CN': '添加到KJK包...',
    },
    'need_admin': {
        'en': 'Administrator privileges are required. Please run as administrator.',
        'zh-HK': '需要管理員權限,請以管理員身份運行。',
        'zh-CN': '需要管理员权限,请以管理员身份运行。',
    },
    'register_success': {
        'en': 'Context menu registered successfully.',
        'zh-HK': '右鍵選單註冊成功。',
        'zh-CN': '右键菜单注册成功。',
    },
    'unregister_success': {
        'en': 'Context menu unregistered successfully.',
        'zh-HK': '右鍵選單解除安裝成功。',
        'zh-CN': '右键菜单卸载成功。',
    },
    'permission_denied': {
        'en': 'Access denied. Please run as administrator.',
        'zh-HK': '存取被拒,請以管理員身份運行。',
        'zh-CN': '访问被拒,请以管理员身份运行。',
    },
    'register_failed': {
        'en': 'Registration failed: {error}',
        'zh-HK': '註冊失敗: {error}',
        'zh-CN': '注册失败: {error}',
    },
    'unregister_failed': {
        'en': 'Unregistration failed: {error}',
        'zh-HK': '解除安裝失敗: {error}',
        'zh-CN': '卸载失败: {error}',
    },
    'usage': {
        'en': 'Usage: www.py [--register | --unregister] [exe_path]',
        'zh-HK': '用法: www.py [--register | --unregister] [exe_path]',
        'zh-CN': '用法: www.py [--register | --unregister] [exe_path]',
    },
}


def _load_lang():
    """从配置文件加载语言设置。"""
    try:
        import json
        # 查找配置文件
        if getattr(sys, 'frozen', False):
            exe_dir = os.path.dirname(sys.executable)
        else:
            exe_dir = os.path.dirname(os.path.abspath(__file__))

        protected = ('Program Files', 'Program Files (x86)', 'Windows')
        if any(p in exe_dir for p in protected):
            base = os.environ.get('APPDATA') or os.path.expanduser('~')
            config_path = os.path.join(base, 'KJK-Encrypter', 'kjk_config.json')
        else:
            config_path = os.path.join(exe_dir, 'kjk_config.json')

        if os.path.exists(config_path):
            with open(config_path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            lang = cfg.get('lang', 'zh-CN')
            if lang in ('en', 'zh-HK', 'zh-CN'):
                return lang
    except Exception:
        pass
    return 'zh-CN'


LANG = _load_lang()


def _t(key, **kwargs):
    entry = I18N.get(key, {}).get(LANG, key)
    if kwargs:
        entry = entry.format(**kwargs)
    return entry


# ======================== 工具函数 ========================


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_as_admin():
    """以管理员权限重新启动当前脚本。"""
    import ctypes
    ctypes.windll.shell32.ShellExecuteW(
        None, 'runas', sys.executable,
        ' '.join(f'"{a}"' if ' ' in a else a for a in sys.argv[1:]),
        None, 1)


def get_main_script_path():
    """返回主程序 main.py 的路径 (脚本模式)。"""
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'python', 'main.py'))


def build_command(exe_path, action_id):
    """构建右键菜单命令。

    如果 exe_path 是 .exe,直接使用:
      "<exe_path>" --<action> "%1"
    如果 exe_path 是 .py (脚本模式),使用 Python 解释器:
      "<python.exe>" "<main.py>" --<action> "%1"
    """
    action_flag = '--' + action_id.replace('_', '-')
    if exe_path.lower().endswith('.exe'):
        return f'"{exe_path}" {action_flag} "%1"'
    else:
        # 脚本模式: 需要 Python 解释器
        python_exe = sys.executable
        return f'"{python_exe}" "{exe_path}" {action_flag} "%1"'


def _get_menu_name():
    return _t(MENU_NAME_KEY)


def _get_localized_menu_items(exe_path):
    """获取所有文件菜单项 (加密相关)。"""
    items = []
    for item in MENU_ITEMS:
        items.append({
            'id': item['id'],
            'label': _t(item['label_key']),
            'command': build_command(exe_path, item['id']),
        })
    return items


def _get_localized_kjk_menu_items(exe_path):
    """获取 .kjk 文件菜单项 (解密相关 + 追加)。"""
    items = []
    for item in KJK_MENU_ITEMS:
        items.append({
            'id': item['id'],
            'label': _t(item['label_key']),
            'command': build_command(exe_path, item['id']),
        })
    return items


# ======================== 注册表操作 ========================


def register_context_menu(exe_path=None):
    """写入右键菜单注册表项。

    注册内容:
      1. 所有文件 (*) 的加密右键菜单
      2. 桌面背景右键菜单
      3. .kjk 文件关联 (ProgID: KJKEncryptor.kjk)
      4. .kjk 文件的解密右键菜单
      5. .kjk 文件默认打开方式
    """
    if not is_admin():
        run_as_admin()
        sys.exit(0)

    if exe_path is None:
        exe_path = get_main_script_path()

    menu_items = _get_localized_menu_items(exe_path)
    kjk_menu_items = _get_localized_kjk_menu_items(exe_path)
    menu_name = _get_menu_name()

    # .kjk 默认打开命令
    open_command = build_command(exe_path, 'decrypt_here')

    try:
        # ===== 1. 所有文件 (*) 的加密菜单 =====
        key_path = fr'*\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path if exe_path.lower().endswith('.exe') else '')

        submenu_path = fr'*\shell\{menu_name}\shell'
        for item in menu_items:
            item_path = fr'{submenu_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])

            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # ===== 2. 桌面背景右键菜单 =====
        bg_key_path = fr'Directory\Background\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, bg_key_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path if exe_path.lower().endswith('.exe') else '')

        bg_sub_path = fr'{bg_key_path}\shell'
        for item in menu_items:
            item_path = fr'{bg_sub_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])

            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # ===== 3. .kjk 文件关联 (ProgID) =====
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, PROG_ID) as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'KJK Encrypted Package')
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\DefaultIcon') as key:
            icon_val = exe_path if exe_path.lower().endswith('.exe') else ''
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, icon_val)

        # .kjk 扩展名关联
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.kjk') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, PROG_ID)

        # ===== 4. .kjk 文件的右键解密菜单 =====
        kjk_shell_path = fr'{PROG_ID}\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, kjk_shell_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path if exe_path.lower().endswith('.exe') else '')

        kjk_sub_path = fr'{kjk_shell_path}\shell'
        for item in kjk_menu_items:
            item_path = fr'{kjk_sub_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])

            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # ===== 5. .kjk 文件默认打开方式 =====
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\shell\open\command') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, open_command)

        return True, _t('register_success')
    except PermissionError:
        return False, _t('permission_denied')
    except Exception as e:
        return False, _t('register_failed', error=str(e))


def unregister_context_menu():
    """删除右键菜单注册表项 (完整清理)。"""
    if not is_admin():
        run_as_admin()
        sys.exit(0)

    menu_name = _get_menu_name()

    try:
        # ===== 清理所有文件右键菜单 =====
        all_ids = [item['id'] for item in MENU_ITEMS]
        for prefix in [fr'*\shell\{menu_name}',
                       fr'Directory\Background\shell\{menu_name}']:
            shell_path = fr'{prefix}\shell'
            for cid in all_ids:
                try:
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{shell_path}\{cid}\command')
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{shell_path}\{cid}')
                except FileNotFoundError:
                    pass
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, shell_path)
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, prefix)
            except FileNotFoundError:
                pass

        # ===== 清理 .kjk 文件右键菜单 =====
        kjk_ids = [item['id'] for item in KJK_MENU_ITEMS]
        kjk_shell_path = fr'{PROG_ID}\shell\{menu_name}\shell'
        for cid in kjk_ids:
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{kjk_shell_path}\{cid}\command')
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{kjk_shell_path}\{cid}')
            except FileNotFoundError:
                pass
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, kjk_shell_path)
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\shell\{menu_name}')
        except FileNotFoundError:
            pass

        # ===== 清理 .kjk 文件默认打开方式 =====
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\shell\open\command')
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\shell\open')
        except FileNotFoundError:
            pass

        # ===== 清理 ProgID 和 .kjk 扩展名关联 =====
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\DefaultIcon')
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{PROG_ID}\shell')
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, PROG_ID)
        except FileNotFoundError:
            pass

        # 删除 .kjk 扩展名关联（仅当指向我们的 ProgID 时）
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '.kjk') as key:
                val, _ = winreg.QueryValueEx(key, '')
                if val == PROG_ID:
                    winreg.CloseKey(key)
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, '.kjk')
        except FileNotFoundError:
            pass
        except Exception:
            pass

        return True, _t('unregister_success')
    except PermissionError:
        return False, _t('permission_denied')
    except Exception as e:
        return False, _t('unregister_failed', error=str(e))


# ======================== 入口 ========================

if __name__ == '__main__':
    silent = '--silent' in sys.argv
    args = [a for a in sys.argv if a != '--silent']

    if len(args) < 2:
        if silent:
            print(_t('usage'))
            sys.exit(0)
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo('Info', _t('usage'))
        root.destroy()
        sys.exit(0)

    action = args[1]
    exe_path = args[2] if len(args) > 2 else None

    if silent:
        # 静默模式: 不弹窗,只打印结果
        if action == '--register':
            ok, msg = register_context_menu(exe_path)
            print(msg)
            sys.exit(0 if ok else 1)
        elif action == '--unregister':
            ok, msg = unregister_context_menu()
            print(msg)
            sys.exit(0 if ok else 1)
        else:
            print(_t('usage'))
            sys.exit(1)
    else:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()

        if action == '--register':
            ok, msg = register_context_menu(exe_path)
            messagebox.showinfo('Result', msg)
        elif action == '--unregister':
            ok, msg = unregister_context_menu()
            messagebox.showinfo('Result', msg)
        else:
            messagebox.showerror('Error', _t('usage'))

        root.destroy()
