# -*- coding: utf-8 -*-
"""KJK Encryptor - Windows 右键菜单管理 (v4 i18n + 解密功能)"""

import winreg
import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from engine import (
    encrypt, decrypt, encrypt_raw,
    re_decrypt,
    pack_kjk, unpack_kjk, append_to_kjk,
    pack_kjk_with_folder, collect_folder_entries,
    encrypt_filename, compress_ciphertext,
    add_password_prefix, detect_password_prefix,
    detect_password_header,
    verify_password, make_password_header,
    detect_kjk_format_version,
    extract_legacy_package_file,
)
from config import load_config as _load_config, get_compat_format


# ======================== 格式兼容性辅助 ========================

def _get_encryption_params():
    """根据配置获取加密参数 (version, legacy)。
    
    Returns:
        version: 'KJKv7' 或 'KJKv5'
        legacy: bool, 是否使用旧版加密算法
        use_password_prefix: bool, 是否使用密码头前缀 (v6/v7 风格)
    """
    cfg = _load_config()
    fmt = get_compat_format(cfg)
    if fmt == 'KJKv5':
        return 'KJKv5', True, False
    else:
        # auto 或 KJKv7 默认使用 v7
        return 'KJKv7', False, True


# ======================== i18n Config ========================


def _load_lang():
    """Load language preference from config file, default to 'en'."""
    try:
        cfg = _load_config()
        lang = cfg.get('lang', 'en')
        if lang in ('en', 'zh-HK', 'zh-CN'):
            return lang
    except Exception:
        pass
    return 'en'


CURRENT_LANG = _load_lang()


# ======================== i18n Dictionary ========================

I18N = {
    # ---- Password dialog ----
    'pwd_title': {
        'en': 'Password',
        'zh-HK': '密碼',
        'zh-CN': '密码',
    },
    'pwd_prompt': {
        'en': 'Enter password (leave empty for no password):',
        'zh-HK': '輸入密碼（留空即唔設密碼）：',
        'zh-CN': '输入密码（留空即不设密码）：',
    },
    'pwd_prompt_required': {
        'en': 'Enter password to decrypt:',
        'zh-HK': '請輸入 Decryption 密碼：',
        'zh-CN': '请输入解密密码：',
    },
    'pwd_required_cancel': {
        'en': 'Password is required to decrypt this file.',
        'zh-HK': 'Decrypt 呢個檔案必須輸入密碼。',
        'zh-CN': '解密此文件必须输入密码。',
    },
    'pwd_wrong': {
        'en': 'Wrong password. Please try again.',
        'zh-HK': '密碼錯誤，請 Retry。',
        'zh-CN': '密码错误，请重试。',
    },
    'btn_ok': {
        'en': 'OK',
        'zh-HK': 'OK',
        'zh-CN': '确定',
    },
    'menu_no_target': {
        'en': 'No file or folder was selected.\nRight-click a file/folder (or a .kjk package) and choose the action again.',
        'zh-HK': '未選取任何檔案或資料夾。\n請對檔案/資料夾（或 .kjk 套件）按右鍵再選動作。',
        'zh-CN': '未选中任何文件或文件夹。\n请对文件/文件夹（或 .kjk 包）点击右键再选择操作。',
    },
    'btn_skip': {
        'en': 'Skip',
        'zh-HK': 'Skip',
        'zh-CN': '跳过',
    },
    'btn_cancel': {
        'en': 'Cancel',
        'zh-HK': '取消',
        'zh-CN': '取消',
    },

    # ---- Progress window ----
    'progress_title': {
        'en': 'Processing',
        'zh-HK': 'Processing',
        'zh-CN': '处理中',
    },
    'preparing': {
        'en': 'Preparing...',
        'zh-HK': 'Preparing...',
        'zh-CN': '准备中...',
    },
    'cancelling': {
        'en': 'Cancelling, waiting for current page...',
        'zh-HK': '正在取消，等待当前分页完成...',
        'zh-CN': '正在取消，等待当前分页完成...',
    },
    'op_cancelled': {
        'en': 'Operation cancelled',
        'zh-HK': '操作已取消',
        'zh-CN': '操作已取消',
    },
    'engine_v9': {
        'en': 'C engine · KJKv9',
        'zh-HK': 'C 引擎 · KJKv9',
        'zh-CN': 'C 引擎 · KJKv9',
    },
    'v9_disabled': {
        'en': 'This is a KJKv9 package, but the output format is set to legacy (KJKv7/KJKv5). Please switch to Auto format in settings to use it.',
        'zh-HK': '這是 KJKv9 套件，但輸出格式已設為舊版(KJKv7/KJKv5)。請在設定中切換為自動格式。',
        'zh-CN': '这是 KJKv9 包，但输出格式已设为旧版(KJKv7/KJKv5)。请在设置中切换为自动格式。',
    },

    # ---- Progress stage templates (used with .format(op=...)) ----
    'stage_preparing': {
        'en': '{op}... (preparing)',
        'zh-HK': '{op}... (preparing)',
        'zh-CN': '{op}...（准备中）',
    },
    'stage_encoding': {
        'en': '{op}... (encoding)',
        'zh-HK': '{op}... (encoding)',
        'zh-CN': '{op}...（编码中）',
    },
    'stage_processing': {
        'en': '{op}... (processing)',
        'zh-HK': '{op}... (processing)',
        'zh-CN': '{op}...（处理中）',
    },
    'stage_finishing': {
        'en': '{op}... (finishing)',
        'zh-HK': '{op}... (finishing)',
        'zh-CN': '{op}...（完成中）',
    },

    # ---- Operation names (used as {op} in stage templates) ----
    'op_encrypt': {
        'en': 'Encrypting',
        'zh-HK': 'Encrypt 緊',
        'zh-CN': '正在加密',
    },
    'op_packing': {
        'en': 'Packing',
        'zh-HK': 'Pack 緊',
        'zh-CN': '正在打包',
    },
    'op_adding': {
        'en': 'Encrypting',
        'zh-HK': 'Encrypt 緊',
        'zh-CN': '正在加密',
    },

    # ---- Status labels ----
    'done': {
        'en': 'Done!',
        'zh-HK': '搞掂！',
        'zh-CN': '完成！',
    },
    'encrypting_label': {
        'en': 'Encrypting...',
        'zh-HK': 'Encrypt 緊...',
        'zh-CN': '正在加密...',
    },
    'packing_label': {
        'en': 'Packing...',
        'zh-HK': 'Pack 緊...',
        'zh-CN': '正在打包...',
    },
    'encrypting_new_file': {
        'en': 'Encrypting new file...',
        'zh-HK': 'Encrypt 緊新檔案...',
        'zh-CN': '正在加密新文件...',
    },
    'appending_to_package': {
        'en': 'Appending to package...',
        'zh-HK': 'Append 緊入 package...',
        'zh-CN': '正在追加到包...',
    },

    # ---- Dialog titles ----
    'encryption_password': {
        'en': 'Encryption Password',
        'zh-HK': 'Encryption 密碼',
        'zh-CN': '加密密码',
    },
    'decryption_password': {
        'en': 'Decryption Password',
        'zh-HK': 'Decryption 密碼',
        'zh-CN': '解密密码',
    },
    'encrypting_file': {
        'en': 'Encrypting {name}',
        'zh-HK': 'Encrypt 緊 {name}',
        'zh-CN': '正在加密 {name}',
    },
    'packing_file': {
        'en': 'Packing {name}',
        'zh-HK': 'Pack 緊 {name}',
        'zh-CN': '正在打包 {name}',
    },
    'adding_to_package': {
        'en': 'Adding {name} to KJK package',
        'zh-HK': 'Add 緊 {name} 入 KJK package',
        'zh-CN': '正在添加 {name} 到KJK包',
    },
    'adding_files': {
        'en': 'Adding {name} to package',
        'zh-HK': 'Add 緊 {name} 入 package',
        'zh-CN': '正在添加 {name} 到包',
    },
    'added_files': {
        'en': 'Added {count} file(s) to {path}',
        'zh-HK': '已添加 {count} 個檔案到 {path}',
        'zh-CN': '已添加 {count} 个文件到 {path}',
    },
    'decrypting_file': {
        'en': 'Decrypting {name}',
        'zh-HK': 'Decrypt 緊 {name}',
        'zh-CN': '正在解密 {name}',
    },

    # ---- File dialog titles / filters ----
    'save_kjk_file': {
        'en': 'Save .kjk file',
        'zh-HK': '儲存 .kjk 檔案',
        'zh-CN': '保存 .kjk 文件',
    },
    'save_kjk_package': {
        'en': 'Save .kjk package',
        'zh-HK': '儲存 .kjk package',
        'zh-CN': '保存 .kjk 包',
    },
    'select_kjk_to_add': {
        'en': 'Select .kjk package to add to',
        'zh-HK': '揀選要 add 入嘅 KJK package',
        'zh-CN': '选择要添加到的KJK包',
    },
    'kjk_package_type': {
        'en': 'KJK Package',
        'zh-HK': 'KJK Package',
        'zh-CN': 'KJK包',
    },
    'all_files_type': {
        'en': 'All files',
        'zh-HK': '所有檔案',
        'zh-CN': '所有文件',
    },

    # ---- Messagebox titles ----
    'success': {
        'en': 'Success',
        'zh-HK': '成功 Success',
        'zh-CN': '成功',
    },
    'error': {
        'en': 'Error',
        'zh-HK': '錯誤 Error',
        'zh-CN': '错误',
    },
    'added_to_package': {
        'en': 'Added to Package',
        'zh-HK': '已 Add 入 Package',
        'zh-CN': '已添加到包',
    },

    # ---- File size units ----
    'bytes_unit': {
        'en': 'bytes',
        'zh-HK': 'bytes',
        'zh-CN': '字节',
    },

    # ---- Messagebox messages (templates) ----
    'encrypted_to': {
        'en': 'Encrypted to:\n{path}',
        'zh-HK': 'Encrypt 完成，儲存咗去：\n{path}',
        'zh-CN': '已加密到：\n{path}',
    },
    'saved_to': {
        'en': 'Saved to:\n{path}',
        'zh-HK': '儲存咗去：\n{path}',
        'zh-CN': '已保存到：\n{path}',
    },
    'file_added_msg': {
        'en': 'File added!\n\nPackage now contains {count} files:\n{file_list}',
        'zh-HK': '檔案已 add！\n\nPackage 入面而家有 {count} 個檔案：\n{file_list}',
        'zh-CN': '文件已添加！\n\n包内现在包含 {count} 个文件：\n{file_list}',
    },
    'decrypted_files': {
        'en': 'Decrypted {count} file(s) to:\n{path}',
        'zh-HK': 'Decrypt 咗 {count} 個檔案到：\n{path}',
        'zh-CN': '已解密 {count} 个文件到：\n{path}',
    },
    'decrypting_progress': {
        'en': 'Decrypting ({current}/{total}): {name}',
        'zh-HK': 'Decrypt 緊 ({current}/{total}): {name}',
        'zh-CN': '正在解密 ({current}/{total}): {name}',
    },

    # ---- Context menu name ----
    'menu_name': {
        'en': 'KJK Encryptor',
        'zh-HK': 'KJK Encryptor',
        'zh-CN': 'KJK Encryptor',
    },

    # ---- Context menu item labels ----
    'menu_encrypt_here': {
        'en': 'Encrypt here (&K)',
        'zh-HK': 'Encrypt 到此資料夾 (&K)',
        'zh-CN': '加密到此文件夹 (&K)',
    },
    'menu_encrypt_to': {
        'en': 'Encrypt to... (&T)',
        'zh-HK': 'Encrypt 到... (&T)',
        'zh-CN': '加密到... (&T)',
    },
    'menu_pack_to': {
        'en': 'Pack encrypted to... (&P)',
        'zh-HK': 'Pack 加密到... (&P)',
        'zh-CN': '打包加密到... (&P)',
    },
    'menu_add_to_kjk': {
        'en': 'Add to this KJK package (&A)',
        'zh-HK': 'Add 入呢個 KJK package (&A)',
        'zh-CN': '添加到此KJK包 (&A)',
    },
    'duplicate_in_package': {
        'en': 'The following {count} item(s) already exist in the package:\n{names}\n\nContinue to overwrite?',
        'zh-HK': '以下 {count} 項已經喺 package 入面:\n{names}\n\n係咪要覆蓋繼續？',
        'zh-CN': '以下 {count} 项已存在于包中：\n{names}\n\n是否覆盖继续？',
    },
    'menu_decrypt_here': {
        'en': 'Decrypt to here (&D)',
        'zh-HK': '解密到呢度 (&D)',
        'zh-CN': '解密到当前位置 (&D)',
    },
    'menu_decrypt_to': {
        'en': 'Decrypt to... (&T)',
        'zh-HK': '解密到... (&T)',
        'zh-CN': '解密到... (&T)',
    },

    # ---- Registration / unregistration messages ----
    'need_admin_register': {
        'en': 'Administrator privileges are required to register the context menu. Please run as administrator.',
        'zh-HK': '需要管理員權限先可以註冊 context menu。請以管理員身份運行。',
        'zh-CN': '需要管理员权限才能注册右键菜单。请以管理员身份运行。',
    },
    'need_admin_unregister': {
        'en': 'Administrator privileges are required to unregister the context menu. Please run as administrator.',
        'zh-HK': '需要管理員權限先可以卸載 context menu。請以管理員身份運行。',
        'zh-CN': '需要管理员权限才能卸载右键菜单。请以管理员身份运行。',
    },
    'register_success': {
        'en': 'Context menu registered successfully!',
        'zh-HK': 'Context menu 註冊成功！',
        'zh-CN': '右键菜单注册成功！',
    },
    'unregister_success': {
        'en': 'Context menu unregistered successfully!',
        'zh-HK': 'Context menu 卸載成功！',
        'zh-CN': '右键菜单卸载成功！',
    },
    'permission_denied': {
        'en': 'Permission denied. Please run as administrator.',
        'zh-HK': '權限不足，請以管理員身份運行。',
        'zh-CN': '权限不足，请以管理员身份运行。',
    },
    'register_failed': {
        'en': 'Registration failed: {error}',
        'zh-HK': '註冊失敗：{error}',
        'zh-CN': '注册失败：{error}',
    },
    'unregister_failed': {
        'en': 'Unregister failed: {error}',
        'zh-HK': '卸載失敗：{error}',
        'zh-CN': '卸载失败：{error}',
    },

    # ---- Batch merge dialog ----
    'batchEncryptTitle': {
        'en': 'Multiple Files Selected',
        'zh-HK': '已選取多個檔案',
        'zh-CN': '已选择多个文件',
    },
    'batchMergeConfirmMsg': {
        'en': 'You have selected {count} item(s).\n\nDo you want to merge them into a single .kjk package?',
        'zh-HK': '你選咗 {count} 個項目。\n\n你想將佢哋合併成一個 .kjk 包裹嗎？',
        'zh-CN': '您已选择 {count} 个项目。\n\n是否要将它们合并为一个 .kjk 包？',
    },
}


def _t(key, **kwargs):
    """Translate a key to the current language, with optional format args."""
    # 动态读取当前语言，而不是使用模块级变量
    current_lang = _load_lang()
    entry = I18N.get(key)
    if entry is None:
        return key
    text = entry.get(current_lang, entry.get('en', key))
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, IndexError):
            pass
    return text


# ======================== 密码输入框 ========================

def ask_password(title=None):
    """弹出密码输入对话框（可跳过，用于加密时）"""
    if title is None:
        title = _t('encryption_password')
    root = tk.Tk()
    # 移出屏幕避免遮挡，某些系统下 withdraw 会导致 Toplevel 无法显示
    root.geometry('1x1+10000+10000')
    root.overrideredirect(True)
    root.attributes('-topmost', True)
    result = [None]

    def on_ok():
        result[0] = entry.get()
        dialog.destroy()

    def on_skip():
        result[0] = ''
        dialog.destroy()

    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry('350x130')
    dialog.resizable(False, False)
    dialog.attributes('-topmost', True)
    dialog.transient(root)

    tk.Label(dialog, text=_t('pwd_prompt'),
             font=('', 10)).pack(pady=(15, 5))
    entry = tk.Entry(dialog, width=30, show='\u2022', font=('', 12))
    entry.pack(pady=5)
    entry.focus_set()

    btn_frame = tk.Frame(dialog)
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text=_t('btn_ok'), command=on_ok, width=8).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text=_t('btn_skip'), command=on_skip, width=8).pack(side=tk.LEFT, padx=5)

    dialog.bind('<Return>', lambda e: on_ok())
    dialog.protocol('WM_DELETE_WINDOW', on_skip)
    dialog.wait_window()
    root.destroy()
    return result[0]


def ask_password_required(title=None, prompt_key='pwd_prompt_required'):
    """弹出密码输入对话框（必填，用于解密时；用户取消则返回 None）"""
    if title is None:
        title = _t('decryption_password')
    root = tk.Tk()
    # 移出屏幕避免遮挡，某些系统下 withdraw 会导致 Toplevel 无法显示
    root.geometry('1x1+10000+10000')
    root.overrideredirect(True)
    root.attributes('-topmost', True)
    result = [None]

    def on_ok():
        pwd = entry.get()
        if not pwd:
            messagebox.showwarning(title, _t('pwd_required_cancel'), parent=dialog)
            return
        result[0] = pwd
        dialog.destroy()

    def on_cancel():
        result[0] = None
        dialog.destroy()

    dialog = tk.Toplevel(root)
    dialog.title(title)
    dialog.geometry('350x130')
    dialog.resizable(False, False)
    dialog.attributes('-topmost', True)
    dialog.transient(root)

    tk.Label(dialog, text=_t(prompt_key),
             font=('', 10)).pack(pady=(15, 5))
    entry = tk.Entry(dialog, width=30, show='\u2022', font=('', 12))
    entry.pack(pady=5)
    entry.focus_set()

    btn_frame = tk.Frame(dialog)
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text=_t('btn_ok'), command=on_ok, width=8).pack(side=tk.LEFT, padx=5)
    tk.Button(btn_frame, text=_t('btn_cancel'), command=on_cancel, width=8).pack(side=tk.LEFT, padx=5)

    dialog.bind('<Return>', lambda e: on_ok())
    dialog.bind('<Escape>', lambda e: on_cancel())
    dialog.protocol('WM_DELETE_WINDOW', on_cancel)
    dialog.wait_window()
    root.destroy()
    return result[0]


# ======================== 进度条窗口 ========================

class ProgressWindow:
    """加密/解密进度条窗口"""

    def __init__(self, title=None, total_files=1):
        if title is None:
            title = _t('progress_title')
        self.root = tk.Tk()
        # 移出屏幕避免遮挡，某些系统下 withdraw 会导致 Toplevel 无法显示
        self.root.geometry('1x1+10000+10000')
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)

        self.win = tk.Toplevel(self.root)
        self.win.title(title)
        self.win.geometry('420x150')
        self.win.resizable(False, False)
        self.win.attributes('-topmost', True)

        self.label = tk.Label(self.win, text=_t('preparing'), font=('', 11))
        self.label.pack(pady=(15, 8))

        self.progress = ttk.Progressbar(self.win, length=380, mode='determinate',
                                         maximum=100 * max(total_files, 1))
        self.progress.pack(pady=5)

        self.pct_label = tk.Label(self.win, text='0%', font=('', 9), fg='#666')
        self.pct_label.pack()

        self._value = 0.0
        # 首次渲染:立即处理事件队列以确保窗口显示
        self.root.update()

    def set_label(self, text):
        self.label.config(text=text)
        self.win.update()

    def update_progress(self, value):
        """更新进度 0.0~1.0 per file, 自动累加文件数"""
        self._value = value
        pct = int(value * 100)
        self.progress['value'] = pct
        self.pct_label.config(text=f'{pct}%')
        self.win.update()

    def close(self):
        try:
            self.win.destroy()
            self.root.destroy()
        except Exception:
            pass


def _make_callback(pw: ProgressWindow, op_key: str):
    """创建进度回调函数，op_key 为操作名称的 i18n key（如 'op_encrypt'）"""
    def cb(progress: float):
        op = _t(op_key)
        if progress < 0.15:
            pw.set_label(_t('stage_preparing', op=op))
        elif progress < 0.45:
            pw.set_label(_t('stage_encoding', op=op))
        elif progress < 0.85:
            pw.set_label(_t('stage_processing', op=op))
        else:
            pw.set_label(_t('stage_finishing', op=op))
    return cb


# ======================== 异步任务框架 (C 引擎) ========================

import threading  # noqa: E402
import time  # noqa: E402


def _thread_below_normal():
    """工作线程降为低于正常优先级, 为系统与其他程序预留性能。"""
    try:
        import ctypes
        ctypes.windll.kernel32.SetThreadPriority(
            ctypes.windll.kernel32.GetCurrentThread(), -1)
    except Exception:
        pass


def _is_auth_error(e):
    """预期性认证失败(密码错误), 供调用方重问密码。"""
    try:
        import kjk9
        return isinstance(e, kjk9.KJK9AuthError)
    except Exception:
        return False


class AsyncTaskWindow:
    """异步进度窗: 任务在低优先级工作线程执行, UI 线程 30ms 轮询刷新。

    进度精确到 0.1%; 取消经 threading.Event 传递给 C 引擎(当前分页完成后停止);
    界面事件循环持续运转, 不会出现未响应/卡顿/死机。"""

    def __init__(self, title, cancelable=True):
        self.root = tk.Tk()
        self.root.geometry('1x1+10000+10000')
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)

        self.win = tk.Toplevel(self.root)
        self.win.title(title)
        self.win.geometry('470x158')
        self.win.resizable(False, False)
        self.win.attributes('-topmost', True)
        self.win.protocol('WM_DELETE_WINDOW', self._on_cancel)

        self.label = tk.Label(self.win, text=_t('preparing'), font=('', 10))
        self.label.pack(pady=(18, 8), padx=14, fill='x')
        self.bar = ttk.Progressbar(self.win, length=420, maximum=1000)
        self.bar.pack(pady=4)
        self.pct = tk.Label(self.win, text='0.0%', font=('', 9), fg='#666')
        self.pct.pack()
        if cancelable:
            tk.Button(self.win, text=_t('btn_cancel'), width=10,
                     command=self._on_cancel).pack(pady=6)

        self._cancel = threading.Event()
        self._state = {'frac': 0.0, 'text': '', 'done': False}
        self._lock = threading.Lock()
        self._result = None
        self._error = None
        self._was_cancelled = False
        self.root.update()

    def _on_cancel(self):
        self._cancel.set()
        self.label.config(text=_t('cancelling'))
        self.win.update_idletasks()

    def _prog(self, frac, text=''):
        with self._lock:
            self._state['frac'] = float(frac or 0.0)
            if text:
                self._state['text'] = str(text)

    def run(self, fn):
        """fn(progress_cb, cancel_event) 在工作线程执行。
        返回 (ok, result, error, cancelled)。"""
        def worker():
            _thread_below_normal()
            try:
                res = fn(self._prog, self._cancel)
                with self._lock:
                    self._result = res
            except Exception as e:  # noqa: BLE001
                # 密码错误等预期性认证失败由调用方重问, 不打堆栈
                if not _is_auth_error(e):
                    import traceback
                    traceback.print_exc()
                with self._lock:
                    self._error = e
            finally:
                with self._lock:
                    self._state['done'] = True

        threading.Thread(target=worker, daemon=True).start()
        while True:
            self.root.update()
            with self._lock:
                frac = self._state['frac']
                txt = self._state['text']
                done = self._state['done']
                err = self._error
            self.bar['value'] = min(1000, int(frac * 1000 + 0.5))
            self.pct.config(text=f'{frac * 100:.1f}%')
            if txt:
                self.label.config(text=txt)
            if err is not None or done:
                break
            time.sleep(0.03)
        try:
            self.win.destroy()
            self.root.destroy()
        except Exception:
            pass
        cancelled = self._cancel.is_set()
        ok = self._error is None and not cancelled
        return ok, self._result, self._error, cancelled


def _kjk9_enabled():
    """compat_format=auto(默认)时右键操作使用 KJKv9 + C 引擎;
    用户显式选择旧格式(KJKv7/KJKv5)时走原文本格式链路。"""
    try:
        cfg = _load_config()
        return cfg.get('compat_format', 'auto') == 'auto'
    except Exception:
        return True


def _kjk9_encrypt(paths, out_path, password):
    """KJKv9 异步加密(多线程 C 引擎, 预留核心, 0.1% 进度, 可取消)。"""
    import kjk9
    names = ', '.join(os.path.basename(str(p).rstrip(os.sep)) for p in paths[:2])
    if len(paths) > 2:
        names += ', ...'
    win = AsyncTaskWindow(_t('encrypting_file', name=names))

    def fn(prog, cancel):
        params = kjk9.plan_params()
        kjk9.encrypt_paths_to_kjk9(paths, out_path, password,
                                   params=params, progress=prog, cancel=cancel)
        return out_path

    ok, res, err, cancelled = win.run(fn)
    if ok:
        messagebox.showinfo(_t('success'),
                            _t('encrypted_to', path=out_path) + f'\n({_t("engine_v9")})')
    elif cancelled:
        _try_cleanup_partial(out_path)
        messagebox.showinfo(_t('progress_title'), _t('op_cancelled'))
    else:
        _try_cleanup_partial(out_path)
        messagebox.showerror(_t('error'), str(err))


def _kjk9_encrypt_flow(paths, out_path):
    """右键加密入口(KJKv9 启用时): 询问密码 → 异步加密。返回 True 表示已处理。"""
    password = ask_password(_t('encryption_password'))
    if password is None:
        return True
    _kjk9_encrypt(paths, out_path, password)
    return True


def _try_cleanup_partial(out_path):
    """取消/失败后删除半成品(若有对应的进度文件也一并清理)。"""
    for p in (out_path, out_path + '.kjkprog'):
        try:
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


def _kjk9_decrypt(filepath, save_dir):
    """KJKv9 异步解密: 密码错误自动重问, 0.1% 进度, 可取消。"""
    import kjk9
    base_name = os.path.basename(filepath)
    while True:
        password = ask_password_required(_t('decryption_password'))
        if password is None:
            return
        win = AsyncTaskWindow(_t('decrypting_file', name=base_name))

        def fn(prog, cancel):
            pkg = kjk9.KJK9Package.open(filepath, password)
            return pkg.extract_files(save_dir, progress=prog, cancel=cancel)

        ok, res, err, cancelled = win.run(fn)
        if ok:
            messagebox.showinfo(
                _t('success'),
                _t('decrypted_files', count=res, path=save_dir)
                + f'\n({_t("engine_v9")})')
            return
        if cancelled:
            messagebox.showinfo(_t('progress_title'), _t('op_cancelled'))
            return
        if isinstance(err, kjk9.KJK9AuthError):
            messagebox.showerror(_t('error'), _t('pwd_wrong'))
            continue  # 重新要密码
        messagebox.showerror(_t('error'), str(err))
        return


def _kjk9_add_files(pkg_path, paths):
    """追加文件到 KJKv9 包(异步, 增量追加不重写已有数据)。"""
    import kjk9
    password = ask_password_required(_t('decryption_password'))
    if password is None:
        return
    names = ', '.join(os.path.basename(str(p).rstrip(os.sep)) for p in paths[:2])
    if len(paths) > 2:
        names += ', ...'
    win = AsyncTaskWindow(_t('adding_files', name=names))

    def fn(prog, cancel):
        pkg = kjk9.KJK9Package.open(pkg_path, password)
        for i, p in enumerate(paths):
            if cancel.is_set():
                raise kjk9.KJK9Cancel('已取消')
            rel = os.path.basename(str(p).rstrip(os.sep))
            pkg.stage_add(p, rel)
            prog(0.1 + 0.4 * (i + 1) / len(paths), f'{rel} ({i + 1}/{len(paths)})')
        pkg.save(progress=prog, cancel=cancel)
        return len(paths)

    ok, res, err, cancelled = win.run(fn)
    if ok:
        messagebox.showinfo(_t('success'),
                            _t('added_files', count=res, path=pkg_path)
                            + f'\n({_t("engine_v9")})')
    elif cancelled:
        messagebox.showinfo(_t('progress_title'), _t('op_cancelled'))
    elif isinstance(err, kjk9.KJK9AuthError):
        messagebox.showerror(_t('error'), _t('pwd_wrong'))
    else:
        messagebox.showerror(_t('error'), str(err))


# ======================== 右键操作辅助函数 ========================

def _ask_merge_dialog(count):
    """弹出合并询问对话框，返回 True/False/None(取消)。"""
    root = tk.Tk()
    root.geometry('1x1+10000+10000')
    root.overrideredirect(True)
    root.attributes('-topmost', True)
    
    ret = messagebox.askyesnocancel(
        _t('batchEncryptTitle'),
        _t('batchMergeConfirmMsg', count=count)
    )
    root.destroy()
    return ret


def _ask_save_kjk_path():
    """弹出保存.kjk文件对话框，返回路径或空字符串。"""
    root = tk.Tk()
    root.geometry('1x1+10000+10000')
    root.overrideredirect(True)
    root.attributes('-topmost', True)
    
    out_path = filedialog.asksaveasfilename(
        title=_t('save_kjk_package'),
        initialfile='encrypted.kjk',
        filetypes=[(_t('kjk_package_type'), '*.kjk')]
    )
    root.destroy()
    return out_path


# ======================== 右键操作函数 ========================

def _pack_folder(folder_path, out_path=None, title_key='packing_file', label_key='packing_label'):
    """将文件夹打包为单个 .kjk,返回输出路径。"""
    if _kjk9_enabled():
        folder_name = os.path.basename(folder_path.rstrip(os.sep))
        if out_path is None:
            out_path = os.path.join(os.path.dirname(folder_path), f'{folder_name}.kjk')
        _kjk9_encrypt_flow([folder_path], out_path)
        return out_path
    pw = None
    try:
        folder_name = os.path.basename(folder_path.rstrip(os.sep))
        if out_path is None:
            out_path = os.path.join(os.path.dirname(folder_path), f'{folder_name}.kjk')

        password = ask_password(_t('encryption_password'))
        if password is None:
            return None

        # 获取格式兼容性参数
        enc_version, legacy, use_pwd_prefix = _get_encryption_params()

        pw = ProgressWindow(title=_t(title_key, name=folder_name))
        pw.set_label(_t(label_key))

        salt = None
        if password and password.strip() and use_pwd_prefix:
            _, salt = make_password_header(password)

        # 收集文件夹条目
        file_entries, empty_dirs = collect_folder_entries(folder_path)
        total = len(file_entries) + len(empty_dirs)
        encrypted_entries = []
        for idx, e in enumerate(file_entries):
            rel = e['rel_path']
            if '.' in rel:
                ename, eext = rel.rsplit('.', 1)
            else:
                ename, eext = rel, ''
            enc_name = encrypt_filename(ename, eext, password, salt, legacy=legacy)
            cipher = encrypt_raw(e['data'], password, salt, legacy=legacy)
            encrypted_entries.append({
                'enc_name': enc_name,
                'ciphertext': cipher,
                'size': len(e['data']),
            })
            pw.update_progress((idx + 1) / total)
            pw.set_label(f"{idx+1}/{total}")
            pw.win.update_idletasks()

        for d in empty_dirs:
            ename, eext = d.rsplit('.', 1) if '.' in d else (d, '')
            enc_name = encrypt_filename(ename, eext, password, salt, legacy=legacy)
            encrypted_entries.append({
                'enc_name': enc_name,
                'ciphertext': '',
                'size': 0,
            })

        kjk = pack_kjk(encrypted_entries, version=enc_version)
        if use_pwd_prefix and password and password.strip():
            kjk, _ = add_password_prefix(kjk, password, salt)

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(kjk)

        pw.update_progress(1.0)
        pw.set_label(_t('done'))
        messagebox.showinfo(_t('success'), _t('saved_to', path=out_path), parent=pw.win)
        return out_path
    except Exception as e:
        print(f'Pack folder failed: {e}')
        try:
            messagebox.showerror(_t('error'), str(e))
        except Exception:
            pass
    finally:
        if pw:
            pw.close()


def _encrypt_here(filepath):
    """加密文件到当前目录"""
    if _kjk9_enabled():
        if os.path.isdir(filepath):
            folder_name = os.path.basename(filepath.rstrip(os.sep)) or 'folder'
            out = os.path.join(os.path.dirname(filepath.rstrip(os.sep)) or os.getcwd(),
                               f'{folder_name}.kjk')
            return _kjk9_encrypt_flow([filepath], out)
        base = os.path.basename(filepath)
        name_parts = base.split('.')
        ext = name_parts.pop() if len(name_parts) > 1 else ''
        name = '.'.join(name_parts) or base
        out = os.path.join(os.path.dirname(filepath), f'{name}.kjk')
        return _kjk9_encrypt_flow([filepath], out)
    if os.path.isdir(filepath):
        _pack_folder(filepath)
        return
    pw = None
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # 先获取密码，再创建进度窗口（避免两个 tk.Tk 同时存在导致卡死）
        password = ask_password(_t('encryption_password'))
        if password is None:
            return

        # 获取格式兼容性参数
        enc_version, legacy, use_pwd_prefix = _get_encryption_params()

        base_name = os.path.basename(filepath)
        pw = ProgressWindow(title=_t('encrypting_file', name=base_name))

        pw.set_label(_t('encrypting_label'))
        salt = None
        if password and password.strip():
            if use_pwd_prefix:
                _, salt = make_password_header(password)
            else:
                # v5 格式: 密码头在条目内,不生成外层 salt
                pass
        cipher = encrypt_raw(data, password, salt, callback=_make_callback(pw, 'op_encrypt'), legacy=legacy)
        pw.update_progress(0.95)

        base = os.path.basename(filepath)
        name_parts = base.split('.')
        ext = name_parts.pop() if len(name_parts) > 1 else ''
        name = '.'.join(name_parts)
        enc_name = encrypt_filename(name, ext, password, salt, legacy=legacy)

        file_entries = [{
            'enc_name': enc_name,
            'has_pwd': bool(password.strip()),
            'ciphertext': cipher,
            'size': len(data),
        }]
        # 打包 .kjk,使用配置的格式版本
        kjk = pack_kjk(file_entries, version=enc_version)
        if use_pwd_prefix and password and password.strip():
            kjk, _ = add_password_prefix(kjk, password, salt)
        out = os.path.join(os.path.dirname(filepath), f'{name}.kjk')
        with open(out, 'w', encoding='utf-8') as f:
            f.write(kjk)

        pw.update_progress(1.0)
        pw.set_label(_t('done'))
        messagebox.showinfo(_t('success'), _t('encrypted_to', path=out), parent=pw.win)
    except Exception as e:
        print(f'Encryption failed: {e}')
        try:
            messagebox.showerror(_t('error'), str(e))
        except Exception:
            pass
    finally:
        if pw:
            pw.close()


def _encrypt_to(filepath):
    """加密文件到指定位置"""
    if _kjk9_enabled():
        if os.path.isdir(filepath):
            folder_name = os.path.basename(filepath.rstrip(os.sep)) or 'folder'
            out = filedialog.asksaveasfilename(
                title=_t('save_kjk_file'), initialfile=f'{folder_name}.kjk')
            if out:
                return _kjk9_encrypt_flow([filepath], out)
            return
        base = os.path.basename(filepath)
        name_parts = base.split('.')
        ext = name_parts.pop() if len(name_parts) > 1 else ''
        name = '.'.join(name_parts) or base
        out = filedialog.asksaveasfilename(
            title=_t('save_kjk_file'), initialfile=f'{name}.kjk')
        if not out:
            return
        return _kjk9_encrypt_flow([filepath], out)
    if os.path.isdir(filepath):
        folder_name = os.path.basename(filepath.rstrip(os.sep))
        out = filedialog.asksaveasfilename(
            title=_t('save_kjk_file'), initialfile=f'{folder_name}.kjk')
        if out:
            _pack_folder(filepath, out, title_key='encrypting_file', label_key='encrypting_label')
        return
    pw = None
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # 先获取密码和保存路径，再创建进度窗口（避免多个 tk 窗口冲突导致卡死）
        password = ask_password(_t('encryption_password'))
        if password is None:
            return

        base = os.path.basename(filepath)
        name_parts = base.split('.')
        ext = name_parts.pop() if len(name_parts) > 1 else ''
        name = '.'.join(name_parts)

        out = filedialog.asksaveasfilename(
            title=_t('save_kjk_file'), initialfile=f'{name}.kjk')
        if not out:
            return

        base_name = os.path.basename(filepath)
        pw = ProgressWindow(title=_t('encrypting_file', name=base_name))

        # 获取格式兼容性参数
        enc_version, legacy, use_pwd_prefix = _get_encryption_params()

        pw.set_label(_t('encrypting_label'))
        salt = None
        if password and password.strip():
            if use_pwd_prefix:
                _, salt = make_password_header(password)
        cipher = encrypt_raw(data, password, salt, callback=_make_callback(pw, 'op_encrypt'), legacy=legacy)

        enc_name = encrypt_filename(name, ext, password, salt, legacy=legacy)

        file_entries = [{
            'enc_name': enc_name,
            'has_pwd': bool(password.strip()),
            'ciphertext': cipher,
            'size': len(data),
        }]
        # 打包 .kjk,使用配置的格式版本
        kjk = pack_kjk(file_entries, version=enc_version)
        if use_pwd_prefix and password and password.strip():
            kjk, _ = add_password_prefix(kjk, password, salt)

        if out:
            with open(out, 'w', encoding='utf-8') as f:
                f.write(kjk)
            pw.update_progress(1.0)
            pw.set_label(_t('done'))
            messagebox.showinfo(_t('success'), _t('encrypted_to', path=out), parent=pw.win)
    except Exception as e:
        print(f'Encryption failed: {e}')
        try:
            messagebox.showerror(_t('error'), str(e))
        except Exception:
            pass
    finally:
        if pw:
            pw.close()


def _pack_to(filepath):
    """打包加密到指定位置"""
    if _kjk9_enabled():
        if os.path.isdir(filepath):
            folder_name = os.path.basename(filepath.rstrip(os.sep)) or 'folder'
            out = filedialog.asksaveasfilename(
                title=_t('save_kjk_package'), initialfile=f'{folder_name}.kjk')
            if out:
                return _kjk9_encrypt_flow([filepath], out)
            return
        base = os.path.basename(filepath)
        name_parts = base.split('.')
        ext = name_parts.pop() if len(name_parts) > 1 else ''
        name = '.'.join(name_parts) or base
        out = filedialog.asksaveasfilename(
            title=_t('save_kjk_package'), initialfile=f'{name}.kjk')
        if not out:
            return
        return _kjk9_encrypt_flow([filepath], out)
    if os.path.isdir(filepath):
        folder_name = os.path.basename(filepath.rstrip(os.sep))
        out = filedialog.asksaveasfilename(
            title=_t('save_kjk_package'), initialfile=f'{folder_name}.kjk')
        if out:
            _pack_folder(filepath, out)
        return
    pw = None
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        # 先获取密码和保存路径，再创建进度窗口（避免多个 tk 窗口冲突导致卡死）
        password = ask_password(_t('encryption_password'))
        if password is None:
            return

        base = os.path.basename(filepath)
        name_parts = base.split('.')
        ext = name_parts.pop() if len(name_parts) > 1 else ''
        name = '.'.join(name_parts)

        out = filedialog.asksaveasfilename(
            title=_t('save_kjk_package'), initialfile=f'{name}.kjk')
        if not out:
            return

        base_name = os.path.basename(filepath)
        pw = ProgressWindow(title=_t('packing_file', name=base_name))

        # 获取格式兼容性参数
        enc_version, legacy, use_pwd_prefix = _get_encryption_params()

        pw.set_label(_t('packing_label'))
        salt = None
        if password and password.strip():
            if use_pwd_prefix:
                _, salt = make_password_header(password)
        cipher = encrypt_raw(data, password, salt, callback=_make_callback(pw, 'op_packing'), legacy=legacy)

        enc_name = encrypt_filename(name, ext, password, salt, legacy=legacy)

        file_entries = [{
            'enc_name': enc_name,
            'has_pwd': bool(password.strip()),
            'ciphertext': cipher,
            'size': len(data),
        }]
        # 打包 .kjk,使用配置的格式版本
        kjk = pack_kjk(file_entries, version=enc_version)
        if use_pwd_prefix and password and password.strip():
            kjk, _ = add_password_prefix(kjk, password, salt)

        if out:
            with open(out, 'w', encoding='utf-8') as f:
                f.write(kjk)
            pw.update_progress(1.0)
            pw.set_label(_t('done'))
            messagebox.showinfo(_t('success'), _t('saved_to', path=out), parent=pw.win)
    except Exception as e:
        print(f'Pack failed: {e}')
        try:
            messagebox.showerror(_t('error'), str(e))
        except Exception:
            pass
    finally:
        if pw:
            pw.close()


def _add_to_kjk(filepath):
    """添加文件或文件夹到已有的 .kjk 包 (右键菜单调用)"""
    target = filedialog.askopenfilename(
        title=_t('select_kjk_to_add'),
        filetypes=[(_t('kjk_package_type'), '*.kjk'), (_t('all_files_type'), '*.*')])
    if not target:
        return
    # KJKv9 包 → 异步增量追加(不重写已有数据, C 引擎)
    try:
        import kjk9
        if kjk9.is_kjk9(target):
            if not _kjk9_enabled():
                messagebox.showerror(_t('error'), _t('v9_disabled'))
                return
            _kjk9_add_files(target, [filepath])
            return
    except Exception:
        pass

    pw = None
    try:
        with open(target, 'r', encoding='utf-8') as f:
            kjk_content = f.read()

        existing_results = unpack_kjk(kjk_content)
        has_pwd_header, exist_salt_hex, exist_hash_hex, exist_actual = detect_password_header(existing_results)

        if has_pwd_header:
            password = ask_password_required(_t('decryption_password'))
            if password is None:
                return
            if not verify_password(password, exist_salt_hex, exist_hash_hex):
                messagebox.showerror(_t('error'), _t('pwd_wrong'))
                return
        else:
            password = ask_password(_t('encryption_password'))
            if password is None:
                return

        # 收集要添加的条目(文件或文件夹)
        if os.path.isdir(filepath):
            file_entries, empty_dirs = collect_folder_entries(filepath)
        else:
            with open(filepath, 'rb') as f:
                data = f.read()
            file_entries = [{'rel_path': os.path.basename(filepath), 'data': data}]
            empty_dirs = []

        new_names = [e['rel_path'] for e in file_entries] + empty_dirs
        duplicates = [n for n in new_names
                      if any(r.get('originalName') == n for r in exist_actual)]
        if duplicates:
            names = '\n'.join(f'  - {n}' for n in duplicates[:5])
            ret = messagebox.askyesno(
                _t('error'),
                _t('duplicate_in_package', names=names, count=len(duplicates)))
            if not ret:
                return

        # v7: 复用现有密码头中的 salt;若要为无密码包新增密码,则生成新 salt
        salt = None
        if password and password.strip():
            if has_pwd_header:
                _, salt = detect_password_prefix(kjk_content)
            else:
                _, salt = make_password_header(password)

        base_name = os.path.basename(filepath.rstrip(os.sep))
        pw = ProgressWindow(title=_t('adding_to_package', name=base_name))
        pw.set_label(_t('encrypting_new_file'))

        new_entries = []
        total = len(file_entries) + len(empty_dirs)
        for idx, e in enumerate(file_entries):
            rel = e['rel_path']
            if '.' in rel:
                name, ext = rel.rsplit('.', 1)
            else:
                name, ext = rel, ''
            enc_name = encrypt_filename(name, ext, password, salt)
            new_entries.append({
                'enc_name': enc_name,
                'ciphertext': encrypt_raw(e['data'], password, salt),
                'size': len(e['data']),
            })
            pw.update_progress((idx + 1) / total * 0.7)
            pw.win.update_idletasks()

        for d in empty_dirs:
            enc_name = encrypt_filename(d, '', password, salt)
            new_entries.append({
                'enc_name': enc_name,
                'ciphertext': '',
                'size': 0,
            })

        pw.set_label(_t('appending_to_package'))
        new_content = append_to_kjk(kjk_content, new_entries)
        if password and password.strip() and not has_pwd_header:
            new_content, _ = add_password_prefix(new_content, password, salt)

        with open(target, 'w', encoding='utf-8') as f:
            f.write(new_content)

        pw.update_progress(1.0)
        pw.set_label(_t('done'))

        results = unpack_kjk(new_content)
        actual_files = [r for r in results
                        if not r.get('_is_password_header')
                        and not r.get('_is_password_prefix_header')]
        file_list = '\n'.join(f"  - {r.get('originalName', 'untitled')} ({r.get('size', 0)} {_t('bytes_unit')})"
                              for r in actual_files)
        messagebox.showinfo(
            _t('added_to_package'),
            _t('file_added_msg', count=len(actual_files), file_list=file_list),
            parent=pw.win)
    except Exception as e:
        print(f'Add to KJK failed: {e}')
        try:
            messagebox.showerror(_t('error'), str(e))
        except Exception:
            pass
    finally:
        if pw:
            pw.close()


def _decrypt_here(filepath):
    """解密 .kjk 文件到当前目录"""
    _do_decrypt(filepath, os.path.dirname(filepath))


def _decrypt_to(filepath):
    """解密 .kjk 文件到指定目录"""
    dest_dir = filedialog.askdirectory(title=_t('save_kjk_file'))
    if not dest_dir:
        return
    _do_decrypt(filepath, dest_dir)


def _peek_password_prefix(filepath):
    """仅读取 .kjk 文件头,探测是否带密码头前缀,返回 (salt_bytes, hash_hex)。

    不整文件加载,只读开头一小段,用于决定是否需要先询问密码。
    """
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            head = f.read(512)
        has_pwd, salt, hash_hex, _ = detect_password_prefix(head)
        if has_pwd and salt and hash_hex:
            return salt, hash_hex
        return None, None
    except Exception:
        return None, None


def _do_decrypt(filepath, save_dir):
    """解密 .kjk 文件到指定目录 (旧版文本流式 + KJKv9 二进制)。

    全程工作线程执行 + 逐行读盘 + 逐条目解密落盘:
    大包不再整文件读入内存/不再卡顿, 0.1% 进度, 可取消。
    """
    # KJKv9 二进制包 → 异步 C 引擎解密(按需分页, 0.1% 进度, 可取消)
    try:
        import kjk9
        if kjk9.is_kjk9(filepath):
            if not _kjk9_enabled():
                messagebox.showerror(_t('error'), _t('v9_disabled'))
                return
            _kjk9_decrypt(filepath, save_dir)
            return
    except Exception:
        pass

    base_name = os.path.basename(filepath)
    password = ''
    salt_bytes = None

    # 仅读文件头探测密码头前缀,若有则先验证密码
    try:
        salt_bytes, hash_hex = _peek_password_prefix(filepath)
        if salt_bytes and hash_hex:
            while True:
                pwd = ask_password_required(_t('decryption_password'))
                if pwd is None:
                    return
                pwd = pwd.strip()
                if verify_password(pwd, salt_bytes.hex(), hash_hex):
                    password = pwd
                    break
                messagebox.showerror(_t('error'), _t('pwd_wrong'))
    except Exception:
        pass

    while True:
        win = AsyncTaskWindow(_t('decrypting_file', name=base_name))

        def fn(prog, cancel):
            return extract_legacy_package_file(
                filepath, password, salt_bytes, save_dir, callback=prog)

        ok, res, err, cancelled = win.run(fn)
        if cancelled:
            messagebox.showinfo(_t('progress_title'), _t('op_cancelled'))
            return
        if ok:
            if res == 0 and not password:
                # 可能为旧版逐条目密码(v5 独立密码头/pwd: 前缀),重问密码再试
                pwd = ask_password_required(_t('decryption_password'))
                if pwd is None:
                    return
                password = pwd.strip()
                continue
            messagebox.showinfo(
                _t('success'),
                _t('decrypted_files', count=res, path=save_dir))
            return
        messagebox.showerror(_t('error'), str(err))
        return


# ======================== 批量合并加密 ========================

def _batch_encrypt_merge(paths, out_path):
    """将多个文件/文件夹合并加密为单个 .kjk 包"""
    if _kjk9_enabled():
        _kjk9_encrypt_flow(paths, out_path)
        return
    pw = None
    try:
        password = ask_password(_t('encryption_password'))
        if password is None:
            return

        # 获取格式兼容性参数
        enc_version, legacy, use_pwd_prefix = _get_encryption_params()

        # 收集所有条目
        all_entries = []
        total = len(paths)
        pw = ProgressWindow(title=_t('batchEncryptTitle'))
        pw.set_label(_t('mergeMultipleTitle', count=total))

        salt = None
        if password and password.strip() and use_pwd_prefix:
            _, salt = make_password_header(password)

        for idx, path in enumerate(paths):
            name = os.path.basename(path.rstrip(os.sep))
            pw.set_label(f'[{idx+1}/{total}] {name}')
            pw.win.update_idletasks()

            if os.path.isdir(path):
                entries, empty_dirs = collect_folder_entries(path)
                for e in entries:
                    if '.' in e['rel_path']:
                        ename, eext = e['rel_path'].rsplit('.', 1)
                    else:
                        ename, eext = e['rel_path'], ''
                    enc_name = encrypt_filename(ename, eext, password, salt, legacy=legacy)
                    all_entries.append({
                        'enc_name': enc_name,
                        'ciphertext': encrypt_raw(e['data'], password, salt, legacy=legacy),
                        'size': len(e['data']),
                    })
                for d in empty_dirs:
                    enc_name = encrypt_filename(d, '', password, salt, legacy=legacy)
                    all_entries.append({
                        'enc_name': enc_name,
                        'ciphertext': '',
                        'size': 0,
                    })
            else:
                with open(path, 'rb') as f:
                    data = f.read()
                base = os.path.basename(path)
                name_parts = base.split('.')
                ext = name_parts.pop() if len(name_parts) > 1 else ''
                ename = '.'.join(name_parts)
                enc_name = encrypt_filename(ename, ext, password, salt, legacy=legacy)
                all_entries.append({
                    'enc_name': enc_name,
                    'ciphertext': encrypt_raw(data, password, salt, legacy=legacy),
                    'size': len(data),
                })
            pw.update_progress((idx + 1) / total)

        # 打包
        pw.set_label(_t('packing_label'))
        pw.win.update_idletasks()
        kjk = pack_kjk(all_entries, version=enc_version)
        if use_pwd_prefix and password and password.strip():
            kjk, _ = add_password_prefix(kjk, password, salt)

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(kjk)

        pw.update_progress(1.0)
        pw.set_label(_t('done'))
        messagebox.showinfo(_t('success'), _t('saved_to', path=out_path), parent=pw.win)
    except Exception as e:
        print(f'Batch encrypt merge failed: {e}')
        import traceback
        traceback.print_exc()
        try:
            messagebox.showerror(_t('error'), str(e))
        except Exception:
            pass
    finally:
        if pw:
            pw.close()


# ======================== 右键菜单注册 ========================

MENU_NAME_KEY = 'menu_name'

# 所有文件的菜单项（仅加密，解密只对 .kjk 有效）
# flag 使用 --batch-encrypt/--batch-decrypt/--batch-add 以支持多选合并到单一实例
MENU_ITEMS = [
    {
        'id': 'encrypt_here',
        'label_key': 'menu_encrypt_here',
        'flag': '--batch-encrypt',
    },
    {
        'id': 'encrypt_to',
        'label_key': 'menu_encrypt_to',
        'flag': '--batch-encrypt',
    },
    {
        'id': 'pack_to',
        'label_key': 'menu_pack_to',
        'flag': '--batch-encrypt',
    },
]

# .kjk 文件的菜单项（解密相关 + 追加）
KJK_MENU_ITEMS = [
    {
        'id': 'decrypt_here',
        'label_key': 'menu_decrypt_here',
        'flag': '--batch-decrypt',
    },
    {
        'id': 'decrypt_to',
        'label_key': 'menu_decrypt_to',
        'flag': '--batch-decrypt',
    },
    {
        'id': 'add_to_kjk',
        'label_key': 'menu_add_to_kjk',
        'flag': '--batch-add',
    },
]


def get_exe_path():
    """返回主程序路径。

    打包模式: 返回 exe 路径
    脚本模式: 返回 main.py 路径 (build_command 会自动加上 Python 解释器)
    """
    if getattr(sys, 'frozen', False):
        return sys.executable
    return os.path.abspath(os.path.join(os.path.dirname(__file__), 'main.py'))


def build_command(exe_path, action_id, flag='--batch-encrypt'):
    """构建右键菜单命令。

    使用 --verb 传递子动作 + --batch-* 携带选中路径。
    使用 "%1"(带引号的单个选中文件)而非 %*: 在部分 Windows 11 上,命令行的
    %* 会被展开成空(导致"未选中任何文件"),而 %1 可靠地传入点击的文件。
    v1.0.3 即采用 "%1" 结构并稳定工作。
    格式: "<exe>" --verb <action> --batch-encrypt "%1"
    """
    if exe_path.lower().endswith('.exe'):
        return f'"{exe_path}" --verb {action_id} {flag} "%1"'
    else:
        python_exe = sys.executable
        return f'"{python_exe}" "{exe_path}" --verb {action_id} {flag} "%1"'


def build_browse_command(exe_path):
    """双击 .kjk 的默认打开命令: 独立浏览窗口(密码→目录树), 不启动主程序。"""
    if exe_path.lower().endswith('.exe'):
        return f'"{exe_path}" --browse "%1"'
    python_exe = sys.executable
    return f'"{python_exe}" "{exe_path}" --browse "%1"'


def _get_menu_name():
    """Get the localized context menu name."""
    return _t(MENU_NAME_KEY)


def _get_localized_menu_items(exe_path=None):
    """Get all-file menu items with localized labels and generated commands."""
    if exe_path is None:
        exe_path = get_exe_path()
    items = []
    for item in MENU_ITEMS:
        items.append({
            'id': item['id'],
            'label': _t(item['label_key']),
            'command': build_command(exe_path, item['id'], flag=item.get('flag', '--batch-encrypt')),
        })
    return items


def _get_localized_kjk_menu_items(exe_path=None):
    """Get .kjk-specific menu items with localized labels and generated commands."""
    if exe_path is None:
        exe_path = get_exe_path()
    items = []
    for item in KJK_MENU_ITEMS:
        items.append({
            'id': item['id'],
            'label': _t(item['label_key']),
            'command': build_command(exe_path, item['id'], flag=item.get('flag', '--batch-encrypt')),
        })
    return items


def is_admin():
    import ctypes
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def register_context_menu(menu_items=None, exe_path=None):
    if not is_admin():
        return False, _t('need_admin_register')

    if exe_path is None:
        exe_path = get_exe_path()
    if menu_items is None:
        menu_items = _get_localized_menu_items(exe_path)
    kjk_menu_items = _get_localized_kjk_menu_items(exe_path)

    menu_name = _get_menu_name()

    try:
        # ===== 所有文件 (*) 的加密菜单 (级联子菜单, 结构对齐 v1.0.3) =====
        key_path = fr'*\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, key_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)

        submenu_path = fr'*\shell\{menu_name}\shell'
        for item in menu_items:
            item_path = fr'{submenu_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])
                winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # ===== 桌面背景右键菜单 =====
        bg_key_path = fr'Directory\Background\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, bg_key_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
        bg_sub_path = fr'Directory\Background\shell\{menu_name}\shell'
        for item in menu_items:
            item_path = fr'{bg_sub_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])
                winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # ===== 文件夹右键菜单 (Directory\shell) =====
        dir_key_path = fr'Directory\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, dir_key_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
        dir_sub_path = fr'Directory\shell\{menu_name}\shell'
        for item in menu_items:
            item_path = fr'{dir_sub_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])
                winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # ===== .kjk 文件关联 (ProgID) =====
        prog_id = 'KJKEncryptor.kjk'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, prog_id) as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, 'KJK Encrypted Package')
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\DefaultIcon') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, exe_path)

        # .kjk 扩展名关联
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, '.kjk') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, prog_id)

        # .kjk 文件的右键解密菜单
        kjk_shell_path = fr'{prog_id}\shell\{menu_name}'
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, kjk_shell_path) as key:
            winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, menu_name)
            winreg.SetValueEx(key, 'SubCommands', 0, winreg.REG_SZ, '')
            winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
        kjk_sub_path = fr'{kjk_shell_path}\shell'
        for item in kjk_menu_items:
            item_path = fr'{kjk_sub_path}\{item["id"]}'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, item_path) as key:
                winreg.SetValueEx(key, 'MUIVerb', 0, winreg.REG_SZ, item['label'])
                winreg.SetValueEx(key, 'Icon', 0, winreg.REG_SZ, exe_path)
            cmd_path = fr'{item_path}\command'
            with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as key:
                winreg.SetValueEx(key, '', 0, winreg.REG_SZ, item['command'])

        # .kjk 文件默认打开方式 (双击 .kjk 文件时直接打开浏览窗口)
        open_cmd = build_browse_command(exe_path)
        with winreg.CreateKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell\open\command') as key:
            winreg.SetValueEx(key, '', 0, winreg.REG_SZ, open_cmd)

        return True, _t('register_success')
    except PermissionError:
        return False, _t('permission_denied')
    except Exception as e:
        return False, _t('register_failed', error=str(e))


def unregister_context_menu():
    if not is_admin():
        return False, _t('need_admin_unregister')

    menu_name = _get_menu_name()
    prog_id = 'KJKEncryptor.kjk'

    try:
        # 清理所有文件/文件夹右键菜单 (新顶级动词 + 旧级联父菜单)
        all_ids = [item['id'] for item in MENU_ITEMS]
        file_roots = [fr'*\shell', fr'Directory\shell', fr'Directory\Background\shell']
        for root in file_roots:
            # 新顶级动词
            for cid in all_ids:
                vk = fr'{root}\KJK{cid}'
                try:
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{vk}\command')
                except FileNotFoundError:
                    pass
                try:
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, vk)
                except FileNotFoundError:
                    pass
            # 旧级联结构: {root}\{menu_name}\shell\{id}
            old_parent = fr'{root}\{menu_name}'
            try:
                old_shell = fr'{old_parent}\shell'
                for cid in all_ids:
                    try:
                        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{old_shell}\{cid}\command')
                    except FileNotFoundError:
                        pass
                    try:
                        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{old_shell}\{cid}')
                    except FileNotFoundError:
                        pass
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, old_shell)
            except FileNotFoundError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, old_parent)
            except FileNotFoundError:
                pass

        # 清理 .kjk 文件右键菜单 (新顶级 + 旧级联)
        kjk_ids = [item['id'] for item in KJK_MENU_ITEMS]
        for cid in kjk_ids:
            vk = fr'{prog_id}\shell\KJK{cid}'
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{vk}\command')
            except FileNotFoundError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, vk)
            except FileNotFoundError:
                pass
        old_kjk = fr'{prog_id}\shell\{menu_name}'
        try:
            old_kjk_shell = fr'{old_kjk}\shell'
            for cid in kjk_ids:
                try:
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{old_kjk_shell}\{cid}\command')
                except FileNotFoundError:
                    pass
                try:
                    winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{old_kjk_shell}\{cid}')
                except FileNotFoundError:
                    pass
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, old_kjk_shell)
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, old_kjk)
        except FileNotFoundError:
            pass

        # 清理 .kjk 文件默认打开方式
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell\open\command')
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell\open')
        except FileNotFoundError:
            pass

        # 清理 ProgID 和 .kjk 扩展名关联
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\DefaultIcon')
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell')
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, prog_id)
        except FileNotFoundError:
            pass

        # 删除 .kjk 扩展名关联（仅当指向我们的 ProgID 时）
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '.kjk') as key:
                val, _ = winreg.QueryValueEx(key, '')
                if val == prog_id:
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


def is_registered() -> bool:
    menu_name = _get_menu_name()
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, fr'*\shell\{menu_name}') as key:
            return True
    except FileNotFoundError:
        return False
    except Exception:
        return False
