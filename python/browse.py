# -*- coding: utf-8 -*-
"""KJK 包浏览模式: 双击 .kjk 打开的轻量资源管理器窗口。

流程: 密码窗(无密码跳过) → 仅解密目录信息(进度窗) → 目录树。
树上操作(重命名/删除/拖入/查看)全部先落在内存暂存, Ctrl+S 才真正写入包;
拖出到外部则在拖拽发起时立即局部解密生成目标文件。
保存/解密/改密码/整理走 kjk9 多线程调度器(C 引擎数据通路, 低优先级,
预留核心给系统), 进度精确到 0.1%, 界面全程响应。
旧格式(KJKv1..v8)兼容加载; 保存时询问是否升级为 KJKv9 引擎格式。
"""

import os
import sys
import threading
import time

_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

import tkinter as tk
from tkinter import ttk

try:
    from config import load_config
except Exception:
    def load_config(default):
        return dict(default)

import kjk9
from kjk9 import (KJK9Error, KJK9AuthError, KJK9Cancel, KJK9Package,
                  encrypt_entries_to_kjk9, peek_info)
import engine

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    _HAS_DND = True
except Exception:
    TkinterDnD = None
    DND_FILES = ''
    _HAS_DND = False


# ======================== i18n ========================

_LANG_KEYS = {
    'appName': {'en': 'KJK Encryptor', 'zh-HK': 'KJK Encryptor', 'zh-CN': 'KJK Encryptor'},
    'winTitle': {'en': 'KJK Package Browser', 'zh-HK': 'KJK 包瀏覽器', 'zh-CN': 'KJK 包浏览器'},
    'pwdTitle': {'en': 'Password Required', 'zh-HK': '需要密碼', 'zh-CN': '需要密码'},
    'pwdPrompt': {'en': 'This package is password-protected.\nEnter password to open:',
                  'zh-HK': '此包受密碼保護。\n請輸入密碼開啟：', 'zh-CN': '此包受密码保护。\n请输入密码打开:'},
    'pwdWrong': {'en': 'Wrong password. Try again.', 'zh-HK': '密碼錯誤，請重試。', 'zh-CN': '密码错误，请重试。'},
    'btnOpen': {'en': 'Open', 'zh-HK': '開啟', 'zh-CN': '打开'},
    'btnCancel': {'en': 'Cancel', 'zh-HK': '取消', 'zh-CN': '取消'},
    'btnOk': {'en': 'OK', 'zh-HK': '確定', 'zh-CN': '确定'},
    'btnYes': {'en': 'Yes', 'zh-HK': '是', 'zh-CN': '是'},
    'btnNo': {'en': 'No', 'zh-HK': '否', 'zh-CN': '否'},
    'btnRetry': {'en': 'Retry', 'zh-HK': '重試', 'zh-CN': '重试'},
    'btnSkip': {'en': 'Skip', 'zh-HK': '跳過', 'zh-CN': '跳过'},
    'btnDiscard': {'en': 'Discard', 'zh-HK': '放棄', 'zh-CN': '放弃'},
    'btnSave': {'en': 'Save', 'zh-HK': '保存', 'zh-CN': '保存'},
    'btnDontSave': {'en': "Don't Save", 'zh-HK': '不保存', 'zh-CN': '不保存'},
    'reading': {'en': 'Reading directory…', 'zh-HK': '正在讀取目錄…', 'zh-CN': '正在读取目录…'},
    'openingPkg': {'en': 'Opening package…', 'zh-HK': '正在開啟包…', 'zh-CN': '正在打开包…'},
    'decrypting': {'en': 'Decrypting…', 'zh-HK': '解密中…', 'zh-CN': '解密中…'},
    'saving': {'en': 'Saving package…', 'zh-HK': '正在保存包…', 'zh-CN': '正在保存包…'},
    'rekeying': {'en': 'Re-encrypting…', 'zh-HK': '正在重加密…', 'zh-CN': '正在重加密…'},
    'compacting': {'en': 'Compacting…', 'zh-HK': '正在整理…', 'zh-CN': '正在整理…'},
    'upgrading': {'en': 'Upgrading to new engine…', 'zh-HK': '正在升級新引擎…', 'zh-CN': '正在升级新引擎…'},
    'canceled': {'en': 'Canceled.', 'zh-HK': '已取消。', 'zh-CN': '已取消。'},
    'openFailed': {'en': 'Open failed', 'zh-HK': '開啟失敗', 'zh-CN': '打开失败'},
    'notFound': {'en': 'File not found:\n{}', 'zh-HK': '找不到檔案：\n{}', 'zh-CN': '找不到文件:\n{}'},
    'errTitle': {'en': 'Error', 'zh-HK': '錯誤', 'zh-CN': '错误'},
    'hintTitle': {'en': 'Hint', 'zh-HK': '提示', 'zh-CN': '提示'},
    'okTitle': {'en': 'Success', 'zh-HK': '成功', 'zh-CN': '成功'},
    'confirmTitle': {'en': 'Confirm', 'zh-HK': '確認', 'zh-CN': '确认'},
    # toolbar
    'tbAdd': {'en': '+ Add', 'zh-HK': '+ 添加', 'zh-CN': '+ 添加'},
    'btnAddFiles': {'en': 'Add files', 'zh-HK': '添加檔案', 'zh-CN': '添加文件'},
    'btnAddFolder': {'en': 'Add folder', 'zh-HK': '添加資料夾', 'zh-CN': '添加文件夹'},
    'tbExtract': {'en': 'Extract…', 'zh-HK': '解壓…', 'zh-CN': '解压…'},
    'tbRename': {'en': 'Rename', 'zh-HK': '重新命名', 'zh-CN': '重命名'},
    'tbDelete': {'en': 'Delete', 'zh-HK': '刪除', 'zh-CN': '删除'},
    'tbPwd': {'en': 'Password', 'zh-HK': '密碼', 'zh-CN': '密码'},
    'tbSave': {'en': 'Save', 'zh-HK': '保存', 'zh-CN': '保存'},
    'tbCompact': {'en': 'Compact', 'zh-HK': '整理', 'zh-CN': '整理'},
    # tree
    'colName': {'en': 'Name', 'zh-HK': '名稱', 'zh-CN': '名称'},
    'colSize': {'en': 'Size', 'zh-HK': '大小', 'zh-CN': '大小'},
    'noSelection': {'en': 'No selection', 'zh-HK': '未選擇', 'zh-CN': '未选择'},
    'selFile': {'en': '1 file', 'zh-HK': '1 個檔案', 'zh-CN': '1 个文件'},
    'selFiles': {'en': '{} files', 'zh-HK': '{} 個檔案', 'zh-CN': '{} 个文件'},
    'selDir': {'en': 'folder, {} items', 'zh-HK': '資料夾，{} 項', 'zh-CN': '文件夹，{} 项'},
    'newMark': {'en': 'new', 'zh-HK': '新增', 'zh-CN': '新增'},
    # status
    'statDirty': {'en': 'Unsaved: +{add} added, {deleted} deleted, {rn} renamed',
                  'zh-HK': '未保存：+{add} 新增、{deleted} 刪除、{rn} 改名',
                  'zh-CN': '未保存: +{add} 新增、{deleted} 删除、{rn} 改名'},
    'statClean': {'en': 'All changes saved', 'zh-HK': '所有修改已保存', 'zh-CN': '所有修改已保存'},
    'statReady': {'en': 'Ready', 'zh-HK': '就緒', 'zh-CN': '就绪'},
    'statBusy': {'en': 'Working…', 'zh-HK': '處理中…', 'zh-CN': '处理中…'},
    'statSaved': {'en': 'Saved {}', 'zh-HK': '已保存 {}', 'zh-CN': '已保存 {}'},
    'statExtracted': {'en': 'Extracted {} file(s)', 'zh-HK': '已解壓 {} 個檔案', 'zh-CN': '已解压 {} 个文件'},
    'statDeleted': {'en': 'Deleted {}', 'zh-HK': '已刪除 {}', 'zh-CN': '已删除 {}'},
    'statRenamed': {'en': 'Renamed', 'zh-HK': '已重新命名', 'zh-CN': '已重命名'},
    'statAdded': {'en': 'Added {} file(s)', 'zh-HK': '已添加 {} 個檔案', 'zh-CN': '已添加 {} 个文件'},
    'statPwdChanged': {'en': 'Password changed', 'zh-HK': '密碼已修改', 'zh-CN': '密码已修改'},
    'statCompact': {'en': 'Compacted: {} → {}', 'zh-HK': '已整理：{} → {}', 'zh-CN': '已整理: {} → {}'},
    'statUpgraded': {'en': 'Upgraded to KJKv9', 'zh-HK': '已升級 KJKv9', 'zh-CN': '已升级 KJKv9'},
    'noChanges': {'en': 'No unsaved changes.', 'zh-HK': '沒有未保存的修改。', 'zh-CN': '没有未保存的修改。'},
    # dialogs
    'extractTo': {'en': 'Extract to folder', 'zh-HK': '解壓到資料夾', 'zh-CN': '解压到文件夹'},
    'delConfirm': {'en': 'Delete "{}" from package?\n(Applied when you save)',
                   'zh-HK': '從包中刪除「{}」？\n（保存時生效）', 'zh-CN': '从包中删除"{}"?\n(保存时生效)'},
    'renameTitle': {'en': 'Rename', 'zh-HK': '重新命名', 'zh-CN': '重命名'},
    'renamePrompt': {'en': 'New name:', 'zh-HK': '新名稱：', 'zh-CN': '新名称:'},
    'badName': {'en': 'Invalid name.', 'zh-HK': '名稱無效。', 'zh-CN': '名称无效。'},
    'nameExists': {'en': 'Name already exists in package.',
                   'zh-HK': '包中已存在同名項。', 'zh-CN': '包中已存在同名项。'},
    'pwdChangeTitle': {'en': 'Change Password', 'zh-HK': '修改密碼', 'zh-CN': '修改密码'},
    'pwdNew': {'en': 'New password:', 'zh-HK': '新密碼：', 'zh-CN': '新密码:'},
    'pwdConfirm': {'en': 'Confirm password:', 'zh-HK': '確認密碼：', 'zh-CN': '确认密码:'},
    'pwdMismatch': {'en': 'Passwords do not match.', 'zh-HK': '兩次輸入不一致。', 'zh-CN': '两次输入不一致。'},
    'pwdNoneWarn': {'en': 'Empty password = no protection. Continue?',
                    'zh-HK': '空密碼即不設密碼，繼續？', 'zh-CN': '空密码即不设密码，继续?'},
    'closeDirty': {'en': 'You have unsaved changes.\nSave before closing?',
                   'zh-HK': '有未保存的修改。\n關閉前要保存嗎？', 'zh-CN': '有未保存的修改。\n关闭前要保存吗?'},
    'saveDirtyFirst': {'en': 'Save changes first, then retry.',
                       'zh-HK': '請先保存修改再操作。', 'zh-CN': '请先保存修改再操作。'},
    'upgradeTitle': {'en': 'Upgrade Engine Format', 'zh-HK': '升級引擎格式', 'zh-CN': '升级引擎格式'},
    'upgradeAsk': {'en': 'This package uses the old text format (KJKv{}).\n'
                          'Upgrade to the new KJKv9 binary engine?\n'
                          '· Faster (C engine multi-threaded)\n'
                          '· On-demand decryption & instant open\n'
                          '· Old file will be replaced after success',
                   'zh-HK': '此包使用舊文字格式 (KJKv{})。\n'
                            '要升級到新 KJKv9 二進制引擎嗎？\n'
                            '· 更快（C 引擎多線程）\n'
                            '· 按需解密、秒開\n'
                            '· 成功後替換原檔案',
                   'zh-CN': '此包使用旧文本格式 (KJKv{})。\n'
                            '要升级到新 KJKv9 二进制引擎吗?\n'
                            '· 更快(C 引擎多线程)\n'
                            '· 按需解密、秒开\n'
                            '· 成功后替换原文件'},
    'upgradeOnlySave': {'en': 'Save requires the old format to be repacked. Upgrade to KJKv9 now?',
                        'zh-HK': '保存需重新打包舊格式。要現在升級 KJKv9 嗎？',
                        'zh-CN': '保存需重新打包旧格式。要现在升级 KJKv9 吗?'},
    'srcMissing': {'en': 'Source file no longer readable:\n{}\n\nSkip this pending add?',
                   'zh-HK': '來源檔案已不可讀：\n{}\n\n跳過此新增？',
                   'zh-CN': '源文件已不可读:\n{}\n\n跳过此新增?'},
    'taskFailed': {'en': 'Operation failed:\n{}\n\nRetry?',
                   'zh-HK': '操作失敗：\n{}\n\n重試？', 'zh-CN': '操作失败:\n{}\n\n重试?'},
    'dragHintBig': {'en': 'Item too large for drag-out. Use Extract instead.',
                    'zh-HK': '項目太大，不支援拖出。請用「解壓」。', 'zh-CN': '项目太大，不支持拖出。请用"解压"。'},
    'dropAddTo': {'en': 'Add {} item(s) to "{}"', 'zh-HK': '添加 {} 項到「{}」', 'zh-CN': '添加 {} 项到"{}"'},
    'dropAddRoot': {'en': 'Add {} item(s) to root', 'zh-HK': '添加 {} 項到根目錄', 'zh-CN': '添加 {} 项到根目录'},
    'dropConfirmTitle': {'en': 'Copy into package', 'zh-HK': '複製到包內', 'zh-CN': '复制到包内'},
    'dropConfirmMsg': {'en': 'Drag copy: {0} item(s) will be copied into the folder "/{1}" inside the package.\n\nContinue?',
                       'zh-HK': '拖放複製：將把 {0} 項複製到包內「/{1}」目錄下。\n\n繼續？',
                       'zh-CN': '拖放复制：将把 {0} 项复制到包内「/{1}」目录下。\n\n继续？'},
    'dropConfirmRootMsg': {'en': 'Drag copy: {0} item(s) will be copied to the ROOT of the package.\n\nContinue?',
                           'zh-HK': '拖放複製：將把 {0} 項複製到包內根目錄。\n\n繼續？',
                           'zh-CN': '拖放复制：将把 {0} 项复制到包内根目录。\n\n继续？'},
    'dropCanceled': {'en': 'Copy canceled', 'zh-HK': '已取消複製', 'zh-CN': '已取消复制'},
    'btnCopyHere': {'en': 'Copy', 'zh-HK': '複製', 'zh-CN': '复制'},
    'emptyPkg': {'en': '(empty package)', 'zh-HK': '(空包)', 'zh-CN': '(空包)'},
    'legacyBadge': {'en': 'legacy', 'zh-HK': '舊格式', 'zh-CN': '旧格式'},
    'engineBadge': {'en': 'C engine', 'zh-HK': 'C 引擎', 'zh-CN': 'C 引擎'},
    'pyBadge': {'en': 'Python fallback', 'zh-HK': 'Python 後備', 'zh-CN': 'Python 后备'},
    'itemsCount': {'en': '{} items', 'zh-HK': '{} 項', 'zh-CN': '{} 项'},
    'viewing': {'en': 'Opening {}…', 'zh-HK': '正在開啟 {}…', 'zh-CN': '正在打开 {}…'},
    'compactNone': {'en': 'No holes to compact.', 'zh-HK': '沒有可整理的空間。', 'zh-CN': '没有可整理的空间。'},
    'compactAsk': {'en': 'Compact now? Frees {}.', 'zh-HK': '現在整理？可釋放 {}。', 'zh-CN': '现在整理? 可释放 {}。'},
    'protectPwd': {'en': 'Passwords never leave this window.',
                   'zh-HK': '密碼不會離開此視窗。', 'zh-CN': '密码不会离开此窗口。'},
}

_CONFIG = load_config({'theme': 'light', 'lang': 'zh-CN'})
_LANG = _CONFIG.get('lang', 'zh-CN')

_COLORS = {
    'light': {
        'bg': '#f5f5f7', 'fg': '#1d1d1f', 'card': '#ffffff',
        'secondary': '#e8e8ed', 'accent': '#0071e3', 'border': '#d2d2d7',
        'text_secondary': '#6e6e73', 'hover': '#e5e5ea',
        'sel_bg': '#e8f1fd', 'danger': '#d70015',
        'guide': '#ececf1', 'new_fg': '#1d8a4e',
        'drop_bg': '#cfe4ff',
    },
    'dark': {
        'bg': '#1c1c1e', 'fg': '#f5f5f7', 'card': '#2c2c2e',
        'secondary': '#3a3a3c', 'accent': '#2997ff', 'border': '#48484a',
        'text_secondary': '#98989d', 'hover': '#3a3a3c',
        'sel_bg': '#1c3a5e', 'danger': '#ff453a',
        'guide': '#3a3a3c', 'new_fg': '#30d158',
        'drop_bg': '#26537a',
    },
}


def _t(key, **kw):
    s = _LANG_KEYS.get(key, {}).get(_LANG) or _LANG_KEYS.get(key, {}).get('zh-CN', key)
    if kw:
        try:
            return s.format(**kw)
        except (KeyError, IndexError):
            return s
    return s


def _c():
    return _COLORS[_CONFIG.get('theme', 'light')]


def _pick_font():
    try:
        import tkinter.font as tf
        avail = set(tf.families())
        for name in ('Microsoft YaHei UI', 'Segoe UI', 'Noto Sans SC', 'Microsoft YaHei'):
            if name in avail:
                return name
    except Exception:
        pass
    return 'TkDefaultFont'


def _fmt_size(n):
    try:
        n = int(n)
    except (TypeError, ValueError):
        return ''
    if n < 1024:
        return f'{n} B'
    for unit in ('KB', 'MB', 'GB', 'TB'):
        n /= 1024.0
        if n < 1024:
            return f'{n:.1f} {unit}' if n >= 10 else f'{n:.2f} {unit}'
    return f'{n:.1f} PB'


def _low_priority():
    """工作线程低优先级: 为系统与其他程序预留性能。"""
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetThreadPriority(k32.GetCurrentThread(), -1)  # BELOW_NORMAL
    except Exception:
        pass


_ICON_CHARS = {
    'img': '🖼', 'pdf': '📕', 'txt': '📄', 'md': '📝', 'zip': '🗜', 'rar': '🗜',
    '7z': '🗜', 'mp3': '🎵', 'wav': '🎵', 'flac': '🎵', 'mp4': '🎬', 'mkv': '🎬',
    'avi': '🎬', 'mov': '🎬', 'exe': '⚙', 'dll': '⚙', 'py': '🐍', 'js': '📜',
    'json': '🗂', 'xml': '🗂', 'html': '🌐', 'css': '🎨', 'doc': '📘', 'docx': '📘',
    'xls': '📗', 'xlsx': '📗', 'ppt': '📙', 'pptx': '📙', 'apk': '📦', 'iso': '💿',
}


def _icon_for(name):
    ext = os.path.splitext(name)[1].lower().lstrip('.')
    return _ICON_CHARS.get(ext, '📄')


# ======================== 通用自定义对话框 ========================

def _master_viewable(master):
    """主窗已显示(未被 withdraw)时才设 transient, 否则弹窗在其隐藏父窗下
    会保持 withdrawn 状态永不显示(windows 下 transient+隐藏父窗不 map)。"""
    try:
        return bool(master.winfo_viewable())
    except Exception:
        return False


class CustomDialog(tk.Toplevel):
    """简约自定义对话框(避免系统样式弹窗)。

    fields: [(label, show_char, initial)] 每项一个输入框
    buttons: [(text, value, primary)] 从左到右
    返回按钮 value; 点 × 返回 None。
    """

    def __init__(self, master, title, message='', fields=None, buttons=None,
                 width=380, wrap=True):
        super().__init__(master)
        c = _c()
        self.configure(bg=c['card'])
        self.title(title)
        if _master_viewable(master):
            self.transient(master)
        self.grab_set()
        self.resizable(False, False)
        self.result = None
        self._done = False
        self._font = _pick_font()

        pad = tk.Frame(self, bg=c['card'], padx=22, pady=18)
        pad.pack(fill=tk.BOTH, expand=True)

        if message:
            msg = tk.Label(pad, text=message, bg=c['card'], fg=c['fg'],
                           font=(self._font, 10), justify=tk.LEFT, anchor='w')
            if wrap:
                msg.configure(wraplength=width - 60)
            msg.pack(fill=tk.X, pady=(0, 10))

        self._entries = []
        for label, show, initial in (fields or []):
            row = tk.Frame(pad, bg=c['card'])
            row.pack(fill=tk.X, pady=(0, 8))
            tk.Label(row, text=label, bg=c['card'], fg=c['text_secondary'],
                     font=(self._font, 9), anchor='w').pack(fill=tk.X)
            ent = tk.Entry(row, show=show, bg=c['bg'], fg=c['fg'],
                           insertbackground=c['fg'], relief=tk.FLAT,
                           font=(self._font, 10),
                           highlightthickness=1, highlightbackground=c['border'],
                           highlightcolor=c['accent'])
            if initial:
                ent.insert(0, initial)
            ent.pack(fill=tk.X, ipady=4, pady=(3, 0))
            self._entries.append(ent)

        btns = tk.Frame(pad, bg=c['card'])
        btns.pack(fill=tk.X, pady=(8, 0))
        for text, value, primary in (buttons or [(_t('btnOk'), 'ok', True)]):
            b = tk.Button(btns, text=text, relief=tk.FLAT, cursor='hand2',
                          font=(self._font, 10), padx=16, pady=4,
                          bg=c['accent'] if primary else c['secondary'],
                          fg='#ffffff' if primary else c['fg'],
                          activebackground=c['accent'] if primary else c['hover'],
                          activeforeground='#ffffff' if primary else c['fg'],
                          command=lambda v=value: self._finish(v))
            b.pack(side=tk.RIGHT, padx=(8, 0))
        self.bind('<Escape>', lambda e: self._finish(None))
        self.protocol('WM_DELETE_WINDOW', lambda: self._finish(None))

        if self._entries:
            self._entries[0].focus_set()
            self._entries[0].select_range(0, 'end')
        self.bind('<Return>', lambda e: self._default_click())

        self.update_idletasks()
        w = max(width, self.winfo_reqwidth())
        h = self.winfo_reqheight()
        self.geometry(f'{w}x{h}')
        self._center(master)

    def _default_click(self):
        # Enter → 第一个 primary 按钮
        pass  # 由子类/调用方绑定, 默认无动作

    def _center(self, master):
        try:
            mx = master.winfo_rootx() + master.winfo_width() // 2
            my = master.winfo_rooty() + master.winfo_height() // 2
        except Exception:
            mx, my = self.winfo_screenwidth() // 2, self.winfo_screenheight() // 2
        self.geometry(f'+{max(0, mx - self.winfo_width() // 2)}+{max(0, my - self.winfo_height() // 2)}')

    def _finish(self, value):
        if self._done:
            return
        self._done = True
        self.result = value
        self.values = [e.get() for e in self._entries]
        try:
            self.grab_release()
            self.destroy()
        except tk.TclError:
            pass

    def show(self):
        self.wait_window()
        return self.result, getattr(self, 'values', [])


def ask_password(master):
    """密码输入对话框。返回 (result, [password])。"""
    dlg = CustomDialog(master, _t('pwdTitle'), _t('pwdPrompt'),
                       fields=[('', '\u2022', '')],
                       buttons=[(_t('btnCancel'), None, False), (_t('btnOpen'), 'ok', True)])
    dlg._default = True

    def _enter(e):
        dlg._finish('ok')
    dlg.bind('<Return>', _enter)
    return dlg.show()


def ask_confirm(master, message, buttons=None, title=None):
    """通用确认框。buttons: [(text, value, primary)]。"""
    dlg = CustomDialog(master, title or _t('confirmTitle'), message,
                       buttons=buttons or [(_t('btnCancel'), None, False),
                                           (_t('btnOk'), 'ok', True)])
    dlg.bind('<Return>', lambda e: dlg._finish('ok'))
    return dlg.show()[0]


def ask_add_source(master):
    """选择添加来源: 'files'(多选文件) / 'folder'(选文件夹) / None(取消)。"""
    dlg = CustomDialog(master, _t('tbAdd'), '',
                       buttons=[(_t('btnCancel'), None, False),
                                (_t('btnAddFiles'), 'files', True),
                                (_t('btnAddFolder'), 'folder', False)])
    dlg.bind('<Return>', lambda e: dlg._finish('files'))
    return dlg.show()[0]


def ask_input(master, title, label, initial=''):
    dlg = CustomDialog(master, title, '',
                       fields=[(label, '', initial)],
                       buttons=[(_t('btnCancel'), None, False), (_t('btnOk'), 'ok', True)])
    dlg.bind('<Return>', lambda e: dlg._finish('ok'))
    res, vals = dlg.show()
    return vals[0] if res == 'ok' else None


def ask_two_passwords(master):
    dlg = CustomDialog(master, _t('pwdChangeTitle'), '',
                       fields=[(_t('pwdNew'), '\u2022', ''), (_t('pwdConfirm'), '\u2022', '')],
                       buttons=[(_t('btnCancel'), None, False), (_t('btnOk'), 'ok', True)])
    dlg.bind('<Return>', lambda e: dlg._finish('ok'))
    return dlg.show()


def show_error(master, message, title=None):
    CustomDialog(master, title or _t('errTitle'), message,
                 buttons=[(_t('btnOk'), 'ok', True)]).show()


# ======================== 异步任务进度窗 ========================

class TaskWindow(tk.Toplevel):
    """异步任务进度窗: 百分比精确到 0.1%, 阶段说明, 可取消。

    线程模型: 工作线程只写共享 dict(锁保护), UI 线程 after 轮询刷新,
    绝不跨线程调用 Tk —— 保证不卡死不串扰。"""

    def __init__(self, master, title):
        super().__init__(master)
        c = _c()
        self._alive = True
        self._title = title
        self.configure(bg=c['card'])
        self.title(title)
        if _master_viewable(master):
            self.transient(master)
        self.resizable(False, False)
        self._font = _pick_font()

        pad = tk.Frame(self, bg=c['card'], padx=24, pady=16)
        pad.pack(fill=tk.BOTH, expand=True)
        self._label = tk.Label(pad, text='', bg=c['card'], fg=c['fg'],
                               font=(self._font, 10), anchor='w', justify=tk.LEFT)
        self._label.pack(fill=tk.X)
        self._pct = tk.Label(pad, text='0.0%', bg=c['card'], fg=c['accent'],
                             font=(self._font, 16, 'bold'), anchor='w')
        self._pct.pack(fill=tk.X, pady=(4, 0))
        self._bar = ttk.Style()
        try:
            self._bar.configure('kjk.Horizontal.TProgressbar',
                                troughcolor=c['secondary'], background=c['accent'],
                                bordercolor=c['card'], lightcolor=c['accent'],
                                darkcolor=c['accent'], thickness=6)
        except tk.TclError:
            pass
        self._prog = ttk.Progressbar(pad, style='kjk.Horizontal.TProgressbar',
                                     mode='determinate', maximum=1000, length=320)
        self._prog.pack(fill=tk.X, pady=(8, 4))
        self._btn = tk.Button(pad, text=_t('btnCancel'), relief=tk.FLAT, cursor='hand2',
                              font=(self._font, 10), padx=16, pady=3,
                              bg=c['secondary'], fg=c['fg'],
                              activebackground=c['hover'], activeforeground=c['fg'],
                              command=self._on_cancel)
        self._btn.pack(pady=(6, 0))
        self.on_cancel = None
        self.protocol('WM_DELETE_WINDOW', self._on_cancel)

        self.update_idletasks()
        w = max(380, self.winfo_reqwidth())
        h = self.winfo_reqheight()
        self.geometry(f'{w}x{h}')
        try:
            mx = master.winfo_rootx() + master.winfo_width() // 2
            my = master.winfo_rooty() + master.winfo_height() // 2
        except Exception:
            mx, my = self.winfo_screenwidth() // 2, self.winfo_screenheight() // 2
        self.geometry(f'+{max(0, mx - w // 2)}+{max(0, my - h // 2)}')

    def set(self, frac, text=''):
        """0..1 进度 + 阶段文本(仅 UI 线程调用)。"""
        if not self._alive:
            return
        frac = max(0.0, min(1.0, float(frac or 0)))
        self._pct.config(text=f'{frac * 100:.1f}%')
        self._prog.config(value=int(frac * 1000))
        if text:
            self._label.config(text=text)

    def _on_cancel(self):
        if self.on_cancel:
            try:
                self.on_cancel()
            except Exception:
                pass
        self._btn.config(state=tk.DISABLED, text=_t('canceled'))

    def close(self):
        self._alive = False
        try:
            self.destroy()
        except tk.TclError:
            pass


class TaskRunner:
    """把阻塞型函数放到低优先级线程跑, TaskWindow 展示 0.1% 进度。"""

    def __init__(self, master):
        self.master = master

    def run(self, title, fn, on_done, busy_setter=None):
        """fn(progress_cb, cancel_event) 在工作线程执行;
        on_done(ok, result, error) 回到 UI 线程执行。"""
        win = TaskWindow(self.master, title)
        cancel = threading.Event()

        def prog(frac, text=''):
            return  # 由轮询读 state, 不做任何 Tk 调用

        state = {'frac': 0.0, 'text': '', 'done': False, 'ok': False,
                 'result': None, 'error': None}
        lock = threading.Lock()

        def cb(frac, text=''):
            with lock:
                state['frac'] = frac or 0.0
                if text:
                    state['text'] = str(text)

        def _cancelled():
            return cancel.is_set()

        win.on_cancel = cancel.set
        if busy_setter:
            busy_setter(True)

        def poll():
            try:
                if not win._alive:
                    return
                with lock:
                    f, t = state['frac'], state['text']
                win.set(f, t)
                if state['done']:
                    win.close()
                    if busy_setter:
                        busy_setter(False)
                    on_done(state['ok'], state['result'], state['error'])
                    return
                self.master.after(30, poll)
            except tk.TclError:
                pass

        def worker():
            _low_priority()
            try:
                res = fn(cb, cancel)
                with lock:
                    state['done'] = True
                    state['ok'] = True
                    state['result'] = res
            except Exception as e:  # noqa: BLE001
                with lock:
                    state['done'] = True
                    state['ok'] = False
                    state['error'] = e

        threading.Thread(target=worker, daemon=True).start()
        self.master.after(30, poll)


# ======================== 旧格式适配器 ========================

class LegacyPackage:
    """旧文本格式 (KJKv1..v8) 的浏览适配器, 接口对齐 KJK9Package。

    全量内存加载(旧格式无法按需解密); 保存时建议升级 KJKv9。"""
    kind = 'legacy'

    def __init__(self, path, password, files):
        # files: {relpath: bytes}
        self.path = os.path.abspath(path)
        self.password = password
        self._files = dict(files)       # 已保存的(rel → bytes)
        self._pending_add = {}           # rel → bytes
        self._pending_rename = {}        # old → new
        self._pending_delete = set()
        self._dirty = False
        self.format_version = LegacyPackage.detect_version(path)

    @staticmethod
    def detect_version(path):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                head = f.readline().strip()
            v = head[:5]
            if v.startswith('KJKv'):
                return v[3:]
        except Exception:
            pass
        return '?'

    @staticmethod
    def needs_password(path):
        try:
            from engine import has_password_prefix
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                head = f.read(300)
            return has_password_prefix(head)
        except Exception:
            return False

    @classmethod
    def open(cls, path, password, progress=None):
        """全量加载旧格式(工作线程内调用, progress 汇报 0..1)。"""
        from engine import unpack_kjk, detect_password_header, try_decrypt_item, verify_password
        size = max(os.path.getsize(path), 1)
        chunks, read = [], 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            while True:
                c = f.read(4 * 1024 * 1024)
                if not c:
                    break
                chunks.append(c)
                read += len(c)
                if progress:
                    progress(0.4 * min(read / size, 1.0), 'Reading package…')
        content = ''.join(chunks)
        results = unpack_kjk(content)
        has_pwd, salt_hex, hash_hex, actual = detect_password_header(results)
        if has_pwd and hash_hex and password:
            if not verify_password(password, salt_hex, hash_hex):
                raise KJK9AuthError('wrong password')
        salt = bytes.fromhex(salt_hex) if salt_hex else None
        is_v7 = bool(salt_hex) or all(r.get('_kjkv7') for r in actual)
        files = {}
        n = max(len(actual), 1)
        for i, r in enumerate(actual):
            # 旧格式条目用加密文件名 enc_name 存储; try_decrypt_item 会正确解出 originalName 与 data。
            ok, data, err = try_decrypt_item(r, password, salt, legacy=not is_v7)
            if not ok:
                raise KJK9AuthError('wrong password or corrupted')
            name = (r.get('originalName') or r.get('name') or '').replace('\\', '/')
            if not name or name.endswith('/'):
                continue
            files[name] = data or b''
            if progress:
                progress(0.4 + 0.6 * (i + 1) / n, f'Decrypting {name}')
        return cls(path, password, files)

    # ---- 视图/暂存 ----
    def file_list(self):
        return [{'p': p, 's': len(d)} for p, d in sorted(self._files.items())]

    def effective_files(self):
        view = {}
        for p, d in self._files.items():
            if p in self._pending_delete:
                continue
            view[self._pending_rename.get(p, p)] = {'p': p, 's': len(d), 'm': 0,
                                                     '_legacy': d}
        for p, d in self._pending_add.items():
            view[p] = {'p': p, 's': len(d), 'm': 0, '_pending': d}
        return view

    def is_dirty(self):
        return self._dirty

    def _recompute_dirty(self):
        self._dirty = bool(self._pending_add or self._pending_rename
                           or self._pending_delete)

    def pending_summary(self):
        return {'add': len(self._pending_add), 'rename': len(self._pending_rename),
                'delete': len(self._pending_delete)}

    def pending_add_info(self):
        return {p: {'src': '', 's': len(d), 'm': 0} for p, d in self._pending_add.items()}

    def stage_add(self, src_path, relpath=None):
        rel = (relpath or os.path.basename(src_path)).replace('\\', '/').lstrip('/')
        with open(src_path, 'rb') as f:
            data = f.read()
        if rel in self._files or rel in self._pending_add:
            base, ext = os.path.splitext(rel)
            i = 1
            while f'{base} ({i}){ext}' in self._files or f'{base} ({i}){ext}' in self._pending_add:
                i += 1
            rel = f'{base} ({i}){ext}'
        self._pending_add[rel] = data
        self._dirty = True
        return rel

    def drop_pending_add(self, rel):
        if self._pending_add.pop(rel, None) is not None:
            self._recompute_dirty()

    def rename_pending_add(self, old, new):
        if old not in self._pending_add:
            raise KJK9Error(f'暂存区无此文件: {old}')
        new = new.replace('\\', '/').lstrip('/')
        if not new or new == old:
            return new
        if new in self._files or new in self._pending_add:
            raise KJK9Error('目标名称已存在')
        self._pending_add[new] = self._pending_add.pop(old)
        return new

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
        self._dirty = True

    # ---- 读取 ----
    def read_file(self, relpath):
        for src, view in self.effective_files().items():
            if src == relpath or view.get('p') == relpath:
                if '_pending' in view:
                    return view['_pending']
                if '_legacy' in view:
                    return view['_legacy']
        raise KJK9Error(f'包内无此文件: {relpath}')

    def extract_files(self, dest_dir, relpaths=None, progress=None, cancel=None,
                      params=None, overwrite=True):
        view = self.effective_files()
        items = []
        for rel in (relpaths or list(view.keys())):
            v = view.get(rel)
            if v is None:
                continue
            data = v.get('_pending', v.get('_legacy'))
            if data is not None:
                items.append((rel, data))
        total = sum(len(d) for _, d in items) or 1
        done = 0
        for rel, data in items:
            if cancel is not None and cancel.is_set():
                raise KJK9Cancel('已取消')
            dest = _safe_dest_join(dest_dir, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, 'wb') as f:
                f.write(data)
            done += len(data)
            if progress:
                progress(min(done / total, 1.0), f'Decrypting {rel}')
        if progress:
            progress(1.0, '解密完成')
        return len(items)

    # ---- 保存(旧格式重打包) ----
    def _final_entries(self):
        out = {}
        for p, d in self._files.items():
            if p in self._pending_delete:
                continue
            out[self._pending_rename.get(p, p)] = d
        out.update(self._pending_add)
        return out

    @staticmethod
    def _name_ext(rel):
        base = os.path.basename(rel)
        if '.' in base:
            stem, ext = base.rsplit('.', 1)
            return rel[:len(rel) - len(ext) - 1], ext
        return rel, ''

    def save(self, progress=None, cancel=None, params=None):
        if not self._dirty:
            if progress:
                progress(1.0, '无修改')
            return False
        from engine import pack_kjk_with_password
        entries = self._final_entries()
        files = []
        for rel, data in entries.items():
            name, ext = self._name_ext(rel)
            files.append({'name': name, 'ext': ext, 'data': data})

        def cb(cur, total):
            if progress:
                progress(0.9 * cur / max(total, 1), f'Repacking {cur}/{total}')
            if cancel is not None and cancel.is_set():
                raise KJK9Cancel('已取消')

        content = pack_kjk_with_password(files, self.password, progress_callback=cb)
        if progress:
            progress(0.95, 'Writing…')
        tmp = self.path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self._files = entries
        self._pending_add.clear()
        self._pending_rename.clear()
        self._pending_delete.clear()
        self._dirty = False
        if progress:
            progress(1.0, '保存完成')
        return True

    def change_password(self, new_password, progress=None, cancel=None, params=None):
        if self._dirty:
            raise KJK9Error('请先保存修改, 再修改密码')
        self.password = new_password
        self._dirty = True
        return self.save(progress=progress, cancel=cancel)

    def hole_size(self):
        return 0

    def upgrade_to_v9(self, progress=None, cancel=None):
        """升级: 全量解密 → 临时目录 → KJKv9 C 引擎加密 → 原子替换。返回 KJK9Package。"""
        import tempfile
        import shutil
        entries = self._final_entries()
        tmpdir = tempfile.mkdtemp(prefix='kjk_upgrade_')
        try:
            total = max(sum(len(d) for d in entries.values()), 1)
            done = 0
            ents = []
            for rel, data in entries.items():
                if cancel is not None and cancel.is_set():
                    raise KJK9Cancel('已取消')
                full = _safe_dest_join(tmpdir, rel)
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, 'wb') as f:
                    f.write(data)
                done += len(data)
                if progress:
                    progress(0.3 * done / total, f'Extracting {rel}')
                ents.append({'p': rel, 'src': full, 's': len(data), 'm': time.time()})

            def p2(frac, text=''):
                if progress:
                    progress(0.3 + 0.65 * (frac or 0), text or 'Encrypting…')

            new_path = self.path + '.kjk9.tmp'
            for stale in (new_path, new_path + '.kjkprog'):
                try:
                    os.remove(stale)
                except OSError:
                    pass
            encrypt_entries_to_kjk9(ents, new_path, self.password, progress=p2,
                                     cancel=cancel)
            if progress:
                progress(0.97, 'Replacing…')
            os.replace(new_path, self.path)
            if progress:
                progress(1.0, 'Done')
            return KJK9Package.open(self.path, self.password)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


def _safe_dest_join(dest_dir, rel):
    raw = str(rel).replace('\\', '/').split('/')
    if any(p == '..' for p in raw):
        raise KJK9Error(f'非法路径: {rel}')
    parts = [p for p in raw if p not in ('', '.')]
    if not parts:
        raise KJK9Error(f'非法路径: {rel}')
    return os.path.join(dest_dir, *parts)


# ======================== 虚拟目录树 ========================

class BrowseTree:
    """资源管理器风格虚拟树: 行池虚拟化 + 拼接式展开 + 内联重命名 + 右键菜单 + 拖放。"""

    _ROW_H = 26
    _POOL = 64
    _INDENT = 16
    _NAME_PAD = 42
    _SIZE_W = 96

    def __init__(self, parent, on_activate=None, on_menu=None,
                 on_drop=None, on_drag_out=None, on_drag_prep=None,
                 on_drag_release=None):
        self.c = _c()
        self.on_activate = on_activate      # 双击文件
        self.on_menu = on_menu              # 右键 (node, event)
        self.on_drop = on_drop              # 拖入 (paths, target_dir_rel)
        self.on_drag_out = on_drag_out      # 拖出 (node) -> 本地文件路径|None
        self.on_drag_prep = on_drag_prep    # 按住行(准备拖出)预渲染回调
        self.on_drag_release = on_drag_release  # 松开(取消预渲染)
        self.selected = None
        self._hover = None
        self._drop_hl = None        # 拖拽悬停时当前高亮的目标目录节点
        self._expand_pending = None  # 拖拽中等待延迟展开的折叠目录
        self._expand_timer = None    # 延迟展开定时器
        self._roots = []
        self._flat = []
        self._slot_idx = {}
        self._pending = False
        self._in_render = False
        self._rename_ui = None
        self._font = _pick_font()

        import tkinter.font as tkfont
        self._name_font = tkfont.Font(family=self._font, size=10)
        self._name_font_new = tkfont.Font(family=self._font, size=10)

        self.outer = tk.Frame(parent, bg=self.c['card'])
        self.canvas = tk.Canvas(self.outer, bg=self.c['card'], highlightthickness=0,
                                yscrollincrement=self._ROW_H, cursor='arrow')
        self.vsb = ttk.Scrollbar(self.outer, orient='vertical',
                                 command=self._yview)
        self.canvas.configure(yscrollcommand=self._scroll_changed)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._bind_wheel(self.canvas)
        self.canvas.bind('<Configure>', lambda e: self._update_scrollregion() or self._schedule())
        self._pool_rows = [self._make_row(k) for k in range(self._POOL)]

        if _HAS_DND:
            try:
                self._register_dnd(self.canvas)
            except tk.TclError:
                pass

        self.canvas.bind('<Button-1>', self._on_click, add='+')
        self.canvas.bind('<Double-Button-1>', self._on_dbl, add='+')
        self.canvas.bind('<Button-3>', self._on_right_click, add='+')
        self.canvas.bind('<Motion>', self._on_motion, add='+')
        self.canvas.bind('<Leave>', lambda e: self._set_hover(None), add='+')

    # ---- 数据 ----

    def set_files(self, view):
        """view: effective_files() → {rel: {'s': size, pending flag}}。"""
        had_state = bool(self._flat)
        expanded = set()
        for node, _ in self._flat:
            if node.get('is_dir') and node.get('expanded', True):
                expanded.add(node['rel'])
        sel_rel = self.selected['rel'] if self.selected else None

        root = {'name': '', 'rel': '', 'is_dir': True, 'children': [],
                'expanded': True, 'pending': None}
        dirs = {'': root}
        for rel in sorted(view):
            parts = [p for p in rel.split('/') if p]
            if not parts:
                continue
            d = root
            for i, part in enumerate(parts[:-1]):
                drel = '/'.join(parts[:i + 1])
                if drel not in dirs:
                    nd = {'name': part, 'rel': drel, 'is_dir': True, 'children': [],
                          'expanded': (drel in expanded) or not had_state,
                          'pending': None}
                    dirs[drel] = nd
                    d['children'].append(nd)
                d = dirs[drel]
            ent = view[rel]
            d['children'].append({
                'name': parts[-1], 'rel': rel, 'is_dir': False,
                'size': int(ent.get('s', 0)), 'expanded': False,
                'pending': '_pending' in ent and 'pending',
                'children': []})

        def sort_kids(node):
            node['children'].sort(key=lambda n: (not n['is_dir'],
                                                n['name'].lower()))
            for ch in node['children']:
                if ch['is_dir']:
                    sort_kids(ch)
        sort_kids(root)

        # 巨大树默认折叠深层
        total = sum(1 for _ in _walk_all(root))
        if total > 4000:
            for n in _walk_all(root):
                if n['is_dir'] and n['rel'].count('/') >= 1:
                    n['expanded'] = False

        self._roots = root['children']
        self._rebuild()
        if sel_rel:
            for node, _ in self._flat:
                if node['rel'] == sel_rel:
                    self.selected = node
                    break
        self._update_scrollregion()
        self._schedule()

    def _rebuild(self):
        self._flat = []
        stack = [(n, 0) for n in reversed(self._roots)]
        while stack:
            node, depth = stack.pop()
            self._flat.append((node, depth))
            if node.get('is_dir') and node.get('children') and node.get('expanded', True):
                stack.extend([(n, depth + 1) for n in reversed(node['children'])])
        self._update_scrollregion()

    def _find_index(self, node):
        for i, (n, _) in enumerate(self._flat):
            if n is node:
                return i
        return -1

    def _visible_count(self, node):
        cnt = 0
        for ch in node.get('children', []):
            cnt += 1 + (self._visible_count(ch) if ch.get('expanded', True) else 0)
        return cnt

    # ---- 展开/折叠(拼接, O(子树)) ----

    def toggle(self, node):
        if not node.get('is_dir') or not node.get('children'):
            return
        node['expanded'] = not node.get('expanded', True)
        idx = self._find_index(node)
        if idx < 0:
            self._rebuild()
            self._schedule()
            return
        if node['expanded']:
            rows = []
            self._collect_visible(node['children'], self._flat[idx][1] + 1, rows)
            self._flat[idx + 1:idx + 1] = rows
        else:
            cnt = self._visible_count(node)
            del self._flat[idx + 1:idx + 1 + cnt]
        self._update_scrollregion()
        self._schedule()

    def _collect_visible(self, nodes, depth, out):
        for n in nodes:
            out.append((n, depth))
            if n.get('is_dir') and n.get('children') and n.get('expanded', True):
                self._collect_visible(n['children'], depth + 1, out)

    # ---- 渲染 ----

    def _make_row(self, slot):
        frame = tk.Frame(self.canvas, bg=self.c['card'], height=self._ROW_H,
                         cursor='hand2')
        indent = tk.Frame(frame, bg=self.c['card'], width=0)
        indent.pack(side=tk.LEFT, fill=tk.Y)
        arrow = tk.Label(frame, text='', bg=self.c['card'],
                         fg=self.c['text_secondary'], font=(self._font, 9), width=2)
        arrow.pack(side=tk.LEFT)
        icon = tk.Label(frame, text='', bg=self.c['card'], fg=self.c['fg'],
                        font=(self._font, 11))
        icon.pack(side=tk.LEFT, padx=(2, 4))
        name = tk.Label(frame, text='', bg=self.c['card'], fg=self.c['fg'],
                        font=self._name_font, anchor='w')
        name.pack(side=tk.LEFT, fill=tk.X, expand=True)
        size = tk.Label(frame, text='', bg=self.c['card'],
                        fg=self.c['text_secondary'], font=(self._font, 9))
        size.pack(side=tk.RIGHT, padx=(0, 10))
        row = {'frame': frame, 'indent': indent, 'arrow': arrow, 'icon': icon,
               'name': name, 'size': size}
        row['win'] = self.canvas.create_window((0, 0), window=frame, anchor='nw',
                                               state='hidden')

        def _sel(e, r=row):
            i = self._slot_idx.get(id(r['frame']))
            if i is not None and i < len(self._flat):
                self._on_row_click(self._flat[i][0])
            if self.on_drag_prep is not None:
                try:
                    i = self._slot_idx.get(id(r['frame']))
                    if i is not None and i < len(self._flat):
                        self.on_drag_prep(self._flat[i][0])
                except Exception:
                    pass

        def _sel_release(e, r=row):
            if self.on_drag_release is not None:
                try:
                    self.on_drag_release()
                except Exception:
                    pass

        def _dbl(e, r=row):
            i = self._slot_idx.get(id(r['frame']))
            if i is not None and i < len(self._flat):
                self._on_row_dbl(self._flat[i][0])

        def _menu(e, r=row):
            i = self._slot_idx.get(id(r['frame']))
            if i is not None and i < len(self._flat):
                self._on_row_menu(self._flat[i][0], e)

        for w in (frame, arrow, icon, name, size):
            w.bind('<Button-1>', _sel, add='+')
            w.bind('<ButtonRelease-1>', _sel_release, add='+')
            w.bind('<Double-Button-1>', _dbl, add='+')
            w.bind('<Button-3>', _menu, add='+')
            if _HAS_DND:
                try:
                    self._register_dnd(w)
                except tk.TclError:
                    pass
        return row

    def _schedule(self):
        if self._pending or not self._alive():
            return
        self._pending = True
        try:
            self.canvas.after_idle(self._do_render)
        except tk.TclError:
            self._pending = False

    def _do_render(self):
        self._pending = False
        if self._in_render or not self._alive():
            return
        self._in_render = True
        try:
            self._render()
        finally:
            self._in_render = False

    def _alive(self):
        try:
            return bool(self.canvas.winfo_exists())
        except Exception:
            return False

    def _render(self):
        ch = self.canvas.winfo_height()
        if ch <= 1:
            ch = 400
        width = max(self.canvas.winfo_width() - 4, 200)
        total = len(self._flat)
        first = max(0, int(self.canvas.canvasy(0) // self._ROW_H) - 4)
        last = min(total, first + ch // self._ROW_H + 10)

        self._slot_idx = {}
        sel = self.selected
        hov = self._hover
        drop_hl = self._drop_hl
        for k, row in enumerate(self._pool_rows):
            i = first + k
            if i >= last:
                self.canvas.itemconfigure(row['win'], state='hidden')
                continue
            node, depth = self._flat[i]
            self._slot_idx[id(row['frame'])] = i
            self._fill(row, node, depth)
            if node is drop_hl:
                bg = self.c['drop_bg']
            elif node is sel:
                bg = self.c['sel_bg']
            elif node is hov:
                bg = self.c['hover']
            else:
                bg = self.c['card']
            for w in (row['frame'], row['indent'], row['arrow'], row['icon'],
                      row['name'], row['size']):
                w.configure(bg=bg)
            if node is sel:
                row['name'].configure(fg=self.c['fg'])
            elif node.get('pending'):
                row['name'].configure(fg=self.c['new_fg'])
            else:
                row['name'].configure(fg=self.c['fg'])
            self.canvas.itemconfigure(row['win'], state='normal')
            self.canvas.coords(row['win'], 0, i * self._ROW_H)
            self.canvas.itemconfigure(row['win'], width=width, height=self._ROW_H)

        self.canvas.delete('guides')
        for i in range(first, last):
            node, depth = self._flat[i]
            if node.get('is_dir'):
                continue
            y = i * self._ROW_H + self._ROW_H - 1
            self.canvas.create_line(self._NAME_PAD + depth * self._INDENT, y,
                                    width, y, fill=self.c['guide'],
                                    tags=('guides',))

    def _fill(self, row, node, depth):
        is_dir = node.get('is_dir')
        kids = node.get('children') or []
        row['indent'].configure(width=depth * self._INDENT)
        row['arrow'].configure(text=('▾' if node.get('expanded', True) else '▸')
                               if is_dir and kids else '')
        row['icon'].configure(text='📁' if is_dir else _icon_for(node.get('name', '')))
        label = node.get('name', '') + ('/' if is_dir else '')
        if node.get('pending'):
            label += '  +'
        row['name'].configure(text=label)
        if is_dir:
            row['size'].configure(text='')
        else:
            row['size'].configure(text=_fmt_size(node.get('size')))

    # ---- 滚动 ----

    def _yview(self, *args):
        self.canvas.yview(*args)
        self._schedule()

    def _scroll_changed(self, first, last):
        self.vsb.set(first, last)
        self._schedule()

    def _bind_wheel(self, w):
        def _wheel(e):
            self.canvas.yview_scroll(int(-e.delta / 120), 'units')
            self._schedule()
        w.bind('<MouseWheel>', _wheel, add='+')
        w.bind('<Enter>', lambda e: w.focus_set(), add='+')

    # ---- 交互 ----

    def _on_click(self, e):
        node = self._node_at(e.y)
        if node is not None:
            self._on_row_click(node)

    def _on_dbl(self, e):
        node = self._node_at(e.y)
        if node is not None:
            self._on_row_dbl(node)

    def _on_right_click(self, e):
        node = self._node_at(e.y)
        if node is not None:
            self._on_row_menu(node, e)

    def _on_motion(self, e):
        node = self._node_at(e.y)
        if node is not self._hover:
            self._set_hover(node)

    def _set_hover(self, node):
        self._hover = node
        self._schedule()

    def _node_at(self, y):
        i = int((self.canvas.canvasy(y)) // self._ROW_H)
        if 0 <= i < len(self._flat):
            return self._flat[i][0]
        return None

    # ---- 新增文件揭示(展开+高亮+滚动到可见+弹回动画) ----

    def reveal_rel(self, rel):
        """展开 rel 的所有祖先目录, 找到节点, 高亮并滚动到可见(带弹回动画)。"""
        parts = [p for p in rel.split('/') if p]
        cur = ''
        for i in range(len(parts) - 1):
            cur = '/'.join(parts[:i + 1])
            d = self._find_node_by_rel(cur)
            if d is not None:
                d['expanded'] = True
        self._rebuild()
        node = self._find_node_by_rel(rel)
        if node is None:
            self._schedule()
            return
        self._reveal_node(node)

    def _find_node_by_rel(self, rel):
        stack = list(self._roots)
        while stack:
            n = stack.pop()
            if n['rel'] == rel:
                return n
            stack.extend(n.get('children', []))
        return None

    def _reveal_node(self, node):
        idx = self._find_index(node)
        if idx < 0:
            self._schedule()
            return
        ch = self.canvas.winfo_height()
        if ch <= 1:
            ch = 400
        rows_per_page = max(1, ch // self._ROW_H)
        total = len(self._flat)
        self.selected = node
        # 一页能显示全部 → 只高亮展开, 不滚动
        if total <= rows_per_page:
            self._schedule()
            return
        max_first = max(0, total - rows_per_page)
        cur_first = max(0, int(self.canvas.canvasy(0) // self._ROW_H))
        top_first = max(0, min(idx, max_first))
        if idx >= cur_first + rows_per_page:
            # 阶段1: 先拉到可见区底部(确保最下面的文件不超出)
            bottom_first = max(0, min(idx - rows_per_page + 1, max_first))
            self._animate_scroll_to(bottom_first,
                                    then=lambda: self._animate_scroll_to(top_first))
        else:
            self._animate_scroll_to(top_first)
        self._schedule()

    def _animate_scroll_to(self, target_first, steps=12, step_ms=16, then=None):
        total = len(self._flat)
        if total <= 0:
            if then:
                then()
            return
        cur_first = self.canvas.canvasy(0) / self._ROW_H
        target_first = max(0, min(target_first, total - 1))
        if abs(target_first - cur_first) < 0.3:
            if then:
                then()
            return
        delta = (target_first - cur_first) / steps
        i = [0]

        def step():
            i[0] += 1
            f = cur_first + delta * i[0]
            self.canvas.yview_moveto(max(0, f) / total)
            self._schedule()
            if i[0] < steps:
                self.canvas.after(step_ms, step)
            elif then:
                then()

        step()

    def _on_row_click(self, node):
        self.selected = node
        if node.get('is_dir') and node.get('children'):
            self.toggle(node)
        else:
            self._schedule()

    def _on_row_dbl(self, node):
        self.selected = node
        if node.get('is_dir'):
            self.toggle(node)
        elif self.on_activate:
            self.on_activate(node)

    def _on_row_menu(self, node, event):
        self.selected = node
        self._schedule()
        if self.on_menu:
            self.on_menu(node, event)

    # ---- 内联重命名 ----

    def begin_rename(self, node, on_commit):
        """在行内出现输入框; on_commit(new_name) 由调用方校验与落暂存。"""
        self._cancel_rename()
        idx = self._find_index(node)
        if idx < 0:
            return
        depth = self._flat[idx][1]
        x = self._NAME_PAD + depth * self._INDENT
        y = idx * self._ROW_H
        c = self.c
        ent = tk.Entry(self.canvas, bg=c['bg'], fg=c['fg'], relief=tk.FLAT,
                      insertbackground=c['fg'], font=self._name_font,
                      highlightthickness=1, highlightbackground=c['accent'],
                      highlightcolor=c['accent'])
        ent.insert(0, node.get('name', ''))
        ent.select_range(0, 'end')
        win = self.canvas.create_window(x, y, window=ent, anchor='nw',
                                        height=self._ROW_H - 6)
        self._rename_ui = (ent, win, node, on_commit)
        ent.focus_set()

        def _commit(e=None):
            val = ent.get().strip()
            self._cancel_rename()
            if val:
                on_commit(val)

        def _cancel(e=None):
            self._cancel_rename()

        ent.bind('<Return>', _commit)
        ent.bind('<Escape>', _cancel)
        ent.bind('<FocusOut>', _commit)

    def _cancel_rename(self):
        if self._rename_ui:
            ent, win, _, _ = self._rename_ui
            self._rename_ui = None
            try:
                ent.unbind('<FocusOut>')
                self.canvas.delete(win)
                ent.destroy()
            except tk.TclError:
                pass

    # ---- 拖放 ----

    def _register_dnd(self, widget):
        """给指定 widget 注册完整的 DnD 事件(目标+源)。
        行框架及其子控件都需要注册, 否则拖拽事件会被它们拦截而不传到 canvas。"""
        widget.drop_target_register(DND_FILES)
        widget.dnd_bind('<<Drop>>', self._on_drop)
        widget.dnd_bind('<<DropEnter>>', self._on_drop_motion)
        widget.dnd_bind('<<DropPosition>>', self._on_drop_motion)
        widget.dnd_bind('<<DropLeave>>', self._clear_drop_hl)
        widget.drag_source_register(1, DND_FILES)
        widget.dnd_bind('<<DragInitCmd>>', self._on_drag_init)
        widget.dnd_bind('<<DragEndCmd>>', lambda e: None)

    def _dnd_y(self, event=None):
        """可靠地把指针所在位置换算成 canvas 内的纵向显示坐标 (以 canvas 顶部为 0)。

        无论事件来自 canvas 还是行框架, 都用 canvas 的屏幕坐标做基准, 保证坐标系统一。
        winfo_pointery() 返回指针的绝对屏幕 Y, winfo_rooty() 返回 widget 的绝对屏幕 Y,
        两者相减得到相对于 widget 顶部的 Y 坐标。"""
        try:
            root = self.canvas.winfo_toplevel()
            return max(0, root.winfo_pointery()
                       - self.canvas.winfo_rooty())
        except (tk.TclError, AttributeError):
            pass
        yr = getattr(event, 'y_root', None)
        if yr is not None:
            try:
                return max(0, yr - self.canvas.winfo_rooty())
            except tk.TclError:
                return max(0, yr)
        return max(0, getattr(event, 'y', 0))

    def _row_at_win_y(self, win_y):
        """显示坐标(以 widget 顶部为 0) → 内容行索引, 越界钳制到 [0, len)。"""
        if not self._flat:
            return -1
        i = int((self.canvas.canvasy(win_y)) // self._ROW_H)
        return max(0, min(i, len(self._flat) - 1))

    def _drop_target_at_win_y(self, win_y):
        """根据拖放位置的 widget 坐标判定目标目录 (rel) 与要实时高亮的目录节点。

        - 首行之上 / 尾行之下的空白区 → 包根目录 (资源管理器语义: 落在空白=当前根)。
        - 命中目录行   → 该目录; 命中文件行 → 该文件所在目录。
        """
        if not self._flat:
            return '', None
        cv_y = self.canvas.canvasy(win_y)
        if cv_y < 0:
            return '', None                       # 首行之上空白 -> 根
        ri = int(cv_y // self._ROW_H)
        if ri >= len(self._flat):
            return '', None                       # 尾行之下空白 -> 根
        node = self._flat[ri][0]
        if node.get('is_dir'):
            return node['rel'], node
        rel = node['rel']
        par = rel.rsplit('/', 1)[0] if '/' in rel else ''
        if par:
            return par, self._find_node_by_rel(par)
        return '', None

    _EXPAND_DELAY_MS = 420   # 拖拽悬停折叠目录多久后自动展开(Explorer 风格)

    def _cancel_expand_timer(self):
        if self._expand_timer is not None:
            try:
                self.canvas.after_cancel(self._expand_timer)
            except tk.TclError:
                pass
            self._expand_timer = None

    def _do_lazy_expand(self):
        self._expand_timer = None
        p = self._expand_pending
        self._expand_pending = None
        if p is None or not p.get('is_dir'):
            return
        p['expanded'] = True
        self._rebuild()
        self._schedule()

    def _on_drop_motion(self, event):
        """拖拽悬停: 实时高亮目标目录; 悬停折叠目录延迟自动展开(防误触)。

        同时返回动作值让 tkdnd 确认本窗口接受该拖放 (否则 OLE 下光标显示禁止且 <<Drop>> 不发)。"""
        if not self.on_drop:
            return None
        hl = self._drop_target_at_win_y(self._dnd_y(event))[1]
        if hl is not self._drop_hl:
            self._drop_hl = hl
            self._schedule()
        if hl is not None and hl.get('is_dir') and hl.get('children') \
                and not hl.get('expanded', True):
            if hl is not self._expand_pending:
                self._expand_pending = hl
                self._cancel_expand_timer()
                self._expand_timer = self.canvas.after(
                    self._EXPAND_DELAY_MS, self._do_lazy_expand)
        else:
            if self._expand_pending is not None:
                self._expand_pending = None
            self._cancel_expand_timer()
        return 'copy'

    def _clear_drop_hl(self, event=None):
        self._cancel_expand_timer()
        self._expand_pending = None
        if self._drop_hl is not None:
            self._drop_hl = None
            self._schedule()

    def _on_drop(self, event):
        if not self.on_drop:
            return
        try:
            paths = list(self.canvas.tk.splitlist(event.data))
        except tk.TclError:
            paths = [event.data]
        paths = [p.strip('{}') for p in paths if p]
        if not paths:
            return
        target_dir, _ = self._drop_target_at_win_y(self._dnd_y(event))
        self._drop_hl = None
        self._expand_pending = None
        self._cancel_expand_timer()
        self._schedule()
        self.on_drop(paths, target_dir)
        return 'copy'

    def _on_drag_init(self, event):
        if not self.on_drag_out:
            return None
        # 以指针所在行为拖出源: 抓取任意可见行即可拖出, 不必先单击成选中(资源管理器行为)。
        node = self._node_at(self._dnd_y(event))
        if node is None:
            node = self.selected
        if node is None:
            return None
        path = self.on_drag_out(node)
        if not path:
            return None
        # Windows 拖出用原生反斜杠路径, 确保 Explorer/SHFileOperation 能正确解析。
        return (['copy'], DND_FILES, '{' + path.replace('/', os.sep) + '}')

    def _update_scrollregion(self):
        try:
            width = max(self.canvas.winfo_width(), 200)
            self.canvas.configure(scrollregion=(0, 0, width,
                                                len(self._flat) * self._ROW_H))
        except tk.TclError:
            pass


def _walk_all(root):
    stack = list(root.get('children', []))
    while stack:
        n = stack.pop()
        yield n
        stack.extend(n.get('children', []))


# ======================== 浏览主窗口 ========================

class BrowseWindow:
    _VIEW_TMP_BASE = os.path.join(tempfile.gettempdir(), 'KJK-View') if False else None

    def __init__(self, root, pkg, runner=None):
        import tempfile
        self._tempfile = tempfile
        self.root = root
        self.pkg = pkg
        self.c = _c()
        self._font = _pick_font()
        self.runner = runner or TaskRunner(root)
        self._busy = False
        self._closing = False
        self._view_dirs = []
        self._drag_tmp = []
        self._prepared = {}         # 拖出预渲染缓存 {rel: dest}, 后台线程填写, 主线程取用
        self._prep_event = {}       # {rel: Event} 在途预渲染完成事件(用于拖出时等一次)
        self._press_node = None     # 按住的行节点(准备拖出)
        self._press_prep_job = None
        self._press_cancelled = False

        self.root.title(f"{os.path.basename(pkg.path)} — {_t('winTitle')}")
        self.root.configure(bg=self.c['bg'])
        self.root.geometry('780x540')
        self.root.minsize(600, 400)
        self._center_window()
        self._set_icon()

        self._build_ui()
        self._bind_keys()
        self.refresh_tree()

    # ---- UI 构建 ----

    def _center_window(self):
        self.root.update_idletasks()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f'+{max(0, (sw - 780) // 2)}+{max(0, (sh - 540) // 2)}')

    def _set_icon(self):
        try:
            from PIL import Image, ImageTk
            icon = os.path.join(_script_dir, 'icon', 'icon.png')
            if os.path.exists(icon):
                self._icon_img = ImageTk.PhotoImage(Image.open(icon))
                self.root.iconphoto(True, self._icon_img)
        except Exception:
            pass

    def _build_ui(self):
        c = self.c
        # 头部
        head = tk.Frame(self.root, bg=c['card'], highlightthickness=1,
                        highlightbackground=c['border'])
        head.pack(fill=tk.X)
        inner = tk.Frame(head, bg=c['card'], padx=16, pady=10)
        inner.pack(fill=tk.X)
        self._title_lbl = tk.Label(inner, text='', bg=c['card'], fg=c['fg'],
                                   font=(self._font, 13, 'bold'), anchor='w')
        self._title_lbl.pack(side=tk.LEFT)
        self._badge_lbl = tk.Label(inner, text='', bg=c['secondary'],
                                   fg=c['text_secondary'], font=(self._font, 8),
                                   padx=8, pady=2)
        self._badge_lbl.pack(side=tk.RIGHT, padx=(8, 0))
        self._stat_lbl = tk.Label(inner, text='', bg=c['card'],
                                  fg=c['text_secondary'], font=(self._font, 9))
        self._stat_lbl.pack(side=tk.RIGHT)

        # 工具栏
        bar = tk.Frame(self.root, bg=c['bg'])
        bar.pack(fill=tk.X, padx=12, pady=(10, 6))
        self._btns = {}
        defs = [
            ('add', _t('tbAdd'), self._act_add),
            ('extract', _t('tbExtract'), self._act_extract),
            ('rename', _t('tbRename'), self._act_rename),
            ('delete', _t('tbDelete'), self._act_delete),
            ('pwd', _t('tbPwd'), self._act_pwd),
            ('compact', _t('tbCompact'), self._act_compact),
            ('save', _t('tbSave'), self._act_save),
        ]
        for key, text, cmd in defs:
            primary = key == 'save'
            b = tk.Button(bar, text=text, relief=tk.FLAT, cursor='hand2',
                          font=(self._font, 10), padx=14, pady=4,
                          bg=c['accent'] if primary else c['card'],
                          fg='#ffffff' if primary else c['fg'],
                          activebackground=c['accent'] if primary else c['hover'],
                          activeforeground='#ffffff' if primary else c['fg'],
                          command=cmd)
            b.pack(side=tk.LEFT if key != 'save' else tk.RIGHT, padx=3)
            if not primary:
                b.bind('<Enter>', lambda e, w=b: w.configure(bg=c['hover']))
                b.bind('<Leave>', lambda e, w=b: w.configure(bg=c['card']))
            self._btns[key] = b

        # 列标题
        cols = tk.Frame(self.root, bg=c['bg'], padx=12)
        cols.pack(fill=tk.X)
        tk.Label(cols, text=_t('colName'), bg=c['bg'], fg=c['text_secondary'],
                 font=(self._font, 9), anchor='w').pack(side=tk.LEFT)
        tk.Label(cols, text=_t('colSize'), bg=c['bg'], fg=c['text_secondary'],
                 font=(self._font, 9), anchor='e', width=10).pack(side=tk.RIGHT)

        # 树卡片
        card = tk.Frame(self.root, bg=c['card'], highlightthickness=1,
                        highlightbackground=c['border'])
        card.pack(fill=tk.BOTH, expand=True, padx=12)
        self.tree = BrowseTree(card, on_activate=self._on_activate,
                              on_menu=self._on_menu, on_drop=self._on_drop,
                              on_drag_out=self._on_drag_out,
                              on_drag_prep=self._on_drag_press,
                              on_drag_release=self._on_drag_release)
        self.tree.outer.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)

        # 状态栏
        status = tk.Frame(self.root, bg=c['bg'])
        status.pack(fill=tk.X, padx=12, pady=(6, 10))
        self._dirty_lbl = tk.Label(status, text='', bg=c['bg'], fg=c['accent'],
                                   font=(self._font, 9), anchor='w')
        self._dirty_lbl.pack(side=tk.LEFT)
        self._status_lbl = tk.Label(status, text=_t('statReady'), bg=c['bg'],
                                     fg=c['text_secondary'], font=(self._font, 9))
        self._status_lbl.pack(side=tk.RIGHT)

        self.root.protocol('WM_DELETE_WINDOW', self._on_close)

    def _bind_keys(self):
        self.root.bind('<Control-s>', lambda e: self._act_save())
        self.root.bind('<Control-S>', lambda e: self._act_save())
        self.root.bind('<F2>', lambda e: self._act_rename())
        self.root.bind('<Delete>', lambda e: self._act_delete())

    # ---- 状态刷新 ----

    def set_status(self, text):
        self._status_lbl.config(text=text)

    def refresh_tree(self):
        view = self.pkg.effective_files()
        # 统一视图形状 {rel: {'s','_pending'?}}
        norm = {}
        for rel, v in view.items():
            norm[rel] = {'s': v.get('s', 0)}
            if '_pending' in v:
                norm[rel]['_pending'] = True
        self.tree.set_files(norm)

        files = len(norm)
        total = sum(v['s'] for v in norm.values())
        self._stat_lbl.config(text=f"{_t('itemsCount').format(files)} · {_fmt_size(total)}")
        if getattr(self.pkg, 'kind', 'v9') == 'legacy':
            ver = getattr(self.pkg, 'format_version', '?')
            self._badge_lbl.config(text=f"KJKv{ver} · {_t('legacyBadge')}")
        else:
            backend = 'C ' + _t('engineBadge') if kjk9._HAS_C else _t('pyBadge')
            self._badge_lbl.config(text=f'KJKv9 · {backend}')
        self._refresh_dirty()

    def _refresh_dirty(self):
        s = self.pkg.pending_summary()
        if self.pkg.is_dirty():
            self._dirty_lbl.config(text='● ' + _t('statDirty').format(
                add=s['add'], deleted=s['delete'], rn=s['rename']))
        else:
            self._dirty_lbl.config(text='')

    # ---- 选择辅助 ----

    def _selected_node(self):
        return self.tree.selected

    def _selected_dir_rel(self):
        """返回"新增文件"应落入的目录 rel:
        选中文件夹 → 该文件夹; 选中文件 → 其父目录; 无选中 → 根目录('')。"""
        node = self.tree.selected
        if node is None:
            return ''
        rel = node.get('rel', '')
        if node.get('is_dir'):
            return rel
        par = rel.rsplit('/', 1)[0] if '/' in rel else ''
        return par

    def _rels_under(self, node):
        """节点(含子树)对应的所有包内 relpath。"""
        view = self.pkg.effective_files()
        if node is None:
            return []
        rel = node['rel']
        if not node.get('is_dir'):
            return [rel] if rel in view else []
        return sorted(p for p in view if p == rel or p.startswith(rel + '/'))

    def _guard_busy(self):
        if self._busy:
            self.set_status(_t('statBusy'))
            return True
        return False

    # ---- 动作 ----

    def _act_add(self):
        from tkinter import filedialog
        if self._guard_busy():
            return
        kind = ask_add_source(self.root)
        if kind is None:
            return
        target_dir = self._selected_dir_rel()
        if kind == 'files':
            files = filedialog.askopenfilenames(parent=self.root, title=_t('tbAdd'))
            if files:
                added, first_rel = self._stage_add_files(list(files), target_dir)
                self._after_stage_add(added, first_rel, target_dir)
        else:
            folder = filedialog.askdirectory(parent=self.root, title=_t('tbAdd'))
            if folder:
                added, first_rel = self._stage_add_files([folder], target_dir)
                self._after_stage_add(added, first_rel, target_dir)

    def _after_stage_add(self, added, first_rel, target_dir):
        if added:
            where = target_dir or '/'
            self.set_status(_t('statAdded').format(added))
            if first_rel:
                self.tree.reveal_rel(first_rel)
        else:
            self.set_status(_t('noSelection'))

    def _stage_add_files(self, paths, target_dir):
        added = 0
        first_rel = None
        for p in paths:
            p = p.strip('"')
            if os.path.isdir(p):
                base = os.path.basename(p.rstrip('\\/'))
                for root, dirs, files in os.walk(p):
                    for fn in sorted(files):
                        full = os.path.join(root, fn)
                        rel = os.path.relpath(full, p).replace('\\', '/')
                        rel = ((target_dir + '/' + base) if target_dir else base) + '/' + rel
                        try:
                            self.pkg.stage_add(full, relpath=rel)
                            added += 1
                            if first_rel is None:
                                first_rel = rel
                        except KJK9Error:
                            pass
            elif os.path.isfile(p):
                rel = os.path.basename(p)
                if target_dir:
                    rel = target_dir + '/' + rel
                try:
                    self.pkg.stage_add(p, relpath=rel)
                    added += 1
                    if first_rel is None:
                        first_rel = rel
                except KJK9Error:
                    pass
        self.refresh_tree()
        return added, first_rel

    def _act_extract(self):
        from tkinter import filedialog
        if self._guard_busy():
            return
        node = self._selected_node()
        rels = self._rels_under(node)
        if not rels:
            self.set_status(_t('noSelection'))
            return
        dest = filedialog.askdirectory(parent=self.root, title=_t('extractTo'))
        if not dest:
            return
        label = _t('decrypting')
        count = len(rels)

        def fn(prog, cancel):
            return self.pkg.extract_files(dest, rels, progress=prog, cancel=cancel)

        def done(ok, res, err):
            if ok:
                self.set_status(_t('statExtracted').format(res))
            else:
                self._task_error(err, lambda: self._act_extract())

        self.runner.run(f"{label} ({count})", fn, done, busy_setter=self._set_busy)

    def _act_rename(self):
        if self._guard_busy():
            return
        node = self._selected_node()
        if node is None:
            self.set_status(_t('noSelection'))
            return

        def commit(new_name):
            self._do_rename(node, new_name)

        self.tree.begin_rename(node, commit)

    def _do_rename(self, node, new_name):
        new_name = new_name.strip()
        if not new_name or '/' in new_name or '\\' in new_name:
            show_error(self.root, _t('badName'))
            return
        old = node['rel']
        if node.get('is_dir'):
            # 目录: 改所有子项前缀
            view = self.pkg.effective_files()
            targets = [p for p in view if p == old or p.startswith(old + '/')]
            prefix = old.rsplit('/', 1)[0]
            new_rel = (prefix + '/' + new_name) if prefix else new_name
            try:
                for p in sorted(targets, key=len, reverse=True):
                    tail = p[len(old):]
                    target = new_rel + tail
                    if '_pending' in view[p] and view[p].get('_pending') is not None \
                            and '_pending' in view[p]:
                        pass
                    if p in self.pkg._pending_add if hasattr(self.pkg, '_pending_add') else False:
                        self.pkg.rename_pending_add(p, target)
                    else:
                        self.pkg.stage_rename(p, target)
            except KJK9Error as e:
                show_error(self.root, str(e))
                return
        else:
            prefix = old.rsplit('/', 1)[0] if '/' in old else ''
            new_rel = (prefix + '/' + new_name) if prefix else new_name
            try:
                info = self.pkg.pending_add_info()
                if old in info:
                    self.pkg.rename_pending_add(old, new_rel)
                else:
                    self.pkg.stage_rename(old, new_rel)
            except KJK9Error as e:
                show_error(self.root, str(e))
                return
        self.refresh_tree()
        # 刷新后从新树定位重命名后的节点并更新选中, 避免旧 node 引用导致
        # 后续删除等操作显示错误名称(set_files 无法用旧 rel 匹配到新 rel)
        new_sel = None
        for n, _ in self.tree._flat:
            if n.get('rel') == new_rel:
                new_sel = n
                break
        if new_sel is not None:
            self.tree.selected = new_sel
        self.set_status(_t('statRenamed'))

    def _act_delete(self):
        if self._guard_busy():
            return
        node = self._selected_node()
        if node is None:
            self.set_status(_t('noSelection'))
            return
        rels = self._rels_under(node)
        if not rels:
            return
        label = node['name'] + ('/' if node.get('is_dir') else '')
        if not ask_confirm(self.root, _t('delConfirm').format(label),
                           buttons=[(_t('btnCancel'), None, False),
                                    (_t('btnDelete'), 'yes', True)]):
            return
        info = self.pkg.pending_add_info()
        for p in rels:
            if p in info:
                self.pkg.drop_pending_add(p)
            else:
                try:
                    self.pkg.stage_delete(p)
                except KJK9Error:
                    pass
        self.tree.selected = None
        self.refresh_tree()
        self.set_status(_t('statDeleted').format(len(rels)))

    def _act_pwd(self):
        if self._guard_busy():
            return
        if self.pkg.is_dirty():
            show_error(self.root, _t('saveDirtyFirst'), _t('pwdChangeTitle'))
            return
        res, vals = ask_two_passwords(self.root)
        if res != 'ok':
            return
        new_pwd, confirm = (vals + ['', ''])[:2]
        if new_pwd != confirm:
            show_error(self.root, _t('pwdMismatch'), _t('pwdChangeTitle'))
            return
        if not new_pwd:
            if not ask_confirm(self.root, _t('pwdNoneWarn'),
                               buttons=[(_t('btnCancel'), None, False),
                                        (_t('btnOk'), 'yes', True)]):
                return

        def fn(prog, cancel):
            return self.pkg.change_password(new_pwd, progress=prog, cancel=cancel)

        def done(ok, res, err):
            if ok:
                self.set_status(_t('statPwdChanged'))
            else:
                self._task_error(err, self._act_pwd)

        self.runner.run(_t('rekeying'), fn, done, busy_setter=self._set_busy)

    def _act_compact(self):
        if self._guard_busy():
            return
        if getattr(self.pkg, 'kind', 'v9') == 'legacy':
            self.set_status(_t('compactNone'))
            return
        if self.pkg.is_dirty():
            show_error(self.root, _t('saveDirtyFirst'))
            return
        hole = self.pkg.hole_size() if hasattr(self.pkg, 'hole_size') else 0
        if not hole:
            self.set_status(_t('compactNone'))
            return
        if not ask_confirm(self.root, _t('compactAsk').format(_fmt_size(hole)),
                           buttons=[(_t('btnCancel'), None, False),
                                    (_t('tbCompact'), 'yes', True)]):
            return
        before = os.path.getsize(self.pkg.path)

        def fn(prog, cancel):
            self.pkg.compact(progress=prog, cancel=cancel)
            return os.path.getsize(self.pkg.path)

        def done(ok, res, err):
            if ok:
                self.refresh_tree()
                self.set_status(_t('statCompact').format(_fmt_size(before),
                                                         _fmt_size(res)))
            else:
                self._task_error(err, self._act_compact)

        self.runner.run(_t('compacting'), fn, done, busy_setter=self._set_busy)

    def _act_save(self):
        if self._guard_busy():
            return
        if not self.pkg.is_dirty():
            self.set_status(_t('noChanges'))
            return
        # 先校验暂存新增的源文件仍可读
        info = self.pkg.pending_add_info()
        missing = [p for p, m in info.items()
                    if not os.path.isfile(str(m.get('src', '')))]
        for p in missing:
            res = ask_confirm(self.root, _t('srcMissing').format(p),
                              buttons=[(_t('btnCancel'), None, False),
                                       (_t('btnSkip'), 'skip', True)])
            if res == 'skip':
                self.pkg.drop_pending_add(p)
            else:
                return  # 中止保存
        if getattr(self.pkg, 'kind', 'v9') == 'legacy':
            self._legacy_save_flow()
            return

        def fn(prog, cancel):
            return self.pkg.save(progress=prog, cancel=cancel)

        def done(ok, res, err):
            if ok:
                self.refresh_tree()
                self.set_status(_t('statSaved').format(
                    time.strftime('%H:%M:%S')))
            else:
                self._task_error(err, self._act_save)

        self.runner.run(_t('saving'), fn, done, busy_setter=self._set_busy)

    def _legacy_save_flow(self):
        """旧格式保存: 询问升级 → KJKv9(C 引擎) / 留在旧格式。"""
        ver = getattr(self.pkg, 'format_version', '?')
        res = ask_confirm(self.root, _t('upgradeAsk').format(ver),
                          buttons=[(_t('btnCancel'), None, False),
                                   (_t('btnNo'), 'legacy', False),
                                   (_t('btnYes'), 'v9', True)],
                          title=_t('upgradeTitle'))

        def fn(prog, cancel):
            if res == 'v9':
                return ('v9', self.pkg.upgrade_to_v9(progress=prog, cancel=cancel))
            return ('legacy', self.pkg.save(progress=prog, cancel=cancel))

        def done(ok, res2, err):
            if not ok:
                self._task_error(err, self._legacy_save_flow)
                return
            mode, _r = res2
            if mode == 'v9':
                self.pkg = _r
                self.set_status(_t('statUpgraded'))
            else:
                self.set_status(_t('statSaved').format(time.strftime('%H:%M:%S')))
            self.refresh_tree()

        self.runner.run(_t('upgrading') if res == 'v9' else _t('saving'),
                        fn, done, busy_setter=self._set_busy)

    # ---- 文件查看/拖出 ----

    def _on_activate(self, node):
        """双击文件 → 立即局部解密到临时目录, 系统默认程序打开。"""
        if self._busy:
            return
        rel = node['rel']
        self.set_status(_t('viewing').format(node['name']))
        self.root.update_idletasks()

        def fn(prog, cancel):
            prog(0.3, rel)
            data = self.pkg.read_file(rel)
            d = os.path.join(self._tempfile.gettempdir(), 'KJK-View',
                             os.path.basename(self.pkg.path))
            dest = _safe_dest_join(d, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            if dest not in self._view_dirs:
                self._view_dirs.append(dest)
            with open(dest, 'wb') as f:
                f.write(data)
            prog(1.0, 'OK')
            return dest

        def done(ok, res, err):
            if ok:
                try:
                    os.startfile(res)  # noqa
                except OSError:
                    pass
                self.set_status(_t('statReady'))
            else:
                self._task_error(err, None)

        self.runner.run(_t('viewing').format(node['name']), fn, done,
                        busy_setter=self._set_busy)

    def _rels_total(self, node):
        view = self.pkg.effective_files()
        return sum(view[r].get('s', 0) for r in self._rels_under(node))

    def _prepare_drag_temp(self, node):
        """纯计算: 将节点(含子树)解密到临时目录并返回目标路径。不触碰 Tk, 可后台线程调用。"""
        rels = self._rels_under(node)
        if not rels:
            return None
        if self._rels_total(node) > 128 * 1024 * 1024:
            return None
        d = os.path.join(self._tempfile.gettempdir(), 'KJK-DragOut',
                         os.path.basename(self.pkg.path))
        try:
            self.pkg.extract_files(d, rels)
        except Exception:
            return None
        return _safe_dest_join(d, node['rel'])

    def _on_drag_out(self, node):
        """拖出: 优先用预渲染结果(后台已解密), 否则同步解密(回退), 交给系统拖放。"""
        rel = node.get('rel')
        in_flight = self._prep_event.get(rel)
        if in_flight is not None:
            # 后台预渲染尚在进行(用户拖早了): 等它的结果, 避免重复解密/并发写同一临时文件
            in_flight.wait(30)
            dest = self._prepared.pop(rel, None)
            if dest:
                self._drag_tmp.append(dest)
                return dest
        if rel and rel in self._prepared:
            dest = self._prepared.pop(rel)
            self._drag_tmp.append(dest)
            return dest
        if not self._rels_under(node):
            return None
        if self._rels_total(node) > 128 * 1024 * 1024:
            self.set_status(_t('dragHintBig'))
            return None
        dest = self._prepare_drag_temp(node)
        if dest:
            self._drag_tmp.append(dest)
        return dest

    def _on_drag_press(self, node):
        """按住行即预准备拖出(后台线程解密到临时), 使正式拖出不阻塞主界面。"""
        self._cancel_press_prep()
        if self._busy or node is None:
            return
        try:
            if not self._rels_under(node) or self._rels_total(node) > 128 * 1024 * 1024:
                return
        except Exception:
            return
        rel = node['rel']
        if rel in self._prepared:
            return
        self._press_node = node
        self._press_cancelled = False
        self._press_prep_job = self.root.after(240, self._start_press_prep)

    def _on_drag_release(self):
        """松开鼠标: 说明只是单击选中, 取消预渲染。"""
        self._cancel_press_prep()
        self._press_cancelled = True
        self._press_node = None

    def _cancel_press_prep(self):
        if self._press_prep_job is not None:
            try:
                self.root.after_cancel(self._press_prep_job)
            except tk.TclError:
                pass
            self._press_prep_job = None

    def _start_press_prep(self):
        self._press_prep_job = None
        if self._press_cancelled:
            self._press_node = None
            return
        node = self._press_node
        self._press_node = None
        if node is None:
            return
        rel = node['rel']
        ev = threading.Event()
        self._prep_event[rel] = ev

        def worker():
            try:
                dest = self._prepare_drag_temp(node)
                if dest:
                    self._prepared[rel] = dest
            finally:
                self._prep_event.pop(rel, None)
                ev.set()

        threading.Thread(target=worker, daemon=True).start()

    def _on_drop(self, paths, target_dir):
        """拖入: 先确认(告知将复制到包内相对路径), 再暂存新增并揭示新增文件。"""
        if self._guard_busy():
            return
        if not paths:
            return
        if not self._confirm_drop_into(paths, target_dir):
            return
        added, first_rel = self._stage_add_files(paths, target_dir)
        where = target_dir if target_dir else '/'
        if added:
            self.set_status(_t('dropAddTo').format(len(paths), where)
                            if target_dir else _t('dropAddRoot').format(len(paths)))
            if first_rel:
                self.tree.reveal_rel(first_rel)
        else:
            self.set_status(_t('noSelection'))

    def _confirm_drop_into(self, paths, target_dir):
        """拖拽外部文件进入包时, 明确告知将复制到包内相对路径, 由用户确认。"""
        n = len(paths)
        if target_dir:
            msg = _t('dropConfirmMsg').format(n, target_dir)
        else:
            msg = _t('dropConfirmRootMsg').format(n)
        res = ask_confirm(self.root, msg, title=_t('dropConfirmTitle'),
                          buttons=[(_t('btnCancel'), None, False),
                                   (_t('btnCopyHere'), 'ok', True)])
        if res != 'ok':
            self.set_status(_t('dropCanceled'))
            return False
        return True

    def _on_menu(self, node, event):
        menu = tk.Menu(self.root, tearoff=0, bg=self.c['card'], fg=self.c['fg'],
                      activebackground=self.c['accent'],
                      activeforeground='#ffffff', relief=tk.FLAT, bd=0)
        is_dir = node.get('is_dir')
        menu.add_command(label=_t('tbExtract'), command=self._act_extract)
        menu.add_command(label=_t('tbRename'), command=self._act_rename)
        menu.add_command(label=_t('tbDelete'), command=self._act_delete)
        menu.add_separator()
        menu.add_command(label=_t('tbAdd'), command=self._act_add)
        menu.add_command(label=_t('tbPwd'), command=self._act_pwd)
        menu.add_command(label=_t('tbSave'), command=self._act_save)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    # ---- 错误处理: 重试/跳过 ----

    def _task_error(self, err, retry_fn):
        msg = str(err)
        if isinstance(err, KJK9Cancel) or '取消' in msg:
            self.set_status(_t('canceled'))
            return
        buttons = [(_t('btnCancel'), None, False)]
        if retry_fn:
            buttons.append((_t('btnRetry'), 'retry', True))
        else:
            buttons.append((_t('btnOk'), 'ok', True))
        res = ask_confirm(self.root, _t('taskFailed').format(msg), buttons=buttons)
        if res == 'retry' and retry_fn:
            retry_fn()

    def _set_busy(self, busy):
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        for b in self._btns.values():
            try:
                b.config(state=state)
            except tk.TclError:
                pass

    # ---- 关闭 ----

    def _on_close(self):
        if self._closing:
            return
        if self.pkg.is_dirty() and not self._busy:
            res = ask_confirm(self.root, _t('closeDirty'),
                              buttons=[(_t('btnCancel'), None, False),
                                       (_t('btnDontSave'), 'no', False),
                                       (_t('btnSave'), 'save', True)])
            if res is None:
                return
            if res == 'save':
                self._closing = True
                self._act_save()
                # 保存完成后在 done 回调里关窗
                self.root.after(300, self._close_after_save)
                return
        self._close_after_save()

    def _close_after_save(self):
        self._closing = True
        self._cancel_press_prep()
        cleanup = list(self._view_dirs) + list(self._drag_tmp) + list(self._prepared.values())
        for d in cleanup:
            try:
                import shutil
                shutil.rmtree(os.path.dirname(d), ignore_errors=True)
            except Exception:
                pass
        self.root.destroy()


# ======================== 入口 ========================

def _peek_legacy_has_password(path):
    """探测旧文本格式包是否带密码头前缀(仅读文件开头一小段)。"""
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            head = f.read(1200)
        has_pwd, _, _, _ = engine.detect_password_prefix(head)
        return bool(has_pwd)
    except Exception:
        return False


def run_browse(path):
    """双击 .kjk 的浏览入口: 密码窗 → 进度(仅目录) → 浏览窗口。
    整个流程包 try/except, 任何异常弹错误窗而非静默退出。"""
    try:
        _run_browse_impl(path)
    except Exception as e:
        try:
            import traceback
            traceback.print_exc()
            root = tk.Tk()
            root.withdraw()
            show_error(root, f'{_t("openFailed")}\n{e}')
            root.destroy()
        except Exception:
            pass


def _run_browse_impl(path):
    """双击 .kjk 的浏览入口: 密码窗 → 进度(仅目录) → 浏览窗口。"""
    if not os.path.isfile(path):
        root = tk.Tk()
        root.withdraw()
        show_error(root, _t('notFound').format(path))
        root.destroy()
        return

    root = None
    try:
        if _HAS_DND:
            root = TkinterDnD.Tk()
        else:
            root = tk.Tk()
    except Exception:
        root = tk.Tk()
    root.withdraw()  # 打开阶段不显示主窗口

    is_v9, has_pwd = peek_info(path)
    if not is_v9:
        # 旧格式: 从包头探测密码头前缀, 首次打开即弹密码框(而非先白错一次)
        has_pwd = _peek_legacy_has_password(path) or None

    pkg = None
    while pkg is None:
        password = ''
        if has_pwd:
            res, vals = ask_password(root)
            if res != 'ok':
                root.destroy()
                return
            password = (vals + [''])[0]
        runner = TaskRunner(root)

        def open_fn(prog, cancel):
            if is_v9:
                prog(0.15, _t('reading'))
                pkg = KJK9Package.open(path, password)
                prog(1.0, 'OK')
                return pkg
            return LegacyPackage.open(path, password, progress=prog)

        result = {}
        done_var = tk.BooleanVar(root, False)

        def on_done(ok, res, err):
            result.update(ok=ok, res=res, err=err)
            done_var.set(True)

        runner.run(_t('openingPkg'), open_fn, on_done)
        root.wait_variable(done_var)

        if result.get('ok'):
            pkg = result['res']
        else:
            err = result.get('err')
            if isinstance(err, KJK9AuthError) or '密码' in str(err) or 'password' in str(err).lower():
                show_error(root, _t('pwdWrong'))
                has_pwd = True  # 让循环继续要密码
                continue
            show_error(root, f'{_t("openFailed")}\n{err}')
            root.destroy()
            return

    root.deiconify()
    BrowseWindow(root, pkg)
    root.mainloop()


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        run_browse(sys.argv[1])
