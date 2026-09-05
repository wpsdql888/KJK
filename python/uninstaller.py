# -*- coding: utf-8 -*-
"""KJK Encryptor - 独立卸载程序 v1.1.0

用法: python uninstaller.py [--silent]
      或以管理员身份运行以完整卸载注册表项
"""

import os
import sys
import ctypes
import shutil
import tkinter as tk
from tkinter import ttk, messagebox


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ======================== i18n ========================
I18N = {
    'window_title': {
        'en': 'KJK Encryptor Uninstaller',
        'zh-HK': 'KJK Encryptor Uninstaller',
        'zh-CN': 'KJK Encryptor 卸载程序',
    },
    'confirm_title': {
        'en': 'Confirm Uninstall',
        'zh-HK': '確認 Uninstall',
        'zh-CN': '确认卸载',
    },
    'confirm_msg': {
        'en': 'Are you sure you want to uninstall KJK Encryptor?\n\nThis will remove all installed files and registry entries.',
        'zh-HK': '確定要 Uninstall KJK Encryptor 嗎？\n\n呢個會刪除所有已安裝嘅檔案同 Registry 項目。',
        'zh-CN': '确定要卸载 KJK Encryptor 吗？\n\n这将删除所有已安装的文件和注册表项。',
    },
    'admin_required': {
        'en': 'Administrator privileges are required to clean registry entries.\nPlease run this uninstaller as administrator.',
        'zh-HK': '需要 Admin 權限先可以清理 Registry 項目。\n請以管理員身份重新運行呢個 Uninstaller。',
        'zh-CN': '需要管理员权限才能清理注册表项。\n请以管理员身份重新运行此卸载程序。',
    },
    'uninstalling': {
        'en': 'Uninstalling...',
        'zh-HK': 'Uninstall 緊...',
        'zh-CN': '正在卸载...',
    },
    'removing_registry': {
        'en': 'Removing registry entries...',
        'zh-HK': '移除 Registry 項目...',
        'zh-CN': '正在移除注册表项...',
    },
    'removing_shortcut': {
        'en': 'Removing desktop shortcut...',
        'zh-HK': '移除桌面 Shortcut...',
        'zh-CN': '正在移除桌面快捷方式...',
    },
    'removing_files': {
        'en': 'Removing installed files...',
        'zh-HK': '移除已安裝檔案...',
        'zh-CN': '正在移除已安装文件...',
    },
    'uninstall_complete': {
        'en': 'Uninstall Complete',
        'zh-HK': 'Uninstall 完成',
        'zh-CN': '卸载完成',
    },
    'uninstall_success': {
        'en': 'KJK Encryptor has been successfully uninstalled.\nResidual files will be cleaned up shortly.',
        'zh-HK': 'KJK Encryptor 已成功 Uninstall。\n殘留檔案將喺片刻後自動清理。',
        'zh-CN': 'KJK Encryptor 已成功卸载。\n残留文件将在片刻后自动清理。',
    },
}


def _t(key, lang='zh-CN'):
    """翻译函数"""
    entry = I18N.get(key, {})
    return entry.get(lang, entry.get('en', key))


def remove_registry(progress_callback=None):
    """移除所有注册表项，返回(success_count, total_count)"""
    import winreg

    menu_name = 'KJK Encryptor'
    prog_id = 'KJKEncryptor.kjk'

    # 所有需要删除的菜单项ID
    all_menu_ids = ['encrypt_here', 'encrypt_to', 'pack_to']
    kjk_menu_ids = ['decrypt_here', 'decrypt_to', 'add_to_kjk']

    # 所有需要处理的注册表前缀（文件、文件夹、桌面背景）
    prefixes = [
        fr'*\shell\{menu_name}',
        fr'Directory\shell\{menu_name}',
        fr'Directory\Background\shell\{menu_name}',
    ]

    success_count = 0
    total_count = 0

    # 1. 移除所有文件/文件夹右键菜单
    for prefix in prefixes:
        shell_path = fr'{prefix}\shell'
        for cid in all_menu_ids:
            total_count += 1
            try:
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{shell_path}\{cid}\command')
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{shell_path}\{cid}')
                success_count += 1
            except FileNotFoundError:
                success_count += 1  # 不存在也算成功
            except Exception:
                pass
        total_count += 2
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, shell_path)
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, prefix)
            success_count += 2
        except FileNotFoundError:
            success_count += 2
        except Exception:
            pass
        if progress_callback:
            progress_callback()

    # 2. 移除 .kjk 文件右键菜单
    kjk_shell = fr'{prog_id}\shell\{menu_name}\shell'
    for cid in kjk_menu_ids:
        total_count += 1
        try:
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{kjk_shell}\{cid}\command')
            winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{kjk_shell}\{cid}')
            success_count += 1
        except FileNotFoundError:
            success_count += 1
        except Exception:
            pass
    if progress_callback:
        progress_callback()

    total_count += 2
    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, kjk_shell)
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell\{menu_name}')
        success_count += 2
    except FileNotFoundError:
        success_count += 2
    except Exception:
        pass

    # 3. 移除 .kjk 默认打开方式
    total_count += 2
    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell\open\command')
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell\open')
        success_count += 2
    except FileNotFoundError:
        success_count += 2
    except Exception:
        pass
    if progress_callback:
        progress_callback()

    # 4. 移除 ProgID 相关项
    total_count += 3
    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\DefaultIcon')
        success_count += 1
    except FileNotFoundError:
        success_count += 1
    except Exception:
        pass

    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, fr'{prog_id}\shell')
        success_count += 1
    except FileNotFoundError:
        success_count += 1
    except Exception:
        pass

    try:
        winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, prog_id)
        success_count += 1
    except FileNotFoundError:
        success_count += 1
    except Exception:
        pass

    # 5. 移除 .kjk 扩展名关联
    total_count += 1
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, '.kjk') as key:
            val, _ = winreg.QueryValueEx(key, '')
            if val == prog_id:
                winreg.CloseKey(key)
                winreg.DeleteKey(winreg.HKEY_CLASSES_ROOT, '.kjk')
        success_count += 1
    except FileNotFoundError:
        success_count += 1
    except Exception:
        pass
    if progress_callback:
        progress_callback()

    # 6. 移除安装信息注册表项
    total_count += 2
    for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        try:
            winreg.DeleteKey(root, r'Software\KJK-Encryptor')
            success_count += 1
        except FileNotFoundError:
            success_count += 1
        except Exception:
            pass
    if progress_callback:
        progress_callback()

    return success_count, total_count


def remove_shortcut():
    """移除桌面快捷方式"""
    try:
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        shortcut_path = os.path.join(desktop, 'KJK Encryptor.lnk')
        if os.path.exists(shortcut_path):
            os.remove(shortcut_path)
        return True
    except Exception:
        return False


def _rmtree_installed(install_dir):
    """递归删除安装目录中未被锁定的文件(含 _internal/engine 子目录)。

    卸载器自身进程正在运行的文件会留下, 由批处理兜底删除。
    """
    if os.path.isdir(install_dir):
        try:
            shutil.rmtree(install_dir, ignore_errors=True)
        except Exception:
            pass


def _schedule_cleanup_batch(install_dir):
    """生成延迟删除安装目录的批处理脚本并启动。

    关键: 批处理先 cd 出安装目录——若 cmd 的工作目录就在安装目录内,
    rmdir 会因目录被占用而整体失败(用户报告"文件一个都没被删除"的根因)。
    并带重试循环应对文件句柄未及时释放。
    """
    temp_dir = os.environ.get('TEMP', '.')
    batch_path = os.path.join(temp_dir, 'kjk_uninstall_cleanup.bat')
    try:
        with open(batch_path, 'w', encoding='gbk') as f:
            f.write('@echo off\n')
            f.write('cd /d "%SystemDrive%\\"\n')
            f.write('for /L %%i in (1,1,8) do (\n')
            f.write(f'  rmdir /s /q "{install_dir}" 2>nul\n')
            f.write(f'  if not exist "{install_dir}" goto done\n')
            f.write('  ping -n 2 127.0.0.1 >nul\n')
            f.write(')\n')
            f.write(':done\n')
            f.write('del "%~f0"\n')
        import subprocess
        subprocess.Popen(['cmd.exe', '/c', 'start', '', '/min', batch_path],
                         creationflags=subprocess.CREATE_NO_WINDOW)
    except Exception:
        pass


class UninstallerApp:
    """带进度显示的卸载程序GUI"""

    def __init__(self, silent=False):
        self.silent = silent
        self.lang = 'zh-CN'

        # 尝试读取语言配置
        try:
            config_dir = os.path.dirname(os.path.abspath(__file__))
            config_path = os.path.join(config_dir, 'kjk_config.json')
            if os.path.exists(config_path):
                import json
                with open(config_path, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    self.lang = cfg.get('lang', 'zh-CN')
        except Exception:
            pass

        if not silent:
            self.root = tk.Tk()
            self.root.title(_t('window_title', self.lang))
            self.root.geometry('450x200')
            self.root.resizable(False, False)
            self.root.attributes('-topmost', True)

            # 进度条
            self.progress = ttk.Progressbar(self.root, mode='determinate', length=400)
            self.progress.pack(pady=(40, 10))

            self.status_label = tk.Label(self.root, text='', font=('', 11))
            self.status_label.pack(pady=5)

            self.root.update()

    def run(self):
        if not self.silent:
            # 确认对话框
            if not messagebox.askyesno(_t('confirm_title', self.lang),
                                        _t('confirm_msg', self.lang)):
                self.root.destroy()
                return

        self._do_uninstall()

    def _do_uninstall(self):
        install_dir = os.path.dirname(os.path.abspath(__file__))

        # 步骤1: 移除注册表
        self._update_status(_t('removing_registry', self.lang), 10)
        if is_admin():
            remove_registry(progress_callback=lambda: self._update_progress(10, 30))
        else:
            if not self.silent:
                messagebox.showwarning(_t('window_title', self.lang),
                                        _t('admin_required', self.lang))

        # 步骤2: 移除快捷方式
        self._update_status(_t('removing_shortcut', self.lang), 50)
        remove_shortcut()

        # 步骤3: 删除安装目录
        self._update_status(_t('removing_files', self.lang), 70)

        # 先直接递归删除能删的部分, 自身被锁定的文件交给批处理兜底
        _rmtree_installed(install_dir)
        _schedule_cleanup_batch(install_dir)

        self._update_progress(100, 100)
        self._update_status(_t('uninstall_complete', self.lang), 100)

        if not self.silent:
            messagebox.showinfo(_t('uninstall_complete', self.lang),
                                _t('uninstall_success', self.lang))
            self.root.destroy()

    def _update_status(self, text, progress):
        if not self.silent:
            self.status_label.config(text=text)
            self.progress['value'] = progress
            self.root.update()

    def _update_progress(self, current, total):
        if not self.silent:
            pct = int(current / total * 100) if total > 0 else 0
            self.progress['value'] = pct
            self.root.update()


def main():
    silent = '--silent' in sys.argv

    if silent:
        # 静默模式: 直接执行卸载
        install_dir = os.path.dirname(os.path.abspath(__file__))

        # 移除注册表
        if is_admin():
            remove_registry()

        # 移除快捷方式
        remove_shortcut()

        # 删除安装目录
        _rmtree_installed(install_dir)
        _schedule_cleanup_batch(install_dir)
    else:
        # GUI模式
        app = UninstallerApp(silent=False)
        app.run()


if __name__ == '__main__':
    main()