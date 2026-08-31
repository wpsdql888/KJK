# -*- coding: utf-8 -*-
"""KJK Encryptor - 安装/卸载程序

多步骤安装向导:
  第1页 - 语言选择
  第2页 - 用户协议
  第3页 - 必读免责声明
  第4页 - 检测已安装 / 选择安装目录
  第5页 - 注册表选项
  第6页 - 安装/卸载完成
"""

import os
import sys
import shutil
import zipfile
import ctypes
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

INSTALLER_VERSION = '1.0.4'


def get_resource_path(relative_path):
    """获取资源文件路径,兼容打包后和脚本模式。"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def get_python_cmd():
    """获取运行 Python 脚本的命令。

    优先使用 py 启动器(Windows 自带),其次 python。
    """
    for cmd in ('py', 'python'):
        try:
            import subprocess
            result = subprocess.run([cmd, '--version'], capture_output=True, timeout=3)
            if result.returncode == 0:
                return cmd
        except Exception:
            pass
    return 'py'


def is_admin():
    """检查是否具有管理员权限。"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_context_menu_registered():
    """检测右键菜单是否已注册，返回 (已注册, 注册路径)。"""
    import winreg
    menu_name = 'KJK Encryptor'
    prefixes = [
        fr'*\shell\{menu_name}',
        fr'Directory\shell\{menu_name}',
    ]
    
    registered_paths = []
    for prefix in prefixes:
        try:
            key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, prefix)
            winreg.CloseKey(key)
            registered_paths.append(prefix)
        except FileNotFoundError:
            pass
        except Exception:
            pass
    
    # 检查 .kjk 文件关联
    prog_id = 'KJKEncryptor.kjk'
    try:
        key = winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, prog_id)
        winreg.CloseKey(key)
        registered_paths.append(prog_id)
    except FileNotFoundError:
        pass
    except Exception:
        pass
    
    return len(registered_paths) > 0, registered_paths


def restart_as_admin():
    """以管理员权限重新启动当前程序。"""
    try:
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, 
            " ".join(sys.argv), None, 1
        )
        return True
    except Exception:
        return False


def create_shortcut(target_path, shortcut_name):
    """创建桌面快捷方式。"""
    try:
        import win32com.client
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        shortcut_path = os.path.join(desktop, shortcut_name)
        shell = win32com.client.Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target_path
        shortcut.WorkingDirectory = os.path.dirname(target_path)
        shortcut.save()
        return True
    except Exception:
        return False


def remove_shortcut(shortcut_name):
    """删除桌面快捷方式。"""
    try:
        desktop = os.path.join(os.environ['USERPROFILE'], 'Desktop')
        shortcut_path = os.path.join(desktop, shortcut_name)
        if os.path.exists(shortcut_path):
            os.remove(shortcut_path)
            return True
    except Exception:
        pass
    return False


def find_existing_install():
    """查找已安装的 KJK Encryptor,返回安装目录或 None。"""
    candidates = []

    # 1. 检查常见安装位置
    common_paths = [
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'KJK-Encryptor'),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'KJK-Encryptor'),
    ]
    for p in common_paths:
        # 检查 exe 或 uninstaller.py 作为安装标记
        if os.path.isdir(p) and (os.path.exists(os.path.join(p, 'KJK-Encryptor.exe'))
                                  or os.path.exists(os.path.join(p, 'uninstaller.py'))):
            candidates.append(p)

    # 2. 检查注册表中的安装路径
    try:
        import winreg
        key_path = r'Software\KJK-Encryptor'
        for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
            try:
                key = winreg.OpenKey(root, key_path)
                path, _ = winreg.QueryValueEx(key, 'InstallPath')
                if os.path.isdir(path) and (os.path.exists(os.path.join(path, 'KJK-Encryptor.exe'))
                                             or os.path.exists(os.path.join(path, 'uninstaller.py'))):
                    candidates.append(path)
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass
    except Exception:
        pass

    # 3. 检查 APPDATA 目录
    appdata = os.environ.get('APPDATA')
    if appdata:
        p = os.path.join(appdata, 'KJK-Encryptor')
        if os.path.isdir(p) and (os.path.exists(os.path.join(p, 'KJK-Encryptor.exe'))
                                  or os.path.exists(os.path.join(p, 'uninstaller.py'))):
            candidates.append(p)

    # 去重并返回第一个
    seen = set()
    for c in candidates:
        norm = os.path.normpath(c).lower()
        if norm not in seen:
            seen.add(norm)
            return c
    return None


def read_installed_version(install_dir):
    """从安装目录读取已安装的版本号,返回字符串或 None。"""
    version_file = os.path.join(install_dir, 'version.txt')
    if os.path.exists(version_file):
        try:
            with open(version_file, 'r', encoding='utf-8') as f:
                return f.read().strip()
        except Exception:
            pass
    return None


def compare_versions(installed_ver, installer_ver):
    """比较已安装版本和安装程序版本,返回: 'same', 'upgrade', 'downgrade'。"""
    if installed_ver == installer_ver:
        return 'same'
    try:
        # 简单比较: 通过 '.' 分割后逐段比较
        inst_parts = [int(x) for x in installed_ver.split('.')]
        installer_parts = [int(x) for x in installer_ver.split('.')]
        # 补齐到相同长度
        while len(inst_parts) < len(installer_parts):
            inst_parts.append(0)
        while len(installer_parts) < len(inst_parts):
            installer_parts.append(0)
        if installer_parts > inst_parts:
            return 'upgrade'
        elif installer_parts < inst_parts:
            return 'downgrade'
        else:
            return 'same'
    except (ValueError, AttributeError):
        # 版本号格式异常,保守处理
        if installed_ver != installer_ver:
            return 'upgrade'
        return 'same'


# ======================== 国际化 ========================

I18N = {
    'window_title': {
        'en': 'KJK Encryptor Installer',
        'zh-HK': 'KJK Encryptor Installer',
        'zh-CN': 'KJK Encryptor 安装程序',
    },
    'welcome_title': {
        'en': 'Welcome to the installation program of KJK Encryptor',
        'zh-HK': '歡迎使用 KJK Encryptor Installer',
        'zh-CN': '欢迎使用 KJK Encryptor 安装程序',
    },
    'select_language': {
        'en': 'Please select your language',
        'zh-HK': '請揀您嘅語言 Language',
        'zh-CN': '请选择您的语言',
    },
    'lang_en': {'en': 'English', 'zh-HK': 'English', 'zh-CN': 'English'},
    'lang_zhHK': {'en': 'Traditional Chinese (Hong Kong)', 'zh-HK': '繁體中文（港）', 'zh-CN': '繁体中文（中国香港）'},
    'lang_zhCN': {'en': 'Simplified Chinese (Mainland)', 'zh-HK': '簡體中文（中國大陸）', 'zh-CN': '简体中文（中国大陆）'},
    'agreement_title': {
        'en': 'Please read and agree to the User Agreement to continue',
        'zh-HK': '請閱讀 User Agreement 並同意先可以繼續',
        'zh-CN': '请阅读用户协议并同意以继续',
    },
    'btn_decline': {'en': 'Decline', 'zh-HK': 'Decline', 'zh-CN': '拒绝'},
    'btn_agree': {'en': 'I Agree', 'zh-HK': 'I Agree', 'zh-CN': '我同意'},
    'license_title': {
        'en': 'KJK Encryptor Source Code License and User Agreement',
        'zh-HK': 'KJK Encryptor Source Code License & User Agreement',
        'zh-CN': 'KJK Encryptor 源代码许可与用户协议',
    },
    'license_desc': {
        'en': 'Please read the following KJK Encryptor Source Code License and User Agreement carefully. You must agree to the terms before installation.',
        'zh-HK': '請仔細閱讀以下《KJK Encryptor Source Code License & User Agreement》。你必須同意相關條款先可以繼續安裝。',
        'zh-CN': '请仔细阅读以下《KJK Encryptor 源代码许可与用户协议》。您必须同意相关条款后方可继续安装。',
    },
    'disclaimer_title': {
        'en': 'Mandatory Disclaimer',
        'zh-HK': '必讀 Disclaimer',
        'zh-CN': '必读免责声明',
    },
    'disclaimer_desc': {
        'en': 'Please read the following disclaimer carefully. You must accept it to continue installation.',
        'zh-HK': '請仔細閱讀以下 Disclaimer。你必須接受先可以繼續安裝。',
        'zh-CN': '请仔细阅读以下免责声明。您必须接受后方可继续安装。',
    },
    'disclaimer_accept': {
        'en': 'I have read and accept the disclaimer',
        'zh-HK': '我已睇咗並接納上述 Disclaimer',
        'zh-CN': '我已阅读并接受上述免责声明',
    },
    'must_accept_disclaimer': {
        'en': 'You must accept the disclaimer to continue.',
        'zh-HK': '你必須接受 Disclaimer 先可以繼續。',
        'zh-CN': '您必须接受免责声明后方可继续。',
    },
    'btn_continue': {'en': 'Continue', 'zh-HK': 'Continue', 'zh-CN': '继续'},
    'btn_accept': {'en': 'Accept', 'zh-HK': 'Accept', 'zh-CN': '接受'},
    'install_dir_title': {
        'en': 'Select Installation Directory',
        'zh-HK': '揀安裝目錄',
        'zh-CN': '选择安装目录',
    },
    'install_dir_desc': {
        'en': 'Please select the directory where KJK Encryptor will be installed.',
        'zh-HK': '請揀 KJK Encryptor 嘅安裝目錄。',
        'zh-CN': '请选择 KJK Encryptor 的安装目录。',
    },
    'btn_browse': {'en': 'Browse...', 'zh-HK': 'Browse...', 'zh-CN': '浏览...'},
    'btn_previous': {'en': 'Previous', 'zh-HK': 'Previous', 'zh-CN': '上一步'},
    'btn_next': {'en': 'Next', 'zh-HK': 'Next', 'zh-CN': '下一步'},
    'registry_title': {
        'en': 'Would you like to add KJK Encryptor to your right-click menu?',
        'zh-HK': '要將 KJK Encryptor 加入你嘅右鍵選單嗎？',
        'zh-CN': '需要将 KJK Encryptor 加入到您的右键菜单吗',
    },
    'registry_desc1': {
        'en': 'This will write to the registry. You can uninstall or install it later.',
        'zh-HK': '呢個會寫入 Registry，你之後可以隨時 Uninstall 或者重新 Install',
        'zh-CN': '这将会发生注册表写入,您可以在后续的使用中卸载或安装',
    },
    'registry_desc2': {
        'en': 'You will get some quick functions for convenience. This will not threaten your computer system security.',
        'zh-HK': '你會用到一啲快捷功能，唔會影響你部電腦嘅系統安全',
        'zh-CN': '您将获得部分快捷功能便于使用,这将不会威胁到您的计算机系统安全',
    },
    'btn_skip': {'en': 'Not Now', 'zh-HK': 'Not Now', 'zh-CN': '暂时不需要'},
    'btn_yes': {'en': 'Yes', 'zh-HK': 'Yes', 'zh-CN': '需要'},
    'install_complete': {
        'en': 'Installation Complete',
        'zh-HK': '安裝完成啦',
        'zh-CN': '安装完成',
    },
    'uninstall_complete': {
        'en': 'Uninstallation Complete',
        'zh-HK': 'Uninstall 完成啦',
        'zh-CN': '卸载完成',
    },
    'install_success': {
        'en': 'KJK Encryptor has been successfully installed to:\n{path}',
        'zh-HK': 'KJK Encryptor 已成功安裝到：\n{path}',
        'zh-CN': 'KJK Encryptor 已成功安装到:\n{path}',
    },
    'install_success_registry': {
        'en': 'KJK Encryptor has been successfully installed and the right-click menu has been registered.',
        'zh-HK': 'KJK Encryptor 已成功安裝，右鍵選單已經 Register 好。',
        'zh-CN': 'KJK Encryptor 已成功安装,右键菜单已注册。',
    },
    'uninstall_success': {
        'en': 'KJK Encryptor has been successfully uninstalled.',
        'zh-HK': 'KJK Encryptor 已成功 Uninstall。',
        'zh-CN': 'KJK Encryptor 已成功卸载。',
    },
    'btn_finish': {'en': 'Finish', 'zh-HK': 'Finish', 'zh-CN': '完成'},
    'powered_by': {'en': 'Powered by DNT Group', 'zh-HK': 'Powered by DNT Group', 'zh-CN': 'Powered by DNT Group'},
    'website': {'en': 'https://DNTeam.top', 'zh-HK': 'https://DNTeam.top', 'zh-CN': 'https://DNTeam.top'},
    'installing': {
        'en': 'Installing...',
        'zh-HK': 'Installing...',
        'zh-CN': '安装中...',
    },
    'uninstalling': {
        'en': 'Uninstalling...',
        'zh-HK': 'Uninstalling...',
        'zh-CN': '卸载中...',
    },
    'admin_required': {
        'en': 'Administrator privileges are required to register the context menu.\nPlease run the installer as administrator.',
        'zh-HK': 'Register 右鍵選單需要 Admin 權限。\n請以管理員身份重新運行 Installer。',
        'zh-CN': '注册右键菜单需要管理员权限。\n请以管理员身份重新运行安装程序。',
    },
    'registry_already_registered': {
        'en': 'Context menu is already registered.',
        'zh-HK': '右鍵選單已經註冊。',
        'zh-CN': '右键菜单已注册。',
    },
    'registry_keep_existing': {
        'en': 'Keep existing context menu (no admin required)',
        'zh-HK': '保留現有右鍵選單（無需 Admin）',
        'zh-CN': '保留现有右键菜单（无需管理员）',
    },
    'btn_restart_admin': {
        'en': 'Restart as Admin',
        'zh-HK': '以 Admin 重啟',
        'zh-CN': '以管理员重启',
    },
    'registry_update_note': {
        'en': 'Note: The context menu will be updated to point to the new installation.',
        'zh-HK': '注意：右鍵選單將更新為指向新安裝位置。',
        'zh-CN': '注意：右键菜单将更新为指向新安装位置。',
    },
    'shortcut_title': {
        'en': 'Create desktop shortcut?',
        'zh-HK': '要整個桌面 Shortcut 嗎？',
        'zh-CN': '需要创建桌面快捷方式吗?',
    },
    'shortcut_desc': {
        'en': 'A shortcut will be created on your desktop for quick access.',
        'zh-HK': '會喺你個 Desktop 整個 Shortcut，方便快速開啟。',
        'zh-CN': '将在您的桌面创建快捷方式以便快速访问。',
    },
    'btn_create_shortcut': {'en': 'Create Shortcut', 'zh-HK': 'Create Shortcut', 'zh-CN': '创建快捷方式'},
    'btn_no_shortcut': {'en': 'Skip', 'zh-HK': 'Skip', 'zh-CN': '跳过'},
    'detect_title': {
        'en': 'Existing Installation Detected',
        'zh-HK': '檢測到已安裝',
        'zh-CN': '检测到已安装',
    },
    'detect_desc': {
        'en': 'KJK Encryptor is already installed at:\n{path}\n\nWhat would you like to do?',
        'zh-HK': 'KJK Encryptor 已經安裝喺：\n{path}\n\n你想做咩？',
        'zh-CN': 'KJK Encryptor 已安装在:\n{path}\n\n您想执行什么操作?',
    },
    'btn_uninstall': {'en': 'Uninstall', 'zh-HK': 'Uninstall', 'zh-CN': '卸载'},
    'btn_reinstall': {'en': 'Reinstall', 'zh-HK': 'Reinstall', 'zh-CN': '重新安装'},
    'btn_new_install': {'en': 'New Installation', 'zh-HK': '新安裝', 'zh-CN': '新安装'},
    'uninstall_confirm': {
        'en': 'Are you sure you want to uninstall KJK Encryptor?\n\nThis will remove all installed files and registry entries.',
        'zh-HK': '確定要 Uninstall KJK Encryptor 嗎？\n\n呢個會刪除所有已安裝嘅檔案同 Registry 項目。',
        'zh-CN': '确定要卸载 KJK Encryptor 吗?\n\n这将删除所有已安装的文件和注册表项。',
    },
    'uninstall_admin_required': {
        'en': 'Administrator privileges are required to uninstall.\nPlease run the installer as administrator.',
        'zh-HK': 'Uninstall 需要 Admin 權限。\n請以管理員身份重新運行 Installer。',
        'zh-CN': '卸载需要管理员权限。\n请以管理员身份重新运行安装程序。',
    },

    # ---- Version-related messages ----
    'version_title': {
        'en': 'Version Information',
        'zh-HK': '版本資訊',
        'zh-CN': '版本信息',
    },
    'version_installed': {
        'en': 'Installed version: {ver}',
        'zh-HK': '已安裝版本：{ver}',
        'zh-CN': '已安装版本：{ver}',
    },
    'version_installer': {
        'en': 'Installer version: {ver}',
        'zh-HK': '安裝程式版本：{ver}',
        'zh-CN': '安装程序版本：{ver}',
    },
    'version_overwrite': {
        'en': 'Same version detected. Do you want to overwrite the existing installation?',
        'zh-HK': '偵測到相同版本。你想覆蓋現有安裝嗎？',
        'zh-CN': '检测到相同版本。是否要覆盖现有安装？',
    },
    'version_upgrade': {
        'en': 'New version available: {ver}. Do you want to upgrade?',
        'zh-HK': '有新版本：{ver}。你想升級嗎？',
        'zh-CN': '有新版本：{ver}。是否要升级？',
    },
    'version_downgrade': {
        'en': 'Installer version is older than installed ({installed} > {installer}). Do you want to downgrade?',
        'zh-HK': '安裝程式版本舊過已安裝版本（{installed} > {installer}）。你想降級嗎？',
        'zh-CN': '安装程序版本低于已安装版本（{installed} > {installer}）。是否要降级？',
    },
    'btn_overwrite': {'en': 'Overwrite', 'zh-HK': '覆蓋', 'zh-CN': '覆盖安装'},
    'btn_upgrade': {'en': 'Upgrade', 'zh-HK': '升級', 'zh-CN': '升级'},
    'btn_downgrade': {'en': 'Downgrade', 'zh-HK': '降級', 'zh-CN': '降级'},
}

# ======================== 用户协议文本 ========================

AGREEMENT_TEXT = {
    'en': """KJK Encryptor Source Code License and User Agreement

Last Updated: August 2026

1. License Grant
KJK Encryptor source code is licensed to you under this agreement. You are free to view, modify, and use the source code for any purpose, including commercial use.

2. Source Code Access
The complete source code is publicly available. You may inspect, fork, and contribute to the codebase at any time.

3. Commercial Use
You may use this software for commercial purposes without restriction. No licensing fees or royalties are required.

4. Modification Rights
You may modify the source code to suit your needs. Modified versions may be distributed under the same open-source terms.

5. Redistribution
You may redistribute the original or modified software, provided that the original copyright notice and this license agreement are preserved.

6. Privacy & Data Protection
The Software processes all data locally on your device. It does not collect, transmit, or store any personal data in the normal course of use. Use of the Software is subject to the Privacy Policy, which complies with the Hong Kong Personal Data (Privacy) Ordinance (Cap. 486, "PDPO") and, where applicable to you, the EU General Data Protection Regulation (Regulation (EU) 2016/679, "GDPR"). You may exercise your data-protection rights as described in the Privacy Policy.

7. Disclaimer
The Software is provided "as is" without any warranty. DNT Group shall not be liable for any direct or indirect damages arising from the use of the Software. You are solely responsible for ensuring that your use of the Software complies with the applicable laws in your jurisdiction, and you must not use it to hide, encrypt, transmit, or distribute illegal content.

8. Account & Tracking
No account, profiling, or behavioural tracking is involved in the use of the Software.

9. Governing Law
This agreement and the use of the Software are governed by the laws of the Hong Kong Special Administrative Region of the People's Republic of China.

10. Changes to Agreement
DNT Group reserves the right to modify this agreement at any time. Material changes will be brought to your attention, and continued use of the Software constitutes acceptance of the modified agreement.""",

    'zh-HK': """KJK Encryptor Source Code License & User Agreement

最後更新：2026年8月

1. 授權許可
KJK Encryptor 原始碼根據本協議授權畀您。您可以自由查看、修改同使用原始碼，包括用於商業用途。

2. 原始碼存取
完整原始碼公開可用。您可以隨時檢視、fork 同貢獻 codebase。

3. 商業用途
您可以將本軟件用於商業用途，唔受任何限制。唔使支付任何 license 費或 royalty。

4. 修改權利
您可以根據需要修改原始碼。修改後嘅版本可以按照相同嘅 open-source 條款分發。

5. 重新分發
您可以重新分發原始或修改後嘅軟件，但必須保留原始版權聲明同本授權協議。

6. 私隱與數據保護
本軟件喺您部 device 上本地處理所有數據。喺正常使用過程中，佢唔會收集、傳輸或儲存任何個人資料。使用本軟件須遵守《私隱政策》，該政策符合中國香港《個人資料（私隱）條例》（第 486 章，「PDPO」），並於適用於您時符合歐盟《通用數據保障條例》（Regulation (EU) 2016/679，「GDPR」）。您可以按《私隱政策》所述行使您嘅數據保護權利。

7. 免責聲明
本軟件按「現狀」提供，不附帶任何擔保。DNT Group 唔對因使用本軟件而產生嘅任何直接或間接損害承擔責任。您須自行負責確保使用本軟件符合您所在地區嘅適用法律，亦不得使用本軟件隱藏、加密、傳輸或分發非法內容。

8. 帳戶與追蹤
使用本軟件唔涉及任何帳戶、profile 或行為追蹤。

9. 適用法律
本協議同使用本軟件受中華人民共和國香港特別行政區法律管轄。

10. 協議變更
DNT Group 保留隨時修改本協議嘅權利。重大變更會適時通知您，繼續使用本軟件即表示您接受修改後嘅協議。""",

    'zh-CN': """KJK Encryptor 源代码许可与用户协议

最后更新：2026年8月

1. 许可授权
KJK Encryptor 源代码根据本协议授权予您。您可以自由查看、修改和使用源代码，包括用于商业用途。

2. 源代码访问
完整源代码公开可用。您可以随时检视、分支和贡献代码库。

3. 商业用途
您可以将本软件用于商业用途，不受任何限制。无需支付任何授权费或版税。

4. 修改权利
您可以根据需要修改源代码。修改后的版本可以按照相同的开源条款分发。

5. 重新分发
您可以重新分发原始或修改后的软件，但必须保留原始版权声明和本授权协议。

6. 隐私与数据保护
本软件在您的设备上本地处理所有数据。在正常使用过程中，它不会收集、传输或存储任何个人资料。使用本软件须遵守《隐私政策》，该政策符合中华人民共和国香港特别行政区《个人资料（私隐）条例》（第 486 章，"PDPO"），并在适用于您时符合欧盟《通用数据保护条例》（Regulation (EU) 2016/679，"GDPR"）。您可以按《隐私政策》所述行使您的数据保护权利。

7. 免责声明
本软件按「现状」提供，不附带任何担保。DNT Group不对因使用本软件而产生的任何直接或间接损害承担责任。您须自行负责确保使用本软件符合您所在地区的适用法律，亦不得使用本软件隐藏、加密、传输或分发非法内容。

8. 账户与追踪
使用本软件不涉及任何账户、用户画像或行为追踪。

9. 适用法律
本协议及使用本软件受中华人民共和国香港特别行政区法律管辖。

10. 协议变更
DNT Group保留随时修改本协议的权利。重大变更会适时通知您，继续使用本软件即表示您接受修改后的协议。""",
}

DISCLAIMER_TEXT = {
    'en': """MANDATORY DISCLAIMER

Last Updated: August 2026

1. No Warranty
KJK Encryptor is provided "as is", without warranty of any kind, express or implied. DNT Group makes no guarantees regarding merchantability, fitness for a particular purpose, security, or non-infringement.

2. Use at Your Own Risk
You assume all risks associated with the use of this software for encryption, decryption, or data transmission. Data loss, file corruption, or inaccessible data may occur. Always keep backups of your original files before performing important operations.

3. Password Responsibility
If you forget or lose your password, DNT Group cannot and will not help you recover the encrypted data. There is no "back door" and no recovery mechanism.

4. Legal Compliance
You are solely responsible for ensuring that your use of KJK Encryptor complies with all applicable laws and regulations in your jurisdiction. You must not use this software to hide, encrypt, transmit, or distribute illegal content, including but not limited to malware, child sexual abuse material, terrorist propaganda, or content that infringes on the intellectual property rights of others.

5. Limitation of Liability
To the maximum extent permitted by applicable law, DNT Group and its contributors shall not be liable for any direct, indirect, incidental, special, or consequential damages arising out of or in connection with the use or inability to use this software.

6. Open Source and Commercial Use
The source code is licensed under the KJK Encryptor Source Code License and User Agreement. Commercial use is permitted, provided that the original copyright notice and license terms are retained. DNT Group is not responsible for any modified versions distributed by third parties.

7. Network Connections
The software may optionally check for updates or open the official website/API documentation in your system browser. These features can be disabled in Settings. All encryption and decryption operations are performed locally on your device.

8. Data Protection Compliance
The Software is provided in compliance with the Hong Kong Personal Data (Privacy) Ordinance (Cap. 486, "PDPO") and, where applicable to you, the EU General Data Protection Regulation (Regulation (EU) 2016/679, "GDPR"). No personal data is collected, transmitted, or stored by the Software in the normal course of use. For details on your data-protection rights, please refer to the Privacy Policy.

9. Governing Law
This disclaimer and the use of the Software are governed by the laws of the Hong Kong Special Administrative Region of the People's Republic of China. This does not limit any mandatory consumer protections available to you under your local law.

By clicking "Accept" or continuing with the installation, you acknowledge that you have read, understood, and accepted this disclaimer in its entirety.""",

    'zh-HK': """必讀 Disclaimer

最後更新：2026年8月

1. 無擔保
KJK Encryptor 按「現狀」提供，不附帶任何明示或暗示擔保。DNT Group 不保證其適銷性、特定用途適用性、安全性或不侵權。

2. 自行承擔使用風險
您須自行承擔使用本軟件進行加密、解密或數據傳輸嘅所有風險，包括數據遺失、檔案損壞或無法存取數據。執行重要操作前，請務必備份原始檔案。

3. 密碼責任
如果您忘記或遺失密碼，DNT Group 無法亦唔會協助您恢復加密數據。本軟件冇「後門」或任何恢復機制。

4. 法律合規
您有責任確保使用 KJK Encryptor 符合您所在地區嘅所有適用法律法規。您不得使用本軟件隱藏、加密、傳輸或分發非法內容，包括但不限於惡意軟件、兒童色情內容、恐怖主義宣傳材料或侵犯他人知識產權嘅內容。

5. 責任限制
在法律允許嘅最大範圍內，DNT Group 及其貢獻者唔會對因使用或無法使用本軟件而導致嘅任何直接、間接、附帶、特殊或 consequential 損害承擔責任。

6. 開源同商業用途
原始碼根據《KJK Encryptor Source Code License & User Agreement》授權。允許商業用途，但必須保留原始版權聲明同許可條款。DNT Group 唔對第三方分發嘅修改版本負責。

7. 網絡連接
本軟件可選擇檢查 update 或喺系統瀏覽器中打開官方網站 / API 文件。呢啲功能可以喺「Settings」中關閉。所有加密同解密操作都喺您部 device 本地完成。

8. 數據保護合規
本軟件嘅提供符合中國香港《個人資料（私隱）條例》（第 486 章，「PDPO」），並於適用於您時符合歐盟《通用數據保障條例》（Regulation (EU) 2016/679，「GDPR」）。喺正常使用過程中，本軟件唔會收集、傳輸或儲存任何個人資料。有關您嘅數據保護權利詳情，請參閱《私隱政策》。

9. 適用法律
本 Disclaimer 同使用本軟件受中華人民共和國香港特別行政區法律管轄。此並唔限制您根據本地法律享有嘅任何強制性消費者保障。

撳「Accept」或繼續安裝，即表示您已完整閱讀、理解並接受本 Disclaimer。""",

    'zh-CN': """必读免责声明

最后更新：2026年8月

1. 无担保
KJK Encryptor 按「现状」提供,不附带任何明示或暗示担保。DNT Group 不保证其适销性、特定用途适用性、安全性或不侵权。

2. 自行承担使用风险
您须自行承担使用本软件进行加密、解密或数据传输的所有风险,包括数据丢失、文件损坏或无法访问数据。执行重要操作前,请务必备份原始文件。

3. 密码责任
如果您忘记或遗失密码,DNT Group 无法亦不会协助您恢复加密数据。本软件没有「后门」或任何恢复机制。

4. 法律合规
您有责任确保使用 KJK Encryptor 符合您所在地区的所有适用法律法规。您不得使用本软件隐藏、加密、传输或分发非法内容,包括但不限于恶意软件、儿童色情内容、恐怖主义宣传材料或侵犯他人知识产权的内容。

5. 责任限制
在法律允许的最大范围内,DNT Group 及其贡献者不会对因使用或无法使用本软件而导致的任何直接、间接、附带、特殊或 consequential 损害承担责任。

6. 开源与商业用途
源代码根据《KJK Encryptor 源代码许可与用户协议》授权。允许商业用途,但必须保留原始版权声明和许可条款。DNT Group 不对第三方分发的修改版本负责。

7. 网络连接
本软件可选择检查更新或在系统浏览器中打开官方网站/API 文档。这些功能可在「设置」中关闭。所有加密和解密操作均在您的设备本地完成。

8. 数据保护合规
本软件的提供符合中华人民共和国香港特别行政区《个人资料（私隐）条例》（第 486 章，"PDPO"），并在适用于您时符合欧盟《通用数据保护条例》（Regulation (EU) 2016/679，"GDPR"）。在正常使用过程中，本软件不会收集、传输或存储任何个人资料。有关您的数据保护权利详情，请参阅《隐私政策》。

9. 适用法律
本免责声明及使用本软件受中华人民共和国香港特别行政区法律管辖。此并不限制您根据本地法律享有的任何强制性消费者保障。

点击「接受」或继续安装，即表示您已完整阅读、理解并接受本免责声明。""",
}


def load_license_text(lang='en'):
    """載入 LICENSE 文件內容;若無則返回內建協議摘要。"""
    license_path = get_resource_path('LICENSE')
    if not os.path.exists(license_path):
        license_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'LICENSE')
    if os.path.exists(license_path):
        try:
            with open(license_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception:
            pass
    return AGREEMENT_TEXT.get(lang, AGREEMENT_TEXT['en'])


# ======================== 颜色主题 ========================

COLORS = {
    'bg': '#FFFFFF',
    'fg': '#1D1D1F',
    'accent': '#0071E3',
    'accent_hover': '#0077ED',
    'border': '#D2D2D7',
    'card': '#F5F5F7',
    'text_secondary': '#86868B',
    'btn_bg': '#FFFFFF',
    'btn_border': '#0071E3',
    'btn_fg': '#0071E3',
}

# ======================== 安装程序类 ========================


class InstallerApp:
    def __init__(self):
        self.lang = 'zh-CN'
        self.root = tk.Tk()
        self.root.title(self._t('window_title'))
        self.root.geometry('700x600')
        self.root.resizable(False, False)
        self.root.configure(bg=COLORS['bg'])

        # 设置窗口图标
        self._set_window_icon()

        self.install_dir = ''
        self.existing_install = find_existing_install()
        self.mode = 'install'  # 'install' or 'uninstall'
        self.want_registry = False
        self.current_page = 0
        self.total_pages = 6

        self._build_ui()
        self._show_page(0)

        # 绑定关闭事件
        self.root.protocol('WM_DELETE_WINDOW', self.root.destroy)

    def _set_window_icon(self):
        """设置窗口图标。"""
        icon_path = get_resource_path('icon.png')
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon', 'icon.png')
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python', 'icon', 'icon.png')
        if os.path.exists(icon_path):
            try:
                img = Image.open(icon_path)
                self.icon_photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, self.icon_photo)
            except Exception:
                pass

    # ======================== 工具方法 ========================

    def _t(self, key, **kwargs):
        entry = I18N.get(key, {}).get(self.lang, key)
        if kwargs:
            try:
                return entry.format(**kwargs)
            except (KeyError, ValueError):
                return entry
        return entry

    def _c(self):
        return COLORS

    def _clear_page(self):
        for widget in self.content_frame.winfo_children():
            widget.destroy()

    # ======================== UI 构建 ========================

    def _build_ui(self):
        c = self._c()

        # 顶部区域: 图标 + 内容
        top_frame = tk.Frame(self.root, bg=c['bg'])
        top_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(20, 0))

        # 左侧图标
        icon_frame = tk.Frame(top_frame, bg=c['bg'], width=100)
        icon_frame.pack(side=tk.LEFT, fill=tk.Y)
        icon_frame.pack_propagate(False)

        self.icon_label = tk.Label(icon_frame, bg=c['bg'])
        icon_path = get_resource_path('icon.png')
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon', 'icon.png')
        if not os.path.exists(icon_path):
            icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'python', 'icon', 'icon.png')
        if os.path.exists(icon_path):
            try:
                img = Image.open(icon_path)
                img = img.resize((96, 96), Image.LANCZOS)
                self.icon_photo = ImageTk.PhotoImage(img)
                self.icon_label.config(image=self.icon_photo)
            except Exception:
                self.icon_label.config(text='\U0001F512', font=('Verdana', 72), fg=c['accent'])
        else:
            self.icon_label.config(text='\U0001F512', font=('Verdana', 72), fg=c['accent'])
        self.icon_label.pack(pady=(10, 0))

        # 右侧内容区
        self.content_frame = tk.Frame(top_frame, bg=c['bg'])
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(20, 0))

        # 底部区域
        bottom_frame = tk.Frame(self.root, bg=c['bg'], height=50)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=30, pady=(0, 15))
        bottom_frame.pack_propagate(False)

        # 底部左侧: Powered by
        self.powered_label = tk.Label(bottom_frame, text=self._t('powered_by'),
                                       bg=c['bg'], fg=c['text_secondary'],
                                       font=('Verdana', 11))
        self.powered_label.pack(side=tk.LEFT)

        # 底部右侧: 网站
        self.website_label = tk.Label(bottom_frame, text=self._t('website'),
                                       bg=c['bg'], fg=c['accent'],
                                       font=('Verdana', 11), cursor='hand2')
        self.website_label.pack(side=tk.RIGHT)

        # 底部按钮区
        self.btn_frame = tk.Frame(bottom_frame, bg=c['bg'])
        self.btn_frame.pack(side=tk.RIGHT, padx=(0, 80))

        self.btn_prev = tk.Button(self.btn_frame, text=self._t('btn_previous'),
                                   bg=c['btn_bg'], fg=c['btn_fg'],
                                   font=('Verdana', 11), relief=tk.FLAT,
                                   bd=1, highlightthickness=1,
                                   highlightbackground=c['btn_border'],
                                   cursor='hand2', width=10)
        self.btn_prev.pack(side=tk.LEFT, padx=4)
        self.btn_prev.bind('<Enter>', lambda e: self.btn_prev.config(bg=c['card']))
        self.btn_prev.bind('<Leave>', lambda e: self.btn_prev.config(bg=c['btn_bg']))

        self.btn_next = tk.Button(self.btn_frame, text=self._t('btn_next'),
                                   bg=c['btn_bg'], fg=c['btn_fg'],
                                   font=('Verdana', 11), relief=tk.FLAT,
                                   bd=1, highlightthickness=1,
                                   highlightbackground=c['btn_border'],
                                   cursor='hand2', width=10)
        self.btn_next.pack(side=tk.LEFT, padx=4)
        self.btn_next.bind('<Enter>', lambda e: self.btn_next.config(bg=c['card']))
        self.btn_next.bind('<Leave>', lambda e: self.btn_next.config(bg=c['btn_bg']))

    # ======================== 页面切换 ========================

    def _show_page(self, page):
        self.current_page = page
        self._clear_page()

        if page == 0:
            self._page_language()
        elif page == 1:
            self._page_license()
        elif page == 2:
            self._page_disclaimer()
        elif page == 3:
            self._page_detect_or_dir()
        elif page == 4:
            self._page_registry()
        elif page == 5:
            self._page_complete()

        self._update_buttons()

    def _update_buttons(self):
        page = self.current_page

        if page == 0:
            self.btn_prev.pack_forget()
            self.btn_next.pack_forget()
        elif page == 1:
            # 源代码许可与用户协议页: 按钮在页面内
            self.btn_prev.pack_forget()
            self.btn_next.pack_forget()
        elif page == 2:
            # 免责声明页: 显示返回按钮,继续按钮在页面内
            self.btn_prev.config(text=self._t('btn_previous'), command=lambda: self._show_page(1))
            self.btn_prev.pack(side=tk.LEFT, padx=4)
            self.btn_next.pack_forget()
        elif page == 3:
            # 检测已安装/选择目录页
            if self.existing_install:
                # 检测到已安装: 隐藏底部按钮,使用页面内的按钮
                self.btn_prev.pack_forget()
                self.btn_next.pack_forget()
            else:
                # 未检测到已安装: 显示上一步按钮
                self.btn_prev.config(text=self._t('btn_previous'), command=lambda: self._show_page(2))
                self.btn_prev.pack(side=tk.LEFT, padx=4)
                self.btn_next.pack_forget()  # 下一步按钮在页面内
        elif page == 4:
            self.btn_prev.config(text=self._t('btn_previous'), command=lambda: self._show_page(3))
            self.btn_prev.pack(side=tk.LEFT, padx=4)
            self.btn_next.config(text=self._t('btn_next'), command=lambda: self._do_install())
            self.btn_next.pack(side=tk.LEFT, padx=4)
        elif page == 5:
            self.btn_prev.pack_forget()
            self.btn_next.config(text=self._t('btn_finish'), command=self.root.destroy)
            self.btn_next.pack(side=tk.LEFT, padx=4)

    # ======================== 第1页: 语言选择 ========================

    def _page_language(self):
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('welcome_title'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w', wraplength=500, justify=tk.LEFT)
        title.pack(fill=tk.X, pady=(10, 4))

        subtitle = tk.Label(self.content_frame, text=self._t('select_language'),
                             bg=c['bg'], fg=c['text_secondary'],
                             font=('Verdana', 13), anchor='w')
        subtitle.pack(fill=tk.X, pady=(0, 16))

        lang_frame = tk.Frame(self.content_frame, bg=c['bg'])
        lang_frame.pack(fill=tk.X)

        langs = [
            ('en', self._t('lang_en')),
            ('zh-HK', self._t('lang_zhHK')),
            ('zh-CN', self._t('lang_zhCN')),
        ]

        for code, name in langs:
            btn = tk.Button(lang_frame, text='\u2192  ' + name,
                             bg=c['btn_bg'], fg=c['btn_fg'],
                             font=('Verdana', 14), relief=tk.FLAT,
                             bd=1, highlightthickness=1,
                             highlightbackground=c['btn_border'],
                             cursor='hand2', anchor='w',
                             padx=16, pady=12)
            btn.pack(fill=tk.X, pady=4)
            btn.bind('<Enter>', lambda e, b=btn: b.config(bg=c['card']))
            btn.bind('<Leave>', lambda e, b=btn: b.config(bg=c['btn_bg']))
            btn.config(command=lambda c=code: self._select_language(c))

    def _select_language(self, lang):
        self.lang = lang
        self._update_all_text()
        self._show_page(1)

    # ======================== 第2页: 源代码许可与用户协议 ========================

    def _page_license(self):
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('license_title'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w', wraplength=500)
        title.pack(fill=tk.X, pady=(10, 4))

        desc = tk.Label(self.content_frame, text=self._t('license_desc'),
                         bg=c['bg'], fg=c['text_secondary'],
                         font=('Verdana', 11), anchor='w', wraplength=500)
        desc.pack(fill=tk.X, pady=(0, 10))

        text_frame = tk.Frame(self.content_frame, bg=c['bg'],
                               highlightbackground=c['border'],
                               highlightthickness=1)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        text_widget = tk.Text(text_frame, bg=c['bg'], fg=c['fg'],
                               font=('Verdana', 9),
                               relief=tk.FLAT, bd=0, wrap=tk.WORD,
                               padx=12, pady=12)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        text_widget.insert('1.0', load_license_text(self.lang))
        text_widget.configure(state='disabled')

        btn_area = tk.Frame(self.content_frame, bg=c['bg'])
        btn_area.pack(fill=tk.X, pady=(0, 4))

        decline_btn = tk.Button(btn_area, text=self._t('btn_decline'),
                                 bg=c['btn_bg'], fg='#FF3B30',
                                 font=('Verdana', 11), relief=tk.FLAT,
                                 bd=1, highlightthickness=1,
                                 highlightbackground='#FF3B30',
                                 cursor='hand2', width=10,
                                 command=self.root.destroy)
        decline_btn.pack(side=tk.RIGHT, padx=4)

        agree_btn = tk.Button(btn_area, text=self._t('btn_agree'),
                               bg=c['btn_bg'], fg=c['btn_fg'],
                               font=('Verdana', 11), relief=tk.FLAT,
                               bd=1, highlightthickness=1,
                               highlightbackground=c['btn_border'],
                               cursor='hand2', width=10,
                               command=lambda: self._show_page(2))
        agree_btn.pack(side=tk.RIGHT, padx=4)

    # ======================== 第3页: 必读免责声明 ========================

    def _page_disclaimer(self):
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('disclaimer_title'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w', wraplength=500)
        title.pack(fill=tk.X, pady=(10, 4))

        desc = tk.Label(self.content_frame, text=self._t('disclaimer_desc'),
                         bg=c['bg'], fg=c['text_secondary'],
                         font=('Verdana', 11), anchor='w', wraplength=500)
        desc.pack(fill=tk.X, pady=(0, 10))

        text_frame = tk.Frame(self.content_frame, bg=c['bg'],
                               highlightbackground=c['border'],
                               highlightthickness=1)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        text_widget = tk.Text(text_frame, bg=c['bg'], fg=c['fg'],
                               font=('Verdana', 9),
                               relief=tk.FLAT, bd=0, wrap=tk.WORD,
                               padx=12, pady=12)
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        text_widget.insert('1.0', DISCLAIMER_TEXT.get(self.lang, DISCLAIMER_TEXT['en']))
        text_widget.configure(state='disabled')

        # 复选框: 必须勾选才能继续
        accept_var = tk.BooleanVar(value=False)
        checkbox = tk.Checkbutton(self.content_frame,
                                   text=self._t('disclaimer_accept'),
                                   variable=accept_var,
                                   bg=c['bg'], fg=c['fg'],
                                   font=('Verdana', 10),
                                   activebackground=c['bg'],
                                   activeforeground=c['fg'],
                                   selectcolor=c['card'])
        checkbox.pack(anchor='w', pady=(0, 8))

        btn_area = tk.Frame(self.content_frame, bg=c['bg'])
        btn_area.pack(fill=tk.X, pady=(0, 4))

        decline_btn = tk.Button(btn_area, text=self._t('btn_decline'),
                                 bg=c['btn_bg'], fg='#FF3B30',
                                 font=('Verdana', 11), relief=tk.FLAT,
                                 bd=1, highlightthickness=1,
                                 highlightbackground='#FF3B30',
                                 cursor='hand2', width=10,
                                 command=self.root.destroy)
        decline_btn.pack(side=tk.RIGHT, padx=4)

        def _on_accept():
            if accept_var.get():
                self._show_page(3)
            else:
                messagebox.showwarning(self._t('window_title'),
                                        self._t('must_accept_disclaimer'))

        accept_btn = tk.Button(btn_area, text=self._t('btn_accept'),
                                bg=c['btn_bg'], fg=c['btn_fg'],
                                font=('Verdana', 11), relief=tk.FLAT,
                                bd=1, highlightthickness=1,
                                highlightbackground=c['btn_border'],
                                cursor='hand2', width=10,
                                command=_on_accept)
        accept_btn.pack(side=tk.RIGHT, padx=4)

    # ======================== 第4页: 检测已安装 / 选择目录 ========================

    def _page_detect_or_dir(self):
        """如果检测到已安装,显示卸载/重装选项;否则显示选择目录。"""
        if self.existing_install:
            self._page_detect_existing()
        else:
            self._page_install_dir()

    def _page_detect_existing(self):
        """显示已安装检测页面，包含版本信息和操作选项。"""
        c = self._c()

        # 主容器 - 使用pack布局确保所有元素正确显示
        main_container = tk.Frame(self.content_frame, bg=c['bg'])
        main_container.pack(fill=tk.BOTH, expand=True)

        # 标题
        title = tk.Label(main_container, text=self._t('detect_title'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w')
        title.pack(fill=tk.X, pady=(10, 8))

        # 描述
        desc = tk.Label(main_container,
                         text=self._t('detect_desc').format(path=self.existing_install),
                         bg=c['bg'], fg=c['text_secondary'],
                         font=('Verdana', 12), anchor='w', wraplength=450,
                         justify=tk.LEFT)
        desc.pack(fill=tk.X, pady=(0, 8))

        # 读取版本信息
        installed_ver = read_installed_version(self.existing_install)

        # 版本信息区域
        ver_frame = tk.Frame(main_container, bg=c['bg'])
        ver_frame.pack(fill=tk.X, pady=(0, 12))

        if installed_ver:
            # 已安装版本
            tk.Label(ver_frame, text=self._t('version_installed', ver=installed_ver),
                      bg=c['bg'], fg=c['accent'], font=('Verdana', 11),
                      anchor='w').pack(side=tk.LEFT)
            tk.Label(ver_frame, text='  |  ', bg=c['bg'], fg=c['text_secondary'],
                      font=('Verdana', 11)).pack(side=tk.LEFT)
            # 安装程序版本
            tk.Label(ver_frame, text=self._t('version_installer', ver=INSTALLER_VERSION),
                      bg=c['bg'], fg=c['accent'], font=('Verdana', 11),
                      anchor='w').pack(side=tk.LEFT)

            # 版本比较结果
            comp = compare_versions(installed_ver, INSTALLER_VERSION)
            if comp == 'same':
                version_msg = self._t('version_overwrite')
            elif comp == 'upgrade':
                version_msg = self._t('version_upgrade', ver=INSTALLER_VERSION)
            else:
                version_msg = self._t('version_downgrade',
                                      installed=installed_ver, installer=INSTALLER_VERSION)
            tk.Label(main_container, text=version_msg,
                      bg=c['bg'], fg=c['fg'], font=('Verdana', 11, 'bold'),
                      anchor='w').pack(fill=tk.X, pady=(0, 12))
        else:
            # 旧版本或无版本文件
            tk.Label(ver_frame, text=self._t('version_installer', ver=INSTALLER_VERSION),
                      bg=c['bg'], fg=c['accent'], font=('Verdana', 11),
                      anchor='w').pack(side=tk.LEFT)

        # 按钮区域 - 使用Frame确保按钮正确显示
        btn_container = tk.Frame(main_container, bg=c['bg'])
        btn_container.pack(fill=tk.X, pady=(20, 0))

        # 第一行: 操作按钮（卸载、重装、新安装）
        action_row = tk.Frame(btn_container, bg=c['bg'])
        action_row.pack(fill=tk.X, pady=(0, 8))

        # 卸载按钮（红色）
        uninstall_btn = tk.Button(action_row, text=self._t('btn_uninstall'),
                                   bg='#FF3B30', fg='white',
                                   font=('Verdana', 12, 'bold'), relief=tk.FLAT,
                                   width=14, height=2,
                                   cursor='hand2',
                                   command=self._on_uninstall)
        uninstall_btn.pack(side=tk.LEFT, padx=8)

        # 根据版本显示不同操作按钮
        if installed_ver:
            comp = compare_versions(installed_ver, INSTALLER_VERSION)
            if comp == 'same':
                action_text = self._t('btn_overwrite')
                action_color = c['accent']
            elif comp == 'upgrade':
                action_text = self._t('btn_upgrade')
                action_color = '#34c759'  # 绿色
            else:
                action_text = self._t('btn_downgrade')
                action_color = '#ff9500'  # 橙色
        else:
            action_text = self._t('btn_reinstall')
            action_color = c['accent']

        action_btn = tk.Button(action_row, text=action_text,
                                bg=action_color, fg='white',
                                font=('Verdana', 12, 'bold'), relief=tk.FLAT,
                                width=14, height=2,
                                cursor='hand2',
                                command=self._on_reinstall)
        action_btn.pack(side=tk.LEFT, padx=8)

        # 新安装按钮
        new_btn = tk.Button(action_row, text=self._t('btn_new_install'),
                             bg=c['btn_bg'], fg=c['btn_fg'],
                             font=('Verdana', 12), relief=tk.FLAT,
                             bd=1, highlightthickness=1,
                             highlightbackground=c['btn_border'],
                             width=14, height=2,
                             cursor='hand2',
                             command=self._on_new_install)
        new_btn.pack(side=tk.LEFT, padx=8)

        # 第二行: 返回按钮
        back_row = tk.Frame(btn_container, bg=c['bg'])
        back_row.pack(fill=tk.X, pady=(8, 0))

        back_btn = tk.Button(back_row, text=self._t('btn_previous'),
                              bg=c['btn_bg'], fg=c['text_secondary'],
                              font=('Verdana', 10), relief=tk.FLAT,
                              bd=1, highlightthickness=1,
                              highlightbackground=c['btn_border'],
                              width=10, cursor='hand2',
                              command=lambda: self._show_page(2))
        back_btn.pack(side=tk.LEFT, padx=8)

    def _on_uninstall(self):
        """执行卸载。"""
        if not is_admin():
            messagebox.showwarning(self._t('window_title'), self._t('uninstall_admin_required'))
            return

        if not messagebox.askyesno(self._t('window_title'), self._t('uninstall_confirm')):
            return

        self.mode = 'uninstall'
        self.install_dir = self.existing_install
        self._do_uninstall()

    def _on_reinstall(self):
        """重新安装到已有目录。"""
        self.mode = 'install'
        self.install_dir = self.existing_install
        self._show_page(4)

    def _on_new_install(self):
        """忽略已有安装,进行新安装。"""
        self.mode = 'install'
        self.existing_install = None
        self._show_page(3)

    def _page_install_dir(self):
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('install_dir_title'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w', wraplength=500)
        title.pack(fill=tk.X, pady=(10, 8))

        desc = tk.Label(self.content_frame, text=self._t('install_dir_desc'),
                         bg=c['bg'], fg=c['text_secondary'],
                         font=('Verdana', 12), anchor='w', wraplength=500)
        desc.pack(fill=tk.X, pady=(0, 16))

        dir_frame = tk.Frame(self.content_frame, bg=c['bg'])
        dir_frame.pack(fill=tk.X, pady=8)

        default_dir = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'KJK-Encryptor')
        self.dir_var = tk.StringVar(value=self.install_dir or default_dir)
        self.install_dir = self.dir_var.get()

        dir_entry = tk.Entry(dir_frame, textvariable=self.dir_var,
                              font=('Verdana', 11),
                              bg=c['card'], fg=c['fg'],
                              relief=tk.FLAT, bd=1,
                              highlightthickness=1,
                              highlightbackground=c['border'])
        dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        browse_btn = tk.Button(dir_frame, text=self._t('btn_browse'),
                                bg=c['btn_bg'], fg=c['btn_fg'],
                                font=('Verdana', 11), relief=tk.FLAT,
                                bd=1, highlightthickness=1,
                                highlightbackground=c['btn_border'],
                                cursor='hand2', width=10,
                                command=self._browse_dir)
        browse_btn.pack(side=tk.RIGHT)

        # 下一步按钮(页面内, 未安装时底部按钮被隐藏)
        next_btn = tk.Button(self.content_frame, text=self._t('btn_next'),
                             bg=c['accent'], fg='#ffffff',
                             font=('Verdana', 12, 'bold'), relief=tk.FLAT,
                             cursor='hand2', padx=24, pady=6,
                             command=lambda: self._show_page(4))
        next_btn.pack(anchor='e', pady=(20, 0))

    def _browse_dir(self):
        c = self._c()
        initial = self.dir_var.get()
        path = filedialog.askdirectory(
            title=self._t('install_dir_title'),
            initialdir=os.path.dirname(initial))
        if path:
            self.install_dir = os.path.join(path, 'KJK-Encryptor')
            self.dir_var.set(self.install_dir)

    # ======================== 第4页: 注册表选项 ========================

    def _page_registry(self):
        """显示右键菜单注册页面，检测已有注册并提供智能选项。"""
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('registry_title'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w', wraplength=500)
        title.pack(fill=tk.X, pady=(10, 8))

        desc1 = tk.Label(self.content_frame, text=self._t('registry_desc1'),
                          bg=c['bg'], fg=c['text_secondary'],
                          font=('Verdana', 12), anchor='w', wraplength=500)
        desc1.pack(fill=tk.X, pady=(0, 4))

        desc2 = tk.Label(self.content_frame, text=self._t('registry_desc2'),
                          bg=c['bg'], fg=c['text_secondary'],
                          font=('Verdana', 12), anchor='w', wraplength=500)
        desc2.pack(fill=tk.X, pady=(0, 12))

        # 检测右键菜单是否已注册
        is_registered, registered_paths = check_context_menu_registered()

        if is_registered:
            # 显示已注册信息
            reg_info = tk.Label(self.content_frame,
                                 text=self._t('registry_already_registered'),
                                 bg=c['bg'], fg='#34c759',
                                 font=('Verdana', 11, 'bold'), anchor='w')
            reg_info.pack(fill=tk.X, pady=(0, 8))

            update_note = tk.Label(self.content_frame,
                                    text=self._t('registry_update_note'),
                                    bg=c['bg'], fg=c['text_secondary'],
                                    font=('Verdana', 10), anchor='w', wraplength=500)
            update_note.pack(fill=tk.X, pady=(0, 12))

        btn_container = tk.Frame(self.content_frame, bg=c['bg'])
        btn_container.pack(fill=tk.X, pady=(12, 0))

        # 左侧按钮区
        left_btns = tk.Frame(btn_container, bg=c['bg'])
        left_btns.pack(side=tk.LEFT)

        # 根据是否已注册显示不同选项
        if is_registered:
            # 已注册：提供保留现有选项（无需管理员）
            keep_btn = tk.Button(left_btns, text=self._t('registry_keep_existing'),
                                  bg='#34c759', fg='white',
                                  font=('Verdana', 11, 'bold'), relief=tk.FLAT,
                                  width=28, height=2,
                                  cursor='hand2',
                                  command=lambda: self._set_registry(False))
            keep_btn.pack(side=tk.LEFT, padx=4)

            # 更新注册（需要管理员）
            update_btn = tk.Button(left_btns, text=self._t('btn_yes'),
                                    bg=c['accent'], fg='white',
                                    font=('Verdana', 11, 'bold'), relief=tk.FLAT,
                                    width=14, height=2,
                                    cursor='hand2',
                                    command=self._on_registry_yes)
            update_btn.pack(side=tk.LEFT, padx=4)
        else:
            # 未注册
            if is_admin():
                # 已有管理员权限
                yes_btn = tk.Button(left_btns, text=self._t('btn_yes'),
                                     bg=c['accent'], fg='white',
                                     font=('Verdana', 12, 'bold'), relief=tk.FLAT,
                                     width=14, height=2,
                                     cursor='hand2',
                                     command=self._on_registry_yes)
                yes_btn.pack(side=tk.LEFT, padx=4)
            else:
                # 无管理员权限：提供重启按钮
                restart_btn = tk.Button(left_btns, text=self._t('btn_restart_admin'),
                                         bg='#ff9500', fg='white',
                                         font=('Verdana', 11, 'bold'), relief=tk.FLAT,
                                         width=18, height=2,
                                         cursor='hand2',
                                         command=self._restart_as_admin)
                restart_btn.pack(side=tk.LEFT, padx=4)

        # 右侧：跳过按钮
        right_btns = tk.Frame(btn_container, bg=c['bg'])
        right_btns.pack(side=tk.RIGHT)

        skip_btn = tk.Button(right_btns, text=self._t('btn_skip'),
                              bg=c['btn_bg'], fg=c['btn_fg'],
                              font=('Verdana', 11), relief=tk.FLAT,
                              bd=1, highlightthickness=1,
                              highlightbackground=c['btn_border'],
                              width=12, height=2,
                              cursor='hand2',
                              command=lambda: self._set_registry(False))
        skip_btn.pack(side=tk.RIGHT, padx=4)

    def _on_registry_yes(self):
        """点击"需要"按钮时检查管理员权限。"""
        # 检测右键菜单是否已注册
        is_registered, _ = check_context_menu_registered()
        
        # 如果已注册，无需管理员权限（安装时会更新指向）
        if is_registered:
            self.want_registry = True
            self._do_install()
            return
        
        # 未注册，需要管理员权限
        if not is_admin():
            messagebox.showwarning(self._t('window_title'), self._t('admin_required'))
            return
        
        self.want_registry = True
        self._do_install()

    def _restart_as_admin(self):
        """以管理员权限重启安装程序。"""
        if messagebox.askyesno(
            self._t('window_title'),
            self._t('admin_required') + '\n\n' + '是否以管理员权限重新启动安装程序？'
        ):
            if restart_as_admin():
                self.root.destroy()
            else:
                messagebox.showerror(self._t('window_title'), '无法以管理员权限重启，请手动以管理员身份运行安装程序。')

    def _set_registry(self, value):
        self.want_registry = value
        self._do_install()

    # ======================== 第5页: 完成 ========================

    def _page_complete(self):
        c = self._c()

        if self.mode == 'uninstall':
            title = tk.Label(self.content_frame, text=self._t('uninstall_complete'),
                              bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                              anchor='w', wraplength=500)
            title.pack(fill=tk.X, pady=(10, 16))

            msg = self._t('uninstall_success')
        else:
            title = tk.Label(self.content_frame, text=self._t('install_complete'),
                              bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                              anchor='w', wraplength=500)
            title.pack(fill=tk.X, pady=(10, 16))

            if self.want_registry:
                msg = self._t('install_success_registry')
            else:
                msg = self._t('install_success').format(path=self.install_dir)

        msg_label = tk.Label(self.content_frame, text=msg,
                              bg=c['bg'], fg=c['fg'],
                              font=('Verdana', 12), anchor='w',
                              wraplength=500, justify=tk.LEFT)
        msg_label.pack(fill=tk.X, pady=(0, 16))

        # 安装模式下显示快捷方式选项
        if self.mode == 'install':
            shortcut_frame = tk.Frame(self.content_frame, bg=c['bg'])
            shortcut_frame.pack(fill=tk.X, pady=(8, 0))

            shortcut_desc = tk.Label(shortcut_frame, text=self._t('shortcut_desc'),
                                      bg=c['bg'], fg=c['text_secondary'],
                                      font=('Verdana', 11), anchor='w')
            shortcut_desc.pack(fill=tk.X, pady=(0, 8))

            shortcut_btn_area = tk.Frame(shortcut_frame, bg=c['bg'])
            shortcut_btn_area.pack(fill=tk.X)

            no_shortcut_btn = tk.Button(shortcut_btn_area, text=self._t('btn_no_shortcut'),
                                         bg=c['btn_bg'], fg=c['btn_fg'],
                                         font=('Verdana', 11), relief=tk.FLAT,
                                         bd=1, highlightthickness=1,
                                         highlightbackground=c['btn_border'],
                                         cursor='hand2', width=12,
                                         command=self._finish)
            no_shortcut_btn.pack(side=tk.RIGHT, padx=4)

            create_shortcut_btn = tk.Button(shortcut_btn_area, text=self._t('btn_create_shortcut'),
                                             bg=c['btn_bg'], fg=c['btn_fg'],
                                             font=('Verdana', 11), relief=tk.FLAT,
                                             bd=1, highlightthickness=1,
                                             highlightbackground=c['btn_border'],
                                             cursor='hand2', width=14,
                                             command=self._create_shortcut_and_finish)
            create_shortcut_btn.pack(side=tk.RIGHT, padx=4)

    def _create_shortcut_and_finish(self):
        """创建快捷方式并完成。"""
        exe_path = ''
        for f in os.listdir(self.install_dir):
            if f.endswith('.exe'):
                exe_path = os.path.join(self.install_dir, f)
                break
        if exe_path:
            create_shortcut(exe_path, 'KJK Encryptor.lnk')
        self._finish()

    def _finish(self):
        """完成,关闭程序。"""
        self.root.destroy()

    # ======================== 安装逻辑 ========================

    def _do_install(self):
        # 如果 install_dir 已设置（从检测已安装页面跳转），直接使用
        # 否则从目录选择页面获取
        if not self.install_dir:
            if hasattr(self, 'dir_var'):
                self.install_dir = self.dir_var.get().strip()
            else:
                messagebox.showwarning('Warning', self._t('install_dir_title'))
                return

        if not self.install_dir:
            messagebox.showwarning('Warning', self._t('install_dir_title'))
            return

        # 显示安装中页面
        self._clear_page()
        # 强制完成重绘, 立即清掉上一个界面(如注册表页)的画面, 避免切换残影
        self.root.update_idletasks()
        self.root.update()
        # 隐藏底部按钮, 避免上一页按钮残留
        self.btn_prev.pack_forget()
        self.btn_next.pack_forget()
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('installing'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w')
        title.pack(fill=tk.X, pady=(10, 16))

        # 进度条
        self.progress = ttk.Progressbar(self.content_frame, mode='determinate',
                                         length=500, style='Custom.Horizontal.TProgressbar')
        self.progress.pack(fill=tk.X, pady=(0, 16))

        self.status_label = tk.Label(self.content_frame, text='',
                                      bg=c['bg'], fg=c['text_secondary'],
                                      font=('Verdana', 11), anchor='w')
        self.status_label.pack(fill=tk.X, pady=(0, 8))

        self.root.update_idletasks()

        try:
            # 步骤1: 创建安装目录
            self._update_progress(10, 'Creating installation directory...')
            os.makedirs(self.install_dir, exist_ok=True)

            # 步骤1.5: 升级清理 — 删除旧版应用文件, 保留用户配置与个人文件
            # (kjk_config.json 与 exe 平级, 误删会丢失用户设置)
            self._update_progress(20, 'Cleaning previous installation...')
            for entry in ('_internal', 'engine', 'KJK-Encryptor.exe', 'version.txt'):
                old = os.path.join(self.install_dir, entry)
                if os.path.isdir(old):
                    shutil.rmtree(old, ignore_errors=True)
                elif os.path.exists(old):
                    try:
                        os.remove(old)
                    except OSError:
                        pass

            # 步骤2: 解压主程序
            self._update_progress(30, 'Extracting application files...')
            main_dist_zip = get_resource_path('main_dist.zip')
            if os.path.exists(main_dist_zip):
                with zipfile.ZipFile(main_dist_zip, 'r') as zf:
                    file_list = zf.namelist()
                    total = len(file_list)
                    for i, name in enumerate(file_list):
                        zf.extract(name, self.install_dir)
                        pct = 30 + int(40 * i / total)
                        self._update_progress(pct, f'Extracting: {name}')
            else:
                dist_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dist')
                if os.path.isdir(dist_dir):
                    items = os.listdir(dist_dir)
                    total = len(items)
                    for i, item in enumerate(items):
                        src = os.path.join(dist_dir, item)
                        dst = os.path.join(self.install_dir, item)
                        if os.path.isfile(src):
                            shutil.copy2(src, dst)
                        elif os.path.isdir(src):
                            if os.path.exists(dst):
                                shutil.rmtree(dst)
                            shutil.copytree(src, dst)
                        self._update_progress(30 + int(40 * i / total), f'Copying: {item}')

            # 步骤3: 复制卸载程序 (优先使用已打包的exe)
            self._update_progress(75, 'Installing tools...')
            uninstaller_exe_src = get_resource_path('KJK-Uninstaller.exe')
            uninstaller_py_src = get_resource_path('uninstaller.py')
            if os.path.exists(uninstaller_exe_src):
                shutil.copy2(uninstaller_exe_src, os.path.join(self.install_dir, 'KJK-Uninstaller.exe'))
            elif os.path.exists(uninstaller_py_src):
                shutil.copy2(uninstaller_py_src, os.path.join(self.install_dir, 'uninstaller.py'))

            # 步骤4: 复制源代码许可与用户协议、免责声明摘要与源代码包
            self._update_progress(80, 'Copying license and source code...')
            for fname in ('LICENSE', 'README-LICENSE.txt', 'README.md', 'source.zip'):
                src = get_resource_path(fname)
                if os.path.exists(src):
                    shutil.copy2(src, os.path.join(self.install_dir, fname))

            # 步骤5: 保存语言配置到主程序配置文件
            self._update_progress(85, 'Saving language settings...')
            config_saved = False
            config_path = ''
            try:
                import json
                # 确定配置文件路径
                protected = ('Program Files', 'Program Files (x86)', 'Windows')
                if any(p in self.install_dir for p in protected):
                    config_dir = os.path.join(os.environ.get('APPDATA') or os.path.expanduser('~'), 'KJK-Encrypter')
                else:
                    config_dir = self.install_dir
                os.makedirs(config_dir, exist_ok=True)
                config_path = os.path.join(config_dir, 'kjk_config.json')
                # 读取现有配置或创建新配置
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        cfg = json.load(f)
                else:
                    cfg = {}
                cfg['lang'] = self.lang
                with open(config_path, 'w', encoding='utf-8') as f:
                    json.dump(cfg, f, ensure_ascii=False, indent=2)
                # 验证配置是否保存成功
                with open(config_path, 'r', encoding='utf-8') as f:
                    verify_cfg = json.load(f)
                if verify_cfg.get('lang') == self.lang:
                    config_saved = True
            except Exception:
                pass

            if not config_saved:
                try:
                    messagebox.showwarning(
                        self._t('window_title'),
                        f'Warning: Could not save language settings to {config_path}. You may need to manually set the language in the application settings.'
                    )
                except Exception:
                    pass

            # 步骤6: 保存版本信息
            self._update_progress(88, 'Saving version information...')
            try:
                ver_path = os.path.join(self.install_dir, 'version.txt')
                with open(ver_path, 'w', encoding='utf-8') as f:
                    f.write(INSTALLER_VERSION)
            except Exception:
                pass

            # 步骤7: 注册表写入 (通过 context_menu 模块直接注册，使用已安装的主程序路径)
            if self.want_registry:
                self._update_progress(92, 'Registering context menu...')
                self._register_via_script()

            self._update_progress(100, 'Installation complete!')
            self.root.update_idletasks()

        except Exception as e:
            messagebox.showerror('Error', str(e))
            return

        self._show_page(5)

    def _register_via_script(self):
        """脚本模式下通过导入 context_menu 模块注册右键菜单，使用已安装的主程序路径。"""
        try:
            # 查找已安装的 exe 文件
            installed_exe = ''
            if os.path.isdir(self.install_dir):
                for f in os.listdir(self.install_dir):
                    if f.endswith('.exe'):
                        installed_exe = os.path.join(self.install_dir, f)
                        break
            script_dir = os.path.dirname(os.path.abspath(__file__))
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)
            import context_menu
            # 传入正确的已安装 exe 路径，避免注册到 installer 自身
            if installed_exe and os.path.exists(installed_exe):
                ok, msg = context_menu.register_context_menu(exe_path=installed_exe)
            else:
                ok, msg = context_menu.register_context_menu()
            if not ok:
                print(f'Context menu registration: {msg}')
        except Exception as e:
            print(f'Context menu registration failed: {e}')

    # ======================== 卸载逻辑 ========================

    def _do_uninstall(self):
        """执行卸载。"""
        self._clear_page()
        # 强制完成重绘, 立即清掉上一个界面画面, 避免切换残影
        self.root.update_idletasks()
        self.root.update()
        # 隐藏底部按钮, 避免上一页按钮残留
        self.btn_prev.pack_forget()
        self.btn_next.pack_forget()
        c = self._c()

        title = tk.Label(self.content_frame, text=self._t('uninstalling'),
                          bg=c['bg'], fg=c['fg'], font=('Verdana', 18, 'bold'),
                          anchor='w')
        title.pack(fill=tk.X, pady=(10, 16))

        self.progress = ttk.Progressbar(self.content_frame, mode='determinate',
                                         length=500, style='Custom.Horizontal.TProgressbar')
        self.progress.pack(fill=tk.X, pady=(0, 16))

        self.status_label = tk.Label(self.content_frame, text='',
                                      bg=c['bg'], fg=c['text_secondary'],
                                      font=('Verdana', 11), anchor='w')
        self.status_label.pack(fill=tk.X, pady=(0, 8))

        self.root.update_idletasks()

        # 检查 installer 是否在安装目录内
        installer_in_target = False
        if getattr(sys, 'frozen', False):
            installer_dir = os.path.dirname(os.path.abspath(sys.executable))
            install_norm = os.path.normpath(self.install_dir).lower()
            installer_norm = os.path.normpath(installer_dir).lower()
            installer_in_target = (install_norm == installer_norm)

        try:
            # 步骤0: 强制关闭正在运行的 KJK Encryptor 进程
            self._update_progress(10, 'Closing running KJK Encryptor processes...')
            try:
                import subprocess
                # 关闭主程序进程
                subprocess.run(
                    ['taskkill', '/F', '/IM', 'KJK-Encryptor.exe'],
                    check=False, capture_output=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW)
                # 如果脚本模式有残留 python 进程也尝试关闭（通过窗口标题匹配）
                subprocess.run(
                    ['taskkill', '/F', '/FI', 'WINDOWTITLE eq KJK Encryptor'],
                    check=False, capture_output=True, timeout=10,
                    creationflags=subprocess.CREATE_NO_WINDOW)
            except Exception:
                pass

            # 步骤1: 卸载注册表 (直接导入 context_menu 卸载)
            self._update_progress(20, 'Removing registry entries...')
            try:
                script_dir = os.path.dirname(os.path.abspath(__file__))
                if script_dir not in sys.path:
                    sys.path.insert(0, script_dir)
                import context_menu
                context_menu.unregister_context_menu()
            except Exception as e:
                print(f'Unregister failed: {e}')

            # 步骤2: 删除桌面快捷方式
            self._update_progress(50, 'Removing desktop shortcut...')
            remove_shortcut('KJK Encryptor.lnk')

            # 步骤3: 删除安装目录
            self._update_progress(70, 'Removing installed files...')
            if os.path.isdir(self.install_dir):
                if installer_in_target:
                    # installer 在安装目录内,无法直接删除自己
                    # 先删能删的, 再生成批处理兜底(批处理必须先 cd 出目录,否则 rmdir
                    # 因当前工作目录占用而整体失败)
                    shutil.rmtree(self.install_dir, ignore_errors=True)
                    batch_path = os.path.join(os.environ.get('TEMP', '.'), 'kjk_uninstall.bat')
                    with open(batch_path, 'w', encoding='gbk') as f:
                        f.write('@echo off\n')
                        f.write('cd /d "%SystemDrive%\\"\n')
                        f.write('for /L %%i in (1,1,8) do (\n')
                        f.write(f'  rmdir /s /q "{self.install_dir}" 2>nul\n')
                        f.write(f'  if not exist "{self.install_dir}" goto done\n')
                        f.write('  ping -n 2 127.0.0.1 >nul\n')
                        f.write(')\n')
                        f.write(':done\n')
                        f.write('del "%~f0"\n')
                    import subprocess
                    subprocess.Popen(
                        ['cmd.exe', '/c', 'start', '', '/min', batch_path],
                        creationflags=subprocess.CREATE_NO_WINDOW)
                    self._update_progress(100, 'Uninstallation complete! (files will be removed shortly)')
                else:
                    # 正常删除
                    errors = []
                    for root_dir, dirs, files in os.walk(self.install_dir, topdown=False):
                        for name in files:
                            fp = os.path.join(root_dir, name)
                            try:
                                os.remove(fp)
                            except PermissionError:
                                errors.append(fp)
                        for name in dirs:
                            dp = os.path.join(root_dir, name)
                            try:
                                os.rmdir(dp)
                            except Exception:
                                errors.append(dp)
                    try:
                        os.rmdir(self.install_dir)
                    except Exception:
                        errors.append(self.install_dir)

                    if errors:
                        self._update_progress(100, f'Uninstallation complete. {len(errors)} items could not be removed (in use).')
                    else:
                        self._update_progress(100, 'Uninstallation complete!')

                self.root.update_idletasks()

        except Exception as e:
            messagebox.showerror('Error', str(e))
            return

        self._show_page(5)

    def _update_progress(self, value, status_text):
        """更新进度条和状态文本。"""
        self.progress['value'] = value
        self.status_label.config(text=status_text)
        # 使用 update() 而非 update_idletasks(): 强制完成几何计算并立即重绘,
        # 否则耗时循环期间窗口仍停留于上一个页面(如注册表页)的旧画面残影。
        self.root.update()

    # ======================== 全局文本更新 ========================

    def _update_all_text(self):
        self.root.title(self._t('window_title'))
        self.powered_label.config(text=self._t('powered_by'))
        self.website_label.config(text=self._t('website'))
        self.btn_prev.config(text=self._t('btn_previous'))
        self.btn_next.config(text=self._t('btn_next'))

    # ======================== 运行 ========================

    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    app = InstallerApp()
    app.run()
