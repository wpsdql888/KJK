# -*- coding: utf-8 -*-
"""KJK Encryptor - 主程序 (Tkinter GUI) v1.1.0"""

import os
import sys

# 确保右键菜单调用时能找到同目录模块
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import threading
import time
import urllib.request
import urllib.error
import ctypes
import tempfile
import argparse
import shutil

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
    _HAS_DND = True
except Exception:
    TkinterDnD = None
    DND_FILES = ''
    _HAS_DND = False

CURRENT_VERSION = '1.1.0'

SERVER_URL_PRIMARY = 'https://dnteam.top/'
SERVER_URL_BACKUP = 'https://www.917813.help/'

DOWNLOAD_URL_PRIMARY = 'https://dnteam.top/KJK/KJK-installer.exe'
DOWNLOAD_URL_BACKUP = 'https://www.917813.help/KJK/KJK-installer.exe'

# ======================== Engine imports with missing-function handling ========================

_MISSING_ENGINE_FUNCS = []


def _missing_engine_msgbox(func_name, parent=None):
    messagebox.showwarning(
        'Engine Update Required',
        f'Function "{func_name}" is not available in the current engine.\n'
        'Please update the engine module to use this feature.',
        parent=parent)


def _ask_append_paths(parent, t):
    """弹小型选择按钮: 追加 '文件' 或 '文件夹', 返回路径列表; 取消返回 None。"""
    from tkinter import filedialog
    result = {'val': None}

    win = tk.Toplevel(parent)
    win.title(t('appendToPackage'))
    win.transient(parent)
    win.grab_set()
    win.resizable(False, False)
    tk.Label(win, text=t('appendAskKind'), padx=22, pady=(18, 6)).pack()

    def pick(kind):
        if kind == 'files':
            files = filedialog.askopenfilenames(title=t('dialogTitleSelectEncrypt'), parent=win)
            result['val'] = list(files) if files else []
        else:
            folder = filedialog.askdirectory(title=t('dialogTitleSelectFolder'), parent=win)
            result['val'] = [folder] if folder else []
        win.destroy()

    btns = tk.Frame(win, padx=22, pady=(4, 18))
    btns.pack()
    for label, kind in ((t('selectFiles'), 'files'), (t('selectFolder'), 'folder')):
        tk.Button(btns, text=label, width=14, command=lambda k=kind: pick(k)).pack(side=tk.LEFT, padx=6)
    tk.Button(btns, text=t('btnClose'), width=14,
              command=lambda: (result.update(val=None), win.destroy())).pack(side=tk.LEFT, padx=6)

    win.wait_window()
    return result['val']


# Core imports that must exist
try:
    from engine import (encrypt, encrypt_raw,
                    pack_kjk, unpack_kjk, re_decrypt,
                    collect_folder_entries,
                    encrypt_filename,
                    append_to_kjk,
                    add_password_prefix, detect_password_prefix,
                    detect_password_header, verify_password,
                    make_password_header,
                    extract_legacy_package_file)
except Exception as _e:
    messagebox.showerror('Fatal Error', f'Failed to import core engine: {_e}')
    raise

# Optional new engine functions (missing -> messagebox)
_OPTIONAL_ENGINE = {
    'pack_kjk_with_paths': None,
    'pack_kjk_with_paths_to_file': None,
    'change_password_kjk': None,
    'delete_entries_kjk': None,
    'rename_entry_kjk': None,
    'extract_entry_to_path': None,
    'add_integrity_hash': None,
    'verify_integrity_hash': None,
    'decrypt_kjk_to_dir': None,
}

import engine as _engine_module
for _name in _OPTIONAL_ENGINE:
    _OPTIONAL_ENGINE[_name] = getattr(_engine_module, _name, None)
    if _OPTIONAL_ENGINE[_name] is None:
        _MISSING_ENGINE_FUNCS.append(_name)


from api_server import start_server, stop_server, set_port
from config import load_config, save_config


def get_resource_path(relative_path):
    """獲取資源文件路徑，兼容 PyInstaller 打包後與腳本模式。"""
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def _set_worker_thread_priority():
    """降低后台加密/解密线程优先级，减少加密时前台卡顿。"""
    try:
        if sys.platform == 'win32':
            kernel32 = ctypes.windll.kernel32
            hthread = kernel32.GetCurrentThread()
            kernel32.SetThreadPriority(hthread, -1)
    except Exception:
        pass


def peek_detect_password_prefix(filepath):
    """仅读取 .kjk 文件头探测密码头前缀,返回 (salt_bytes, hash_hex|None)。

    不整文件加载,只读开头一小段,用于流式解密时确定是否/如何用密码。
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


# ======================== Config ========================
DEFAULT_CONFIG = {
    'theme': 'light',
    'preview': True,
    'api_port': 5000,
    'api_enabled': False,
    'lang': 'en',
    'geometry': '840x580',
    'check_update': True,
    'update_server': '',
}


# ======================== Policy Texts ========================
PRIVACY_TEXT = {
    'en': """Privacy Policy

Last Updated: August 2026

1. Data Controller
KJK Encryptor is developed, published, and operated by DNT Group ("we", "us", or "our"). We act as the data controller for the limited processing activities described in this Privacy Policy. This policy applies to the use of the KJK Encryptor desktop application, the web version, and the official website.

2. Principle of Data Minimisation
KJK Encryptor operates on a strict data-minimisation basis. We do not collect, transmit, or store any personal data as a necessary part of the software's operation. All encryption and decryption operations, including files, text, and passwords, are performed entirely on your local device and never leave it.

3. Categories of Personal Data Processed
Because the core encryption functionality is purely local, we generally do not process any personal data. The only data that may be touched is limited to the categories below, each of which applies only when the corresponding optional feature is enabled by you:
  a) Installation / update status data (e.g. whether an update check succeeded) — used solely to keep the software up to date.
  b) Language and user-interface preferences stored in a local configuration file on your device.
We do not process special-category (sensitive) data, and we do not intentionally collect data from children under the age of 16. If you or your legal guardian believe a child's data has been submitted, contact us and we will delete it.

4. Purpose and Legal Bases of Processing (GDPR)
Where any limited processing occurs (for example, an update check), it is carried out:
  a) to perform the contract between you and us for the use of the software (Art. 6(1)(b) GDPR);
  b) to pursue our legitimate interest in keeping the software stable, secure, and up to date (Art. 6(1)(f) GDPR); and
  c) on the basis of your prior consent where such consent is required (Art. 6(1)(a) GDPR), which you may withdraw at any time.
Where KJK Encryptor is used in Hong Kong, it complies with the Personal Data (Privacy) Ordinance (Cap. 486) ("PDPO"), and personal data is collected only for a purpose directly related to the relevant function.

5. Local Processing & Storage
All files, text, and passwords you process through KJK Encryptor remain on your device. Your configuration (language, theme, API preferences) is stored locally in a configuration file; this file contains no personal information.

6. Third-Party Services
KJK Encryptor does not integrate with any third-party analytics, advertising, or tracking services. There is no advertising SDK, no tracker, and no cross-site cookie set by this software.

7. API Service
If you choose to enable the embedded API server, it operates entirely on your local machine. No external connections are made and no data is transmitted to us.

8. Update Checker & International Transfer
The update checker connects to dnteam.top solely to request new-version information. Where an update request is routed through infrastructure located outside the European Economic Area and outside Hong Kong, we ensure an appropriate legal ground for such transfer exists, relying on the principles set out in Art. 44–49 GDPR and equivalent safeguards under the PDPO, and only the minimal technical data contained in an ordinary HTTP request is involved. This connection can be disabled in Settings.

9. Retention
Because we do not collect personal data, there is generally no personal data to retain. The local configuration file is kept only as long as the software is installed and can be deleted by you at any time together with the application. Update-check logs, if any, are retained only for as long as necessary to maintain the service and are not used for profiling.

10. Your Data-Protection Rights
Where the law applies to you, you have the right to:
  a) access, rectify, or erase your personal data;
  b) restrict or object to processing;
  c) data portability;
  d) withdraw consent at any time without affecting the lawfulness of processing carried out before withdrawal; and
  e) lodge a complaint with a supervisory authority.
Under the Hong Kong PDPO you additionally have the right to request access to and correction of your personal data held by us.
Because we process no personal data by default, exercising these rights will in most cases simply require uninstalling the software or removing the local configuration file. To exercise any right, contact us using the details in Section 11.

11. Contact & Data Protection Contacts
For any questions about this Privacy Policy or to exercise your data-protection rights, please visit https://dnteam.top or contact us at the address published on the official website. We will respond without undue delay and no later than one month after receiving a valid request.""",

    'zh-HK': """私隱政策 Privacy Policy

最後更新：2026年8月

1. 數據控制者
KJK Encryptor 由 DNT Group（下稱「我們」）開發、發布同營運。我哋就本私隱政策所述嘅有限處理活動擔任數據控制者。本政策適用於 KJK Encryptor 桌面版、網頁版同官方網站嘅使用。

2. 數據最小化原則
KJK Encryptor 堅持嚴格嘅數據最小化原則。軟件嘅運行唔以收集、傳輸或儲存任何個人資料為前提。所有加密同解密操作（包括檔案、文字同密碼）都喺您部 device 本地完成，絕唔會離開您部 device。

3. 處理嘅個人資料類別
由於核心加密功能完全喺本地進行，我哋一般唔會處理任何個人資料。唯一可能涉及嘅數據僅限於以下類別，且僅當您啟用對應可選功能時先適用：
  a) 安裝 / 更新狀態數據（例如更新檢查是否成功）——僅用於令軟件保持最新版本；
  b) 存喺您部 device 本地 config file 入面嘅語言同界面偏好。
我哋唔處理特殊類別（敏感）數據，亦唔會有意識噉收集未滿 16 歲兒童嘅數據。如您或其法定監護人認為兒童數據已被提交，請聯絡我哋，我哋會予以刪除。

4. 處理目的與法律依據（GDPR）
如發生任何有限處理（例如更新檢查），其依據為：
  a) 履行您同我哋之間關於使用本軟件嘅合約（GDPR 第 6(1)(b) 條）；
  b) 我哋維護軟件穩定、安全同更新嘅正當利益（GDPR 第 6(1)(f) 條）；以及
  c) 喺需要同意時，基於您事先給予嘅可隨時撤回嘅同意（GDPR 第 6(1)(a) 條）。
當 KJK Encryptor 喺中國香港使用時，其符合《個人資料（私隱）條例》（第 486 章）（「PDPO」），個人資料僅喺同相關功能有直接關係嘅目的下收集。

5. 本地處理與儲存
您透過 KJK Encryptor 處理嘅所有檔案、文字同密碼都保留喺您部 device 上。您嘅設定（語言、主題、API 偏好）存喺 device 本地嘅 config file 入面；呢個 file 唔包含任何個人資訊。

6. 第三方服務
KJK Encryptor 唔會整合任何第三方分析、廣告或追蹤服務。本軟件唔包含任何廣告 SDK、tracker，亦唔會設定跨站 Cookie。

7. API 服務
如果您選擇啟用內嵌 API server，佢會完全喺您部本地機器上運行，唔建立任何外部連接，亦唔向我哋傳輸任何數據。

8. 更新檢查與國際傳輸
Update checker 僅連接 dnteam.top 請求新版本資訊。若更新請求經由位於歐洲經濟區及中國香港以外嘅設施路由，我哋會確保存在適當嘅國際傳輸法律依據（依據 GDPR 第 44–49 條及 PDPO 下嘅同等保障），且僅涉及普通 HTTP 請求所含嘅最少技術數據。呢個連接可以喺 Settings 入面關閉。

9. 保留期限
由於我哋唔收集個人資料，一般亦冇個人資料需要保留。本地 config file 僅喺軟件安裝期間保留，您可以隨時連同應用程式一併刪除。更新檢查日誌（如有）僅保留至維護服務所需嘅時間，且唔會用於分析用戶行為。

10. 您嘅數據保護權利
喺法律適用於您嘅情況下，您有權：
  a) 查閱、更正或刪除您嘅個人資料；
  b) 限制或反對處理；
  c) 數據可攜帶性；
  d) 隨時撤回同意，且唔影響撤回前基於同意而進行處理嘅合法性；以及
  e) 向監管機構提出申訴。
根據中國香港 PDPO，您仲有權要求查閱同更正我哋持有嘅您嘅個人資料。
由於我哋默認唔處理個人資料，喺大多數情況下行使上述權利只需要卸載軟件或刪除本地 config file 即可。如要行使任何權利，請透過第 11 節聯絡方法同我哋聯繫。

11. 聯繫方法與數據保護聯繫
如對本私隱政策有任何疑問或要行使您嘅數據保護權利，請訪問 https://dnteam.top 或透過官方網站公布嘅地址同我哋聯繫。我哋會喺收到有效請求後盡快回覆，且最遲唔超過一個月。""",

    'zh-CN': """隐私政策

最后更新：2026年8月

1. 数据控制者
KJK Encryptor 由 DNT Group（下称"我们"）开发、发布和运营。我们就本隐私政策所述的有限处理活动担任数据控制者。本政策适用于 KJK Encryptor 桌面版、网页版及官方网站的使用。

2. 数据最小化原则
KJK Encryptor 坚持严格的数据最小化原则。软件的运行不以收集、传输或存储任何个人资料为前提。所有加密和解密操作（包括文件、文本和密码）均在您的设备本地完成，绝不会离开您的设备。

3. 处理的个人资料类别
由于核心加密功能完全在本地进行，我们一般不会处理任何个人资料。唯一可能涉及的数据仅限于以下类别，且仅当您启用对应可选功能时才适用：
  a) 安装/更新状态数据（如更新检查是否成功）——仅用于保持软件为最新版本；
  b) 存储在您设备本地配置文件中的语言和界面偏好。
我们不处理特殊类别（敏感）数据，也不有意收集未满 16 周岁儿童的数据。如您或其法定监护人认为儿童数据已被提交，请联系我们，我们将予以删除。

4. 处理目的与法律依据（GDPR）
如发生任何有限处理（例如更新检查），其依据为：
  a) 履行您与我们之间关于使用本软件的合同（GDPR 第 6(1)(b) 条）；
  b) 我们维护软件稳定、安全与更新的正当利益（GDPR 第 6(1)(f) 条）；以及
  c) 在需要同意时，基于您事先给予的可随时撤回的同意（GDPR 第 6(1)(a) 条）。
当 KJK Encryptor 在中国香港使用时，其符合《个人资料（私隐）条例》（第 486 章）（"PDPO"），个人资料仅在与相关功能直接相关的目的下收集。

5. 本地处理与存储
您通过 KJK Encryptor 处理的所有文件、文本和密码均保留在您的设备上。您的配置（语言、主题、API偏好）存储在设备本地的配置文件中；该文件不包含任何个人信息。

6. 第三方服务
KJK Encryptor 不会集成任何第三方分析、广告或追踪服务。本软件不包含任何广告 SDK、追踪器，也不会设置跨站 Cookie。

7. API 服务
如果您选择启用内嵌 API 服务器，它将完全在您的本地机器上运行，不建立任何外部连接，也不向我们传输任何数据。

8. 更新检查与国际传输
更新检查器仅连接 dnteam.top 请求新版本信息。若更新请求经由位于欧洲经济区及中国香港以外的设施路由，我们将确保存在适当的国际传输法律依据（依据 GDPR 第 44–49 条及 PDPO 下的同等保障），且仅涉及普通 HTTP 请求所含的最少技术数据。此连接可在设置中关闭。

9. 保留期限
由于我们不收集个人资料，一般也没有个人资料需要保留。本地配置文件仅在软件安装期间保留，您可随时连同应用一并删除。更新检查日志（如有）仅保留至维护服务所需的时间，且不用于画像分析。

10. 您的数据保护权利
在法律适用于您的情况下，您有权：
  a) 查阅、更正或删除您的个人资料；
  b) 限制或反对处理；
  c) 数据可携带性；
  d) 随时撤回同意，且不影响撤回前基于同意而进行处理的合法性；以及
  e) 向监管机构提出申诉。
根据中国香港 PDPO，您还有权要求查阅和更正我们持有的您的个人资料。
由于我们默认不处理个人资料，在大多数情况下行使上述权利只需卸载软件或删除本地配置文件即可。如要行使任何权利，请通过第 11 节联系方式与我们联系。

11. 联系方式与数据保护联系
如对本隐私政策有任何疑问或要行使您的数据保护权利，请访问 https://dnteam.top 或通过官方网站公布的地址与我们联系。我们将在收到有效请求后及时回复，且最迟不超过一个月。""",
}

TERMS_TEXT = {
    'en': """Terms of Service

Last Updated: August 2026

1. Acceptance of Terms
By using KJK Encryptor, you agree to these Terms of Service (the "Terms"). If you do not agree, please discontinue use of the software. By installing or using the Software, you also confirm that you have read and understood our Privacy Policy.

2. Service Provided
KJK Encryptor is a local file-encryption tool. Encryption and decryption are performed entirely on your device. We do not store, transmit, or access your passwords, files, or decrypted content.

3. Open Source License
KJK Encryptor is open-source software. You are free to view, modify, and use the source code for any purpose, including commercial use, subject to the accompanying open-source license.

4. Permitted Use
You may use KJK Encryptor for personal, educational, or commercial purposes. You may modify and redistribute the software under the same open-source terms.

5. Prohibited Use
You may not use KJK Encryptor for any illegal purpose or to infringe upon the rights of others. You must not use the software to hide, encrypt, transmit, or distribute illegal content, including but not limited to malware, child sexual abuse material, terrorist propaganda, or content that infringes the intellectual property rights of others. You remain solely responsible for your own use.

6. Accounts and Registration
No account is required to use KJK Encryptor. As a result, no user account, profiling, or behavioural tracking is performed.

7. Data Protection & Compliance
Use of the Software is subject to the Privacy Policy, which complies with the Hong Kong Personal Data (Privacy) Ordinance (Cap. 486, "PDPO") and, where applicable to you, the EU General Data Protection Regulation (Regulation (EU) 2016/679, "GDPR"). Because the Software processes data locally, no personal data is collected or processed by us in the normal course of use.

8. Disclaimer of Warranty
The software is provided "as is" without any warranty of any kind, express or implied. DNT Group makes no guarantees regarding merchantability, fitness for a particular purpose, security, or non-infringement.

9. Limitation of Liability
To the maximum extent permitted by applicable law, DNT Group and its contributors shall not be liable for any direct, indirect, incidental, special, or consequential damages, including data loss or corruption, arising out of or in connection with the use or inability to use KJK Encryptor. You are responsible for maintaining backups of your data.

10. Third-Party Rights
The Software does not integrate any third-party analytics, advertising, or tracking services. Where open-source components are used, their respective license notices are preserved.

11. Changes to Terms
DNT Group reserves the right to modify these Terms at any time. Material changes will be brought to your attention, and continued use of the software after such changes constitutes acceptance of the modified Terms. The "Last Updated" date at the top of these Terms marks the latest revision.

12. Governing Law & Dispute Resolution
These Terms are governed by the laws of the Hong Kong Special Administrative Region of the People's Republic of China, without regard to conflict-of-law principles. Any dispute arising out of or relating to these Terms shall be subject to the exclusive jurisdiction of the courts of Hong Kong. This does not limit any statutory rights you may have as a consumer under applicable law.

13. Severability
If any provision of these Terms is found to be invalid or unenforceable, the remaining provisions shall continue in full force and effect.

14. Contact
If you have questions about these Terms, please visit https://dnteam.top or contact DNT Group via the address published on the official website.""",

    'zh-HK': """服務條款 Terms of Service

最後更新：2026年8月

1. 條款接受
使用 KJK Encryptor 即表示您同意本服務條款（下稱「本條款」）。如果您唔同意，請停止使用本軟件。安裝或使用本軟件，即表示您亦已閱讀並理解我哋嘅《私隱政策》。

2. 服務範圍
KJK Encryptor 係一款本地檔案加密工具。加密同解密都完全喺您部 device 上進行。我哋唔會儲存、傳輸或存取您嘅密碼、檔案或解密後嘅內容。

3. 開源授權
KJK Encryptor 係 open-source 軟件。您可以按附帶嘅開源授權條款，自由查看、修改同使用原始碼，包括用於商業用途。

4. 允許用途
您可以將 KJK Encryptor 用於個人、教育或商業用途。您可以按照相同嘅 open-source 條款修改同重新分發本軟件。

5. 禁止用途
您唔可以將 KJK Encryptor 用於任何非法用途或侵犯他人權利。您不得使用本軟件隱藏、加密、傳輸或分發非法內容，包括但不限於惡意軟件、兒童色情材料、恐怖主義宣傳材料或侵犯他人知識產權嘅內容。您須對自己嘅使用行為負全部責任。

6. 帳戶與註冊
使用 KJK Encryptor 唔需要任何帳戶。因此，我哋唔會進行任何用戶帳戶、user profiling 或行為追蹤。

7. 數據保護與合規
使用本軟件須遵守《私隱政策》，該政策符合中國香港《個人資料（私隱）條例》（第 486 章，「PDPO」），並於適用於您時符合歐盟《通用數據保障條例》（Regulation (EU) 2016/679，「GDPR」）。由於本軟件喺本地處理數據，喺正常使用過程中，我哋唔會收集或處理任何個人資料。

8. 免責聲明
本軟件按「現狀」提供，不附帶任何明示或暗示嘅擔保。DNT Group 唔保證其適銷性、特定用途適用性、安全性或不侵權。

9. 責任限制
喺適用法律允許嘅最大範圍內，DNT Group 及其貢獻者唔會對因使用或無法使用 KJK Encryptor 而導致嘅任何直接、間接、附帶、特殊或 consequential 損害（包括數據遺失或損壞）承擔責任。您有責任自行備份您嘅數據。

10. 第三方權利
本軟件唔會整合任何第三方分析、廣告或追蹤服務。如使用開源組件，會保留其相應嘅授權聲明。

11. 條款變更
DNT Group 保留隨時修改本條款嘅權利。重大變更會適時通知您，喺變更後繼續使用本軟件即表示您接受修改後嘅條款。本條款頂部嘅「最後更新」日期標示最新修訂。

12. 適用法律與爭議解決
本條款受中華人民共和國香港特別行政區法律管轄，不考慮法律衝突原則。因本條款產生或與本條款有關嘅任何爭議，均受香港法院嘅專屬管轄。此不限制您作為消費者喺適用法律下享有嘅任何法定權利。

13. 可分性
如本條款任何規定被認定無效或不可執行，其餘規定應繼續具有完整效力。

14. 聯繫方式
如果您對本條款有任何疑問，請訪問 https://dnteam.top 或透過官方網站公布嘅地址同 DNT Group 聯繫。""",

    'zh-CN': """服务条款

最后更新：2026年8月

1. 条款接受
使用 KJK Encryptor 即表示您同意本服务条款（下称"本条款"）。如果您不同意，请停止使用本软件。安装或使用本软件，即表示您亦已阅读并理解我们的《隐私政策》。

2. 服务范围
KJK Encryptor 是一款本地文件加密工具。加密和解密完全在您的设备上进行。我们不会存储、传输或访问您的密码、文件或解密后的内容。

3. 开源授权
KJK Encryptor 是开源软件。您可以根据随附的开源许可条款，自由查看、修改和使用源代码，包括用于商业用途。

4. 允许用途
您可以将 KJK Encryptor 用于个人、教育或商业用途。您可以按照相同的开源条款修改和重新分发本软件。

5. 禁止用途
您不得将 KJK Encryptor 用于任何非法用途或侵犯他人权利。您不得使用本软件隐藏、加密、传输或分发非法内容，包括但不限于恶意软件、儿童色情材料、恐怖主义宣传材料或侵犯他人知识产权的内容。您须对自己的使用行为负全部责任。

6. 账户与注册
使用 KJK Encryptor 无需任何账户。因此，我们不会进行任何用户账户、用户画像或行为追踪。

7. 数据保护与合规
使用本软件须遵守《隐私政策》，该政策符合中华人民共和国香港特别行政区《个人资料（私隐）条例》（第 486 章，"PDPO"），并在适用于您时符合欧盟《通用数据保护条例》（Regulation (EU) 2016/679，"GDPR"）。由于本软件在本地处理数据，在正常使用过程中，我们不会收集或处理任何个人资料。

8. 免责声明
本软件按「现状」提供，不附带任何明示或暗示的担保。DNT Group不保证其适销性、特定用途适用性、安全性或不侵权。

9. 责任限制
在适用法律允许的最大范围内，DNT Group及其贡献者不对因使用或无法使用 KJK Encryptor 而导致的任何直接、间接、附带、特殊或后果性损害（包括数据丢失或损坏）承担责任。您有责任自行备份您的数据。

10. 第三方权利
本软件不会集成任何第三方分析、广告或追踪服务。如使用开源组件，将保留其相应的许可声明。

11. 条款变更
DNT Group保留随时修改本条款的权利。重大变更会适时通知您，在变更后继续使用本软件即表示您接受修改后的条款。本条款顶部的"最后更新"日期标示最新修订。

12. 适用法律与争议解决
本条款受中华人民共和国香港特别行政区法律管辖，不考虑法律冲突原则。因本条款产生或与本条款有关的任何争议，均受香港法院的专属管辖。此不限制您作为消费者在适用法律下享有的任何法定权利。

13. 可分性
如本条款任何规定被认定无效或不可执行，其余规定应继续具有完整效力。

14. 联系方式
如果您对本条款有任何疑问，请访问 https://dnteam.top 或通过官方网站公布的地址与 DNT Group 联系。""",
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
The source code is licensed under the MIT License. Commercial use is permitted, provided that the original copyright notice and license terms are retained. DNT Group is not responsible for any modified versions distributed by third parties.

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
原始碼根據 MIT License 授權。允許商業用途，但必須保留原始版權聲明同許可條款。DNT Group 唔對第三方分發嘅修改版本負責。

7. 網絡連接
本軟件可選擇檢查 update 或喺系統瀏覽器中打開官方網站 / API 文件。呢啲功能可以喺「Settings」入面關閉。所有加密同解密操作都喺您部 device 本地完成。

8. 數據保護合規
本軟件嘅提供符合中國香港《個人資料（私隱）條例》（第 486 章，「PDPO」），並於適用於您時符合歐盟《通用數據保障條例》（Regulation (EU) 2016/679，「GDPR」）。喺正常使用過程中，本軟件唔會收集、傳輸或儲存任何個人資料。有關您嘅數據保護權利詳情，請參閱《私隱政策》。

9. 適用法律
本 Disclaimer 同使用本軟件受中華人民共和國香港特別行政區法律管轄。此並唔限制您根據本地法律享有嘅任何強制性消費者保障。

撳「Accept」或繼續安裝，即表示您已完整閱讀、理解並接受本 Disclaimer。""",

    'zh-CN': """必读免责声明

最后更新：2026年8月

1. 无担保
KJK Encryptor 按「现状」提供，不附带任何明示或暗示担保。DNT Group 不保证其适销性、特定用途适用性、安全性或不侵权。

2. 自行承担使用风险
您须自行承担使用本软件进行加密、解密或数据传输的所有风险，包括数据丢失、文件损坏或无法访问数据。执行重要操作前，请务必备份原始文件。

3. 密码责任
如果您忘记或遗失密码，DNT Group 无法亦不会协助您恢复加密数据。本软件没有「后门」或任何恢复机制。

4. 法律合规
您有责任确保使用 KJK Encryptor 符合您所在地区的所有适用法律法规。您不得使用本软件隐藏、加密、传输或分发非法内容，包括但不限于恶意软件、儿童色情内容、恐怖主义宣传材料或侵犯他人知识产权的内容。

5. 责任限制
在法律允许的最大范围内，DNT Group 及其贡献者不会对因使用或无法使用本软件而导致的任何直接、间接、附带、特殊或后果性损害承担责任。

6. 开源与商业用途
源代码根据 MIT License 授权。允许商业用途，但必须保留原始版权声明和许可条款。DNT Group 不对第三方分发的修改版本负责。

7. 网络连接
本软件可选择检查更新或在系统浏览器中打开官方网站/API 文档。这些功能可在「设置」中关闭。所有加密和解密操作均在您的设备本地完成。

8. 数据保护合规
本软件的提供符合中华人民共和国香港特别行政区《个人资料（私隐）条例》（第 486 章，"PDPO"），并在适用于您时符合欧盟《通用数据保护条例》（Regulation (EU) 2016/679，"GDPR"）。在正常使用过程中，本软件不会收集、传输或存储任何个人资料。有关您的数据保护权利详情，请参阅《隐私政策》。

9. 适用法律
本免责声明及使用本软件受中华人民共和国香港特别行政区法律管辖。此并不限制您根据本地法律享有的任何强制性消费者保障。

点击「接受」或继续安装，即表示您已完整阅读、理解并接受本免责声明。""",
}


def _format_size(num_bytes: int) -> str:
    """将字节数格式化为人类可读字符串。"""
    if num_bytes < 1024:
        return f'{num_bytes} B'
    for unit in ('KB', 'MB', 'GB', 'TB'):
        num_bytes /= 1024.0
        if num_bytes < 1024:
            return f'{num_bytes:.1f} {unit}'
    return f'{num_bytes:.1f} PB'




# ======================== GUI Application ========================
class KJKApp:
    def __init__(self, batch_paths=None):
        self.config = load_config(DEFAULT_CONFIG)
        if _HAS_DND:
            try:
                self.root = TkinterDnD.Tk()
            except Exception:
                self.root = tk.Tk()
        else:
            self.root = tk.Tk()
        self._set_window_icon()

        # State
        self.encrypt_files = []
        self.encrypt_folders = []
        self.encrypt_result = None
        self.decrypt_results = []
        self.api_url = None
        self._last_salt_hex = None
        self._last_is_v7 = False
        self._current_package_path = None
        self._current_package_content = None
        self._current_package_password = ''
        self._current_pkg_format = ''
        self._selected_tree_node = None

        # i18n dictionary
        self.i18n = {
            'disclaimerTitle': {'en': 'Disclaimer', 'zh-HK': 'Disclaimer', 'zh-CN': '免责声明'},
            'disclaimerFirstRun': {'en': 'Welcome to KJK Encryptor!\n\nPlease read the following disclaimer carefully before using this software.', 'zh-HK': '歡迎使用 KJK Encryptor！\n\n使用本軟件前請仔細閱讀以下 Disclaimer。', 'zh-CN': '欢迎使用 KJK Encryptor！\n\n使用本软件前请仔细阅读以下免责声明。'},
            'disclaimerAccept': {'en': 'I Accept', 'zh-HK': 'I Accept', 'zh-CN': '我接受'},
            'encryptPasswordPopup': {'en': 'Encryption Password', 'zh-HK': 'Encryption Password', 'zh-CN': '加密密码'},
            'encryptPasswordHint': {'en': 'Enter password (or leave empty for no password):', 'zh-HK': '輸入密碼（留空即唔設密碼）：', 'zh-CN': '输入密码（留空即不设密码）：'},
            'menuFile': {'en': 'File', 'zh-HK': '檔案 File', 'zh-CN': '文件'},
            'menuSettings': {'en': 'Settings', 'zh-HK': '設定 Settings', 'zh-CN': '设置'},
            'menuHelp': {'en': 'Help', 'zh-HK': '幫助 Help', 'zh-CN': '帮助'},
            'menuOpenEncrypt': {'en': 'Open Files to Encrypt...', 'zh-HK': '開啟檔案加密...', 'zh-CN': '打开文件加密...'},
            'menuOpenDecrypt': {'en': 'Open .kjk to Decrypt...', 'zh-HK': '開啟 .kjk 解密...', 'zh-CN': '打开.kjk解密...'},
            'menuOpenPackage': {'en': 'Open .kjk Package...', 'zh-HK': '開啟 .kjk Package...', 'zh-CN': '打开.kjk包管理...'},
            'menuExit': {'en': 'Exit', 'zh-HK': '結束 Exit', 'zh-CN': '退出'},
            'menuSettingsItem': {'en': 'Settings', 'zh-HK': 'Settings', 'zh-CN': '设置'},
            'menuRegisterContext': {'en': 'Register Context Menu (Admin)', 'zh-HK': '註冊右鍵選單 (Admin)', 'zh-CN': '注册右键菜单 (管理员)'},
            'menuUnregisterContext': {'en': 'Unregister Context Menu (Admin)', 'zh-HK': '解除安裝右鍵選單 (Admin)', 'zh-CN': '卸载右键菜单 (管理员)'},
            'menuAbout': {'en': 'About', 'zh-HK': '關於 About', 'zh-CN': '关于'},
            'menuPrivacy': {'en': 'Privacy Policy', 'zh-HK': '私隱政策 Privacy Policy', 'zh-CN': '隐私政策'},
            'menuTerms': {'en': 'Terms of Service', 'zh-HK': '服務條款 Terms of Service', 'zh-CN': '服务条款'},
            'menuDisclaimer': {'en': 'Disclaimer', 'zh-HK': 'Disclaimer', 'zh-CN': '免责声明'},
            'menuApiDocs': {'en': 'API Documentation', 'zh-HK': 'API Documentation', 'zh-CN': 'API 文档'},
            'menuDownloadSource': {'en': 'Save Source Code', 'zh-HK': 'Save Source Code', 'zh-CN': '保存源代码'},
            'menuWebsite': {'en': 'Official Website', 'zh-HK': '官方網站 Official Website', 'zh-CN': '官方网站'},

            # Tabs
            'tabEncrypt': {'en': '  🔒 Encrypt ', 'zh-HK': '  🔒 加密 Encrypt ', 'zh-CN': '  🔒 加密 '},
            'tabDecrypt': {'en': '  🔓 Decrypt ', 'zh-HK': '  🔓 解密 Decrypt ', 'zh-CN': '  🔓 解密 '},
            'tabPackageManager': {'en': '  📦 Package Manager ', 'zh-HK': '  📦 套件管理 Package Manager ', 'zh-CN': '  📦 包管理器 '},

            # Encrypt tab
            'textInput': {'en': 'Text Input:', 'zh-HK': '文字輸入:', 'zh-CN': '文本输入:'},
            'selectFiles': {'en': '+ Select Files', 'zh-HK': '+ 揀檔案 Select Files', 'zh-CN': '+ 选择文件'},
            'selectFolder': {'en': '+ Select Folder', 'zh-HK': '+ 揀資料夾 Select Folder', 'zh-CN': '+ 选择文件夹'},
            'noFilesSelected': {'en': 'No files selected', 'zh-HK': '未揀檔案', 'zh-CN': '未选择文件'},
            'filesCount': {'en': '{} files', 'zh-HK': '{} 個檔案', 'zh-CN': '{} 个文件'},
            'passwordOptional': {'en': 'Password (optional):', 'zh-HK': '密碼 Password (可選):', 'zh-CN': '密码 (可选):'},
            'mergeIntoOnePackage': {'en': 'Merge into one package', 'zh-HK': '合併為單一 package', 'zh-CN': '合并为一个包'},
            'encryptAlgorithm': {'en': 'Algorithm:', 'zh-HK': '演算法:', 'zh-CN': '加密算法:'},
            'algKjk9': {'en': 'KJKv9 (binary, save as .kjk file)', 'zh-HK': 'KJKv9 (二進制, 只可儲存 .kjk 檔案)', 'zh-CN': 'KJKv9（二进制，仅保存 .kjk 文件）'},
            'algText': {'en': 'Legacy text (copyable ciphertext)', 'zh-HK': '舊版文字 (可複製密文)', 'zh-CN': '旧版本文本（可复制密文）'},
            'msgKjk9Saved': {'en': 'KJKv9 is a binary format and cannot be pasted as text. It has been saved to:\n{}', 'zh-HK': 'KJKv9 係二進制格式, 唔可以貼做文字。已儲存到:\n{}', 'zh-CN': 'KJKv9 为二进制格式，无法粘贴为文本。已保存到：\n{}'},
            'btnEncrypt': {'en': '🔐 Encrypt', 'zh-HK': '🔐 Encrypt', 'zh-CN': '🔐 加密'},
            'btnDecrypt': {'en': '🔓 Decrypt', 'zh-HK': '🔓 Decrypt', 'zh-CN': '🔓 解密'},
            'btnDownloadKjk': {'en': '⬇ Download .kjk', 'zh-HK': '⬇ Download .kjk', 'zh-CN': '⬇ 下载 .kjk'},
            'btnCopyCipher': {'en': '📋 Copy Cipher', 'zh-HK': '📋 Copy Cipher', 'zh-CN': '📋 复制密文'},
            'btnClear': {'en': '🗑 Clear', 'zh-HK': '🗑 Clear', 'zh-CN': '🗑 清除'},

            # Decrypt tab
            'uploadKjk': {'en': 'Upload .kjk file:', 'zh-HK': '上傳 .kjk 檔案:', 'zh-CN': '上传 .kjk 文件:'},
            'selectKjkFile': {'en': '📂 Select .kjk File', 'zh-HK': '📂 揀 .kjk 檔案 Select', 'zh-CN': '📂 选择.kjk文件'},
            'orPasteCipher': {'en': 'Or paste cipher:', 'zh-HK': '或貼上密文:', 'zh-CN': '或粘贴密文:'},
            'password': {'en': 'Password:', 'zh-HK': '密碼:', 'zh-CN': '密码:'},
            'btnDownloadAll': {'en': '⬇ Download All', 'zh-HK': '⬇ Download All', 'zh-CN': '⬇ 全部下载'},
            'btnRetryPassword': {'en': '🔑 Retry Password', 'zh-HK': '🔑 Retry Password', 'zh-CN': '🔑 重试密码'},
            'btnDownload': {'en': '⬇ Download', 'zh-HK': '⬇ Download', 'zh-CN': '⬇ 下载'},
            'noDecryptResults': {'en': 'No decrypt results yet', 'zh-HK': '暫無解密結果', 'zh-CN': '暂无解密结果'},
            'unknownFile': {'en': 'Unknown File', 'zh-HK': '未知檔案 Unknown File', 'zh-CN': '未知文件'},
            'treeNoSelection': {'en': 'No selection', 'zh-HK': '未選擇', 'zh-CN': '未选择'},
            'binaryContent': {'en': '[Binary content - cannot preview]', 'zh-HK': '[二進制內容 - 無法預覽]', 'zh-CN': '[二进制内容 - 无法预览]'},
            'btnOpen': {'en': '📂 Open', 'zh-HK': '📂 Open', 'zh-CN': '📂 打开'},
            'pkgPasteHint': {'en': 'Paste a .kjk file path or old-format cipher:', 'zh-HK': '貼上 .kjk 路徑或舊格式密文:', 'zh-CN': '粘贴 .kjk 路径或旧格式密文:'},

            # Status
            'statusReady': {'en': 'Ready', 'zh-HK': '準備就緒 Ready', 'zh-CN': '就绪'},
            'statusEncrypting': {'en': 'Encrypting... ({}/{})', 'zh-HK': 'Encrypt 緊... ({}/{})', 'zh-CN': '加密中... ({}/{})'},
            'statusEncryptComplete': {'en': 'Encryption complete! {} files total', 'zh-HK': 'Encrypt 完成！共 {} 個檔案', 'zh-CN': '加密完成! 共 {} 个文件'},
            'statusDecryptComplete': {'en': 'Decryption complete! {} files total', 'zh-HK': 'Decrypt 完成！共 {} 個檔案', 'zh-CN': '解密完成! 共 {} 个文件'},
            'statusSaved': {'en': 'Saved: {}', 'zh-HK': '已 Save: {}', 'zh-CN': '已保存: {}'},
            'statusCopied': {'en': 'Cipher copied to clipboard', 'zh-HK': '密文已 Copy 到剪貼簿', 'zh-CN': '密文已复制到剪贴板'},
            'statusCleared': {'en': 'Cleared', 'zh-HK': '已 Clear', 'zh-CN': '已清除'},
            'statusDecryptedFile': {'en': 'Decrypted: {}', 'zh-HK': '已 Decrypt: {}', 'zh-CN': '解密完成: {}'},
            'statusPasswordRetry': {'en': 'Re-decrypted with new password', 'zh-HK': '已用新密碼重新 Decrypt', 'zh-CN': '已使用新密码重新解密'},
            'statusDownloadComplete': {'en': 'Download complete', 'zh-HK': 'Download 完成', 'zh-CN': '下载完成'},
            'statusTotalFiles': {'en': '{} files', 'zh-HK': '{} 個檔案', 'zh-CN': '{} 个文件'},
            'statusTotalSize': {'en': '{} total', 'zh-HK': '{} 總共', 'zh-CN': '{} 总计'},
            'statusProtected': {'en': '🔒 Protected', 'zh-HK': '🔒 受密碼保護', 'zh-CN': '🔒 已加密'},
            'statusFormat': {'en': 'Format: {}', 'zh-HK': '格式：{}', 'zh-CN': '格式：{}'},
            'statusDroppedEncrypt': {'en': '{} item(s) added to encrypt list', 'zh-HK': '已將 {} 個項目加入加密清單', 'zh-CN': '已将 {} 个项目加入加密列表'},
            'statusDroppedDecrypt': {'en': '{} package(s) sent to decrypt', 'zh-HK': '已將 {} 個包送去解密', 'zh-CN': '已将 {} 个包送去解密'},
            'statusDroppedOpen': {'en': '{} package(s) opened', 'zh-HK': '已開啟 {} 個包', 'zh-CN': '已打开 {} 个包'},
            'statusDropNoKjk': {'en': 'Drop .kjk files here to decrypt/open', 'zh-HK': '請拖入 .kjk 檔案進行解密/開啟', 'zh-CN': '请拖入 .kjk 文件进行解密/打开'},

            # Progress
            'progressPreparing': {'en': 'Preparing...', 'zh-HK': 'Preparing...', 'zh-CN': '准备中...'},
            'progressEncrypting': {'en': 'Encrypting...', 'zh-HK': 'Encrypting...', 'zh-CN': '加密中...'},
            'progressDecrypting': {'en': 'Decrypting...', 'zh-HK': 'Decrypting...', 'zh-CN': '解密中...'},
            'progressParsing': {'en': 'Parsing...', 'zh-HK': '解析中...', 'zh-CN': '解析中...'},
 'msgWrongPwd': {'en': 'Wrong password.', 'zh-HK': '密碼錯誤。', 'zh-CN': '密码错误。'},
 'directReadingFile': {'en': 'Reading .kjk file...', 'zh-HK': '讀取 .kjk 檔案中...', 'zh-CN': '正在读取 .kjk 文件...'},
 'directExtractingTo': {'en': 'Extracting to: {}', 'zh-HK': '解壓到: {}', 'zh-CN': '正在解压到: {}'},
 'statusExtractedTo': {'en': 'Extracted {count} file(s) to {path}', 'zh-HK': '已解壓 {count} 個檔案到 {path}', 'zh-CN': '已解压 {count} 个文件到 {path}'},
            'progressComplete': {'en': 'Complete!', 'zh-HK': '完成！Done！', 'zh-CN': '完成!'},

            # Dialog titles
            'dialogTitleSelectEncrypt': {'en': 'Select files to encrypt', 'zh-HK': '揀要 Encrypt 嘅檔案', 'zh-CN': '选择要加密的文件'},
            'dialogTitleSelectFolder': {'en': 'Select folder to encrypt', 'zh-HK': '揀要 Encrypt 嘅資料夾', 'zh-CN': '选择要加密的文件夹'},
            'dialogTitleSelectKjk': {'en': 'Select .kjk file', 'zh-HK': '揀 .kjk 檔案', 'zh-CN': '选择.kjk文件'},
            'dialogTitleSaveKjk': {'en': 'Save .kjk file', 'zh-HK': 'Save .kjk 檔案', 'zh-CN': '保存.kjk文件'},
            'dialogTitlePackageManager': {'en': 'KJK Package Manager', 'zh-HK': 'KJK Package Manager', 'zh-CN': 'KJK 包管理器'},
            'dialogTitleSaveFile': {'en': 'Save file', 'zh-HK': 'Save 檔案', 'zh-CN': '保存文件'},
            'dialogTitleSaveAll': {'en': 'Select folder to save all files', 'zh-HK': '揀選資料夾儲存全部檔案', 'zh-CN': '选择保存全部文件的文件夹'},
            'dialogTitleSaveAs': {'en': 'Save: {}', 'zh-HK': 'Save: {}', 'zh-CN': '保存: {}'},
            'selectOutputPath': {'en': 'Select output directory', 'zh-HK': '選擇輸出目錄', 'zh-CN': '选择输出目录'},
            'fileTypeKjk': {'en': 'KJK Files', 'zh-HK': 'KJK 檔案', 'zh-CN': 'KJK文件'},
            'fileTypeAll': {'en': 'All Files', 'zh-HK': '所有檔案 All Files', 'zh-CN': '所有文件'},

            # Messages
            'msgTitleHint': {'en': 'Hint', 'zh-HK': '提示 Hint', 'zh-CN': '提示'},
            'msgTitleError': {'en': 'Error', 'zh-HK': '錯誤 Error', 'zh-CN': '错误'},
            'msgTitleSuccess': {'en': 'Success', 'zh-HK': '成功 Success', 'zh-CN': '成功'},
            'msgTitleInfo': {'en': 'Info', 'zh-HK': '資訊 Info', 'zh-CN': '信息'},
            'msgTitleWarning': {'en': 'Warning', 'zh-HK': '警告 Warning', 'zh-CN': '警告'},
            'msgTitleEncryptFail': {'en': 'Encryption Failed', 'zh-HK': 'Encrypt 失敗', 'zh-CN': '加密失败'},
            'msgTitleDecryptFail': {'en': 'Decryption Failed', 'zh-HK': 'Decrypt 失敗', 'zh-CN': '解密失败'},
            'msgTitleParseFail': {'en': 'Parse Failed', 'zh-HK': 'Parse 失敗', 'zh-CN': '解析失败'},
            'msgTitleApiError': {'en': 'API Error', 'zh-HK': 'API 錯誤', 'zh-CN': 'API错误'},
            'msgSourceNotFound': {'en': 'Source code package not found.\nPlease reinstall or contact support.', 'zh-HK': '搵唔到 source code package。\n請重新安裝或聯絡支援。', 'zh-CN': '找不到源代码包。\n请重新安装或联系支持。'},
            'msgSourceSaved': {'en': 'Source code has been extracted to:\n{path}', 'zh-HK': 'Source code 已解壓到：\n{path}', 'zh-CN': '源代码已解压到:\n{path}'},
            'msgInputRequired': {'en': 'Please enter text or select files.', 'zh-HK': '請輸入文字或揀檔案。', 'zh-CN': '请输入文本或选择文件。'},
            'msgUploadRequired': {'en': 'Please upload .kjk file or paste cipher.', 'zh-HK': '請上傳 .kjk 檔案或貼上密文。', 'zh-CN': '请上传.kjk文件和粘贴密文。'},
            'msgReadFileFail': {'en': 'Failed to read file: {}', 'zh-HK': '讀取檔案失敗: {}', 'zh-CN': '读取文件失败: {}'},
            'msgReadFolderFail': {'en': 'Failed to read folder: {}', 'zh-HK': '讀取資料夾失敗: {}', 'zh-CN': '读取文件夹失败: {}'},
            'msgParseFileFail': {'en': 'Cannot parse file {}:\n{}', 'zh-HK': '無法解析檔案 {}:\n{}', 'zh-CN': '无法解析文件 {}:\n{}'},
            'msgParseCipherFail': {'en': 'Cannot parse cipher:\n{}', 'zh-HK': '無法解析密文:\n{}', 'zh-CN': '无法解析密文:\n{}'},
            'msgPasswordRequired': {'en': 'Password is required!', 'zh-HK': '需要輸入密碼！', 'zh-CN': '需要输入密码!'},
            'msgEnterPasswordRetry': {'en': 'Please enter password and retry', 'zh-HK': '請輸入密碼後重試', 'zh-CN': '请输入密码后重试'},
            'msgApiStartFail': {'en': 'Failed to start API service:\n{}', 'zh-HK': '啟動 API 服務失敗:\n{}', 'zh-CN': '启动API服务失败:\n{'},

            # Direct .kjk open & extract
            'dlgExtractTitle': {'en': 'Extract .kjk Package', 'zh-HK': '解壓 .kjk Package', 'zh-CN': '解压 .kjk 包'},
            'dlgExtractPrompt': {'en': 'This .kjk is password-protected.\nEnter decryption password:', 'zh-HK': '呢個 .kjk 受密碼保護。\n請輸入解密密碼：', 'zh-CN': '此 .kjk 受密码保护。\n请输入解密密码:'},
            'dlgSelectExtractDir': {'en': 'Select a folder to extract to', 'zh-HK': '選擇解壓位置', 'zh-CN': '选择解压位置'},
            'dlgDefaultSubfolder': {'en': 'Extract into a subfolder "{name}" beside the .kjk?', 'zh-HK': '是否解壓到 .kjk 旁的子資料夾 "{name}"？', 'zh-CN': '是否解压到 .kjk 旁的子文件夹 "{name}"？'},
            'dlgExtracting': {'en': 'Extracting...', 'zh-HK': '解壓緊...', 'zh-CN': '正在解压...'},
            'dlgExtractedOk': {'en': 'Extracted {count} file(s) to:\n{path}', 'zh-HK': '已解壓 {count} 個檔案到：\n{path}', 'zh-CN': '已解压 {count} 个文件到：\n{path}'},
            'dlgOpenFolder': {'en': 'Open Folder', 'zh-HK': '開啟資料夾', 'zh-CN': '打开文件夹'},
            'dlgWrongPwd': {'en': 'Wrong password. Please try again.', 'zh-HK': '密碼錯誤，請重試。', 'zh-CN': '密码错误，请重试。'},
            'dlgNoFiles': {'en': 'No extractable files found in this .kjk.', 'zh-HK': '呢個 .kjk 入面搵唔到可解壓嘅檔案。', 'zh-CN': '此 .kjk 中没有可解压的文件。'},
            'packageManager': {'en': 'Package Manager', 'zh-HK': '套件管理器', 'zh-CN': '包管理器'},
            'pkgAddFiles': {'en': '+ Add Files', 'zh-HK': '+ Add 檔案', 'zh-CN': '+ 添加文件'},
            'pkgAddFolder': {'en': '+ Add Folder', 'zh-HK': '+ Add 資料夾', 'zh-CN': '+ 添加文件夹'},
            'pkgSave': {'en': 'Save Package', 'zh-HK': 'Save Package', 'zh-CN': '保存包'},
            'pkgClose': {'en': 'Close', 'zh-HK': 'Close', 'zh-CN': '关闭'},
            'pkgContents': {'en': 'Package Contents ({} files)', 'zh-HK': 'Package 內容 ({} 個檔案)', 'zh-CN': '包内容 ({} 个文件)'},
            'pkgPasswordPrompt': {'en': 'This package is password-protected. Enter password:', 'zh-HK': '呢個 Package 受密碼保護。請輸入密碼：', 'zh-CN': '此包受密码保护。请输入密码:'},
            'pkgNoFiles': {'en': 'No files in package', 'zh-HK': 'Package 入面冇檔案', 'zh-CN': '包中没有文件'},
            'pkgAddedSuccess': {'en': 'Files added successfully!', 'zh-HK': '檔案 Add 成功！', 'zh-CN': '文件添加成功!'},
            'pkgSavedSuccess': {'en': 'Package saved successfully!', 'zh-HK': '套件儲存成功!', 'zh-CN': '包保存成功!'},
            'pkgExtractAll': {'en': '📂 Extract All', 'zh-HK': '📂 全部解壓', 'zh-CN': '📂 全部解压'},
            'extractSelected': {'en': '📂 Extract Selected', 'zh-HK': '📂 解壓已選', 'zh-CN': '📂 解压选中'},
            'deleteSelected': {'en': '🗑 Delete Selected', 'zh-HK': '🗑 刪除已選', 'zh-CN': '🗑 删除选中'},
            'renameEntry': {'en': '✏ Rename', 'zh-HK': '✏ 重新命名', 'zh-CN': '✏ 重命名'},
            'renamePwdPrompt': {'en': 'This package is password-protected.\nEnter password to rename:', 'zh-HK': '呢個 Package 受密碼保護。\n請輸入密碼以重新命名：', 'zh-CN': '此包受密码保护。\n请输入密码以重命名:'},
            'renameEnterNew': {'en': 'Enter new name (without extension):', 'zh-HK': '輸入新名稱（不含副檔名）：', 'zh-CN': '输入新名称（不含扩展名）:'},
            'renameNewExt': {'en': 'Enter new extension (optional):', 'zh-HK': '輸入新副檔名（可選）：', 'zh-CN': '输入新扩展名（可选）:'},
            'changePassword': {'en': '🔑 Change Password', 'zh-HK': '🔑 更改密碼', 'zh-CN': '🔑 修改密码'},
            'verifyIntegrity': {'en': '✓ Verify Integrity', 'zh-HK': '✓ 驗證完整性', 'zh-CN': '✓ 验证完整性'},
            'appendToPackage': {'en': '+ Append Files/Folders', 'zh-HK': '+ Append 檔案/資料夾', 'zh-CN': '+ 追加文件/文件夹'},
            'appendAskKind': {'en': 'Add files or a folder to the package?', 'zh-HK': '要 Add 檔案定資料夾入 Package？', 'zh-CN': '添加文件还是文件夹到包中？'},
            'savePackage': {'en': '💾 Save Package', 'zh-HK': '💾 Save Package', 'zh-CN': '💾 保存包'},
            'pkgConfirmDel': {'en': 'Delete "{name}" from package?', 'zh-HK': '確定從套件中刪除 "{name}"？', 'zh-CN': '确定从包中删除"{name}"？'},
            'pkgSelectDir': {'en': 'Select extraction directory', 'zh-HK': '選擇解壓目錄', 'zh-CN': '选择解压目录'},
            'pkgExtracted': {'en': 'Extracted {count} files to:\n{path}', 'zh-HK': '已解壓 {count} 個檔案到：\n{path}', 'zh-CN': '已解压 {count} 个文件到：\n{path}'},
            'pkgConfirmDelTitle': {'en': 'Confirm Delete', 'zh-HK': '確認刪除', 'zh-CN': '确认删除'},
            'pkgDeleted': {'en': 'Item deleted from package.', 'zh-HK': '已從套件中刪除項目。', 'zh-CN': '已从包中删除项目。'},
            'fileExistsOverwrite': {'en': 'already exists in package. Overwrite?', 'zh-HK': '已在套件中存在，是否覆蓋？', 'zh-CN': '已在包中存在，是否覆盖？'},
            'integrityOk': {'en': 'Integrity check passed.', 'zh-HK': '完整性檢查通過。', 'zh-CN': '完整性检查通过。'},
            'integrityFailed': {'en': 'Integrity check failed.', 'zh-HK': '完整性檢查失敗。', 'zh-CN': '完整性检查失败。'},
            'integrityNoHash': {'en': 'No integrity hash found in package.', 'zh-HK': 'Package 中沒有完整性雜湊。', 'zh-CN': '包中没有完整性哈希。'},
            'batchEncryptTitle': {'en': 'Batch Encrypt', 'zh-HK': 'Batch Encrypt', 'zh-CN': '批量加密'},
            'statusEncryptDone': {'en': 'Encrypted {} items to {}', 'zh-HK': '已 Encrypt {} 個項目到 {}', 'zh-CN': '已加密 {} 个项目到 {}'},
            'upgradeAsk': {'en': 'This package uses the old text format.\nUpgrade to the new KJKv9 binary engine?', 'zh-HK': '此套件使用舊文本格式。\n要升級到新 KJKv9 二進制引擎嗎？', 'zh-CN': '此包使用旧文本格式。\n要升级到新 KJKv9 二进制引擎吗？'},
            'statusUpgraded': {'en': 'Upgraded to KJKv9: {}', 'zh-HK': '已升級 KJKv9：{}', 'zh-CN': '已升级 KJKv9：{}'},
            'openPackageManagerAfterEncrypt': {'en': 'Encryption complete. Open Package Manager?', 'zh-HK': 'Encrypt 完成，是否開啟 Package Manager？', 'zh-CN': '加密完成，是否打开包管理器？'},
            'batchMergeConfirmTitle': {'en': 'Batch Encrypt', 'zh-HK': 'Batch Encrypt', 'zh-CN': '批量加密'},
            'batchMergeConfirmMsg': {'en': 'Detected {} item(s).\nMerge into one .kjk package?', 'zh-HK': '檢測到 {} 個項目。\n是否合併為一個 .kjk package？', 'zh-CN': '检测到 {} 个项目。\n是否合并为一个 .kjk 包？'},
            'batchSeparateTargetTitle': {'en': 'Select output folder', 'zh-HK': '揀選輸出資料夾', 'zh-CN': '选择输出文件夹'},
            'selectKjkFiles': {'en': 'Please select at least one .kjk file.', 'zh-HK': '請揀選至少一個 .kjk 檔案。', 'zh-CN': '请至少选择一个 .kjk 文件。'},
            'decryptPassword': {'en': 'Decryption Password', 'zh-HK': 'Decrypt 密碼', 'zh-CN': '解密密码'},
            'decryptPasswordHint': {'en': 'Enter password (leave empty if none):', 'zh-HK': '輸入密碼（如無密碼請留空）：', 'zh-CN': '输入密码（如无密码请留空）：'},
            'statusDecrypting': {'en': 'Decrypting...', 'zh-HK': 'Decrypt 緊...', 'zh-CN': '正在解密...'},
            'decryptDone': {'en': 'Decrypted {} files.', 'zh-HK': '已 Decrypt {} 個檔案。', 'zh-CN': '已解密 {} 个文件。'},
            'statusDecryptDone': {'en': 'Decryption complete: {} files', 'zh-HK': 'Decrypt 完成：{} 個檔案', 'zh-CN': '解密完成：{} 个文件'},
            'selectKjkTarget': {'en': 'Please select a .kjk package as target.', 'zh-HK': '請揀選一個 .kjk package 作為目標。', 'zh-CN': '请选择一个 .kjk 包作为目标。'},
            'wrongPassword': {'en': 'Wrong password.', 'zh-HK': '密碼錯誤。', 'zh-CN': '密码错误。'},

            # Settings
            'settingsTitle': {'en': 'Settings', 'zh-HK': '設定', 'zh-CN': '设置'},
            'settingsTheme': {'en': 'Theme', 'zh-HK': '主題', 'zh-CN': '主题'},
            'settingsThemeLight': {'en': '☀ Light', 'zh-HK': '☀ 淺色', 'zh-CN': '☀ 浅色'},
            'settingsThemeDark': {'en': '🌙 Dark', 'zh-HK': '🌙 深色', 'zh-CN': '🌙 深色'},
            'settingsLanguage': {'en': 'Language', 'zh-HK': '語言 Language', 'zh-CN': '语言'},
            'settingsLangEn': {'en': 'English', 'zh-HK': 'English', 'zh-CN': '英语'},
            'settingsLangZhHK': {'en': '繁體中文 (香港)', 'zh-HK': '繁體中文 (香港)', 'zh-CN': '繁体中文 (香港)'},
            'settingsLangZhCN': {'en': '简体中文', 'zh-HK': '簡體中文', 'zh-CN': '简体中文'},
            'settingsPreview': {'en': 'Enable content preview', 'zh-HK': '啟用內容預覽', 'zh-CN': '启用内容预览'},
            'settingsApiService': {'en': 'API Service', 'zh-HK': 'API 服務', 'zh-CN': 'API 服务'},
            'settingsApiEnable': {'en': 'Start embedded API server', 'zh-HK': '啟動內嵌 API 伺服器', 'zh-CN': '启动内嵌API服务器'},
            'settingsApiPort': {'en': 'Port:', 'zh-HK': '端口:', 'zh-CN': '端口:'},
            'settingsUpdateCheck': {'en': 'Update Check', 'zh-HK': '更新檢查', 'zh-CN': '更新检查'},
            'settingsUpdateEnable': {'en': 'Check for updates on startup', 'zh-HK': '啟動時檢查更新', 'zh-CN': '启动时检查更新'},
            'settingsUpdateServer': {'en': 'Server:', 'zh-HK': '伺服器:', 'zh-CN': '服务器:'},
            'settingsFormatCompat': {'en': 'Format Compatibility', 'zh-HK': '格式兼容性', 'zh-CN': '格式兼容性'},
            'settingsFormatAuto': {'en': 'Auto (detect automatically)', 'zh-HK': '自動 (自動檢測)', 'zh-CN': '自动 (自动检测)'},
            'settingsFormatV7': {'en': 'KJKv7 (v1.0.3 AES-256-GCM)', 'zh-HK': 'KJKv7 (v1.0.3 AES-256-GCM)', 'zh-CN': 'KJKv7 (v1.0.3 AES-256-GCM)'},
            'settingsFormatV5': {'en': 'KJKv5 (v1.0.2 SHA-256)', 'zh-HK': 'KJKv5 (v1.0.2 SHA-256)', 'zh-CN': 'KJKv5 (v1.0.2 SHA-256)'},
            'settingsSave': {'en': 'Save', 'zh-HK': '儲存', 'zh-CN': '保存'},
            'settingsSaved': {'en': 'Settings saved.', 'zh-HK': '設定已儲存。', 'zh-CN': '设置已保存。'},
            'btnVisitWebsite': {'en': 'Visit Website', 'zh-HK': '訪問官網', 'zh-CN': '访问官网'},
            'btnClose': {'en': 'Close', 'zh-HK': '關閉', 'zh-CN': '关闭'},

            # About
            'aboutTitle': {'en': 'About', 'zh-HK': '關於', 'zh-CN': '关于'},
            'aboutVersion': {'en': 'Version {}', 'zh-HK': '版本 {}', 'zh-CN': '版本 {}'},
            'aboutAppName': {'en': 'KJK Encryptor', 'zh-HK': 'KJK Encryptor', 'zh-CN': 'KJK Encryptor'},
            'aboutPoweredBy': {'en': 'Powered by DNT Group', 'zh-HK': '由 DNT Group 提供技術支援', 'zh-CN': '由 DNT Group 提供技术支持'},

            # Update checker
            'checkUpdate': {'en': 'Check for Updates', 'zh-HK': '檢查更新', 'zh-CN': '检查更新'},
            'latestVersion': {'en': 'You are on the latest version!', 'zh-HK': '您已經是最新版本！', 'zh-CN': '您已是最新版本！'},
            'updateAvailable': {'en': 'Update Available', 'zh-HK': '有可用更新', 'zh-CN': '有可用更新'},
            'newVersion': {'en': 'New Version', 'zh-HK': '新版本', 'zh-CN': '新版本'},
            'currentVersion': {'en': 'Current Version', 'zh-HK': '當前版本', 'zh-CN': '当前版本'},
            'changelog': {'en': 'Changelog', 'zh-HK': '更新日誌', 'zh-CN': '更新日志'},
            'downloadPrimary': {'en': 'Download (Primary)', 'zh-HK': '下載（主伺服器）', 'zh-CN': '下载（主服务器）'},
            'downloadBackup': {'en': 'Download (Backup)', 'zh-HK': '下載（備用伺服器）', 'zh-CN': '下载（备用服务器）'},
            'remindLater': {'en': 'Remind Me Later', 'zh-HK': '稍後提醒', 'zh-CN': '稍后提醒'},
            'downloading': {'en': 'Downloading...', 'zh-HK': '下載中...', 'zh-CN': '下载中...'},
            'downloadComplete': {'en': 'Download Complete! Starting installer...', 'zh-HK': '下載完成！正在啟動安裝程式...', 'zh-CN': '下载完成！正在启动安装程序...'},
            'updateError': {'en': 'Failed to check for updates', 'zh-HK': '檢查更新失敗', 'zh-CN': '检查更新失败'},
            'chooseDownload': {'en': 'Please choose a download source', 'zh-HK': '請選擇一個下載地址', 'zh-CN': '请选择一个下载地址'},
            'downloadServerPrimary': {'en': 'Primary Server (dnteam.top)', 'zh-HK': '主伺服器 (dnteam.top)', 'zh-CN': '主服务器 (dnteam.top)'},
            'downloadServerBackup': {'en': 'Backup Server (917813.help)', 'zh-HK': '備用伺服器 (917813.help)', 'zh-CN': '备用服务器 (917813.help)'},
            'updateConnectFail': {'en': 'Cannot connect to server', 'zh-HK': '無法連接到伺服器', 'zh-CN': '无法连接到服务器'},
            'btnRetry': {'en': 'Retry', 'zh-HK': '重試', 'zh-CN': '重试'},

            # Preview
            'contentPreview': {'en': 'Content Preview', 'zh-HK': '內容預覽', 'zh-CN': '内容预览'},
            'previewError': {'en': 'Preview error: {}', 'zh-HK': '預覽錯誤：{}', 'zh-CN': '预览错误：{}'},
            'fileLabel': {'en': '[File]', 'zh-HK': '[檔案]', 'zh-CN': '[文件]'},
            'imageLabel': {'en': '[Image]', 'zh-HK': '[圖片]', 'zh-CN': '[图片]'},
            'audioLabel': {'en': '[Audio]', 'zh-HK': '[音頻]', 'zh-CN': '[音频]'},
            'passwordBadge': {'en': ' 🔒PWD ', 'zh-HK': ' 🔒密碼 ', 'zh-CN': ' 🔒密码 '},
            'totalLabel': {'en': 'total', 'zh-HK': '總共', 'zh-CN': '总共'},
            'bytesLabel': {'en': 'bytes', 'zh-HK': '位元組', 'zh-CN': '字节'},

            'langChangedPrompt': {
                'en': 'Language changed successfully.\n\nIf you have registered the context menu, you may need to re-register it (Settings → Register Context Menu) to update the menu language.',
                'zh-HK': '語言已更改。\n\n如果您已註冊右鍵選單，可能需要重新註冊（設定 → 註冊右鍵選單）以更新選單語言。',
                'zh-CN': '语言已更改。\n\n如果您已注册右键菜单，可能需要重新注册（设置 → 注册右键菜单）以更新菜单语言。',
            },
        }

        self.root.title(self._t('aboutAppName'))
        geo = self.config.get('geometry', '840x580')
        # v1.0.4 一次性迁移: 旧版保存的过大窗口重置为紧凑默认值
        if not self.config.get('geometry_migrated_v104'):
            try:
                saved_w = int(str(geo).split('x')[0])
            except (ValueError, IndexError):
                saved_w = 0
            if saved_w > 840:
                geo = '840x580'
            self.config['geometry_migrated_v104'] = True
            try:
                save_config(self.config)
            except Exception:
                pass
        self.root.geometry(geo)
        self.root.minsize(660, 460)

        # Theme colors
        self.colors = {
            'light': {
                'bg': '#f5f5f7', 'fg': '#1d1d1f', 'card': '#ffffff',
                'secondary': '#e8e8ed', 'accent': '#0071e3', 'border': '#d2d2d7',
                'text_secondary': '#6e6e73', 'hover': '#e5e5ea', 'selected': '#0071e3',
            },
            'dark': {
                'bg': '#1c1c1e', 'fg': '#f5f5f7', 'card': '#2c2c2e',
                'secondary': '#3a3a3c', 'accent': '#2997ff', 'border': '#48484a',
                'text_secondary': '#98989d', 'hover': '#3a3a3c', 'selected': '#2997ff',
            }
        }

        self._build_ui()
        self._apply_theme()
        self._bind_events()

        if self.config.get('api_enabled'):
            self._toggle_api()

        self.root.after(1500, self._silent_check_update)

        if not self.config.get('disclaimer_shown'):
            self.root.after(500, self._show_first_run_disclaimer)

        self.root.protocol('WM_DELETE_WINDOW', self._on_close)
        self._update_all_ui_text()

        # Batch encrypt queue polling
        self._batch_paths = batch_paths or []
        if self._batch_paths:
            # 将自己的路径也写入队列,等待收集完毕后一起处理
            _try_send_to_running_instance(self._batch_paths)
            self._batch_paths = []
            self.root.after(800, self._process_collected_batch)
        self._start_batch_queue_poller()

    def _set_window_icon(self):
        """设置窗口图标。"""
        try:
            from PIL import Image, ImageTk
            icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon', 'icon.png')
            if os.path.exists(icon_path):
                img = Image.open(icon_path)
                self._icon_photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, self._icon_photo)
        except Exception:
            pass

    def _t(self, key):
        lang = self.config.get('lang', 'en')
        return self.i18n.get(key, {}).get(lang, key)

    @staticmethod
    def _font_name():
        """返回当前系统可用的平滑字体(Windows 优先 Microsoft YaHei UI / Segoe UI)。"""
        try:
            import tkinter.font as _tf
            avail = set(_tf.families())
            for name in ('Microsoft YaHei UI', 'Segoe UI', 'Noto Sans SC', 'Microsoft YaHei'):
                if name in avail:
                    return name
        except Exception:
            pass
        return 'TkDefaultFont'

    # ======================== UI Construction ========================
    def _build_ui(self):
        root = self.root
        c = self._c()

        # Menu bar
        self.menubar = tk.Menu(root)
        root.config(menu=self.menubar)

        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.file_menu.add_command(label=self._t('menuOpenEncrypt'), command=self._open_files_for_encrypt)
        self.file_menu.add_command(label=self._t('menuOpenDecrypt'), command=self._open_file_for_decrypt)
        self.file_menu.add_separator()
        self.file_menu.add_command(label=self._t('menuOpenPackage'), command=self._open_package_manager)
        self.file_menu.add_separator()
        self.file_menu.add_command(label=self._t('menuExit'), command=self._on_close)
        self.menubar.add_cascade(label=self._t('menuFile'), menu=self.file_menu)

        self.setting_menu = tk.Menu(self.menubar, tearoff=0)
        self.setting_menu.add_command(label=self._t('menuSettingsItem'), command=self._open_settings)
        self.setting_menu.add_separator()
        self.setting_menu.add_command(label=self._t('menuRegisterContext'), command=self._do_register_menu)
        self.setting_menu.add_command(label=self._t('menuUnregisterContext'), command=self._do_unregister_menu)
        self.menubar.add_cascade(label=self._t('menuSettings'), menu=self.setting_menu)

        self.help_menu = tk.Menu(self.menubar, tearoff=0)
        self.help_menu.add_command(label=self._t('menuAbout'), command=self._show_about)
        self.help_menu.add_separator()
        self.help_menu.add_command(label=self._t('menuPrivacy'), command=self._open_privacy_policy)
        self.help_menu.add_command(label=self._t('menuTerms'), command=self._open_terms_of_service)
        self.help_menu.add_command(label=self._t('menuDisclaimer'), command=self._show_disclaimer)
        self.help_menu.add_command(label=self._t('menuApiDocs'), command=self._open_api_docs)
        self.help_menu.add_command(label=self._t('menuDownloadSource'), command=self._download_source_code)
        self.help_menu.add_command(label=self._t('menuWebsite'), command=self._open_official_website)
        self.menubar.add_cascade(label=self._t('menuHelp'), menu=self.help_menu)

        # Header bar: 应用标题 + 版本
        self.header_bar = tk.Frame(root, bg=c['card'], relief=tk.FLAT, bd=0,
                                   highlightthickness=1, highlightbackground=c['border'])
        self.header_bar.pack(fill=tk.X, padx=12, pady=(8, 0))
        self.header_title = tk.Label(self.header_bar, text='🔐 ' + self._t('aboutAppName'),
                                     bg=c['card'], fg=c['fg'],
                                     font=(self._font_name(), 12, 'bold'), anchor='w')
        self.header_title.pack(side=tk.LEFT, padx=10, pady=5)
        self.header_sub = tk.Label(self.header_bar, text='v1.1.0',
                                   bg=c['card'], fg=c['text_secondary'],
                                   font=(self._font_name(), 9), anchor='w')
        self.header_sub.pack(side=tk.LEFT, pady=5)

        # Main container
        self.main_frame = tk.Frame(root, bg=c['bg'])
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=(6, 6))

        style = ttk.Style()
        style.theme_use('clam')
        try:
            style.configure('TNotebook', background=c['bg'], borderwidth=0, tabmargins=(3, 4, 3, 0))
            style.configure('TNotebook.Tab', background=c['secondary'], foreground=c['fg'],
                            padding=(14, 5), font=(self._font_name(), 10))
            style.map('TNotebook.Tab',
                      background=[('selected', c['card']), ('active', c['hover'])],
                      foreground=[('selected', c['accent'])])
        except Exception:
            pass
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Encrypt Tab
        self.encrypt_frame = tk.Frame(self.notebook, bg=c['bg'])
        self.notebook.add(self.encrypt_frame, text=self._t('tabEncrypt'))
        self._build_encrypt_tab()

        # Decrypt Tab
        self.decrypt_frame = tk.Frame(self.notebook, bg=c['bg'])
        self.notebook.add(self.decrypt_frame, text=self._t('tabDecrypt'))
        self._build_decrypt_tab()

        # Package Manager Tab
        self.package_frame = tk.Frame(self.notebook, bg=c['bg'])
        self.notebook.add(self.package_frame, text=self._t('tabPackageManager'))
        self._build_package_tab()

        # Update bar
        self.update_bar = tk.Frame(root, bg=c['bg'])
        self.update_bar.pack(fill=tk.X, padx=16, pady=(8, 4))
        self.check_update_btn = tk.Button(self.update_bar, text=self._t('checkUpdate'),
                                          bg=c['secondary'], fg=c['fg'], relief=tk.FLAT,
                                          padx=14, pady=4, cursor='hand2', font=(self._font_name(), 9),
                                          command=self.check_update)
        self.check_update_btn.pack(side=tk.RIGHT)

        # Status bars
        self.status_bar = tk.Label(root, text=self._t('statusReady'), bg=c['secondary'], fg=c['fg'],
                                   anchor='w', padx=12, font=(self._font_name(), 9))
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.api_label = tk.Label(root, text='', bg=c['secondary'], fg=c['text_secondary'],
                                  font=(self._font_name(), 9), padx=12)
        self.api_label.pack(fill=tk.X, side=tk.BOTTOM)

        # 主窗口拖拽: 按落点所在标签页路由操作
        if _HAS_DND:
            try:
                root.drop_target_register(DND_FILES)
                root.dnd_bind('<<Drop>>', self._on_main_drop)
            except Exception:
                pass

    def _on_main_drop(self, event):
        """主窗口拖放: 按指针落点所在标签页路由(加密/解密/包管理器), 不看文件类型。"""
        try:
            paths = list(self.root.tk.splitlist(event.data))
        except tk.TclError:
            paths = [event.data]
        paths = [p.strip('{}') for p in paths if p]
        if not paths:
            return
        try:
            idx = self.notebook.index('current')
        except Exception:
            idx = 0
        if idx == 1:
            self._drop_to_decrypt(paths)
        elif idx == 2:
            self._drop_to_open(paths)
        else:
            self._drop_to_encrypt(paths)

    def _drop_to_encrypt(self, paths):
        for p in paths:
            if os.path.isdir(p):
                self.encrypt_folders.append(p)
            elif os.path.isfile(p):
                self.encrypt_files.append(type('_FileObj', (), {'name': p})())
        self._update_encrypt_file_list()
        self.set_status(self._t('statusDroppedEncrypt').format(len(paths)))

    def _drop_to_decrypt(self, paths):
        kjk_files = [p for p in paths if os.path.isfile(p)]
        if not kjk_files:
            self.set_status(self._t('statusDropNoKjk'))
            return
        import kjk9
        for p in kjk_files:
            if kjk9.is_kjk9(p):
                self._launch_browse(p)
            else:
                with open(p, 'rb') as f:
                    self._process_decrypt_file(f)
        self.set_status(self._t('statusDroppedDecrypt').format(len(kjk_files)))

    def _drop_to_open(self, paths):
        kjk_files = [p for p in paths if os.path.isfile(p) and p.lower().endswith('.kjk')]
        others = [p for p in paths if p not in kjk_files]
        for p in kjk_files:
            self._load_package(p)
        if others:
            self._append_dropped(others)
        self.set_status(self._t('statusDroppedOpen').format(len(paths)))

    def set_status(self, text):
        """更新底部状态栏文字。"""
        self.status_bar.config(text=text)

    def _build_encrypt_tab(self):
        c = self._c()
        f = self.encrypt_frame

        # Text input
        self.encrypt_text_label = tk.Label(f, text=self._t('textInput'), bg=c['bg'], fg=c['fg'],
                                            font=('', 12), anchor='w')
        self.encrypt_text_label.pack(fill=tk.X, pady=(8, 4))
        self.encrypt_text = scrolledtext.ScrolledText(
            f, height=4, font=(self._font_name(), 10),
            bg=c['card'], fg=c['fg'], insertbackground=c['fg'],
            relief=tk.FLAT, bd=1, highlightthickness=1,
            highlightbackground=c['border'], highlightcolor=c['accent'])
        self.encrypt_text.pack(fill=tk.X, pady=(0, 8))

        # File toolbar
        self.encrypt_file_frame = tk.Frame(f, bg=c['bg'])
        self.encrypt_file_frame.pack(fill=tk.X, pady=4)
        btn_frame = tk.Frame(self.encrypt_file_frame, bg=c['bg'])
        btn_frame.pack(fill=tk.X)
        self.add_file_btn = tk.Button(btn_frame, text=self._t('selectFiles'), bg=c['accent'], fg='white',
                                       relief=tk.FLAT, padx=12, pady=4, cursor='hand2',
                                       font=(self._font_name(), 10), command=self._open_files_for_encrypt)
        self.add_file_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.add_folder_btn = tk.Button(btn_frame, text=self._t('selectFolder'), bg=c['secondary'], fg=c['fg'],
                                         relief=tk.FLAT, padx=12, pady=4, cursor='hand2',
                                         font=(self._font_name(), 10), command=self._open_folder_for_encrypt)
        self.add_folder_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.clear_encrypt_btn_top = tk.Button(btn_frame, text=self._t('btnClear'), bg=c['secondary'], fg=c['fg'],
                                                relief=tk.FLAT, padx=12, pady=4, cursor='hand2',
                                                font=(self._font_name(), 10), command=self._clear_encrypt)
        self.clear_encrypt_btn_top.pack(side=tk.LEFT, padx=(0, 8))
        self.encrypt_file_count = tk.Label(btn_frame, text=self._t('noFilesSelected'), bg=c['bg'],
                                            fg=c['text_secondary'], font=(self._font_name(), 10))
        self.encrypt_file_count.pack(side=tk.LEFT)

        # File list (card)
        list_card = tk.Frame(self.encrypt_file_frame, bg=c['card'], relief=tk.FLAT, bd=1,
                              highlightthickness=1, highlightbackground=c['border'])
        list_card.pack(fill=tk.X, pady=(4, 0))
        self.encrypt_file_listbox = tk.Listbox(
            list_card, height=4, font=(self._font_name(), 10),
            bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=0,
            highlightthickness=0, selectbackground=c['selected'],
            selectforeground='white')
        self.encrypt_file_listbox.pack(fill=tk.X, padx=4, pady=4)

        # Merge toggle
        self.merge_var = tk.BooleanVar(value=False)
        self.merge_check = tk.Checkbutton(f, text=self._t('mergeIntoOnePackage'), variable=self.merge_var,
                                           bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                                           font=(self._font_name(), 10))
        self.merge_check.pack(anchor='w', pady=(4, 0))

        # 加密算法选择 (KJKv9 二进制 vs 旧版本文本可复制)
        alg_frame = tk.Frame(f, bg=c['bg'])
        alg_frame.pack(fill=tk.X, pady=(6, 0))
        tk.Label(alg_frame, text=self._t('encryptAlgorithm'), bg=c['bg'], fg=c['fg'],
                 font=(self._font_name(), 10)).pack(side=tk.LEFT, padx=(0, 8))
        self.encrypt_alg_var = tk.StringVar(value=self._t('algKjk9'))
        self.encrypt_alg = ttk.Combobox(alg_frame, state='readonly', textvariable=self.encrypt_alg_var,
                                        values=[self._t('algKjk9'), self._t('algText')], width=30,
                                        font=(self._font_name(), 10))
        self.encrypt_alg.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Password + action buttons
        action_frame = tk.Frame(f, bg=c['bg'])
        action_frame.pack(fill=tk.X, pady=(8, 4))
        self.encrypt_btn = tk.Button(action_frame, text=self._t('btnEncrypt'),
                                      bg=c['accent'], fg='white', relief=tk.FLAT,
                                      padx=16, pady=5, cursor='hand2', font=(self._font_name(), 11, 'bold'),
                                      command=self._do_encrypt)
        self.encrypt_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.download_btn = tk.Button(action_frame, text=self._t('btnDownloadKjk'),
                                       bg=c['secondary'], fg=c['fg'], relief=tk.FLAT,
                                       padx=14, pady=8, cursor='hand2', font=(self._font_name(), 10),
                                       command=self._download_kjk)
        self.download_btn.pack(side=tk.LEFT, padx=(0, 8))

        # Progress
        self.encrypt_progress_frame = tk.Frame(f, bg=c['bg'])
        self.encrypt_progress_frame.pack(fill=tk.X, pady=4)
        self.encrypt_pb_label = tk.Label(self.encrypt_progress_frame, text='',
                                          bg=c['bg'], fg=c['text_secondary'], font=(self._font_name(), 9))
        self.encrypt_pb_label.pack(anchor='w')
        self.encrypt_pb = ttk.Progressbar(self.encrypt_progress_frame, length=100,
                                          mode='determinate', maximum=100)
        self.encrypt_pb.pack(fill=tk.X)

        # Result area (只读, 不可复制)
        result_card = tk.Frame(f, bg=c['card'], relief=tk.FLAT, bd=1,
                                highlightthickness=1, highlightbackground=c['border'])
        result_card.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        self.encrypt_result_text = scrolledtext.ScrolledText(
            result_card, font=(self._font_name(), 9),
            bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=0,
            highlightthickness=0, wrap=tk.WORD, state='disabled',
            cursor='arrow', takefocus=0)
        self.encrypt_result_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _build_decrypt_tab(self):
        c = self._c()
        f = self.decrypt_frame

        # 选择文件按钮(新版本解密文件在独立浏览窗口展示)
        decrypt_btn_frame = tk.Frame(f, bg=c['bg'])
        decrypt_btn_frame.pack(fill=tk.X, pady=(8, 4))
        self.add_kjk_btn = tk.Button(decrypt_btn_frame, text=self._t('selectKjkFile'),
                                      bg=c['accent'], fg='white', relief=tk.FLAT,
                                      padx=12, pady=4, cursor='hand2', font=(self._font_name(), 10),
                                      command=self._open_file_for_decrypt)
        self.add_kjk_btn.pack(side=tk.LEFT, padx=(0, 8))

        # 粘贴框(向下兼容旧文本格式密文)
        self.decrypt_paste_label = tk.Label(f, text=self._t('orPasteCipher'), bg=c['bg'], fg=c['fg'],
                                             font=('', 11), anchor='w')
        self.decrypt_paste_label.pack(fill=tk.X, pady=(8, 4))
        self.decrypt_text = scrolledtext.ScrolledText(
            f, height=4, font=(self._font_name(), 9),
            bg=c['card'], fg=c['fg'], insertbackground=c['fg'],
            relief=tk.FLAT, bd=1, highlightthickness=1,
            highlightbackground=c['border'], highlightcolor=c['accent'])
        self.decrypt_text.pack(fill=tk.X, pady=(0, 8))

        # Password
        pwd_frame = tk.Frame(f, bg=c['bg'])
        pwd_frame.pack(fill=tk.X, pady=(0, 8))
        tk.Label(pwd_frame, text=self._t('password'), bg=c['bg'], fg=c['fg'],
                 font=(self._font_name(), 10)).pack(side=tk.LEFT, padx=(0, 8))
        self.decrypt_password = tk.Entry(pwd_frame, show='\u2022', font=(self._font_name(), 10),
                                          bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=1,
                                          highlightthickness=1, highlightbackground=c['border'])
        self.decrypt_password.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.decrypt_btn = tk.Button(f, text=self._t('btnDecrypt'),
                                      bg=c['accent'], fg='white', relief=tk.FLAT,
                                      padx=16, pady=5, cursor='hand2', font=(self._font_name(), 11, 'bold'),
                                      command=self._do_decrypt)
        self.decrypt_btn.pack(pady=4)

        self.decrypt_progress_frame = tk.Frame(f, bg=c['bg'])
        self.decrypt_progress_frame.pack(fill=tk.X, pady=4)
        self.decrypt_pb_label = tk.Label(self.decrypt_progress_frame, text='',
                                          bg=c['bg'], fg=c['text_secondary'], font=(self._font_name(), 9))
        self.decrypt_pb_label.pack(anchor='w')
        self.decrypt_pb = ttk.Progressbar(self.decrypt_progress_frame, length=100,
                                          mode='determinate', maximum=100)
        self.decrypt_pb.pack(fill=tk.X)

        # 文字结果(可复制)
        result_card = tk.Frame(f, bg=c['card'], relief=tk.FLAT, bd=1,
                                highlightthickness=1, highlightbackground=c['border'])
        result_card.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        self.decrypt_result_text = scrolledtext.ScrolledText(
            result_card, font=(self._font_name(), 9),
            bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=0,
            highlightthickness=0, wrap=tk.WORD)
        self.decrypt_result_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

    def _build_package_tab(self):
        c = self._c()
        f = self.package_frame

        # 选择文件按钮(打开后跳转独立浏览窗口)
        toolbar = tk.Frame(f, bg=c['bg'])
        toolbar.pack(fill=tk.X, pady=(8, 4))
        self.pkg_open_btn = tk.Button(toolbar, text=self._t('selectKjkFile'), bg=c['accent'], fg='white',
                                       relief=tk.FLAT, padx=12, pady=4, cursor='hand2',
                                       font=(self._font_name(), 10), command=self._open_package_manager)
        self.pkg_open_btn.pack(side=tk.LEFT, padx=(0, 6))

        # 粘贴框(向下兼容: 文件路径或旧格式密文)
        self.pkg_paste_label = tk.Label(f, text=self._t('pkgPasteHint'), bg=c['bg'], fg=c['fg'],
                                         font=('', 11), anchor='w')
        self.pkg_paste_label.pack(fill=tk.X, pady=(8, 4))
        self.pkg_paste_text = scrolledtext.ScrolledText(
            f, height=4, font=(self._font_name(), 9),
            bg=c['card'], fg=c['fg'], insertbackground=c['fg'],
            relief=tk.FLAT, bd=1, highlightthickness=1,
            highlightbackground=c['border'], highlightcolor=c['accent'])
        self.pkg_paste_text.pack(fill=tk.X, pady=(0, 8))

        self.pkg_open_paste_btn = tk.Button(f, text=self._t('btnOpen'),
                                             bg=c['accent'], fg='white', relief=tk.FLAT,
                                             padx=16, pady=5, cursor='hand2',
                                             font=(self._font_name(), 11, 'bold'),
                                             command=self._pkg_open_paste)
        self.pkg_open_paste_btn.pack(pady=4)

        # 文字结果(可复制)
        pkg_result_card = tk.Frame(f, bg=c['card'], relief=tk.FLAT, bd=1,
                                    highlightthickness=1, highlightbackground=c['border'])
        pkg_result_card.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        self.pkg_result_text = scrolledtext.ScrolledText(
            pkg_result_card, font=(self._font_name(), 9),
            bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=0,
            highlightthickness=0, wrap=tk.WORD)
        self.pkg_result_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # 状态标签
        self.pkg_status_label = tk.Label(f, text=self._t('treeNoSelection'), bg=c['bg'], fg=c['text_secondary'],
                                          font=(self._font_name(), 10), anchor='w')
        self.pkg_status_label.pack(fill=tk.X, pady=(4, 0))

    # ======================== Theme ========================
    def _c(self):
        return self.colors[self.config.get('theme', 'light')]

    def _apply_theme(self):
        c = self._c()
        self.root.configure(bg=c['bg'])
        for widget in [self.main_frame, self.encrypt_frame, self.decrypt_frame,
                       self.package_frame, self.update_bar]:
            try:
                widget.configure(bg=c['bg'])
            except Exception:
                pass
        try:
            self.header_bar.configure(bg=c['card'], highlightbackground=c['border'])
            self.header_title.configure(bg=c['card'], fg=c['fg'])
            self.header_sub.configure(bg=c['card'], fg=c['text_secondary'])
        except Exception:
            pass
        try:
            style = ttk.Style()
            style.configure('TNotebook', background=c['bg'], borderwidth=0)
            style.configure('TNotebook.Tab', background=c['secondary'], foreground=c['fg'],
                            padding=(18, 8), font=(self._font_name(), 10))
            style.map('TNotebook.Tab',
                      background=[('selected', c['card']), ('active', c['hover'])],
                      foreground=[('selected', c['accent'])])
        except Exception:
            pass
        self._update_decrypt_results()
        self._update_pkg_result()

    def _toggle_theme(self):
        self.config['theme'] = 'dark' if self.config.get('theme') == 'light' else 'light'
        self._apply_theme()
        save_config(self.config)

    # ======================== Events ========================
    def _bind_events(self):
        self.root.bind('<Control-Return>', lambda e: self._do_encrypt()
                       if self.notebook.index('current') == 0 else self._do_decrypt())

    # ======================== File Dialogs ========================
    def _open_files_for_encrypt(self):
        files = filedialog.askopenfiles(title=self._t('dialogTitleSelectEncrypt'), parent=self.root)
        if files:
            for f in files:
                self.encrypt_files.append(f)
            self._update_encrypt_file_list()

    def _open_folder_for_encrypt(self):
        folder = filedialog.askdirectory(title=self._t('dialogTitleSelectFolder'), parent=self.root)
        if folder:
            self.encrypt_folders.append(folder)
            self._update_encrypt_file_list()

    def _open_file_for_decrypt(self):
        files = filedialog.askopenfiles(
            title=self._t('dialogTitleSelectKjk'), parent=self.root,
            filetypes=[(self._t('fileTypeKjk'), '*.kjk'), (self._t('fileTypeAll'), '*.*')])
        if files:
            for f in files:
                if f.name.lower().endswith('.kjk'):
                    self._process_decrypt_file(f)

    def _open_package_manager(self):
        """打开 .kjk 包管理器"""
        filepath = filedialog.askopenfilename(
            title=self._t('dialogTitleSelectKjk'), parent=self.root,
            filetypes=[(self._t('fileTypeKjk'), '*.kjk'), (self._t('fileTypeAll'), '*.*')])
        if not filepath:
            return
        self._load_package(filepath)

    def _launch_browse(self, filepath):
        """在独立进程打开 KJKv9 包(密码→目录树浏览窗口), 不阻塞主窗口。"""
        try:
            import context_menu
            import subprocess
            exe = context_menu.get_exe_path()
            if exe.lower().endswith('.exe'):
                cmd = [exe, '--browse', filepath]
            else:
                cmd = [sys.executable, exe, '--browse', filepath]
            subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                             if hasattr(subprocess, 'CREATE_NEW_PROCESS_GROUP') else 0,
                             close_fds=True)
        except Exception as e:
            messagebox.showerror(self._t('msgTitleError'), str(e))

    def _load_package(self, filepath):
        import kjk9
        if kjk9.is_kjk9(filepath):
            self._launch_browse(filepath)
            return
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            messagebox.showerror(self._t('msgTitleError'), self._t('msgReadFileFail').format(str(e)))
            return
        self._current_package_path = filepath
        self._load_old_package_content(content, os.path.basename(filepath))

    def _load_old_package_content(self, content, source_name):
        """解析并解密旧文本格式(KJKv5/v7)内容, 结果写入文字结果区。"""
        try:
            results = unpack_kjk(content)
        except Exception as e:
            messagebox.showerror(self._t('msgTitleParseFail'),
                                 self._t('msgParseFileFail').format(source_name, str(e)))
            return

        has_pwd, salt_hex, hash_hex, actual_files = detect_password_header(results)
        if not has_pwd:
            needs_pwd_old = any(r.get('_needs_password') for r in results)
            if needs_pwd_old:
                has_pwd = True
                actual_files = results

        password = ''
        is_v7 = bool(salt_hex) or all(r.get('_kjkv7') for r in actual_files)
        self._current_pkg_format = 'KJKv7' if is_v7 else 'KJKv5'
        if has_pwd:
            pwd = simpledialog.askstring(
                self._t('dialogTitlePackageManager'),
                self._t('pkgPasswordPrompt'),
                parent=self.root, show='\u2022')
            if not pwd:
                return
            password = pwd
            if salt_hex and hash_hex:
                if not verify_password(password, salt_hex, hash_hex):
                    messagebox.showerror(self._t('msgTitleError'), self._t('msgPasswordRequired'))
                    return
            salt_bytes = bytes.fromhex(salt_hex) if salt_hex else None
            for r in actual_files:
                if r.get('_needs_password') or (password and password.strip()):
                    try:
                        r['data'] = re_decrypt(r, password, salt_bytes, legacy=not is_v7)
                        r['_needs_password'] = False
                    except Exception:
                        pass
            self._last_salt_hex = salt_hex
            self._last_is_v7 = is_v7

        self._current_package_content = content
        self._current_package_password = password
        self.decrypt_results = actual_files
        self._update_decrypt_results()
        self._update_pkg_result()
        self.set_status(self._t('statusDecryptedFile').format(source_name))

    # ======================== Encrypt file list ========================
    def _update_encrypt_file_list(self):
        self.encrypt_file_listbox.delete(0, tk.END)
        for f in self.encrypt_files:
            name = os.path.basename(f.name)
            size = os.path.getsize(f.name)
            self.encrypt_file_listbox.insert(tk.END, f'{self._icon_for_ext(name)} {name} ({self._format_size(size)})')
        for folder in self.encrypt_folders:
            name = os.path.basename(folder.rstrip(os.sep))
            self.encrypt_file_listbox.insert(tk.END, f'📁 {name}/')
        cnt = len(self.encrypt_files) + len(self.encrypt_folders)
        if cnt > 0:
            self.encrypt_file_count.config(text=self._t('filesCount').format(cnt))
        else:
            self.encrypt_file_count.config(text=self._t('noFilesSelected'))

    @staticmethod
    def _format_size(num_bytes):
        return _format_size(num_bytes)

    @staticmethod
    def _icon_for_ext(name):
        ext = os.path.splitext(name)[1].lower().lstrip('.')
        if ext in ('txt', 'log', 'md', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'yaml', 'yml', 'toml', 'ini', 'cfg', 'conf'):
            return '📄'
        if ext in ('jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp'):
            return '🖼'
        if ext in ('svg',):
            return '🖼'
        if ext in ('mp4', 'mov', 'avi', 'mkv', 'webm', 'flv'):
            return '🎬'
        if ext in ('mp3', 'wav', 'flac', 'ogg', 'aac'):
            return '🎵'
        if ext in ('zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'kjk'):
            return '📦'
        if ext == 'pdf':
            return '📋'
        if ext in ('exe', 'dll', 'msi', 'app'):
            return '⚙'
        return '📎'

    # ======================== Encrypt ========================
    def _do_encrypt(self):
        text = self.encrypt_text.get('1.0', tk.END).strip()

        password = simpledialog.askstring(
            self._t('encryptPasswordPopup'),
            self._t('encryptPasswordHint'),
            parent=self.root, show='\u2022')
        if password is None:
            return
        has_pwd = bool(password)

        if not text and not self.encrypt_files and not self.encrypt_folders:
            messagebox.showwarning(self._t('msgTitleHint'), self._t('msgInputRequired'))
            return

        self.encrypt_btn.config(state='disabled', text='⏳ ' + self._t('progressEncrypting'))
        self.encrypt_pb['value'] = 0
        self.encrypt_pb_label.config(text=self._t('progressPreparing'))

        is_text_only = bool(text) and not self.encrypt_files and not self.encrypt_folders
        # 加密算法: KJKv9 为二进制, 只能保存 .kjk 文件; 旧版本文本才可输出可复制密文
        use_kjk9 = self.encrypt_alg_var.get() == self._t('algKjk9')
        self._text_temp_path = None

        # KJKv9(二进制)或文件/文件夹: 必须先选保存位置; 仅旧算法纯文本走内存可复制
        save_path = None
        if (not is_text_only) or use_kjk9:
            save_path = filedialog.asksaveasfilename(
                title=self._t('dialogTitleSaveKjk'),
                defaultextension='.kjk',
                filetypes=[(self._t('fileTypeKjk'), '*.kjk'), (self._t('fileTypeAll'), '*.*')],
                parent=self.root)
            if not save_path:
                self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt'))
                return

        def _encrypt_worker():
            _set_worker_thread_priority()

            # 旧版本文本 + 纯文本: 内存加密, 输出可复制密文
            if is_text_only and not use_kjk9:
                try:
                    def on_progress(p):
                        self.root.after(0, lambda: self._update_encrypt_progress(p * 100, self._t('statusEncrypting').format(1, 1)))

                    output = encrypt(text.encode('utf-8'), password, callback=on_progress)
                    self.encrypt_result = {'content': output, 'type': 'text'}
                    self.root.after(0, self._on_encrypt_done_text, output)
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror(self._t('msgTitleEncryptFail'), str(e)))
                    self.root.after(0, lambda: self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt')))
                return

            # 构建路径列表；文本输入转成临时文件一起打包
            paths = []
            for f in self.encrypt_files:
                paths.append(f.name)
            for folder in self.encrypt_folders:
                paths.append(folder)
            if text:
                fd, tmp_path = tempfile.mkstemp(suffix='.txt', prefix='kjk_text_')
                with os.fdopen(fd, 'wb') as fp:
                    fp.write(text.encode('utf-8'))
                paths.append(tmp_path)
                self._text_temp_path = tmp_path

            file_count = len(self.encrypt_files) + len(self.encrypt_folders) + (1 if text else 0)

            def on_progress(current, total):
                pct = (current / max(total, 1)) * 100
                self.root.after(0, lambda: self._update_encrypt_progress(pct, self._t('progressEncrypting')))

            def on_kjk9_progress(frac, label=''):
                self.root.after(0, lambda: self._update_encrypt_progress(frac * 100, label or self._t('progressEncrypting')))

            try:
                if use_kjk9:
                    # KJKv9 二进制: 强制写入 .kjk 文件, 不输出文本密文
                    import kjk9
                    kjk9.encrypt_paths_to_kjk9(paths, save_path, password, progress=on_kjk9_progress)
                    self.encrypt_result = {'path': save_path, 'type': 'kjk9',
                                           'files': [{'size': 0} for _ in range(file_count)]}
                    self.root.after(0, self._on_encrypt_done_file, save_path, file_count)
                    return

                # 旧版本文本: 文件/文件夹打包为文本 .kjk
                fn_file = _OPTIONAL_ENGINE.get('pack_kjk_with_paths_to_file')
                fn_mem = _OPTIONAL_ENGINE.get('pack_kjk_with_paths')
                if fn_file is None and fn_mem is None:
                    self.root.after(0, lambda: _missing_engine_msgbox('pack_kjk_with_paths', parent=self.root))
                    self.root.after(0, lambda: self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt')))
                    return

                if fn_file is not None and save_path:
                    # 流式直写: 大包不进内存
                    fn_file(paths, save_path, password, progress_callback=on_progress)
                    self.encrypt_result = {'path': save_path, 'type': 'kjk',
                                           'files': [{'size': 0} for _ in range(file_count)]}
                    self.root.after(0, self._on_encrypt_done_file, save_path, file_count)
                else:
                    kjk_content = fn_mem(paths, password, progress_callback=on_progress)
                    self.encrypt_result = {'content': kjk_content, 'type': 'kjk',
                                           'files': [{'size': 0} for _ in range(file_count)]}
                    self.root.after(0, self._on_encrypt_done, self.encrypt_result['files'])
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(self._t('msgTitleEncryptFail'), str(e)))
                self.root.after(0, lambda: self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt')))
            finally:
                tmp = getattr(self, '_text_temp_path', None)
                if tmp and os.path.exists(tmp):
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass

        threading.Thread(target=_encrypt_worker, daemon=True).start()

    def _update_encrypt_progress(self, value, label=''):
        now = time.time()
        if not hasattr(self, '_last_encrypt_progress_time'):
            self._last_encrypt_progress_time = 0
        if now - self._last_encrypt_progress_time < 0.05 and value < 100:
            return
        self._last_encrypt_progress_time = now
        self.encrypt_pb['value'] = value
        self.encrypt_pb_label.config(text=label or f'{int(value)}%')

    def _set_encrypt_result(self, text):
        self.encrypt_result_text.config(state='normal')
        self.encrypt_result_text.delete('1.0', tk.END)
        self.encrypt_result_text.insert('1.0', text)
        self.encrypt_result_text.config(state='disabled')
        self.encrypt_result_text.see('1.0')

    def _on_encrypt_done(self, file_data):
        self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt'))
        self.encrypt_pb['value'] = 100
        self.encrypt_pb_label.config(text=self._t('progressComplete'))
        self._set_encrypt_result(self.encrypt_result['content'][:1000])
        self.set_status(self._t('statusEncryptComplete').format(len(file_data)))

    def _on_encrypt_done_text(self, output):
        self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt'))
        self.encrypt_pb['value'] = 100
        self.encrypt_pb_label.config(text=self._t('progressComplete'))
        self._set_encrypt_result(output[:1000])
        self.set_status(self._t('statusEncryptComplete').format(1))

    def _on_encrypt_done_file(self, path, file_count):
        """流式打包完成: .kjk 已直接写入磁盘。KJKv9 为二进制, 只显示保存提示。"""
        self.encrypt_btn.config(state='normal', text=self._t('btnEncrypt'))
        self.encrypt_pb['value'] = 100
        self.encrypt_pb_label.config(text=self._t('progressComplete'))
        is_kjk9 = bool(self.encrypt_result) and self.encrypt_result.get('type') == 'kjk9'
        if is_kjk9:
            self._set_encrypt_result(self._t('msgKjk9Saved').format(os.path.basename(path), path))
        else:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    head = f.read(1000)
                self._set_encrypt_result(head)
            except OSError:
                self._set_encrypt_result(path)
        self.set_status(self._t('statusSaved').format(os.path.basename(path)))

    def _download_kjk(self):
        if not self.encrypt_result:
            return
        if self.encrypt_result.get('path'):
            # 流式打包: 加密时已直接保存到该文件
            messagebox.showinfo(self._t('msgTitleSuccess'),
                                self._t('dlgExtractedOk').format(count=0, path=self.encrypt_result['path']))
            self.set_status(self._t('statusSaved').format(
                os.path.basename(self.encrypt_result['path'])))
            return
        result_type = self.encrypt_result.get('type', 'kjk')
        ext = '.txt' if result_type == 'text' else '.kjk'
        fname = filedialog.asksaveasfilename(
            title=self._t('dialogTitleSaveKjk'),
            defaultextension=ext,
            filetypes=[(self._t('fileTypeKjk'), '*.kjk'), (self._t('fileTypeAll'), '*.*')],
            parent=self.root)
        if fname:
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(self.encrypt_result['content'])
            self.set_status(self._t('statusSaved').format(os.path.basename(fname)))

    def _clear_encrypt(self):
        self.encrypt_text.delete('1.0', tk.END)
        self.encrypt_files = []
        self.encrypt_folders = []
        self.encrypt_result = None
        self._set_encrypt_result('')
        self.encrypt_file_listbox.delete(0, tk.END)
        self.encrypt_file_count.config(text=self._t('noFilesSelected'))
        self.encrypt_pb['value'] = 0
        self.encrypt_pb_label.config(text='')
        self.set_status(self._t('statusCleared'))

    # ======================== Decrypt ========================
    def _make_extract_progress_dialog(self):
        """创建解压进度对话框, 返回 (win, pb, info)。"""
        c = self._c()
        win = tk.Toplevel(self.root)
        win.title(self._t('dlgExtractTitle'))
        win.configure(bg=c['bg'])
        win.transient(self.root)
        win.resizable(False, False)
        lbl = tk.Label(win, text=self._t('dlgExtracting'), bg=c['bg'], fg=c['fg'],
                       font=(self._font_name(), 11))
        lbl.pack(padx=24, pady=(16, 8))
        pb = ttk.Progressbar(win, length=360, mode='determinate')
        pb.pack(padx=24, pady=(0, 6))
        info = tk.Label(win, text='0%', bg=c['bg'], fg=c['text_secondary'],
                        font=(self._font_name(), 9))
        info.pack(padx=24, pady=(0, 16))
        win.update_idletasks()
        try:
            x = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_reqwidth()) // 2
            y = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_reqheight()) // 2
            win.geometry(f'+{x}+{y}')
        except Exception:
            pass
        return win, pb, info

    def _open_decrypt_file_direct(self, filepath):
        """直接打开 .kjk 文件(双击/关联): 全程异步。
        免询问直接解压到 .kjk 旁的同名子文件夹, 完成后从磁盘延迟加载目录树。"""
        import kjk9
        if kjk9.is_kjk9(filepath):
            self._launch_browse(filepath)
            return
        decrypt_to_dir = _OPTIONAL_ENGINE['decrypt_kjk_to_dir']
        base_name = os.path.splitext(os.path.basename(filepath))[0] or 'extracted'
        target_dir = os.path.join(os.path.dirname(filepath) or '.', base_name)

        if decrypt_to_dir is None:
            self.notebook.select(self.decrypt_frame)
            self.set_status(self._t('progressParsing'))
            self._do_decrypt()
            return

        win, pb, info = self._make_extract_progress_dialog()
        self.notebook.select(self.decrypt_frame)

        state = {'content': None, 'has_pwd': False, 'salt': None, 'hash': None,
                 'password': '', 'error': None, 'count': 0}

        def _set_phase(text, indeterminate=False):
            try:
                pb.configure(mode='indeterminate' if indeterminate else 'determinate')
                if indeterminate:
                    pb.start(12)
                else:
                    pb.stop()
                    pb['value'] = 0
                info.config(text=text)
            except Exception:
                pass

        def _close_dialog():
            try:
                pb.stop()
                win.destroy()
            except Exception:
                pass

        def _stage1_read():
            _set_worker_thread_priority()
            try:
                with open(filepath, 'r', encoding='utf-8') as fp:
                    content = fp.read()
                state['content'] = content
                has_pwd, salt_bytes, hash_hex, _ = detect_password_prefix(content)
                if not has_pwd:
                    try:
                        results = unpack_kjk(content)
                        hp, sh, hh, _ = detect_password_header(results)
                        has_pwd, salt_bytes, hash_hex = hp, (bytes.fromhex(sh) if sh else None), hh
                    except Exception:
                        pass
                state.update(has_pwd=has_pwd, salt=salt_bytes, hash=hash_hex)
            except Exception as e:
                state['error'] = e
            self.root.after(0, _stage2_password)

        def _stage2_password():
            if state['error']:
                _close_dialog()
                messagebox.showerror(self._t('msgTitleError'),
                                     self._t('msgReadFileFail').format(state['error']))
                return
            if state['has_pwd']:
                password = simpledialog.askstring(
                    self._t('dlgExtractTitle'), self._t('dlgExtractPrompt'),
                    parent=self.root, show='\u2022')
                if password is None:
                    _close_dialog()
                    return
                password = password.strip()
                try:
                    if state['salt'] and state['hash']:
                        if not verify_password(password, state['salt'].hex(), state['hash']):
                            _close_dialog()
                            messagebox.showerror(self._t('dlgExtractTitle'), self._t('msgWrongPwd'))
                            return
                except Exception:
                    pass
                state['password'] = password
            _set_phase(self._t('directExtractingTo').format(target_dir))
            threading.Thread(target=_stage3_extract, daemon=True).start()

        def _stage3_extract():
            try:
                count = decrypt_to_dir(state['content'], target_dir, state['password'],
                                       progress_callback=lambda cur, total: self.root.after(
                                           0, lambda cu=cur, tt=total: _on_progress(cu, tt)))
                state['count'] = count
            except Exception as e:
                state['error'] = e
            self.root.after(0, _stage4_done)

        def _on_progress(cur, total):
            try:
                pct = int(cur / total * 100) if total else 100
                pb['value'] = pct
                info.config(text=f'{cur}/{total}  ({pct}%)')
            except Exception:
                pass

        def _stage4_done():
            _close_dialog()
            if state['error']:
                messagebox.showerror(self._t('dlgExtractTitle'),
                                     self._t('msgParseCipherFail').format(state['error']))
                return
            if state['count'] <= 0:
                messagebox.showinfo(self._t('dlgExtractTitle'), self._t('dlgNoFiles'))
                return
            # 从磁盘延迟加载目录树(不把内容塞进 Text, 不再全量解密到内存)
            self._current_package_path = filepath
            self._current_package_content = state['content']
            self.decrypt_password.delete(0, tk.END)
            if state['password']:
                self.decrypt_password.insert(0, state['password'])
            self._load_results_from_dir(target_dir)
            self.set_status(self._t('statusExtractedTo').format(
                count=state['count'], path=target_dir))
            try:
                os.startfile(target_dir)
            except Exception:
                pass

        _set_phase(self._t('directReadingFile'), indeterminate=True)
        threading.Thread(target=_stage1_read, daemon=True).start()

    def _load_results_from_dir(self, folder):
        """从已解压的磁盘目录构建延迟加载的结果列表(点击预览/下载时才读文件)。"""
        results = []
        for root, dirs, files in os.walk(folder):
            dirs.sort()
            rel_root = os.path.relpath(root, folder).replace('\\', '/')
            if rel_root != '.':
                results.append({'originalName': rel_root + '/', 'name': rel_root,
                                'data': None, 'size': 0})
            for fn in sorted(files):
                full = os.path.join(root, fn)
                rel = f'{rel_root}/{fn}' if rel_root != '.' else fn
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                results.append({'originalName': rel, 'name': rel,
                                'data': None, 'size': size, '_disk_path': full})
        self.decrypt_results = results
        self._update_decrypt_results()

    def _process_decrypt_file(self, f):
        # 任何 .kjk 包(含主程序加密区/旧版本生成的文本格式)统一进包管理器
        # (密码→目录树), 而不是扁平文字结果区。
        self._launch_browse(f.name)
        return

    def _after_decrypt_parse(self, results, source_name):
        """解析(工作线程)完成后的主线程续处理: 密码检测/校验 + 启动解密 worker。"""
        try:
            has_pwd, salt_hex, hash_hex, actual_files = detect_password_header(results)
            if not has_pwd:
                is_kjkv7_no_pwd = all(r.get('_kjkv7') for r in results)
                if not is_kjkv7_no_pwd:
                    needs_pwd_old = any(r.get('_needs_password') for r in results)
                    if needs_pwd_old:
                        has_pwd = True
                        actual_files = results

            password = self.decrypt_password.get().strip()
            if has_pwd and not password:
                password = simpledialog.askstring(
                    self._t('msgTitleInfo'),
                    self._t('msgEnterPasswordRetry'),
                    parent=self.root, show='\u2022')
                if not password:
                    self.decrypt_btn.config(state='normal', text=self._t('btnDecrypt'))
                    return
                self.decrypt_password.delete(0, tk.END)
                self.decrypt_password.insert(0, password)

            if has_pwd:
                if salt_hex and hash_hex:
                    if not verify_password(password, salt_hex, hash_hex):
                        messagebox.showerror(self._t('msgTitleDecryptFail'), self._t('msgPasswordRequired'))
                        self.decrypt_btn.config(state='normal', text=self._t('btnDecrypt'))
                        return

            self._run_decrypt_worker(actual_files, password, salt_hex, source_name)
        except Exception as e:
            messagebox.showerror(self._t('msgTitleParseFail'),
                                 self._t('msgParseFileFail').format(source_name, e))
            self.decrypt_btn.config(state='normal', text=self._t('btnDecrypt'))

    def _do_decrypt(self):
        text = self.decrypt_text.get('1.0', tk.END).strip()
        if not text:
            messagebox.showwarning(self._t('msgTitleHint'), self._t('msgUploadRequired'))
            return
        self._do_decrypt_text(text)

    def _do_decrypt_text(self, text):
        self.decrypt_results = []
        self._update_decrypt_results()
        self.decrypt_btn.config(state='disabled', text='⏳ ' + self._t('progressParsing'))
        self.decrypt_pb['value'] = 0
        self.decrypt_pb_label.config(text=self._t('progressParsing'))

        def _parse_worker():
            _set_worker_thread_priority()
            try:
                results = unpack_kjk(text)
                self.root.after(0, self._after_decrypt_parse, results, 'clipboard')
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    self._t('msgTitleParseFail'), self._t('msgParseCipherFail').format(e)))
                self.root.after(0, lambda: self.decrypt_btn.config(
                    state='normal', text=self._t('btnDecrypt')))

        threading.Thread(target=_parse_worker, daemon=True).start()

    def _run_decrypt_worker(self, actual_files, password, salt_hex, source_name):
        self.decrypt_btn.config(state='disabled', text='⏳ ' + self._t('progressDecrypting'))
        self.decrypt_pb['value'] = 0
        self.decrypt_pb_label.config(text=self._t('progressParsing'))
        self.notebook.select(self.decrypt_frame)

        def _decrypt_worker():
            _set_worker_thread_priority()
            try:
                salt_bytes = bytes.fromhex(salt_hex) if salt_hex else None
                is_kjkv7 = all(r.get('_kjkv7') for r in actual_files) if actual_files else False
                is_v7 = bool(salt_hex) or is_kjkv7
                self._current_pkg_format = 'KJKv7' if is_v7 else 'KJKv5'
                total = len(actual_files)
                last_ui_update = 0
                UI_UPDATE_INTERVAL = 0.1

                def schedule_progress(value, label):
                    nonlocal last_ui_update
                    now = time.time()
                    if now - last_ui_update >= UI_UPDATE_INTERVAL:
                        self.root.after(0, lambda v=value, l=label: self._update_decrypt_progress(v, l))
                        last_ui_update = now

                for idx, r in enumerate(actual_files):
                    display_name = r.get('enc_name', f'file_{idx}')
                    progress = (idx / total) * 100
                    schedule_progress(progress, f'⏳ ({idx+1}/{total}) {display_name}')

                    needs_decrypt = r.get('_needs_password') or ('data' not in r) or bool(password and password.strip())
                    if needs_decrypt:
                        try:
                            r['data'] = re_decrypt(r, password, salt_bytes, legacy=not is_v7)
                            r['_needs_password'] = False
                        except Exception:
                            try:
                                r['data'] = re_decrypt(r, password, salt_bytes, legacy=is_v7)
                                r['_needs_password'] = False
                            except Exception:
                                pass
                    fname = r.get('originalName', r.get('name', f'file_{idx}'))
                    schedule_progress(100, f'✅ ({idx+1}/{total}) {fname}')

                self._last_salt_hex = salt_hex
                self._last_is_v7 = is_v7
                self.root.after(0, self._on_decrypt_done, actual_files)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror(
                    self._t('msgTitleDecryptFail'), self._t('msgParseCipherFail').format(e)))
                self.root.after(0, lambda: self.decrypt_btn.config(
                    state='normal', text=self._t('btnDecrypt')))

        threading.Thread(target=_decrypt_worker, daemon=True).start()

    def _update_decrypt_progress(self, value, label=''):
        now = time.time()
        if not hasattr(self, '_last_decrypt_progress_time'):
            self._last_decrypt_progress_time = 0
        if now - self._last_decrypt_progress_time < 0.05 and value < 100:
            return
        self._last_decrypt_progress_time = now
        self.decrypt_pb['value'] = value
        self.decrypt_pb_label.config(text=label or f'{int(value)}%')

    def _on_decrypt_done(self, results):
        self.decrypt_btn.config(state='normal', text=self._t('btnDecrypt'))
        self.decrypt_pb['value'] = 100
        self.decrypt_pb_label.config(text=self._t('progressComplete'))
        self.decrypt_results = results
        self._update_decrypt_results()
        status = self._t('statusDecryptComplete').format(len(results))
        if self._current_pkg_format:
            status += f' · {self._current_pkg_format}'
        self.set_status(status)

    def _retry_password(self):
        password = simpledialog.askstring(
            self._t('msgTitleInfo'),
            self._t('msgEnterPasswordRetry'),
            parent=self.root, show='\u2022')
        if not password:
            return
        try:
            salt_hex = getattr(self, '_last_salt_hex', None)
            is_v7 = getattr(self, '_last_is_v7', False)
            salt_bytes = bytes.fromhex(salt_hex) if salt_hex else None
            for item in self.decrypt_results:
                if item.get('_needs_password') and item.get('_ciphertext'):
                    try:
                        item['data'] = re_decrypt(item, password, salt_bytes, legacy=not is_v7)
                        item['_needs_password'] = False
                    except Exception:
                        try:
                            item['data'] = re_decrypt(item, password, salt_bytes, legacy=is_v7)
                            item['_needs_password'] = False
                        except Exception:
                            pass
                    item['_password_used'] = password
            self._update_decrypt_results()
            self._update_pkg_result()
            self.set_status(self._t('statusPasswordRetry'))
        except Exception:
            messagebox.showerror(self._t('msgTitleDecryptFail'), self._t('msgPasswordRequired'))

    # ======================== Results (Text) ========================
    def _update_decrypt_results(self):
        self._render_results_text(self.decrypt_result_text, self.decrypt_results)

    def _update_pkg_result(self):
        self._render_results_text(self.pkg_result_text, self.decrypt_results)

    def _render_results_text(self, widget, results):
        widget.delete('1.0', tk.END)
        if not results:
            widget.insert('1.0', self._t('noDecryptResults'))
            widget.see('1.0')
            return
        # 单个纯文本条目: 仅输出文本本身, 不带 '── 名称 (大小) ──' 包络
        entries = [it for it in results
                   if not it.get('_is_password_header') and not it.get('_is_password_prefix_header')]
        if len(entries) == 1:
            data = entries[0].get('data')
            if data is not None:
                try:
                    plain = data.decode('utf-8')
                except (UnicodeDecodeError, AttributeError):
                    plain = None
                if plain is not None:
                    widget.insert('1.0', plain)
                    widget.see('1.0')
                    return
        blocks = []
        for item in entries:
            name = item.get('originalName', item.get('name', self._t('unknownFile')))
            data = item.get('data')
            size = len(data) if data is not None else item.get('size', 0)
            blocks.append('── {} ({}) ──'.format(name, self._format_size(size)))
            if data is not None:
                try:
                    text = data.decode('utf-8')
                except (UnicodeDecodeError, AttributeError):
                    text = self._t('binaryContent')
                blocks.append(text)
            else:
                blocks.append(self._t('passwordBadge'))
            blocks.append('')
        widget.insert('1.0', '\n'.join(blocks))
        widget.see('1.0')

    def _pkg_open_paste(self):
        """包管理器粘贴框: 支持 .kjk 文件路径或旧格式密文(向下兼容)。"""
        text = self.pkg_paste_text.get('1.0', tk.END).strip()
        if not text:
            messagebox.showwarning(self._t('msgTitleHint'), self._t('msgUploadRequired'))
            return
        candidate = text.strip('"')
        if os.path.isfile(candidate) and candidate.lower().endswith('.kjk'):
            self._load_package(candidate)
            return
        self._load_old_package_content(text, 'clipboard')



    # ======================== Settings ========================
    def _open_settings(self):
        win = tk.Toplevel(self.root)
        win.title(self._t('settingsTitle'))
        win.geometry('460x600')
        win.resizable(True, True)
        c = self._c()
        win.configure(bg=c['bg'])
        win.transient(self.root)
        win.grab_set()

        frame = tk.Frame(win, bg=c['bg'], padx=20, pady=16)
        frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(frame, text=self._t('settingsLanguage'), bg=c['bg'], fg=c['fg'],
                 font=('', 12, 'bold')).pack(anchor='w', pady=(0, 4))
        lang_var = tk.StringVar(value=self.config.get('lang', 'en'))
        lang_frame = tk.Frame(frame, bg=c['bg'])
        lang_frame.pack(fill=tk.X, pady=4)
        tk.Radiobutton(lang_frame, text=self._t('settingsLangEn'), variable=lang_var, value='en',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        command=lambda: self._change_language(lang_var.get())).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(lang_frame, text=self._t('settingsLangZhHK'), variable=lang_var, value='zh-HK',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        command=lambda: self._change_language(lang_var.get())).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(lang_frame, text=self._t('settingsLangZhCN'), variable=lang_var, value='zh-CN',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        command=lambda: self._change_language(lang_var.get())).pack(side=tk.LEFT, padx=4)

        tk.Frame(frame, bg=c['border'], height=1).pack(fill=tk.X, pady=12)

        tk.Label(frame, text=self._t('settingsTheme'), bg=c['bg'], fg=c['fg'],
                 font=('', 12, 'bold')).pack(anchor='w', pady=(0, 4))
        current_theme = self.config.get('theme', 'light')
        if current_theme not in ['light', 'dark']:
            current_theme = 'light'
        theme_var = tk.StringVar(value=current_theme)
        theme_frame = tk.Frame(frame, bg=c['bg'])
        theme_frame.pack(fill=tk.X, pady=4)
        tk.Radiobutton(theme_frame, text=self._t('settingsThemeLight'), variable=theme_var, value='light',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        command=lambda: self._change_theme(theme_var.get())).pack(side=tk.LEFT, padx=4)
        tk.Radiobutton(theme_frame, text=self._t('settingsThemeDark'), variable=theme_var, value='dark',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        command=lambda: self._change_theme(theme_var.get())).pack(side=tk.LEFT, padx=4)

        tk.Frame(frame, bg=c['border'], height=1).pack(fill=tk.X, pady=12)

        tk.Label(frame, text=self._t('settingsApiService'), bg=c['bg'], fg=c['fg'],
                 font=('', 12, 'bold')).pack(anchor='w', pady=(0, 4))
        api_var = tk.BooleanVar(value=self.config.get('api_enabled', False))
        tk.Checkbutton(frame, text=self._t('settingsApiEnable'), variable=api_var,
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        font=('', 11)).pack(anchor='w', pady=4)

        port_frame = tk.Frame(frame, bg=c['bg'])
        port_frame.pack(fill=tk.X, pady=4)
        tk.Label(port_frame, text=self._t('settingsApiPort'), bg=c['bg'], fg=c['fg'],
                 font=('', 10)).pack(side=tk.LEFT, padx=(20, 8))
        port_entry = tk.Entry(port_frame, width=8, font=('', 10),
                               bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=1)
        port_entry.insert(0, str(self.config.get('api_port', 5000)))
        port_entry.pack(side=tk.LEFT)

        tk.Frame(frame, bg=c['border'], height=1).pack(fill=tk.X, pady=12)

        tk.Label(frame, text=self._t('settingsUpdateCheck'), bg=c['bg'], fg=c['fg'],
                 font=('', 12, 'bold')).pack(anchor='w', pady=(0, 4))
        update_var = tk.BooleanVar(value=self.config.get('check_update', True))
        tk.Checkbutton(frame, text=self._t('settingsUpdateEnable'), variable=update_var,
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card'],
                        font=('', 11)).pack(anchor='w', pady=4)

        server_frame = tk.Frame(frame, bg=c['bg'])
        server_frame.pack(fill=tk.X, pady=4)
        tk.Label(server_frame, text=self._t('settingsUpdateServer'), bg=c['bg'], fg=c['fg'],
                 font=('', 10)).pack(side=tk.LEFT, padx=(20, 8))
        server_entry = tk.Entry(server_frame, width=28, font=('', 10),
                                 bg=c['card'], fg=c['fg'], relief=tk.FLAT, bd=1)
        server_entry.insert(0, self.config.get('update_server', ''))
        server_entry.pack(side=tk.LEFT)

        tk.Frame(frame, bg=c['border'], height=1).pack(fill=tk.X, pady=12)

        # 格式兼容性
        tk.Label(frame, text=self._t('settingsFormatCompat'), bg=c['bg'], fg=c['fg'],
                 font=('', 12, 'bold')).pack(anchor='w', pady=(0, 4))
        fmt_var = tk.StringVar(value=self.config.get('compat_format', 'auto'))
        fmt_frame = tk.Frame(frame, bg=c['bg'])
        fmt_frame.pack(fill=tk.X, pady=4)
        tk.Radiobutton(fmt_frame, text=self._t('settingsFormatAuto'), variable=fmt_var, value='auto',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card']).pack(anchor='w', padx=4, pady=2)
        tk.Radiobutton(fmt_frame, text=self._t('settingsFormatV7'), variable=fmt_var, value='KJKv7',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card']).pack(anchor='w', padx=4, pady=2)
        tk.Radiobutton(fmt_frame, text=self._t('settingsFormatV5'), variable=fmt_var, value='KJKv5',
                        bg=c['bg'], fg=c['fg'], selectcolor=c['card']).pack(anchor='w', padx=4, pady=2)

        def _save_settings():
            try:
                self.config['api_enabled'] = api_var.get()
                try:
                    self.config['api_port'] = int(port_entry.get())
                except ValueError:
                    pass
                self.config['check_update'] = update_var.get()
                self.config['update_server'] = server_entry.get().strip()
                self.config['compat_format'] = fmt_var.get()
                save_config(self.config)
                if api_var.get():
                    self._toggle_api()
                else:
                    if self.api_url:
                        stop_server()
                        self.api_url = None
                        self.api_label.config(text='')
                self._update_decrypt_results()
                self._update_pkg_result()
                messagebox.showinfo(self._t('msgTitleInfo'), self._t('settingsSaved'), parent=win)
            except Exception as e:
                messagebox.showerror(self._t('msgTitleError'), str(e), parent=win)
            finally:
                win.destroy()

        tk.Button(frame, text=self._t('settingsSave'), bg=c['accent'], fg='white',
                   relief=tk.FLAT, padx=20, pady=6, cursor='hand2',
                   font=('', 11), command=_save_settings).pack(pady=16)

    def _change_theme(self, theme):
        self.config['theme'] = theme
        self._apply_theme()
        save_config(self.config)

    def _change_language(self, lang):
        old_lang = self.config.get('lang', 'en')
        self.config['lang'] = lang
        save_config(self.config)
        self._update_all_ui_text()
        if old_lang != lang:
            messagebox.showinfo(
                self._t('msgTitleInfo'),
                self._t('langChangedPrompt'),
                parent=self.root)

    def _update_all_ui_text(self):
        self.root.title(self._t('aboutAppName'))

        self.menubar.delete(0, 'end')
        self.menubar.add_cascade(label=self._t('menuFile'), menu=self.file_menu)
        self.menubar.add_cascade(label=self._t('menuSettings'), menu=self.setting_menu)
        self.menubar.add_cascade(label=self._t('menuHelp'), menu=self.help_menu)

        self.file_menu.entryconfigure(0, label=self._t('menuOpenEncrypt'))
        self.file_menu.entryconfigure(1, label=self._t('menuOpenDecrypt'))
        self.file_menu.entryconfigure(3, label=self._t('menuOpenPackage'))
        self.file_menu.entryconfigure(5, label=self._t('menuExit'))

        self.setting_menu.entryconfigure(0, label=self._t('menuSettingsItem'))
        self.setting_menu.entryconfigure(2, label=self._t('menuRegisterContext'))
        self.setting_menu.entryconfigure(3, label=self._t('menuUnregisterContext'))

        self.help_menu.entryconfigure(0, label=self._t('menuAbout'))
        self.help_menu.entryconfigure(2, label=self._t('menuPrivacy'))
        self.help_menu.entryconfigure(3, label=self._t('menuTerms'))
        self.help_menu.entryconfigure(4, label=self._t('menuDisclaimer'))
        self.help_menu.entryconfigure(5, label=self._t('menuApiDocs'))
        self.help_menu.entryconfigure(6, label=self._t('menuDownloadSource'))
        self.help_menu.entryconfigure(7, label=self._t('menuWebsite'))

        self.notebook.tab(0, text=self._t('tabEncrypt'))
        self.notebook.tab(1, text=self._t('tabDecrypt'))
        self.notebook.tab(2, text=self._t('tabPackageManager'))

        self.encrypt_text_label.config(text=self._t('textInput'))
        self.add_file_btn.config(text=self._t('selectFiles'))
        self.add_folder_btn.config(text=self._t('selectFolder'))
        self.clear_encrypt_btn_top.config(text=self._t('btnClear'))
        self.encrypt_btn.config(text=self._t('btnEncrypt'))
        self.download_btn.config(text=self._t('btnDownloadKjk'))
        self.merge_check.config(text=self._t('mergeIntoOnePackage'))

        self.add_kjk_btn.config(text=self._t('selectKjkFile'))
        self.decrypt_paste_label.config(text=self._t('orPasteCipher'))
        self.decrypt_btn.config(text=self._t('btnDecrypt'))

        self.pkg_open_btn.config(text=self._t('selectKjkFile'))
        self.pkg_paste_label.config(text=self._t('pkgPasteHint'))
        self.pkg_open_paste_btn.config(text=self._t('btnOpen'))

        self.status_bar.config(text=self._t('statusReady'))
        self.check_update_btn.config(text=self._t('checkUpdate'))

        cnt = len(self.encrypt_files) + len(self.encrypt_folders)
        self.encrypt_file_count.config(text=self._t('filesCount').format(cnt) if cnt else self._t('noFilesSelected'))
        self.pkg_status_label.config(text=self._t('treeNoSelection'))

        self.encrypt_pb_label.config(text='')
        self.decrypt_pb_label.config(text='')

        if self.api_url:
            self.api_label.config(text=f'API: {self.api_url}')

        self._update_decrypt_results()
        self._update_pkg_result()

    def _toggle_api(self):
        port = self.config.get('api_port', 5000)
        try:
            set_port(port)
            self.api_url = start_server(port)
            self.api_label.config(text=f'API: {self.api_url}')
        except Exception as e:
            messagebox.showerror(self._t('msgTitleApiError'), self._t('msgApiStartFail').format(e))

    # ======================== Context Menu ========================
    def _do_register_menu(self):
        try:
            import context_menu
        except ImportError as e:
            messagebox.showerror(self._t('msgTitleError'), f'context_menu module not found: {e}')
            return
        if not context_menu.is_admin():
            messagebox.showwarning(
                self._t('msgTitleError'),
                '需要管理员权限才能注册右键菜单。请以管理员身份重新运行本程序。')
            return
        try:
            ok, msg = context_menu.register_context_menu()
            if ok:
                messagebox.showinfo(self._t('msgTitleSuccess'), msg)
            else:
                messagebox.showerror(self._t('msgTitleError'), msg)
        except Exception as e:
            messagebox.showerror(self._t('msgTitleError'), str(e))

    def _do_unregister_menu(self):
        try:
            import context_menu
        except ImportError as e:
            messagebox.showerror(self._t('msgTitleError'), f'context_menu module not found: {e}')
            return
        if not context_menu.is_admin():
            messagebox.showwarning(
                self._t('msgTitleError'),
                '需要管理员权限才能卸载右键菜单。请以管理员身份重新运行本程序。')
            return
        try:
            ok, msg = context_menu.unregister_context_menu()
            if ok:
                messagebox.showinfo(self._t('msgTitleSuccess'), msg)
            else:
                messagebox.showerror(self._t('msgTitleError'), msg)
        except Exception as e:
            messagebox.showerror(self._t('msgTitleError'), str(e))

    # ======================== Update Checker ========================
    def _silent_check_update(self):
        if not self.config.get('check_update', True):
            return
        threading.Thread(target=self._silent_check_worker, daemon=True).start()

    def _silent_check_worker(self):
        data = self._kjk_version_request()
        if data is None:
            return
        needs_update = data.get('has_update', False)
        if needs_update:
            self.root.after(0, lambda d=data: self._show_update_dialog(d))

    def check_update(self):
        self.check_update_btn.config(state='disabled', text='⏳ ...')
        threading.Thread(target=self._check_update_worker, daemon=True).start()

    def _kjk_version_request(self):
        import json
        payload = json.dumps({
            'header': 'kjk_version',
            'version': CURRENT_VERSION
        }).encode('utf-8')
        custom_server = self.config.get('update_server', '').strip()
        if custom_server:
            urls = [custom_server]
        else:
            urls = [SERVER_URL_PRIMARY, SERVER_URL_BACKUP]
        for url in urls:
            try:
                req = urllib.request.Request(url, data=payload,
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': 'KJK-Encryptor/' + CURRENT_VERSION
                    })
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode('utf-8', 'replace'))
                    if isinstance(data, dict):
                        return data
            except Exception:
                continue
        return None

    def _check_update_worker(self):
        data = self._kjk_version_request()

        def enable():
            try:
                self.check_update_btn.config(state='normal', text=self._t('checkUpdate'))
            except Exception:
                pass

        self.root.after(0, enable)
        if data is None:
            self.root.after(0, lambda: messagebox.showerror(
                self._t('msgTitleError'), self._t('updateConnectFail')))
            return
        if data.get('has_update'):
            self.root.after(0, lambda d=data: self._show_update_dialog(d))
        else:
            self.root.after(0, lambda: messagebox.showinfo(
                self._t('msgTitleInfo'), self._t('latestVersion')))

    def _show_update_dialog(self, data):
        win = tk.Toplevel(self.root)
        win.title(self._t('updateAvailable'))
        win.geometry('440x360')
        win.resizable(False, False)
        c = self._c()
        win.configure(bg=c['bg'])
        win.transient(self.root)
        tk.Label(win, text=self._t('newVersion') + ': ' + str(data.get('latest_version', '?')),
                 bg=c['bg'], fg=c['fg'], font=('', 12, 'bold')).pack(pady=(12, 4))
        tk.Label(win, text=self._t('currentVersion') + ': ' + CURRENT_VERSION,
                 bg=c['bg'], fg=c['text_secondary']).pack()
        tk.Label(win, text=self._t('changelog') + ':', bg=c['bg'], fg=c['fg'],
                 anchor='w').pack(fill=tk.X, padx=16, pady=(16, 4))
        st = scrolledtext.ScrolledText(win, height=8, bg=c['card'], fg=c['fg'],
                                       relief=tk.FLAT, font=(self._font_name(), 9))
        st.pack(fill=tk.BOTH, expand=True, padx=16, pady=4)
        lang = self.config.get('lang', 'en')
        uc = data.get('update_content') or {}
        changelog = uc.get(lang) or uc.get('zh-CN') or uc.get('en') or data.get('changelog', '')
        st.insert(tk.END, changelog)
        st.config(state='disabled')
        btn_frame = tk.Frame(win, bg=c['bg'])
        btn_frame.pack(fill=tk.X, padx=16, pady=12)

        def open_url(url):
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                pass
            win.destroy()

        tk.Button(btn_frame, text=self._t('downloadPrimary'), bg=c['secondary'], fg=c['fg'],
                  relief=tk.FLAT, padx=10,
                  command=lambda: open_url(DOWNLOAD_URL_PRIMARY)).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text=self._t('downloadBackup'), bg=c['secondary'], fg=c['fg'],
                  relief=tk.FLAT, padx=10,
                  command=lambda: open_url(DOWNLOAD_URL_BACKUP)).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_frame, text=self._t('remindLater'), bg=c['accent'], fg='white',
                  relief=tk.FLAT, padx=10, command=win.destroy).pack(side=tk.RIGHT, padx=4)

    def _show_first_run_disclaimer(self):
        lang = self.config.get('lang', 'en')
        win = tk.Toplevel(self.root)
        win.title(self._t('disclaimerTitle'))
        win.geometry('620x520')
        c = self._c()
        win.configure(bg=c['bg'])
        win.transient(self.root)
        win.grab_set()
        tk.Label(win, text=self._t('disclaimerFirstRun'),
                 bg=c['bg'], fg=c['fg'], font=('', 12, 'bold')).pack(pady=10)
        st = scrolledtext.ScrolledText(win, bg=c['card'], fg=c['fg'],
                                       relief=tk.FLAT, font=(self._font_name(), 9))
        st.pack(fill=tk.BOTH, expand=True, padx=16, pady=8)
        st.insert(tk.END, DISCLAIMER_TEXT.get(lang, DISCLAIMER_TEXT['en']))
        st.config(state='disabled')

        def accept():
            self.config['disclaimer_shown'] = True
            save_config(self.config)
            win.destroy()

        def decline():
            self.root.destroy()

        btn_frame = tk.Frame(win, bg=c['bg'])
        btn_frame.pack(fill=tk.X, padx=16, pady=12)
        tk.Button(btn_frame, text=self._t('btnClose'), bg=c['secondary'], fg=c['fg'],
                  relief=tk.FLAT, padx=16, command=decline).pack(side=tk.RIGHT, padx=4)
        tk.Button(btn_frame, text=self._t('disclaimerAccept'), bg=c['accent'], fg='white',
                  relief=tk.FLAT, padx=16, command=accept).pack(side=tk.RIGHT, padx=4)

    def _show_about(self):
        messagebox.showinfo(
            self._t('aboutTitle'),
            f"{self._t('aboutAppName')}\n"
            f"{self._t('aboutVersion').format(CURRENT_VERSION)}\n"
            f"{self._t('aboutPoweredBy')}")

    def _open_privacy_policy(self):
        self._show_text_dialog(self._t('menuPrivacy'), PRIVACY_TEXT)

    def _open_terms_of_service(self):
        self._show_text_dialog(self._t('menuTerms'), TERMS_TEXT)

    def _show_disclaimer(self):
        self._show_text_dialog(self._t('menuDisclaimer'), DISCLAIMER_TEXT)

    def _show_text_dialog(self, title, text_dict):
        lang = self.config.get('lang', 'en')
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry('620x520')
        c = self._c()
        win.configure(bg=c['bg'])
        win.transient(self.root)
        st = scrolledtext.ScrolledText(win, bg=c['card'], fg=c['fg'],
                                       relief=tk.FLAT, font=(self._font_name(), 9))
        st.pack(fill=tk.BOTH, expand=True, padx=16, pady=16)
        st.insert(tk.END, text_dict.get(lang, text_dict['en']))
        st.config(state='disabled')
        tk.Button(win, text=self._t('btnClose'), bg=c['secondary'], fg=c['fg'],
                  relief=tk.FLAT, padx=20, pady=4, command=win.destroy).pack(pady=8)

    def _open_api_docs(self):
        try:
            import webbrowser
            webbrowser.open(SERVER_URL_PRIMARY + 'api/docs')
        except Exception:
            pass

    def _open_official_website(self):
        try:
            import webbrowser
            webbrowser.open(SERVER_URL_PRIMARY)
        except Exception:
            pass

    def _download_source_code(self):
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'source.zip')
        if os.path.exists(src):
            dest = filedialog.asksaveasfilename(
                title=self._t('menuDownloadSource'),
                defaultextension='.zip',
                filetypes=[('ZIP', '*.zip'), (self._t('fileTypeAll'), '*.*')],
                parent=self.root)
            if dest:
                try:
                    import shutil
                    shutil.copy2(src, dest)
                    messagebox.showinfo(self._t('msgTitleSuccess'),
                                        self._t('msgSourceSaved').format(path=dest))
                except Exception as e:
                    messagebox.showerror(self._t('msgTitleError'), str(e))
        else:
            messagebox.showwarning(self._t('msgTitleInfo'), self._t('msgSourceNotFound'))

    def _process_batch_paths(self):
        if not self._batch_paths:
            return
        actions = {}
        raw_paths = []
        for payload in self._batch_paths:
            if '|' in payload:
                action, path = payload.split('|', 1)
            else:
                action, path = 'encrypt_here', payload
            path = path.strip('"')
            if os.path.exists(path):
                actions.setdefault(action, []).append(path)
            raw_paths.append(path)
        self._batch_paths = []
        for action, paths in actions.items():
            if action in ('encrypt_here', 'encrypt_to', 'pack_to'):
                self._batch_encrypt_package(paths, action)
            elif action in ('decrypt_here', 'decrypt_to'):
                self._batch_decrypt_package(paths, action)
            elif action == 'add_to_kjk':
                self._batch_add_to_kjk(paths)
            elif action == 'open':
                for p in paths:
                    self._open_decrypt_file_direct(p)
        if not actions:
            # 兼容旧版：没有 action_id 时直接加入加密列表
            added = False
            for p in raw_paths:
                if os.path.isdir(p):
                    self.encrypt_folders.append(p)
                    added = True
                elif os.path.isfile(p):
                    self.encrypt_files.append(type('_FileObj', (), {'name': p})())
                    added = True
            if added:
                self.notebook.select(self.encrypt_frame)
                self._update_encrypt_file_list()
                self.root.title(self._t('batchEncryptTitle') + ' - ' + self._t('aboutAppName'))

    def _batch_encrypt_package(self, paths, action_id):
        """右键批量加密：多个文件/文件夹可合并为一个 .kjk,也可分别加密。"""
        if not paths:
            return
        password = simpledialog.askstring(
            self._t('encryptPasswordPopup'),
            self._t('encryptPasswordHint'),
            parent=self.root, show='\u2022')
        if password is None:
            return

        merge = True
        if len(paths) > 1:
            merge = messagebox.askyesno(
                self._t('batchMergeConfirmTitle'),
                self._t('batchMergeConfirmMsg').format(len(paths)),
                parent=self.root)

        if merge:
            if action_id == 'encrypt_here':
                parent = os.path.dirname(paths[0]) or os.getcwd()
                base = os.path.basename(paths[0].rstrip(os.sep))
                out_path = os.path.join(parent, (base or 'Archive') + '.kjk')
            else:
                out_path = filedialog.asksaveasfilename(
                    title=self._t('savePackage'),
                    defaultextension='.kjk',
                    filetypes=[(self._t('fileTypeKjk'), '*.kjk'), (self._t('fileTypeAll'), '*.*')],
                    parent=self.root)
            if not out_path:
                return
            self._run_encrypt_worker(paths, out_path, password, len(paths))
            return

        # 分别加密：每个路径生成自己的 .kjk
        target_dir = None
        if action_id in ('encrypt_to', 'pack_to'):
            target_dir = filedialog.askdirectory(title=self._t('batchSeparateTargetTitle'), parent=self.root)
            if not target_dir:
                return

        out_infos = []
        for p in paths:
            if target_dir:
                base = os.path.basename(p.rstrip(os.sep))
                out_infos.append((p, os.path.join(target_dir, base + '.kjk')))
            else:
                if os.path.isfile(p):
                    out_infos.append((p, p + '.kjk'))
                else:
                    parent = os.path.dirname(p) or os.getcwd()
                    base = os.path.basename(p.rstrip(os.sep))
                    out_infos.append((p, os.path.join(parent, base + '.kjk')))

        self._run_encrypt_separate_worker(out_infos, password)

    def _run_encrypt_worker(self, paths, out_path, password, count):
        """单个后台任务：将 paths 合并写入 out_path。"""
        # 切换到加密标签页,显示进度
        self.notebook.select(self.encrypt_frame)
        self.encrypt_pb['value'] = 0
        self.encrypt_pb_label.config(text='0%')
        try:
            self.encrypt_btn.config(state='disabled')
        except Exception:
            pass
        self.set_status(self._t('progressPreparing'))

        def worker():
            try:
                import context_menu
                if context_menu._kjk9_enabled():
                    self._run_kjk9_encrypt_worker(paths, out_path, password, count)
                    return
                fn = _OPTIONAL_ENGINE.get('pack_kjk_with_paths_to_file')
                if fn is None:
                    fn2 = _OPTIONAL_ENGINE.get('pack_kjk_with_paths')
                    if fn2 is None:
                        raise RuntimeError('engine 缺少 pack_kjk_with_paths')
                    content = fn2(paths, password,
                                  progress_callback=lambda cur, tot: self.root.after(0, lambda: self._update_encrypt_progress((cur / max(tot, 1)) * 100)))
                    with open(out_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                else:
                    fn(paths, out_path, password,
                       progress_callback=lambda cur, tot: self.root.after(0, lambda: self._update_encrypt_progress((cur / max(tot, 1)) * 100)))
                self.root.after(0, lambda: self._on_batch_encrypt_done(out_path, count))
            except Exception as e:
                self.root.after(0, lambda err=str(e): messagebox.showerror(self._t('msgTitleError'), err))
                self.root.after(0, lambda: self._reset_encrypt_ui())

        threading.Thread(target=worker, daemon=True).start()

    def _run_kjk9_encrypt_worker(self, paths, out_path, password, count):
        """KJKv9 加密(worker 线程内调用 C 引擎, 主窗口进度条刷新, 不阻塞 UI)。"""
        import kjk9
        try:
            params = kjk9.plan_params()

            def prog(frac, text=''):
                self.root.after(0, lambda f=float(frac or 0.0): self._update_encrypt_progress(min(100.0, f * 100)))

            kjk9.encrypt_paths_to_kjk9(paths, out_path, password, params=params, progress=prog)
            self.root.after(0, lambda: self._on_batch_encrypt_done(out_path, count))
        except Exception as e:
            import context_menu
            context_menu._try_cleanup_partial(out_path)
            self.root.after(0, lambda err=str(e): messagebox.showerror(self._t('msgTitleError'), err))
            self.root.after(0, lambda: self._reset_encrypt_ui())

    def _reset_encrypt_ui(self):
        """重置加密 UI 状态。"""
        try:
            self.encrypt_btn.config(state='normal')
        except Exception:
            pass
        self.encrypt_pb['value'] = 0
        self.encrypt_pb_label.config(text='')
        self.set_status(self._t('statusReady'))

    def _run_encrypt_separate_worker(self, out_infos, password):
        """单个后台任务：将每个路径分别加密为独立 .kjk。"""
        self.notebook.select(self.encrypt_frame)
        self.encrypt_pb['value'] = 0
        self.encrypt_pb_label.config(text='0%')
        try:
            self.encrypt_btn.config(state='disabled')
        except Exception:
            pass
        self.set_status(self._t('progressPreparing'))

        def worker():
            try:
                import context_menu
                if context_menu._kjk9_enabled():
                    self._run_kjk9_encrypt_separate_worker(out_infos, password)
                    return
                fn = _OPTIONAL_ENGINE.get('pack_kjk_with_paths_to_file')
                if fn is None:
                    fn = _OPTIONAL_ENGINE.get('pack_kjk_with_paths')
                if fn is None:
                    raise RuntimeError('engine 缺少 pack_kjk_with_paths')
                total = len(out_infos)
                completed = []
                for i, (src, out_path) in enumerate(out_infos):
                    if hasattr(fn, '__name__') and fn.__name__ == 'pack_kjk_with_paths_to_file':
                        fn([src], out_path, password,
                           progress_callback=lambda cur, tot: self.root.after(0, lambda: self._update_encrypt_progress((cur / max(tot, 1)) * 100)))
                    else:
                        content = fn([src], password)
                        with open(out_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                    completed.append(out_path)
                    pct = ((i + 1) / total) * 100
                    self.root.after(0, lambda p=pct: self._update_encrypt_progress(p))
                self.root.after(0, lambda: self._on_batch_encrypt_done(completed[-1] if completed else '', len(completed)))
            except Exception as e:
                self.root.after(0, lambda err=str(e): messagebox.showerror(self._t('msgTitleError'), err))
                self.root.after(0, lambda: self._reset_encrypt_ui())

        threading.Thread(target=worker, daemon=True).start()

    def _run_kjk9_encrypt_separate_worker(self, out_infos, password):
        """KJKv9 分别加密: 每个路径独立 .kjk, 主窗口进度条刷新。"""
        import kjk9
        try:
            params = kjk9.plan_params()
            total = len(out_infos)
            completed = []

            def prog(frac, text=''):
                self.root.after(0, lambda f=float(frac or 0.0): self._update_encrypt_progress(min(100.0, f * 100)))

            for i, (src, out_path) in enumerate(out_infos):
                kjk9.encrypt_paths_to_kjk9([src], out_path, password, params=params, progress=prog)
                completed.append(out_path)
                pct = ((i + 1) / total) * 100
                self.root.after(0, lambda p=pct: self._update_encrypt_progress(p))
            self.root.after(0, lambda: self._on_batch_encrypt_done(completed[-1] if completed else '', len(completed)))
        except Exception as e:
            import context_menu
            for _, out_path in out_infos:
                context_menu._try_cleanup_partial(out_path)
            self.root.after(0, lambda err=str(e): messagebox.showerror(self._t('msgTitleError'), err))
            self.root.after(0, lambda: self._reset_encrypt_ui())

    def _on_batch_encrypt_done(self, out_path, count):
        self.encrypt_pb['value'] = 100
        self.encrypt_pb_label.config(text='100%')
        self.set_status(self._t('statusEncryptDone').format(count, out_path))
        try:
            self.encrypt_btn.config(state='normal')
        except Exception:
            pass
        if messagebox.askyesno(self._t('msgTitleSuccess'), self._t('openPackageManagerAfterEncrypt')):
            self._load_package(out_path)

    def _batch_decrypt_package(self, paths, action_id):
        """右键批量解密：多个 .kjk 解密到同一目录或各自目录。"""
        kjk_paths = [p for p in paths if p.lower().endswith('.kjk')]
        if not kjk_paths:
            messagebox.showwarning(self._t('msgTitleInfo'), self._t('selectKjkFiles'))
            return
        password = simpledialog.askstring(
            self._t('decryptPassword'),
            self._t('decryptPasswordHint'),
            parent=self.root, show='\u2022')
        if password is None:
            return

        if action_id == 'decrypt_here':
            out_dirs = {p: os.path.dirname(p) or os.getcwd() for p in kjk_paths}
        else:
            folder = filedialog.askdirectory(title=self._t('selectOutputPath'), parent=self.root)
            if not folder:
                return
            out_dirs = {p: folder for p in kjk_paths}

        self.set_status(self._t('statusDecrypting'))

        import kjk9
        v9_paths = [p for p in kjk_paths if kjk9.is_kjk9(p)]
        legacy_paths = [p for p in kjk_paths if not kjk9.is_kjk9(p)]

        def worker():
            total_count = 0
            try:
                # KJKv9: 多线程 C 引擎按需解密, 主窗口进度条刷新
                for p in v9_paths:
                    def prog(frac, text=''):
                        self.root.after(0, lambda f=float(frac or 0.0): self._update_decrypt_progress(min(100.0, f * 100)))
                    try:
                        pkg = kjk9.KJK9Package.open(p, password)
                        total_count += pkg.extract_files(out_dirs[p], progress=prog)
                    except kjk9.KJK9AuthError:
                        self.root.after(0, lambda err=os.path.basename(p): messagebox.showerror(
                            self._t('msgTitleError'), self._t('wrongPassword') + f': {err}'))
                        continue
                # 旧版文本格式: 流式解密(逐行读盘+逐条目落盘, 不再整文件入内存)
                for p in legacy_paths:
                    salt_bytes = None
                    try:
                        salt_bytes, _ = peek_detect_password_prefix(p)
                    except Exception:
                        salt_bytes = None
                    def prog(frac):
                        self.root.after(0, lambda f=float(frac or 0.0):
                                        self._update_decrypt_progress(min(100.0, f * 100)))
                    try:
                        total_count += extract_legacy_package_file(
                            p, password, salt_bytes, out_dirs[p], callback=prog)
                    except Exception as e:
                        self.root.after(0, lambda err=e, nm=os.path.basename(p): messagebox.showerror(
                            self._t('msgTitleError'), self._t('msgParseFileFail').format(nm, err)))
                        continue
                self.root.after(0, lambda: messagebox.showinfo(self._t('msgTitleSuccess'),
                                                                self._t('decryptDone').format(count=total_count)))
                self.root.after(0, lambda: self.set_status(self._t('statusDecryptDone').format(count=total_count)))
            except Exception as e:
                self.root.after(0, lambda err=e: messagebox.showerror(self._t('msgTitleError'), str(err)))

        threading.Thread(target=worker, daemon=True).start()

    def _batch_add_to_kjk(self, paths):
        """右键「添加到此 KJK 包」：第一个 .kjk 作为目标，其余作为追加内容。"""
        kjk_paths = [p for p in paths if p.lower().endswith('.kjk')]
        file_paths = [p for p in paths if not p.lower().endswith('.kjk')]
        if not kjk_paths:
            messagebox.showwarning(self._t('msgTitleInfo'), self._t('selectKjkTarget'))
            return
        target = kjk_paths[0]
        if not file_paths:
            self._load_package(target)
            return
        import kjk9
        if kjk9.is_kjk9(target):
            self._run_kjk9_add_to_package(target, file_paths)
            return
        try:
            with open(target, 'r', encoding='utf-8') as f:
                kjk_content = f.read()
            has_pwd, salt_bytes, hash_hex, remaining = detect_password_prefix(kjk_content)
            password = ''
            if has_pwd:
                password = simpledialog.askstring(
                    self._t('decryptPassword'),
                    self._t('decryptPasswordHint'),
                    parent=self.root, show='\u2022') or ''
                if not verify_password(password, salt_bytes.hex(), hash_hex):
                    messagebox.showerror(self._t('msgTitleError'), self._t('wrongPassword'))
                    return
            salt = salt_bytes
            new_entries = []
            for p in file_paths:
                with open(p, 'rb') as f:
                    data = f.read()
                basename = os.path.basename(p)
                name, ext = os.path.splitext(basename)
                ext = ext.lstrip('.')
                enc_name = encrypt_filename(name, ext, password, salt)
                new_entries.append({
                    'enc_name': enc_name,
                    'ciphertext': encrypt_raw(data, password, salt),
                    'size': len(data),
                })
            kjk_content = append_to_kjk(kjk_content, new_entries)
            with open(target, 'w', encoding='utf-8') as f:
                f.write(kjk_content)
            self._load_package(target)
            messagebox.showinfo(self._t('msgTitleSuccess'), self._t('pkgAddedSuccess'))
        except Exception as e:
            messagebox.showerror(self._t('msgTitleError'), str(e))

    def _run_kjk9_add_to_package(self, target, file_paths):
        """KJKv9 追加: worker 线程内增量追加(不重写已有数据), 主窗口进度条刷新。"""
        password = simpledialog.askstring(
            self._t('decryptPassword'),
            self._t('decryptPasswordHint'),
            parent=self.root, show='\u2022')
        if password is None:
            return
        self.notebook.select(self.encrypt_frame)
        self.encrypt_pb['value'] = 0
        self.encrypt_pb_label.config(text='0%')
        self.set_status(self._t('progressPreparing'))

        def worker():
            import kjk9
            try:
                pkg = kjk9.KJK9Package.open(target, password)
                total = len(file_paths)

                def prog(frac, text=''):
                    self.root.after(0, lambda f=float(frac or 0.0): self._update_encrypt_progress(min(100.0, f * 100)))

                for i, p in enumerate(file_paths):
                    rel = os.path.basename(p.rstrip(os.sep))
                    pkg.stage_add(p, rel)
                    prog(0.1 + 0.4 * (i + 1) / max(total, 1), f'{rel} ({i + 1}/{total})')
                pkg.save(progress=prog)
                self.root.after(0, lambda: self._on_batch_encrypt_done(target, total))
            except kjk9.KJK9AuthError:
                self.root.after(0, lambda: messagebox.showerror(self._t('msgTitleError'), self._t('wrongPassword')))
                self.root.after(0, lambda: self._reset_encrypt_ui())
            except Exception as e:
                self.root.after(0, lambda err=str(e): messagebox.showerror(self._t('msgTitleError'), err))
                self.root.after(0, lambda: self._reset_encrypt_ui())

        threading.Thread(target=worker, daemon=True).start()

    def _process_collected_batch(self):
        """从队列收集完所有路径后一次性处理。"""
        qp = _get_batch_queue_path()
        lines = []
        try:
            if os.path.exists(qp):
                with open(qp, 'r', encoding='utf-8') as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
                try:
                    os.remove(qp)
                except Exception:
                    pass
        except Exception:
            pass
        if lines:
            self._batch_paths = lines
            self._process_batch_paths()

    def _start_batch_queue_poller(self):
        def poll():
            qp = _get_batch_queue_path()
            try:
                if os.path.exists(qp):
                    with open(qp, 'r', encoding='utf-8') as f:
                        lines = [ln.strip() for ln in f if ln.strip()]
                    if lines:
                        try:
                            os.remove(qp)
                        except Exception:
                            pass
                        self._batch_paths.extend(lines)
                        self._process_batch_paths()
            except Exception:
                pass
            self.root.after(500, poll)

        self.root.after(500, poll)

    def _on_close(self):
        try:
            if self.api_url:
                stop_server()
        except Exception:
            pass
        try:
            self.config['geometry'] = self.root.geometry()
            save_config(self.config)
        except Exception:
            pass
        self.root.destroy()


def _get_app_lock_path():
    return os.path.join(tempfile.gettempdir(), 'KJK_Encrypter_v1_0_3.lock')


def _get_batch_queue_path():
    return os.path.join(tempfile.gettempdir(), 'KJK_Encrypter_v1_0_3.queue')


def _try_send_to_running_instance(paths):
    qp = _get_batch_queue_path()
    try:
        with open(qp, 'a', encoding='utf-8') as f:
            for p in paths:
                f.write(p + '\n')
        return True
    except Exception:
        return False


def _handle_batch_standalone(batch_items):
    """独立批处理模式: 使用轻量对话框处理,不打开完整 GUI。
    
    batch_items: list of "action|path"
    """
    try:
        # 将 action|path 解析为 (action, path)
        parsed = []
        for item in batch_items:
            if '|' in item:
                action, path = item.split('|', 1)
                parsed.append((action, path.strip()))
            else:
                # 默认当作 encrypt_here
                parsed.append(('encrypt_here', item.strip()))
        
        # 导入 context_menu 中的工具函数
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import context_menu
        
        # 解析: 区分批量加密/解密/添加
        actions = {}
        for action, path in parsed:
            actions.setdefault(action, []).append(path)
        
        # 多文件合并为单个kjk -> 提示合并
        if len(actions) > 1:
            # 不同操作类型无法合并,直接打开完整GUI
            return False

        # 已识别动作的处理器集合。对已识别的动作即使执行出错也"已处理",
        # 绝不回退到完整主界面(否则表现为右键点击跳主界面而无法正常使用)。
        def _dispatch(items, fn):
            handled = 0
            failed = 0
            for p in items:
                try:
                    fn(p)
                    handled += 1
                except Exception as e:  # noqa: BLE001
                    failed += 1
                    print(f'_handle_batch_standalone dispatch error: {e}')
                    try:
                        import tkinter as tk
                        from tkinter import messagebox
                        r = tk.Tk()
                        r.withdraw()
                        messagebox.showerror(context_menu._t('error'), str(e))
                        r.destroy()
                    except Exception:
                        pass
            return handled + failed > 0

        # 单一操作类型,使用轻量处理
        if 'encrypt_here' in actions:
            paths = actions['encrypt_here']
            if len(paths) > 1:
                # 多文件: 弹出合并询问
                ret = context_menu._ask_merge_dialog(len(paths))
                if ret is None:
                    return True  # 用户取消
                if ret:
                    # 合并为一个包
                    out_path = context_menu._ask_save_kjk_path()
                    if not out_path:
                        return True
                    context_menu._batch_encrypt_merge(paths, out_path)
                else:
                    # 每个单独加密
                    _dispatch(paths, context_menu._encrypt_here)
            else:
                # 单个文件/文件夹
                _dispatch(paths, context_menu._encrypt_here)
            return True

        elif 'encrypt_to' in actions:
            _dispatch(actions['encrypt_to'], context_menu._encrypt_to)
            return True

        elif 'pack_to' in actions:
            _dispatch(actions['pack_to'], context_menu._pack_to)
            return True

        elif 'decrypt_here' in actions:
            paths = [p for p in actions['decrypt_here'] if p.lower().endswith('.kjk')]
            _dispatch(paths, context_menu._decrypt_here)
            return True

        elif 'decrypt_to' in actions:
            _dispatch(actions['decrypt_to'], context_menu._decrypt_to)
            return True

        elif 'add_to_kjk' in actions:
            _dispatch(actions['add_to_kjk'], context_menu._add_to_kjk)
            return True

        # 未知操作 -> 回退到完整GUI
        return False

    except Exception as e:
        # 解析/入参层面出错才回退到完整GUI; 已识别动作的失败在上方各自兜底
        print(f'_handle_batch_standalone error: {e}')
        return False


def _show_menu_notice(verb):
    """右键菜单动作已发起但无法/无需执行: 以小提示框告知用户后干净退出。

    绝不回退打开完整主界面(否则表现为"点菜单只打开主程序")。"""
    import context_menu as _cm
    msg = _cm._t('menu_no_target')
    try:
        import tkinter as tk
        from tkinter import messagebox
        r = tk.Tk()
        r.withdraw()
        messagebox.showinfo('KJK Encryptor', msg)
        r.destroy()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--batch-encrypt', nargs='*', default=None)
    parser.add_argument('--batch-decrypt', nargs='*', default=None)
    parser.add_argument('--batch-add', nargs='*', default=None)
    parser.add_argument('--verb', default=None,
                        help='右键菜单子动作: encrypt_here/encrypt_to/pack_to/decrypt_here/decrypt_to/add_to_kjk')
    parser.add_argument('--browse', metavar='PATH', default=None,
                        help='浏览 KJK 包(双击 .kjk 文件): 密码窗口→目录树, 不显示主窗口')
    parser.add_argument('--register-menu', help='Register context menu (admin only)', action='store_true')
    parser.add_argument('--unregister-menu', help='Unregister context menu (admin only)', action='store_true')
    parser.add_argument('paths', nargs='*', help='旧版右键菜单/命令行直接传入的路径(默认当作加密)')
    args = parser.parse_args()

    # 双击 .kjk 文件 → 独立浏览窗口(密码→目录树), 不进主程序也不受单实例锁限制
    if args.browse:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import browse
        browse.run_browse(args.browse)
        sys.exit(0)

    batch_paths = args.batch_encrypt or args.batch_decrypt or args.batch_add or []

    # 新右键菜单(--verb + %*)传入的是裸路径,组装成 "verb|path" 格式(队列文件也是该格式)
    if args.verb and batch_paths and not any('|' in p for p in batch_paths):
        batch_paths = [f'{args.verb}|{p}' for p in batch_paths]
    
    # 处理 --register-menu / --unregister-menu (注册表操作)
    if args.register_menu or args.unregister_menu:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        if script_dir not in sys.path:
            sys.path.insert(0, script_dir)
        import context_menu
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        if args.register_menu:
            ok, msg = context_menu.register_context_menu()
            messagebox.showinfo('KJK Encryptor', msg)
        else:
            ok, msg = context_menu.unregister_context_menu()
            messagebox.showinfo('KJK Encryptor', msg)
        root.destroy()
        sys.exit(0)
    
    # 兼容旧版注册表命令(没有 --batch-* 参数):将位置参数视为 encrypt_here 批量任务
    if not batch_paths and args.paths:
        batch_paths = [f'encrypt_here|{p}' for p in args.paths]
    
    # 尝试独立批处理(轻量模式,不打开完整GUI)
    if batch_paths:
        if _handle_batch_standalone(batch_paths):
            sys.exit(0)
        # 有目标但批处理回退(异常/多动作/未知动作): 菜单动作已发起, 不打开完整主界面
        if args.verb:
            _show_menu_notice(args.verb)
            sys.exit(0)

    # 右键菜单(--verb)被显式调用却未获得任何目标路径
    # (例如在文件夹空白处右击且未选中项目,%* 展开为空):
    # 视为已处理——提示后退出, 绝不回退打开完整主界面
    # (否则表现为"点菜单只打开主程序"而"无法正常使用")。
    if args.verb:
        _show_menu_notice(args.verb)
        sys.exit(0)

    lock_path = _get_app_lock_path()
    acquired = False
    lock_file = None
    try:
        lock_file = open(lock_path, 'a+', encoding='utf-8')
        try:
            import msvcrt
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            acquired = True
        except Exception:
            acquired = False
    except Exception:
        pass
    if not acquired:
        if batch_paths:
            if _try_send_to_running_instance(batch_paths):
                sys.exit(0)
        sys.exit(0)
    app = KJKApp(batch_paths=batch_paths)
    app.root.mainloop()
    try:
        if lock_file:
            lock_file.close()
        if os.path.exists(lock_path):
            os.remove(lock_path)
    except Exception:
        pass


if __name__ == '__main__':
    main()

