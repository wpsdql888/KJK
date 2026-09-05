# KJK Encryptor — 更新日志 (Changelog)

所有值得注意的改动都会记录在此文件。遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 规范，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。
本文件以 **上一正式版 v1.0.3** 为基线，列出 v1.0.4 相对 v1.0.3 的净差异；并追加 **v1.1.0 相对 v1.0.4** 的新增 / 修改 / 修复。

## 格式说明

- `[+]` = 新增 · `[~]` = 修改/重构 · `[x]` = 移除 · `[*]` = 修复

---

## [v1.1.0] - 2026-09-05

### 新增 (Added)

#### 桌面版主程序 (`main.py`) — 加密算法可选
- `[+]` 加密页新增**加密算法下拉选择**：`KJKv9（二进制 .kjk 文件）` / `旧版本文本（可复制密文）`。
- `[+]` 新增 i18n 键：`encryptAlgorithm`、`algKjk9`、`algText`、`msgKjk9Saved`（三语）。
- `[+]` 选择 KJKv9 时走 `kjk9.encrypt_paths_to_kjk9()` 强制写盘为 `.kjk`；结果区仅提示"已保存到…"，不复制二进制。

#### 网页版 (`index.html`) — 加密算法可选
- `[+]` 加密页顶部新增加密算法下拉 `<select id="encryptAlgSelect">`，可选 `KJKv9` / `legacy`。
- `[+]` 新增 JS 状态 `encryptAlg` + `setEncryptAlg()` / `loadEncryptAlg()`（选择持久化到 `localStorage`）、`setEncryptCopyVisible()`（KJKv9 隐藏复制按钮）。
- `[+]` 新增 i18n 键：`encryptAlgorithm`、`algKjk9`、`algLegacy`、`kjk9Done`（三语）。

### 修改 (Changed)

#### 桌面版 (`main.py`)
- `[~]` `_encrypt()` / `_encrypt_worker()`：以 `use_kjk9 = encrypt_alg_var.get() == algKjk9` 分支 —— KJKv9 强制选保存位置并写盘、旧算法纯文本走内存 `encrypt()` 输出可复制密文、旧算法文件仍用 `pack_kjk_with_paths[_to_file]`。
- `[~]` `_on_encrypt_done_file()`：KJKv9 时结果区只显示 `msgKjk9Saved`（保存路径提示），不再尝试当文本读取。

#### 网页版 (`index.html`)
- `[~]` `doEncrypt()`：以 `encryptAlg === 'KJKv9'` 驱动 `useV9`（取代旧的 `formatCompat` 分支）；纯文本并入任务列表，KJKv9 打包为单个 `.kjk`、旧算法输出可复制密文；结果渲染改为：KJKv9 → 显示 `kjk9Done` 提示 + **自动触发下载** + 隐藏复制按钮；旧算法 → 显示密文（前 300 字）+ 显示复制按钮。

### 修复 (Fixes)

- `[*]` **网页版旧算法加密较大文件报 substring 错误**：`compressCiphertext()` 原用 `btoa(String.fromCharCode(...compressed))`，数据稍大（约 60KB+ 不可压缩数据）即超出参数上限触发 `RangeError`；`doEncrypt` 中 KJKv9 结果又去读不存在的 `encryptResultData.content`，二次触发 `Cannot read properties of undefined (reading 'substring')`。改为**分块拼接**（`subarray` + 循环 `String.fromCharCode`，块长 0x8000）后再 `btoa`，并对结果渲染加了 `encryptResultData` 判空与 `|| ''` 兜底。
- `[*]` **桌面版纯文本解密输出多余包络**：`_render_results_text()` 在只有**单个纯文本条目**时直接解码 `utf-8` 输出明文，去除 `── 名称 (大小 B) ──` 等包络信息；解密结果为**文件 / 包**时才进入包管理器目录树。
- `[*]` **桌面版包管理器滚轮失效**：`browse.py _bind_wheel()` 原只绑 canvas 的 `<MouseWheel>`，焦点落在行内控件时捕获不到。改为进程级 `top.bind_all('<MouseWheel>')` + 指针落点在 canvas 可视区内（`x_root/y_root` 范围判断）才滚动，返回 `'break'` 防冒泡。`main.py` 与 `browse.py` 均 `py_compile` 通过。

---

## [v1.0.4] - 2026-08-31

### 新增 (Added)

#### 新模块
- `[+]` **`kjk9.py`（新）**：KJKv9 二进制格式封装。采用 64B 文件头 + 4MB 分块 AES-256-GCM、加密目录区，全 C 多线程调度（线程池 / 看门狗 / OVERLAPPED I/O / 精确进度回调 / `<BELOW_NORMAL` 优先级预留系统资源），支持断点续传（`_Checkpoint`）与 `KJK9AuthError` / `KJK9Cancel` 异常体系。核心：`KJK9Package`（`open` / `files` / `read_file` / `extract_files` / `stage_add` / `stage_rename` / `stage_delete` / `save` / `compact` / `change_password`）、`encrypt_paths_to_kjk9()` / `encrypt_entries_to_kjk9()`、`run_paged()`、`plan_params()`。
- `[+]` **`browse.py`（新）**：独立包浏览器目录树窗口（v1.0.3 的简易内嵌包管理抽离升级，独立进程）。支持 Windows 资源管理器式操作（视口虚拟化渲染、悬停高亮、近邻目标判定、自动展开、拖放添加/外部拖入拖出、右键重命名/删除、局部解密、脏标记与关闭提示、改密/压缩/完整性校验），内置 `LegacyPackage`（旧文本包打开、密码探测、升级为 KJKv9）、`TaskRunner` / `TaskWindow`（后台任务与进度）及自定义对话框。
- `[+]` **`kjkfast.c`（新）**：C 加密引擎源码，编译产出 `engine/kjkfast v<版本>.dll` 由 `engine.py` 动态加载。

#### 引擎层 (`engine.py`)
- `[+]` kjkfast C 引擎接入：`_kjkfast_candidates()`（枚举 `engine/kjkfast-<版本>.dll`）、`_load_kjkfast()`（加载最新可用 DLL）、`engine_backend_name()`（报告当前后端）；token 编解码走 C 引擎，失败自动回退 numpy / 纯 Python，三者互等。
- `[+]` `decrypt_entry_to_file(item, out_path, password, ...)`：单条目直接解密落盘，目录树按需提取，不整包载入内存。
- `[+]` 旧文本格式（v1/v5）完整提取：`extract_legacy_package_file()` / `extract_legacy_package_text()`（配套 `_emit/_final/_advance/_progress/_lines`）、`_decode_entry_ciphertext()`、`_entry_name_from_parts()`、`_legacy_original_name()`、`_legacy_entry_plain()`、`_write_legacy_entry()`、`_safe_join()`（路径穿越防护）。
- `[+]` 整包解密落盘：`decrypt_kjk_to_dir(content, save_dir, password, ...)`（配套 `_inner`），支持旧文本包与 KJKv9。
- `[+]` 打包进度细化：`_fm_line_count()`、`_build_pack_lines()`，按行条目统计让进度更平滑。
- `[~]` `rename_entry_kjk(...)`：新增 `password` 参数（密码感知重命名）。

#### 右键菜单 (`context_menu.py`)
- `[+]` `AsyncTaskWindow`（`_on_cancel` / `_prog` / `run` / `worker`）：右键加解密后台调度窗口，可取消，0.1% 精度进度（区别于 v1.0.3 的基础进度弹窗）。
- `[+]` KJKv9 右键流程：`_kjk9_enabled()`、`_kjk9_encrypt()`、`_kjk9_encrypt_flow()`、`_try_cleanup_partial()`、`_kjk9_decrypt()`、`_kjk9_add_files()`；辅助 `_thread_below_normal()`（后台线程降至低优先级，为其它应用留资源）、`_is_auth_error()`。
- `[+]` `_peek_password_prefix(filepath)`：右键前只读文件头探测旧格式是否带密码。
- `[+]` `build_browse_command(exe_path)`：`.kjk` 双击直开目录树（新增 `--verb browse` 动作路由）。
- `[+]` 新增 i18n 文案 `menu_no_target`（未选中目标时的确定性提示）。

#### 主程序 (`main.py`)
- `[+]` 双击 / 命令行打开 `.kjk` 直开包浏览器：`_launch_browse(filepath)`（独立进程启动 `browse.py`），配分阶段流程 `_stage1_read/_stage2_password/_stage3_extract/_stage4_done`（先读目录与基本信息、内容磁盘延迟加载）。
- `[+]` 主窗口拖放：`_on_main_drop()` 及 `_drop_to_encrypt()` / `_drop_to_decrypt()` / `_drop_to_open()`，把 `.kjk`/文件直接拖进主窗即可加密/解密/打开。
- `[+]` KJKv9 批处理接入 C 引擎：`_run_kjk9_encrypt_worker()`、`_run_kjk9_encrypt_separate_worker()`（`prog(frac, text)` 精确进度）、`_run_kjk9_add_to_package()`。
- `[+]` `peek_detect_password_prefix(filepath)`：不整载文件仅读头探测密码前缀，供双击弹窗判断。
- `[+]` **`_font_name()`**：按语言选用平滑字体（Microsoft YaHei UI / Segoe UI）。

#### 本地 API (`api_server.py`)
- `[+]` 新增 6 个 KJK 包管理端点（v1.0.3 无）：`api_pkg_open()`（打开/读包清单）、`api_pkg_append()`（追加文件）、`api_pkg_rename()`（重命名条目）、`api_pkg_delete()`（删除条目）、`api_pkg_change_password()`（修改密码）、`api_pkg_verify()`（完整性校验）及辅助 `_open_pkg()` / `_pkg_files()` / `_pkg_err()`。注：`/settings/compat-format`、`/detect-format` 为 v1.0.3 已有，非本版新增。

#### 卸载器 (`uninstaller.py`)
- `[+]` `_rmtree_installed(install_dir)`：递归清理程序文件、`engine/` 引擎文件夹与注册表项；`_schedule_cleanup_batch(install_dir)`：删除占用文件失败时注册延迟清理批处理，彻底解决 v1.0.3 遗留的卸载残留。

### 改进 (Changed)

- `[~]` 右键菜单命令结构（对齐更清晰的路由）：v1.0.3 为 `--batch-* "action|%1"`（内联动作），v1.0.4 改为 `--verb <action> --batch-* "%1"`（独立子动作 + 独立选中路径），动作分发与路径传递解耦，为 KJKv9 / browse 等新动作提供统一入口。
- `[~]` 包管理器：由 v1.0.3 内嵌在 `main.py` 的单一 Tab（`_build_package_tab` 等）抽离为独立的 `browse.py` 目录树窗口，操作完整度对齐 Windows 资源管理器，支持双击独立打开。
- `[~]` 解密页与包管理页 UI 精简：仅保留「选择文件」按钮 + 粘贴框（向后兼容），加密页隐藏输出框可复制内容。
- `[~]` 主程序整体视觉与字体现代化（紧凑布局、按语言平滑字体），图形风格一致触达简体中文 / 繁体中文 / English。

### 修复 (Fixed)

- `[*]` **卸载残留（v1.0.3 遗留）**：旧卸载器无法清除程序文件、`engine/` 与注册表项；v1.0.4 由 `_rmtree_installed` / `_schedule_cleanup_batch` 兜底清理。
- `[*]` 双击 / 打开 `.kjk` 未按密码分流：新增 `peek_detect_password_prefix()`（main）、`_peek_legacy_has_password()`（browse）、`LegacyPackage.open` 内 `try_decrypt_item` 密码感知，双击能正确弹出密码窗而非直接失败。
- `[*]` 外部/内部拖放落点与拖出卡顿：`_drop_target_at_win_y()` 对空白区返回包根目录（资源管理器语义）、`_dnd_y()` 采用 `winfo_pointery()-winfo_rooty()` 免疫高分屏 DPI；`<<DragInitCmd>>` 改为按下时后台预渲染，拖出时直接取结果，不再冻结 Tk 事件循环。

### 性能 (Performance)

- `[+]` KJKv9 全 C 多线程调度（线程池 / 看门狗 / OVERLAPPED I/O / 进度回调），数据通路零 Python 开销；`plan_params()` 按 CPU/内存自动预留系统资源。
- `[+]` 4MB 分块流式 + 目录树视口虚拟化：大文件不断流、十万节点展开毫秒级。
- `[+]` 右键加解密线程优先级 `< BELOW_NORMAL`，为其它应用保留资源；`engine/` 引擎插件化，`kjkfast-<版本>.dll` 多代共存、秒开启动。

### 兼容性 (Compatibility)

- 完整向后兼容 v1.0.1 / v1.0.2 / v1.0.3：KJKv5/v7 文本包自动识别、可浏览 / 解密 / 升级为 KJKv9。
- 设置中「格式兼容」沿用 KJKv9 / KJKv7 / 旧版工作区（`get_compat_format`），网页版与桌面版加密算法互通同步。
- API 为 v1.0.3 的严格超集：旧端点（`/status` `/encrypt` `/decrypt` `/shutdown` `/settings/compat-format` `/detect-format`）契约不变，仅新增 `/package/*` 端点。

### 移除 / 清理

- `[x]` 删除 v1.0.3 遗留的测试文件（`test_engine.py`、`test_streaming.py`、`_test_engine_quick.py`），源码包仅保留发布所需文件。