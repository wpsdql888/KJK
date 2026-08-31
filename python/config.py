# -*- coding: utf-8 -*-
"""KJK Encryptor - 配置管理

配置文件存储在程序所在目录,便于便携使用。
"""

import json
import os
import sys


def get_config_dir() -> str:
    """返回配置目录。

    打包后的 exe 如果安装在 Program Files 等受保护目录,
    则使用 APPDATA 目录存储配置,避免权限问题。
    """
    if getattr(sys, 'frozen', False):
        exe_dir = os.path.dirname(sys.executable)
        # 检查是否在受保护的系统目录
        protected = ('Program Files', 'Program Files (x86)', 'Windows')
        if any(p in exe_dir for p in protected):
            # 使用 APPDATA 目录
            base = os.environ.get('APPDATA') or os.path.expanduser('~')
            return os.path.join(base, 'KJK-Encrypter')
        return exe_dir
    else:
        return os.path.dirname(os.path.abspath(__file__))


def get_config_path() -> str:
    """返回配置文件完整路径。"""
    return os.path.join(get_config_dir(), 'kjk_config.json')


def _old_config_path() -> str:
    """旧版配置文件路径(用户配置目录)。"""
    if os.name == 'nt':
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
    else:
        base = os.path.expanduser('~/.config')
    return os.path.join(base, 'KJK-Encrypter', 'kjk_config.json')


def load_config(defaults=None):
    """加载配置,失败时返回 defaults 的副本。"""
    path = get_config_path()
    # 首次运行时迁移旧配置
    if not os.path.exists(path):
        old_path = _old_config_path()
        if os.path.exists(old_path):
            try:
                with open(old_path, 'r', encoding='utf-8') as f:
                    old_cfg = json.load(f)
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(old_cfg, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

    if os.path.exists(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                cfg = json.load(f)
            if defaults:
                for k, v in defaults.items():
                    cfg.setdefault(k, v)
            return cfg
        except Exception:
            pass
    return dict(defaults or {})


def save_config(cfg):
    """保存配置。返回是否成功。"""
    try:
        path = get_config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False


# ======================== 格式兼容性配置 ========================

# 兼容格式选项: 'auto' (自动检测), 'KJKv7' (v1.0.3), 'KJKv5' (v1.0.2)
COMPAT_FORMAT_OPTIONS = ['auto', 'KJKv7', 'KJKv5']


def get_compat_format(cfg=None) -> str:
    """获取当前兼容格式设置,默认为 'auto'。"""
    if cfg is None:
        cfg = load_config()
    fmt = cfg.get('compat_format', 'auto')
    if fmt not in COMPAT_FORMAT_OPTIONS:
        fmt = 'auto'
    return fmt


def set_compat_format(fmt: str) -> bool:
    """设置兼容格式。"""
    if fmt not in COMPAT_FORMAT_OPTIONS:
        return False
    cfg = load_config()
    cfg['compat_format'] = fmt
    return save_config(cfg)


def format_label(fmt: str) -> str:
    """返回格式选项的显示标签。"""
    labels = {
        'auto': 'Auto (自动检测)',
        'KJKv7': 'KJKv7 (v1.0.3 AES-256-GCM)',
        'KJKv5': 'KJKv5 (v1.0.2 SHA-256)',
    }
    return labels.get(fmt, fmt)
