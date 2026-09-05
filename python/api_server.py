# -*- coding: utf-8 -*-
"""KJK Encryptor - Flask API 服务器（延迟导入，Flask为可选依赖）"""

import threading
import io
import os
import base64

from engine import (encrypt, decrypt, encrypt_raw, pack_kjk, unpack_kjk,
                    encrypt_filename, re_decrypt, add_password_prefix,
                    detect_password_header, verify_password, make_password_header,
                    detect_kjk_format_version)
from config import get_compat_format, set_compat_format, COMPAT_FORMAT_OPTIONS, format_label
from kjk9 import KJK9Package, KJK9AuthError, is_kjk9, peek_info

_api_port = 5000
_server_thread = None


def _check_flask():
    """检查Flask是否可用"""
    try:
        from flask import Flask, request, jsonify, send_file
        return True
    except ImportError:
        return False


def _open_pkg(body):
    """从请求体打开 KJKv9 包, 返回 (pkg, info)。非 v9 或路径无效抛 ValueError。"""
    path = (body.get('path') or '').strip()
    if not path:
        raise ValueError('path is required')
    if not os.path.isfile(path):
        raise ValueError(f'file not found: {path}')
    is9, has_pwd = peek_info(path)
    if not is9:
        raise ValueError('not a KJKv9 package (legacy formats are not supported)')
    pkg = KJK9Package.open(path, body.get('password') or '')
    return pkg, {'format': 'kjk9', 'has_password': has_pwd}


def _pkg_files(pkg):
    return [{'name': f['p'], 'size': int(f.get('s', 0)),
             'mtime': int(f.get('m', 0))} for f in pkg.file_list()]


def _get_app():
    """延迟创建Flask应用"""
    from flask import Flask, request, jsonify, send_file

    app = Flask(__name__)

    @app.route('/status', methods=['GET'])
    def status():
        return jsonify({'status': 'ok', 'name': 'KJK Encryptor API', 'version': '1.1.0'})

    @app.route('/settings/compat-format', methods=['GET', 'POST'])
    def api_compat_format():
        """获取/设置格式兼容性设置。"""
        if request.method == 'GET':
            current = get_compat_format()
            return jsonify({
                'format': current,
                'options': COMPAT_FORMAT_OPTIONS,
                'label': format_label(current),
            })
        else:
            body = request.get_json(silent=True) or {}
            fmt = body.get('format', 'auto')
            if fmt not in COMPAT_FORMAT_OPTIONS:
                return jsonify({'error': f'Invalid format. Must be one of: {COMPAT_FORMAT_OPTIONS}'}), 400
            if set_compat_format(fmt):
                return jsonify({'status': 'ok', 'format': fmt})
            return jsonify({'error': 'Failed to save format setting'}), 500

    @app.route('/detect-format', methods=['POST'])
    def api_detect_format():
        """检测 .kjk 内容的格式版本。"""
        if request.content_type == 'application/octet-stream':
            content = request.data.decode('utf-8')
        else:
            body = request.get_json(silent=True) or {}
            content = body.get('kjk', '')
        fmt = detect_kjk_format_version(content)
        return jsonify({'format': fmt})

    @app.route('/encrypt', methods=['POST'])
    def api_encrypt():
        password = request.args.get('password', '')
        if request.content_type == 'application/octet-stream':
            data = request.data
        else:
            body = request.get_json(silent=True) or {}
            text = body.get('data', '')
            password = body.get('password', password)
            data = text.encode('utf-8')

        # v7: 条目用 encrypt_raw (不加密码头前缀),有密码时在最外层添加密码头前缀
        salt = None
        if password and password.strip():
            _, salt = make_password_header(password)
        cipher = encrypt_raw(data, password, salt)

        name = request.args.get('filename', 'untitled')
        ext = request.args.get('ext', 'txt')
        enc_name = encrypt_filename(name, ext, password, salt)
        has_pwd = bool(password.strip())
        kjk_content = pack_kjk([{'enc_name': enc_name, 'has_pwd': has_pwd, 'ciphertext': cipher, 'size': len(data)}])
        if has_pwd:
            kjk_content, _ = add_password_prefix(kjk_content, password, salt)

        if request.args.get('format') == 'json':
            return jsonify({'ciphertext': cipher, 'kjk': kjk_content})

        buf = io.BytesIO(kjk_content.encode('utf-8'))
        return send_file(buf, mimetype='application/octet-stream',
                         as_attachment=True, download_name=f'{name}.kjk')

    @app.route('/decrypt', methods=['POST'])
    def api_decrypt():
        if request.content_type == 'application/octet-stream':
            content = request.data.decode('utf-8')
            password = request.args.get('password', '')
        else:
            body = request.get_json(silent=True) or {}
            content = body.get('kjk', '')
            password = body.get('password', '')

        try:
            results = unpack_kjk(content)
        except Exception as e:
            return jsonify({'error': str(e)}), 400

        # v6: 检测密码头 (v6 前缀 / v5 独立条目 / 旧版 pwd: 前缀)
        has_pwd, salt_hex, hash_hex, actual_results = detect_password_header(results)

        # 旧版兼容: 无密码头但条目标记需要密码
        if not has_pwd:
            needs_pwd = any(r.get('_needs_password') for r in results)
            if needs_pwd:
                has_pwd = True
                actual_results = results
        else:
            results = actual_results

        if has_pwd:
            if not password:
                return jsonify({'error': 'password required'}), 401
            # v6: 用哈希验证密码
            if salt_hex and hash_hex:
                if not verify_password(password, salt_hex, hash_hex):
                    return jsonify({'error': 'wrong password'}), 401
            else:
                # 旧版: 用第一个条目试解密验证
                try:
                    re_decrypt(results[0], password)
                except Exception:
                    return jsonify({'error': 'wrong password'}), 401
            salt_bytes = bytes.fromhex(salt_hex) if salt_hex else None
            is_v7 = bool(salt_hex) or all(r.get('_kjkv7') for r in results)
            for r in results:
                if r.get('_needs_password') or (password and password.strip()):
                    try:
                        r['data'] = re_decrypt(r, password, salt_bytes, legacy=not is_v7)
                    except Exception:
                        pass

        if request.args.get('format') == 'json':
            items = []
            for r in results:
                data = r.get('data')
                if data is None:
                    continue
                # 二进制文件使用 base64 返回,避免 .decode() 破坏数据
                items.append({
                    'name': r.get('originalName', 'untitled'),
                    'data': base64.b64encode(data).decode('ascii'),
                    'size': len(data),
                })
            return jsonify({'files': items})

        if results:
            buf = io.BytesIO(results[0]['data'])
            return send_file(buf, mimetype='application/octet-stream',
                             as_attachment=True,
                             download_name=results[0].get('originalName', 'decrypted'))
        return jsonify({'error': 'no files found'}), 404

    # ======================== 包管理 (KJKv9) ========================

    def _pkg_err(e):
        if isinstance(e, KJK9AuthError):
            return jsonify({'error': str(e)}), 401
        return jsonify({'error': str(e)}), 400

    @app.route('/package/open', methods=['POST'])
    def api_pkg_open():
        """打开 KJKv9 包并返回文件清单。"""
        body = request.get_json(silent=True) or {}
        try:
            pkg, info = _open_pkg(body)
        except Exception as e:
            return _pkg_err(e)
        return jsonify({**info, 'files': _pkg_files(pkg)})

    @app.route('/package/append', methods=['POST'])
    def api_pkg_append():
        """向 KJKv9 包追加文件并保存。files: [{src_path, relpath?}]"""
        body = request.get_json(silent=True) or {}
        files = body.get('files') or []
        if not files:
            return jsonify({'error': 'files is required'}), 400
        try:
            pkg, info = _open_pkg(body)
            added = 0
            for f in files:
                src = (f.get('src_path') or '').strip()
                if not src or not os.path.isfile(src):
                    continue
                rel = (f.get('relpath') or '').strip() or None
                pkg.stage_add(src, relpath=rel)
                added += 1
            pkg.save()
        except Exception as e:
            return _pkg_err(e)
        return jsonify({'status': 'ok', 'added': added, 'files': _pkg_files(pkg)})

    @app.route('/package/rename', methods=['POST'])
    def api_pkg_rename():
        """重命名 KJKv9 包内条目并保存。"""
        body = request.get_json(silent=True) or {}
        old = (body.get('old') or '').strip()
        new = (body.get('new') or '').strip()
        if not old or not new:
            return jsonify({'error': 'old and new are required'}), 400
        try:
            pkg, info = _open_pkg(body)
            pkg.stage_rename(old, new)
            pkg.save()
        except Exception as e:
            return _pkg_err(e)
        return jsonify({'status': 'ok', 'files': _pkg_files(pkg)})

    @app.route('/package/delete', methods=['POST'])
    def api_pkg_delete():
        """删除 KJKv9 包内条目并保存。relpaths: [relpath, ...]"""
        body = request.get_json(silent=True) or {}
        relpaths = body.get('relpaths') or []
        if not relpaths:
            return jsonify({'error': 'relpaths is required'}), 400
        try:
            pkg, info = _open_pkg(body)
            deleted = 0
            for r in relpaths:
                try:
                    pkg.stage_delete(r)
                    deleted += 1
                except Exception:
                    pass
            pkg.save()
        except Exception as e:
            return _pkg_err(e)
        return jsonify({'status': 'ok', 'deleted': deleted, 'files': _pkg_files(pkg)})

    @app.route('/package/change-password', methods=['POST'])
    def api_pkg_change_password():
        """修改 KJKv9 包密码并保存。new_password 为空 = 移除密码。"""
        body = request.get_json(silent=True) or {}
        new_password = body.get('new_password') or ''
        try:
            pkg, info = _open_pkg(body)
            pkg.change_password(new_password)
        except Exception as e:
            return _pkg_err(e)
        return jsonify({'status': 'ok'})

    @app.route('/package/verify', methods=['POST'])
    def api_pkg_verify():
        """验证 KJKv9 包格式与密码。"""
        body = request.get_json(silent=True) or {}
        path = (body.get('path') or '').strip()
        if not path or not os.path.isfile(path):
            return jsonify({'error': 'path is required and must exist'}), 400
        is9, has_pwd = peek_info(path)
        if not is9:
            return jsonify({'valid': False, 'format': 'unknown', 'has_password': None})
        try:
            KJK9Package.open(path, body.get('password') or '')
            return jsonify({'valid': True, 'format': 'kjk9', 'has_password': has_pwd})
        except KJK9AuthError:
            return jsonify({'valid': False, 'format': 'kjk9', 'has_password': has_pwd})
        except Exception:
            return jsonify({'valid': False, 'format': 'kjk9', 'has_password': has_pwd})

    @app.route('/shutdown', methods=['POST'])
    def shutdown():
        """停止服务器"""
        func = request.environ.get('werkzeug.server.shutdown')
        if func:
            func()
        return jsonify({'status': 'shutting down'})

    return app


def set_port(port: int):
    global _api_port
    _api_port = port


def start_server(port: int = 5000, debug: bool = False):
    """在后台线程启动API服务器"""
    global _api_port, _server_thread

    if not _check_flask():
        raise RuntimeError(
            'Flask 未安装。请运行: pip install flask\n'
            '或安装所有可选依赖: pip install -r requirements.txt'
        )

    _api_port = port
    app = _get_app()
    _server_thread = threading.Thread(
        target=app.run,
        kwargs={'host': '127.0.0.1', 'port': port, 'debug': debug},
        daemon=True
    )
    _server_thread.start()
    return f'http://127.0.0.1:{port}'


def stop_server():
    """停止API服务器"""
    try:
        import requests
        requests.post(f'http://127.0.0.1:{_api_port}/shutdown', timeout=1)
    except Exception:
        pass