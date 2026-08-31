#!/usr/bin/env python3
"""Web UI for JT Wazuh Manager with login support.

Icons from Iconoir (https://iconoir.com/)
MIT License - Copyright 2021 Luca Burgio
https://github.com/iconoir-icons/iconoir/blob/main/LICENSE
"""

from . import __version__ as VERSION

import json
import os
import glob
import secrets
import logging
from datetime import datetime
from typing import Optional
from functools import wraps

# Setup logging
def setup_logging(log_file: str = None):
    """Setup logging to file and console."""
    if log_file is None:
        log_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        log_file = os.path.join(log_dir, 'wazuh_agent_mgr.log')

    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # File handler
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    # Get logger
    logger = logging.getLogger('wazuh_mgr')
    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    return logger

# Initialize logger
logger = setup_logging()

try:
    from flask import Flask, render_template_string, jsonify, request, session, redirect, url_for
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

try:
    import requests as http_requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from .config import get_config

import re
import shlex

# ============ Security Utilities ============

# Allowed base paths for file operations (whitelist)
ALLOWED_PATHS = [
    '/var/ossec/etc/',
    '/var/ossec/ruleset/',
    '/var/ossec/logs/',
    '/var/ossec/queue/',
]

# Valid patterns for various inputs
VALID_NODE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
VALID_AGENT_ID_PATTERN = re.compile(r'^[0-9]{1,6}$')
VALID_GROUP_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')
VALID_PATH_COMPONENT_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.\/]+$')
VALID_USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_\-\.]+$')


def validate_node_name(name: str) -> bool:
    """Validate node name to prevent injection attacks."""
    if not name or len(name) > 128:
        return False
    return bool(VALID_NODE_NAME_PATTERN.match(name))


def validate_agent_id(agent_id: str) -> bool:
    """Validate agent ID format."""
    if not agent_id:
        return False
    return bool(VALID_AGENT_ID_PATTERN.match(str(agent_id)))


def validate_group_name(name: str) -> bool:
    """Validate group name to prevent injection attacks."""
    if not name or len(name) > 128:
        return False
    return bool(VALID_GROUP_NAME_PATTERN.match(name))


def validate_username(name: str) -> bool:
    """Validate username to prevent injection attacks."""
    if not name or len(name) > 64:
        return False
    return bool(VALID_USERNAME_PATTERN.match(name))


def validate_path(path: str) -> bool:
    """Validate that path is within allowed directories and has no injection."""
    if not path:
        return False

    # Normalize path to prevent directory traversal
    try:
        normalized = os.path.normpath(path)
    except Exception:
        return False

    # Check for directory traversal attempts
    if '..' in path or '\x00' in path:
        return False

    # Check for shell metacharacters
    dangerous_chars = ['$', '`', '|', ';', '&', '>', '<', '\n', '\r', '(', ')', '{', '}', '[', ']', '!', '#']
    if any(c in path for c in dangerous_chars):
        return False

    # Validate path pattern
    if not VALID_PATH_COMPONENT_PATTERN.match(path):
        return False

    # Check if path is within allowed directories
    for allowed in ALLOWED_PATHS:
        if normalized.startswith(allowed) or normalized.rstrip('/') + '/' == allowed:
            return True

    return False


def safe_shell_arg(arg: str) -> str:
    """Safely escape argument for shell command."""
    return shlex.quote(arg)


def sanitize_for_log(value: str, max_length: int = 200) -> str:
    """Sanitize value for logging to prevent log injection."""
    if not value:
        return ''
    # Remove control characters and limit length
    sanitized = ''.join(c for c in str(value) if c.isprintable())
    return sanitized[:max_length]


# Login page template
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JT Wazuh Manager - Login</title>
    <link rel="icon" type="image/png" href="/images/logo-1.png">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .login-container {
            background: #16213e;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 440px;
        }
        .logo {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo h1 {
            color: #4fc3f7;
            font-size: 28px;
            margin-bottom: 5px;
            white-space: nowrap;
        }
        .logo p {
            color: #888;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-group label {
            display: block;
            color: #aaa;
            margin-bottom: 8px;
            font-size: 14px;
        }
        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 2px solid #0f3460;
            background: #1a1a2e;
            color: #eee;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        .form-group input:focus {
            outline: none;
            border-color: #4fc3f7;
        }
        .form-group input:disabled {
            background: #0d0d1a;
            color: #666;
            cursor: not-allowed;
            border-color: #0a0a1a;
        }
        .btn-login {
            width: 100%;
            padding: 14px;
            background: #4fc3f7;
            color: #1a1a2e;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn-login:hover {
            background: #81d4fa;
        }
        .btn-login:disabled {
            background: #555;
            cursor: not-allowed;
        }
        .error-message {
            background: #e9456033;
            border: 1px solid #e94560;
            color: #ff6b6b;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 14px;
        }
        .info-text {
            color: #666;
            font-size: 12px;
            text-align: center;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>JT Wazuh Manager</h1>
            <div style="font-size: 14px; color: #888; margin-top: 5px;">v{{ version }}</div>
            <p style="margin-top: 15px;">Login with your Wazuh credentials</p>
        </div>

        {% if error %}
        <div class="error-message">{{ error }}</div>
        {% endif %}

        <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{{ csrf_token or '' }}">
            <input type="hidden" name="host" value="{{ host or 'localhost' }}">
            <input type="hidden" name="port" value="{{ port or '55000' }}">
            <div class="form-group">
                <label for="username">Wazuh API Username</label>
                <input type="text" id="username" name="username" value="{{ username or '' }}" required autocomplete="username" placeholder="Username">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
                <p style="margin-top: 8px; font-size: 12px; color: #ffc107;">Session expires after {{ token_timeout_minutes }} minutes</p>
            </div>
            <button type="submit" class="btn-login">Login</button>
        </form>
        <p class="info-text">
            API: {{ host or 'localhost' }}:{{ port or '55000' }}
            <a href="#" onclick="toggleAdvanced(); return false;" style="color:#4fc3f7;margin-left:10px;font-size:11px;">Settings</a>
        </p>
        <div id="advancedSettings" style="display:none;margin-top:15px;padding:15px;background:#1a1a2e;border-radius:6px;">
            <div class="form-group" style="margin-bottom:10px;">
                <label for="hostInput" style="font-size:12px;">API Host</label>
                <input type="text" id="hostInput" value="{{ host or 'localhost' }}" style="font-size:14px;" onchange="document.querySelector('input[name=host]').value=this.value">
            </div>
            <div class="form-group" style="margin-bottom:0;">
                <label for="portInput" style="font-size:12px;">API Port</label>
                <input type="number" id="portInput" value="{{ port or '55000' }}" style="font-size:14px;" onchange="document.querySelector('input[name=port]').value=this.value">
            </div>
        </div>
        <script>
            function toggleAdvanced() {
                var el = document.getElementById('advancedSettings');
                el.style.display = el.style.display === 'none' ? 'block' : 'none';
            }
        </script>
    </div>
</body>
</html>
'''


# Main application template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>JT Wazuh Manager</title>
    <link rel="icon" type="image/png" href="/images/logo-1.png">
    <!-- CodeMirror for config editor -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.css" integrity="sha384-zaeBlB/vwYsDRSlFajnDd7OydJ0cWk+c2OWybl3eSUf6hW2EbhlCsQPqKr3gkznT" crossorigin="anonymous" referrerpolicy="no-referrer">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/theme/dracula.min.css" integrity="sha384-ccdJwIIg/K0Ab6aXF4MPACh7ckk61tvQFTrfkhXZEALgAETURNZIAuQLcS/aPbrM" crossorigin="anonymous" referrerpolicy="no-referrer">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/codemirror.min.js" integrity="sha384-ZYmwuq4n2gOcNxMSiJ6jyTj+BbIrilr7p6dlq6q5nmSWKmsH9UU4K1qqjycMkfmR" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/xml/xml.min.js" integrity="sha384-xPpkMo5nDgD98fIcuRVYhxkZV6/9Y4L8s3p0J5c4MxgJkyKJ8BJr+xfRkq7kn6Tw" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/mode/javascript/javascript.min.js" integrity="sha384-g0o+WW9mdIxA7LaaCKTkRm0M5TVT+Bb4s9eocxPsI2G0Xm0POG9iD6G6qP1IIsfS" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/codemirror/5.65.16/addon/mode/simple.min.js" integrity="sha384-5+aYjV0V2W3IwhAYp/9WOrGMv1TaYkCjnkkW7Hv3yJQo28MergRCSRaUIUzDUs2J" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
    <script>
    // Custom Wazuh alerts.log mode
    document.addEventListener('DOMContentLoaded', function() {
        if (typeof CodeMirror !== 'undefined' && CodeMirror.defineSimpleMode) {
            CodeMirror.defineSimpleMode('wazuh-alerts', {
                start: [
                    {regex: /^\*\* Alert \d+\.\d+:/, token: 'keyword'},
                    {regex: /^Rule: \d+ \(level \d+\)/, token: 'def'},
                    {regex: /-> '[^']*'/, token: 'string'},
                    {regex: /- [a-zA-Z0-9_,]+,$/, token: 'tag'},
                    {regex: /^\d{4} [A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2}/, token: 'number'},
                    {regex: /[a-zA-Z0-9_-]+->(?:journald|\/var\/log\/[^\s]+)/, token: 'variable-2'},
                    {regex: /(?:Src IP|Src Port|User|uid|Dst IP|Dst Port|Protocol|Action):/, token: 'attribute'},
                    {regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/, token: 'number'},
                    {regex: /\b\d+\b/, token: 'number'}
                ]
            });
        }
    });
    </script>
    <style>
        /* CodeMirror custom styles */
        .CodeMirror { font-size: 14px; line-height: 1.6; }
        .CodeMirror-lines { padding: 10px 0; }
        .CodeMirror-gutters { background: #1a1a2e; border-right: 2px solid #4fc3f7; }
        .CodeMirror-linenumber { color: #666; padding: 0 8px 0 8px; min-width: 40px; text-align: right; }
        .json-gutter { width: 28px; display: flex; align-items: center; justify-content: center; }
        .json-expand-marker { cursor: pointer; display: flex; align-items: center; justify-content: center; width: 100%; height: 21px; }
        .json-expand-marker svg { width: 12px; height: 12px; color: #4fc3f7; transition: color 0.2s; }
        .json-expand-marker:hover svg { color: #fff; }
        .json-expand-marker.expanded svg { color: #4ade80; }
        .json-expanded-widget { background: #0d1117; border-left: 3px solid #4fc3f7; margin: 4px 0 4px 20px; padding: 8px 12px; font-family: monospace; font-size: 13px; white-space: pre; overflow-x: auto; max-height: 300px; overflow-y: auto; color: #e6edf3; }
        .json-expanded-widget .json-key { color: #ff79c6; }
        .json-expanded-widget .json-string { color: #50fa7b; }
        .json-expanded-widget .json-number { color: #bd93f9; }
        .json-expanded-widget .json-boolean { color: #ffb86c; }
        .json-expanded-widget .json-null { color: #ff5555; }
        .json-expanded-widget .json-bracket { color: #f8f8f2; }

        * { box-sizing: border-box; margin: 0; padding: 0; }
        html { height: 100%; overflow: hidden; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; color: #eee; display: flex; flex-direction: column; height: 100%; overflow: hidden; }
        .container { margin: 0 auto; padding: 20px 20px 10px 20px; flex: 1; display: flex; flex-direction: column; width: 100%; overflow: hidden; min-height: 0; }
        header { background: #16213e; padding: 20px; margin-bottom: 20px; border-radius: 8px; display: flex; justify-content: space-between; align-items: center; }
        header h1 { color: #4fc3f7; }
        .header-right { display: flex; align-items: center; gap: 20px; }
        .user-info { color: #aaa; font-size: 13px; text-align: center; }
        .user-info > div { margin-bottom: 6px; }
        .user-info > div:last-child { margin-bottom: 0; }
        .user-info strong { color: #4fc3f7; }
        .header-buttons { display: flex; flex-direction: row; gap: 8px; align-self: stretch; }
        .btn-settings { box-sizing: border-box; height: 100%; min-width: 62px; padding: 6px 14px; background: #0f3460; color: #4fc3f7; border: 1px solid #4fc3f7; border-radius: 6px; cursor: pointer; font-size: 12px; display: inline-flex; flex-direction: column; align-items: center; justify-content: center; gap: 5px; text-decoration: none; }
        .btn-settings:hover { background: #1a4a7a; }
        .btn-settings .icon { width: 18px; height: 18px; }
        .btn-logout { box-sizing: border-box; height: 100%; min-width: 62px; padding: 6px 14px; background: #e94560; color: #fff; border: 1px solid #e94560; border-radius: 6px; cursor: pointer; text-decoration: none; font-size: 12px; display: inline-flex; flex-direction: column; align-items: center; justify-content: center; gap: 5px; }
        .btn-logout:hover { background: #ff6b6b; border-color: #ff6b6b; }
        .btn-logout .icon { width: 18px; height: 18px; }
        .stats-bar { display: flex; gap: 20px; }
        .stat-item { background: #0f3460; padding: 10px 20px; border-radius: 6px; text-align: center; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s; }
        .stat-item:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .stat-value { font-size: 24px; font-weight: bold; color: #4fc3f7; overflow: hidden; position: relative; height: 32px; line-height: 32px; }
        .stat-value span { display: block; }
        .stat-value span.slide-in { animation: slideIn 0.3s ease-out; }
        @keyframes slideIn { from { transform: translateY(-100%); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
        .stat-label { font-size: 12px; color: #aaa; }
        .stat-item.disconnected .stat-value { color: #e94560; }
        .stat-item.pending .stat-value { color: #ffc107; }
        .stat-item.active .stat-value { color: #00c853; }

        .tabs { display: flex; gap: 2px; margin-bottom: 0; }
        .tab { padding: 10px 20px; background: #0a0a15; border: none; color: #888; cursor: pointer; border-radius: 6px 6px 0 0; display: inline-flex; align-items: center; gap: 8px; position: relative; bottom: -1px; border: 1px solid transparent; border-bottom: none; }
        .tab.active { background: #16213e; color: #4fc3f7; border-color: #0f3460; z-index: 1; }
        .tab:hover:not(.active) { color: #aaa; background: #0f0f1a; }

        .panel { background: #16213e; border-radius: 0 8px 8px 8px; padding: 20px 20px 10px 20px; display: none; flex-direction: column; flex: 1; overflow: hidden; border: 1px solid #0f3460; min-height: 0; }
        .panel.active { display: flex; }

        .toolbar { display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap; align-items: center; flex-shrink: 0; }
        .toolbar-row { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .toolbar-spacer { flex: 1; min-width: 10px; }
        .action-bar-container { position: relative; min-height: 52px; margin-bottom: 10px; }
        .action-bar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; flex-shrink: 0; padding: 10px 15px; background: #0f3460; border-radius: 6px; min-height: 44px; position: absolute; top: 0; left: 0; right: 0; z-index: 10; opacity: 0; pointer-events: none; transition: opacity 0.2s; }
        .action-bar.visible { opacity: 1; pointer-events: auto; }
        .distribution-bar { display: flex; gap: 12px; align-items: center; padding: 10px 15px; background: #0f3460; border-radius: 6px; min-height: 44px; }
        .distribution-bar select { padding: 4px 8px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; font-size: 12px; cursor: pointer; }
        .distribution-chart { flex: 1; height: 24px; background: #1a1a2e; border-radius: 4px; overflow: hidden; display: flex; gap: 2px; padding: 0 1px; }
        .distribution-chart.animating .distribution-segment { animation: segmentExpand 0.4s ease-out; }
        @keyframes segmentExpand { from { transform: scaleX(0); } to { transform: scaleX(1); } }
        .distribution-segment { transform-origin: left center; }
        .distribution-segment { height: 100%; display: flex; align-items: center; justify-content: center; font-size: 10px; color: #fff; overflow: hidden; min-width: 0; transition: width 0.3s; cursor: pointer; border-radius: 2px; }
        .distribution-segment:hover { filter: brightness(1.2); }
        .distribution-segment span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; text-shadow: 0 0 2px rgba(0,0,0,0.5); padding: 0 6px; }
        .toolbar select { padding: 8px 12px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; }
        .toolbar > input[type="text"], .toolbar-filters > input[type="text"] { padding: 8px 12px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; min-width: 180px; flex-shrink: 1; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; display: inline-flex; align-items: center; gap: 6px; }
        .btn-primary { background: #4fc3f7; color: #1a1a2e; }
        .btn-danger { background: #e94560; color: #fff; }
        .btn-success { background: #00c853; color: #fff; }
        .btn-warning { background: #ffc107; color: #1a1a2e; }
        .btn:hover { opacity: 0.9; }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .btn-sm { padding: 4px 8px; font-size: 12px; gap: 4px; }
        .btn-icon { padding: 4px 6px; font-size: 14px; line-height: 1; }
        .btn-wrap { display: flex; flex-wrap: wrap; gap: 5px; }
        #nodesTable .btn-wrap .btn { width: 100px; justify-content: center; box-sizing: border-box; }
        #groupsTable .btn-wrap .btn { width: 110px; justify-content: center; box-sizing: border-box; }
        /* Icons - Iconoir MIT License */
        .icon { width: 16px; height: 16px; flex-shrink: 0; }
        .btn-sm .icon { width: 14px; height: 14px; }
        .tab .icon { width: 18px; height: 18px; }

        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; vertical-align: middle; }
        tbody tr { height: 50px; }
        th { background: #0f3460; color: #4fc3f7; position: sticky; top: 0; z-index: 2; }
        th.sortable { cursor: pointer; user-select: none; white-space: nowrap; }
        th.sortable:hover { background: #1a3a70; }
        th.sortable .sort-icon { width: 12px; height: 12px; margin-left: 4px; opacity: 0.3; vertical-align: middle; }
        th.sortable .sort-asc, th.sortable .sort-desc { display: none; }
        th.sortable.asc .sort-asc { display: inline; opacity: 1; }
        th.sortable.asc .sort-desc { display: none; }
        th.sortable.desc .sort-desc { display: inline; opacity: 1; }
        th.sortable.desc .sort-asc { display: none; }
        th.sortable:not(.asc):not(.desc) .sort-asc { display: inline; }
        tr:hover { background: #1a1a2e; }
        .modal-body table tr td { padding-left: 8px; padding-right: 8px; border-radius: 4px; }

        .checkbox-cell { width: 40px; }
        input[type="checkbox"] { width: 18px; height: 18px; cursor: pointer; }

        .status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; }
        .status-active { background: #00c853; color: #fff; }
        .status-disconnected { background: #e94560; color: #fff; }
        .status-pending { background: #ffc107; color: #1a1a2e; }
        .status-never { background: #666; color: #fff; }

        .sync-status { padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; white-space: nowrap; }
        .sync-ok { background: #00c85333; color: #00c853; }
        .sync-pending { background: #ffc10733; color: #ffc107; }
        .sync-unknown { background: #66666633; color: #888; }

        .group-label { display: inline-block; padding: 1px 4px; margin: 1px 2px; border-radius: 3px; font-size: 11px; background: #0f3460; color: #4fc3f7; }

        .queue-entry { display: flex; gap: 6px; align-items: center; white-space: nowrap; }
        .queue-size { font-weight: 500; min-width: 60px; text-align: right; }
        .queue-node { color: #888; font-size: 11px; }

        .table-container { flex: 1; overflow-y: auto; min-height: 0; }
        .log-container { flex: 1; overflow: hidden; min-height: 0; display: flex; flex-direction: column; }
        .log-container pre { flex: 1; overflow: auto; min-height: 0; margin: 0; }
        .rules-content { flex: 1; overflow: auto; min-height: 0; }
        .stats-content { flex: 1; overflow: auto; min-height: 0; }
        #nodesTable td:first-child { white-space: nowrap; }

        /* Rules Tree Styles */
        .rule-tree { font-family: monospace; }
        .rule-tree ul { list-style: none; padding-left: 20px; margin: 0; }
        .rule-tree > ul { padding-left: 0; }
        .rule-tree li { position: relative; padding: 5px 0; }
        .rule-tree li::before { content: ''; position: absolute; left: -15px; top: 0; border-left: 1px solid #444; height: 100%; }
        .rule-tree li::after { content: ''; position: absolute; left: -15px; top: 15px; border-top: 1px solid #444; width: 15px; }
        .rule-tree li:last-child::before { height: 15px; }
        .rule-tree > ul > li::before, .rule-tree > ul > li::after { display: none; }
        .rule-node { display: inline-flex; align-items: center; gap: 8px; padding: 8px 12px; background: #1a1a2e; border: 1px solid #333; border-radius: 4px; cursor: pointer; transition: all 0.2s; }
        .rule-node:hover { background: #252545; border-color: #4fc3f7; }
        .rule-node.highlight { background: #2d4a3e; border-color: #4ade80; box-shadow: 0 0 10px rgba(74, 222, 128, 0.3); }
        .rule-node.parent { border-color: #ffc107; }
        .rule-node.child { border-color: #17a2b8; }
        .rule-id { font-weight: bold; color: #4fc3f7; }
        .rule-level { font-size: 11px; padding: 2px 6px; border-radius: 3px; background: #333; }
        .rule-level.high { background: #dc3545; }
        .rule-level.medium { background: #ffc107; color: #000; }
        .rule-level.low { background: #28a745; }
        .rule-level.zero { background: #6c757d; color: #ccc; font-style: italic; }
        .rule-desc { color: #aaa; font-size: 12px; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .rule-file { color: #888; font-size: 11px; }
        .rule-file.custom { color: #f39c12; }
        .rule-custom-badge { font-size: 10px; padding: 1px 5px; border-radius: 3px; background: #f39c12; color: #000; font-weight: bold; margin-left: 5px; }
        .rule-if-group-badge { font-size: 10px; padding: 1px 5px; border-radius: 3px; background: #9b59b6; color: #fff; font-weight: bold; margin-left: 5px; }
        .rule-node.group { background: #2d3e50; border-color: #5dade2; cursor: default; }
        .rule-node.group .rule-id { color: #5dade2; font-weight: bold; }
        .rule-node.more { background: transparent; border: none; color: #888; cursor: default; font-style: italic; }
        .rule-expand { color: #888; cursor: pointer; margin-left: -5px; padding: 4px; border-radius: 4px; background: rgba(255,255,255,0.05); transition: all 0.2s; }
        .rule-expand:hover { color: #4fc3f7; background: rgba(79,195,247,0.2); }
        .rule-content { margin-top: 0; padding: 0; background: #0a0a15; border-radius: 4px; font-size: 12px; line-height: 1.6; overflow: hidden; max-height: 0; opacity: 0; transition: max-height 0.3s ease, opacity 0.3s ease, padding 0.3s ease, margin 0.3s ease; position: relative; }
        .rule-content.show { max-height: 2000px; opacity: 1; padding: 15px; padding-right: 50px; overflow-x: auto; margin-top: 10px; }
        .rule-content code { color: #e0e0e0; white-space: pre; display: block; tab-size: 2; }
        .rule-copy-btn { position: absolute; top: 8px; right: 8px; background: #333; border: 1px solid #444; color: #aaa; padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 11px; transition: all 0.2s; }
        .rule-copy-btn:hover { background: #444; color: #fff; border-color: #4fc3f7; }
        .rule-copy-btn.copied { background: #28a745; color: #fff; border-color: #28a745; }
        .rule-content .xml-tag { color: #4fc3f7; }
        .rule-content .xml-attr { color: #f39c12; }
        .rule-content .xml-value { color: #4ade80; }
        .rule-content .xml-comment { color: #6c757d; font-style: italic; }
        .rule-content .xml-text { color: #e0e0e0; }
        .rule-tree li > ul { max-height: 5000px; overflow: hidden; transition: max-height 0.3s ease-out, opacity 0.3s ease-out; opacity: 1; }
        .collapsed > ul { max-height: 0 !important; opacity: 0; transition: max-height 0.2s ease-in, opacity 0.2s ease-in; }
        .rule-expand svg { transition: transform 0.2s ease; }
        .collapsed .rule-expand svg { transform: rotate(-90deg); }

        /* Rules Mode Toggle */
        .rules-mode-toggle { display: inline-flex; border-radius: 4px; overflow: hidden; border: 1px solid #0f3460; }
        .rules-mode-toggle button { padding: 6px 14px; background: #1a1a2e; color: #888; border: none; cursor: pointer; font-size: 13px; display: inline-flex; align-items: center; gap: 5px; transition: all 0.2s; }
        .rules-mode-toggle button:not(:last-child) { border-right: 1px solid #0f3460; }
        .rules-mode-toggle button.active { background: #0f3460; color: #4fc3f7; }
        .rules-mode-toggle button:hover:not(.active) { background: #0f0f25; color: #aaa; }
        .rules-mode-toggle button .icon { width: 14px; height: 14px; }

        /* Rules All Table */
        #rulesAllTable th, #rulesAllTable td { font-size: 13px; }
        #rulesAllTable .rule-id-link { color: #4fc3f7; cursor: pointer; text-decoration: none; font-weight: 600; }
        #rulesAllTable .rule-id-link:hover { text-decoration: underline; color: #81d4fa; }
        .rule-type-badge { font-size: 10px; padding: 1px 5px; border-radius: 3px; font-weight: bold; }
        .rule-type-badge.custom { background: #f39c12; color: #000; }
        .rule-type-badge.builtin { background: #555; color: #ccc; }
        .rules-group-tags { display: flex; flex-wrap: wrap; gap: 2px; max-width: 250px; }
        .rules-group-tag { display: inline-block; padding: 1px 4px; border-radius: 3px; font-size: 10px; background: #0f3460; color: #4fc3f7; white-space: nowrap; }
        .rules-toolbar-filters { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
        .rules-toolbar-filters select, .rules-toolbar-filters input[type="number"] { padding: 6px 8px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; font-size: 13px; }
        .rules-toolbar-filters input[type="number"] { width: 60px; }
        .rules-content-search { display: inline-flex; gap: 6px; align-items: center; }
        .rules-content-search input { padding: 6px 8px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; font-size: 13px; min-width: 220px; }
        .rules-content-search select { padding: 6px 8px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; font-size: 13px; }
        .rules-pagination { display: flex; gap: 8px; align-items: center; justify-content: center; padding: 8px 0; flex-shrink: 0; font-size: 13px; color: #888; }
        .rules-pagination button { padding: 4px 10px; background: #0f3460; color: #4fc3f7; border: 1px solid #0f3460; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .rules-pagination button:hover { background: #1a4a7a; }
        .rules-pagination button:disabled { opacity: 0.4; cursor: not-allowed; }
        .rules-pagination input { width: 50px; padding: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; text-align: center; font-size: 12px; }
        .rules-pagination select { padding: 4px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; font-size: 12px; }

        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; }
        .modal.show { display: flex; justify-content: center; align-items: center; }
        .modal-content { background: #16213e; padding: 30px; border-radius: 8px; min-width: 500px; max-width: 800px; max-height: 90vh; overflow-y: auto; }
        .modal-content.resizable { resize: both; overflow: auto; min-width: 600px; min-height: 400px; max-width: 95vw; max-height: 90vh; cursor: default; position: relative; }
        .modal-content.resizable::after { content: ''; position: absolute; bottom: 5px; right: 5px; width: 15px; height: 15px; cursor: se-resize; background: linear-gradient(135deg, transparent 50%, #4fc3f7 50%, #4fc3f7 60%, transparent 60%, transparent 70%, #4fc3f7 70%, #4fc3f7 80%, transparent 80%); pointer-events: none; z-index: 10; }
        .modal-content.wide { max-width: 95vw; width: 1000px; }
        .modal-header { display: flex; justify-content: space-between; margin-bottom: 20px; }
        .modal-close { background: none; border: none; color: #aaa; font-size: 24px; cursor: pointer; }
        .modal-body { margin-bottom: 20px; }
        .modal-content.resizable .modal-body { flex: 1; overflow: auto; display: flex; flex-direction: column; min-height: 0; margin-bottom: 10px; }
        .modal-content.resizable { display: flex; flex-direction: column; }
        .modal-footer { display: flex; gap: 10px; justify-content: flex-end; }

        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; color: #aaa; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; }

        .alert { padding: 15px; border-radius: 4px; margin-bottom: 15px; }
        .alert-success { background: #00c85333; border: 1px solid #00c853; }
        .alert-error { background: #e9456033; border: 1px solid #e94560; }
        .alert-warning { background: #ffc10733; border: 1px solid #ffc107; }

        .loading { text-align: center; padding: 40px; color: #aaa; }
        .spinner { border: 3px solid #0f3460; border-top: 3px solid #4fc3f7; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 10px; }
        .icon-spin { animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .connection-error { text-align: center; padding: 60px 40px; color: #aaa; }
        .connection-error .error-icon { font-size: 48px; margin-bottom: 15px; color: #e94560; }
        .connection-error .error-title { font-size: 18px; color: #e94560; margin-bottom: 10px; font-weight: bold; }
        .connection-error .error-message { font-size: 14px; color: #888; margin-bottom: 20px; }
        .connection-error .retry-btn { padding: 10px 24px; background: #4fc3f7; color: #0a0a1a; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: bold; }
        .connection-error .retry-btn:hover { background: #81d4fa; }
        .api-status.disconnected { background: #e94560; color: #fff; }

        .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; background: #0f3460; }
        .badge-master { background: #9c27b0; color: #fff; }
        .badge-worker { background: #0288d1; color: #fff; }
        .badge-disconnected { background: #e94560; color: #fff; }
        .badge-not-in-cluster { background: #ff9800; color: #fff; }

        /* Service status indicators */
        .service-status { display: flex; flex-wrap: wrap; gap: 4px; max-width: 500px; }
        .service-indicator { display: inline-flex; align-items: center; gap: 4px; padding: 2px 6px; border-radius: 4px; font-size: 11px; background: #0f3460; width: 90px; }
        .service-indicator .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
        .service-indicator .dot.running { background: #00c853; box-shadow: 0 0 4px #00c853; }
        .service-indicator .dot.stopped { background: #e94560; box-shadow: 0 0 4px #e94560; }
        .service-indicator .dot.pending { background: #ffc107; box-shadow: 0 0 4px #ffc107; }
        .service-indicator .dot.unknown { background: #888; }
        .service-indicator .dot.source { background: #4fc3f7; box-shadow: 0 0 4px #4fc3f7; }
        .service-indicator.sync-item { cursor: pointer; width: 80px; }
        .service-indicator.sync-source { width: 80px; opacity: 0.85; }

        .dry-run-notice { background: #ffc10722; border: 1px dashed #ffc107; padding: 10px; border-radius: 4px; margin-bottom: 15px; }

        .selected-count { background: #4fc3f733; padding: 6px 14px; border-radius: 4px; color: #4fc3f7; font-weight: 500; }

        .api-status { font-size: 12px; padding: 4px 8px; border-radius: 4px; }
        .api-status.connected { background: #00c85333; color: #00c853; }
        .api-status.disconnected { background: #e9456033; color: #e94560; }

        .pagination-bar { display: flex; justify-content: space-between; align-items: center; padding: 8px 0 0 0; border-top: 1px solid #0f3460; margin-top: 10px; flex-shrink: 0; }
        .pagination-info { color: #aaa; font-size: 14px; }
        .pagination-controls { display: flex; align-items: center; gap: 10px; }
        .pagination-controls label { color: #aaa; font-size: 14px; display: flex; align-items: center; gap: 8px; }
        .pagination-controls select { padding: 6px 10px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; }
        .pagination-controls .btn { padding: 6px 12px; min-width: auto; }
        .pagination-controls .btn:disabled { opacity: 0.4; cursor: not-allowed; }
        .page-indicator { color: #aaa; font-size: 14px; display: flex; align-items: center; gap: 5px; }
        .page-indicator input { width: 60px; padding: 6px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; text-align: center; }

        #stats-panel table { table-layout: fixed; margin-bottom: 10px; }
        #stats-panel h3 { color: #4fc3f7; margin-bottom: 10px; }

        /* Multi-select dropdown */
        .multi-select { position: relative; display: inline-block; }
        .multi-select-btn { padding: 8px 14px; border: 1px solid #0f3460; background: #1a1a2e; color: #eee; border-radius: 4px; cursor: pointer; font-size: 14px; white-space: nowrap; display: inline-flex; align-items: center; gap: 6px; }
        .multi-select-btn:hover { border-color: #4fc3f7; background: #1f2a4a; }
        .multi-select-btn.active { border-color: #4fc3f7; background: #1f2a4a; }
        .multi-select-btn .icon { width: 12px; height: 12px; color: #888; }
        .multi-select-dropdown { display: none; position: absolute; top: calc(100% + 4px); left: 0; background: #1a1a2e; border: 1px solid #0f3460; border-radius: 6px; max-height: 280px; overflow-y: auto; overflow-x: hidden; z-index: 100; box-shadow: 0 4px 16px rgba(0,0,0,0.4); }
        .multi-select-dropdown.show { display: block; }
        .multi-select-item { padding: 6px 12px; cursor: pointer; font-size: 13px; white-space: nowrap; line-height: 20px; }
        .multi-select-item:hover { background: #0f3460; }
        .multi-select-item input[type="checkbox"] { width: 14px; height: 14px; vertical-align: middle; accent-color: #4fc3f7; cursor: pointer; margin: 0; }
        .multi-select-item-text { vertical-align: middle; margin-left: 8px; }
        .multi-select-clear { padding: 8px 12px; border-top: 1px solid #0f3460; color: #4fc3f7; cursor: pointer; text-align: center; font-size: 13px; }
        .multi-select-clear:hover { background: #0f3460; }
        .filter-badge { background: #4fc3f7; color: #1a1a2e; padding: 2px 7px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-left: 6px; }
        /* Toggle switch with box background */
        .toggle-switch-box { display: flex; align-items: center; gap: 8px; cursor: pointer; user-select: none; background: #0f3460; padding: 6px 12px; border-radius: 6px; border: 1px solid #1a3a5c; }
        .toggle-switch-box:hover { border-color: #4fc3f7; }
        .toggle-switch-box input { display: none; }
        .toggle-switch-box .toggle-slider { width: 36px; height: 20px; background: #444; border-radius: 10px; position: relative; transition: background 0.2s; flex-shrink: 0; }
        .toggle-switch-box .toggle-slider::after { content: ''; position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; background: #888; border-radius: 50%; transition: transform 0.2s, background 0.2s; }
        .toggle-switch-box input:checked + .toggle-slider { background: #4fc3f7; }
        .toggle-switch-box input:checked + .toggle-slider::after { transform: translateX(16px); background: #fff; }
        .toggle-switch-box .toggle-label { color: #aaa; font-size: 13px; white-space: nowrap; }
        .toggle-switch-box input:checked ~ .toggle-label { color: #4fc3f7; }

        /* Export dropdown */
        .export-dropdown { position: relative; display: inline-block; }
        .export-menu { display: none; position: absolute; top: calc(100% + 4px); left: 0; background: #1a1a2e; border: 1px solid #0f3460; border-radius: 6px; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.3); min-width: 80px; }
        .export-menu.show { display: block; }
        .export-item { padding: 8px 14px; cursor: pointer; font-size: 13px; transition: background 0.15s; }
        .export-item:hover { background: #0f3460; }
        .export-item:first-child { border-radius: 6px 6px 0 0; }
        .export-item:last-child { border-radius: 0 0 6px 6px; }

        /* Toast notifications */
        .toast-container { position: fixed; top: 20px; right: 20px; z-index: 2000; display: flex; flex-direction: column; gap: 10px; }
        .toast { padding: 14px 20px; border-radius: 6px; color: #fff; font-size: 14px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); animation: toastIn 0.3s ease-out; max-width: 400px; display: flex; align-items: center; gap: 10px; }
        .toast.success { background: #00c853; }
        .toast.error { background: #e94560; }
        .toast.warning { background: #ffc107; color: #1a1a2e; }
        .toast.info { background: #4fc3f7; color: #1a1a2e; }
        .toast-close { background: none; border: none; color: inherit; font-size: 18px; cursor: pointer; margin-left: auto; opacity: 0.7; }
        .toast-close:hover { opacity: 1; }
        @keyframes toastIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        @keyframes toastOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
    </style>
</head>
<body>
    <!-- Icons from Iconoir (https://iconoir.com/) - MIT License Copyright 2021 Luca Burgio -->
    <svg xmlns="http://www.w3.org/2000/svg" style="display:none;">
        <symbol id="icon-refresh" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21.168 8A10.003 10.003 0 0 0 12 2c-5.185 0-9.449 3.947-9.95 9"/><path d="M17 8h4.4a.6.6 0 0 0 .6-.6V3M2.881 16c1.544 3.532 5.068 6 9.168 6 5.186 0 9.45-3.947 9.951-9"/><path d="M7.05 16h-4.4a.6.6 0 0 0-.6.6V21"/></symbol>
        <symbol id="icon-clock" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 6v6h6"/><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/></symbol>
        <symbol id="icon-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m5 13 4 4L19 7"/></symbol>
        <symbol id="icon-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.4 20H9.6a.6.6 0 0 1-.6-.6V9.6a.6.6 0 0 1 .6-.6h9.8a.6.6 0 0 1 .6.6v9.8a.6.6 0 0 1-.6.6Z"/><path d="M15 9V4.6a.6.6 0 0 0-.6-.6H4.6a.6.6 0 0 0-.6.6v9.8a.6.6 0 0 0 .6.6H9"/></symbol>
        <symbol id="icon-edit" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.363 5.652l1.48-1.48a2 2 0 0 1 2.829 0l1.414 1.414a2 2 0 0 1 0 2.828l-1.48 1.48m-4.243-4.242l-9.616 9.616a2 2 0 0 0-.578 1.238l-.242 2.74a1 1 0 0 0 1.084 1.085l2.74-.242a2 2 0 0 0 1.24-.578l9.615-9.616m-4.243-4.243l4.243 4.243"/></symbol>
        <symbol id="icon-download" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 20h12M12 4v12m0 0l3.5-3.5M12 16l-3.5-3.5"/></symbol>
        <symbol id="icon-restart" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6.677 20.567C2.531 18.021.758 12.758 2.717 8.144 4.875 3.06 10.745.688 15.829 2.846c5.084 2.158 7.456 8.029 5.298 13.113a9.954 9.954 0 0 1-3.962 4.608"/><path d="M17 16v4.4a.6.6 0 0 1-.6.6H12m10-9h-1"/></symbol>
        <symbol id="icon-link" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 11.998C14 9.506 11.683 7 8.857 7H7.143C4.303 7 2 9.238 2 11.998c0 2.378 1.71 4.368 4 4.873m4-4.873c0 2.492 2.317 4.999 5.143 4.999h1.714c2.84 0 5.143-2.237 5.143-4.997 0-2.379-1.71-4.37-4-4.874"/></symbol>
        <symbol id="icon-trash" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 9l-1.995 11.346A2 2 0 0 1 16.035 22h-8.07a2 2 0 0 1-1.97-1.654L4 9m17-3h-5.625M3 6h5.625m0 0V4a2 2 0 0 1 2-2h2.75a2 2 0 0 1 2 2v2m-6.75 0h6.75"/></symbol>
        <symbol id="icon-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 12h6m6 0h-6m0 0V6m0 6v6"/></symbol>
        <symbol id="icon-eye" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4Z"/><path d="M21 12c-1.889 2.991-5.282 6-9 6s-7.111-3.009-9-6c2.299-2.842 4.992-6 9-6s6.701 3.158 9 6Z"/></symbol>
        <symbol id="icon-upload" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 20h12M12 16V4m0 0l3.5 3.5M12 4L8.5 7.5"/></symbol>
        <symbol id="icon-move" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8l4 4-4 4M6 8l-4 4 4 4M2 12h20"/></symbol>
        <symbol id="icon-search" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m17 17 4 4M3 11a8 8 0 1 0 16 0 8 8 0 0 0-16 0Z"/></symbol>
        <symbol id="icon-users" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1 20v-1a7 7 0 0 1 7-7v0a7 7 0 0 1 7 7v1"/><path d="M13 14v0a5 5 0 0 1 5-5v0a5 5 0 0 1 5 5v.5"/><path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Zm10-1a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/></symbol>
        <symbol id="icon-logout" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 12h7m0 0-3 3m3-3-3-3M19 6V5a2 2 0 0 0-2-2H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-1"/></symbol>
        <symbol id="icon-server" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 17.5v-11h12v11H6Z"/><path d="M5 13.5H4a1 1 0 0 0-1 1v3a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1v-3a1 1 0 0 0-1-1h-1"/><path d="M5 10.5H4a1 1 0 0 1-1-1v-3a1 1 0 0 1 1-1h16a1 1 0 0 1 1 1v3a1 1 0 0 1-1 1h-1M6 9h1m-1 6h1"/></symbol>
        <symbol id="icon-stats" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 20v-8m-5 8V10m-5 10v-4M3 3v18h18"/></symbol>
        <symbol id="icon-file" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21.4V2.6a.6.6 0 0 1 .6-.6h11.652a.6.6 0 0 1 .424.176l3.148 3.148a.6.6 0 0 1 .176.424V21.4a.6.6 0 0 1-.6.6H4.6a.6.6 0 0 1-.6-.6Z"/><path d="M16 2v4h4"/></symbol>
        <symbol id="icon-file-code" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21.4V2.6a.6.6 0 0 1 .6-.6h11.652a.6.6 0 0 1 .424.176l3.148 3.148a.6.6 0 0 1 .176.424V21.4a.6.6 0 0 1-.6.6H4.6a.6.6 0 0 1-.6-.6Z"/><path d="M16 2v4h4"/><path d="M9 13l-2 2 2 2m6-4l2 2-2 2"/></symbol>
        <symbol id="icon-folder" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 11V4.6a.6.6 0 0 1 .6-.6h6.178a.6.6 0 0 1 .39.144l3.164 2.712a.6.6 0 0 0 .39.144H21.4a.6.6 0 0 1 .6.6V11M2 11v8.4a.6.6 0 0 0 .6.6h18.8a.6.6 0 0 0 .6-.6V11M2 11h20"/></symbol>
        <symbol id="icon-export" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 19V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/><path d="M8.5 15.5L12 12m0 0l3.5 3.5M12 12v-4"/></symbol>
        <symbol id="icon-agents" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/><circle cx="12" cy="10" r="1" fill="currentColor"/></symbol>
        <symbol id="icon-rename" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3v4M7 3v4M3 9.5h18M4 3h16a1 1 0 0 1 1 1v16a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm5 10h6"/></symbol>
        <symbol id="icon-remove" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9.172 14.828 12.001 12m2.828-2.828L12.001 12m0 0L9.172 9.172M12.001 12l2.828 2.828M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/></symbol>
        <symbol id="icon-add-group" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 10h2m2 0h-2m0 0V8m0 2v2M1 20v-1a7 7 0 0 1 7-7v0a7 7 0 0 1 7 7v1"/><path d="M8 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"/></symbol>
        <symbol id="icon-exclusive" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M6 18.01l.01-.011M6 6.01l.01-.011M2 12.01l.01-.011M18 12.01l.01-.011M12 12.01l.01-.011M2 18.01l.01-.011M2 6.01l.01-.011M22 6v12M12 2v20M12 6.01l.01-.011M12 18.01l.01-.011M6 12.01l.01-.011"/></symbol>
        <symbol id="icon-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10Z"/><path d="M12 8h.01"/><path d="M11 12h1v4h1"/></symbol>
        <symbol id="icon-nav-arrow-down" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></symbol>
        <symbol id="icon-nav-arrow-up" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 15 6-6 6 6"/></symbol>
        <symbol id="icon-undo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4.5 8H15s0 0 0 0 5 0 5 4.706C20 18 15 18 15 18H6.286"/><path d="M7.5 11.5 4 8l3.5-3.5"/></symbol>
        <symbol id="icon-redo" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M19.5 8H9s0 0 0 0-5 0-5 4.706C4 18 9 18 9 18h8.714"/><path d="m16.5 11.5 3.5-3.5-3.5-3.5"/></symbol>
        <symbol id="icon-xmark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6.758 17.243 10.485-10.486m0 10.486L6.758 6.757"/></symbol>
        <symbol id="icon-save" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 20.4V3.6a.6.6 0 0 1 .6-.6h13.686a.6.6 0 0 1 .424.176l3.314 3.314a.6.6 0 0 1 .176.424V20.4a.6.6 0 0 1-.6.6H3.6a.6.6 0 0 1-.6-.6Z"/><path d="M8 3v4h8V3m-4 18v-6H8v6"/></symbol>
        <symbol id="icon-database" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.657 4.03 3 9 3s9-1.343 9-3V5"/><path d="M3 12c0 1.657 4.03 3 9 3s9-1.343 9-3"/></symbol>
        <symbol id="icon-columns" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="18" rx="1"/><rect x="14" y="3" width="7" height="18" rx="1"/></symbol>
        <symbol id="icon-column-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h4m4 0h10M3 12h4m4 0h10M3 18h4m4 0h10"/><circle cx="9" cy="6" r="2"/><circle cx="9" cy="12" r="2"/><circle cx="9" cy="18" r="2"/></symbol>
        <symbol id="icon-package" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2Z"/><path d="M12 4v8l2.5-1.5L17 12V4"/></symbol>
        <symbol id="icon-settings" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z"/><path d="M19.622 10.395l-1.097-2.65L20 6l-2-2-1.735 1.483-2.707-1.113L12.935 2h-1.954l-.632 2.401-2.645 1.115L6 4 4 6l1.453 1.789-1.08 2.657L2 11v2l2.401.656 1.113 2.707L4 18l2 2 1.791-1.46 2.606 1.072L11 22h2l.604-2.387 2.651-1.098C16.697 18.832 18 20 18 20l2-2-1.484-1.734 1.083-2.658L22 13v-2l-2.378-.605Z"/></symbol>
        <symbol id="icon-tree" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v8m0 0l4-4m-4 4l-4-4"/><path d="M3 14h4v6H3zm14 0h4v6h-4zM12 14v-2m0 8v-2m0 0H7m5 0h5"/><rect x="9" y="14" width="6" height="6" rx="1"/></symbol>
        <symbol id="icon-bell" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8.4c0-1.697-.632-3.325-1.757-4.525C15.117 2.675 13.59 2 12 2c-1.591 0-3.117.674-4.243 1.875C6.632 5.075 6 6.703 6 8.4 6 15.867 3 18 3 18h18s-3-2.133-3-9.6Z"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></symbol>
        <symbol id="icon-file-text" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21.4V2.6a.6.6 0 0 1 .6-.6h11.652a.6.6 0 0 1 .424.176l3.148 3.148a.6.6 0 0 1 .176.424V21.4a.6.6 0 0 1-.6.6H4.6a.6.6 0 0 1-.6-.6Z"/><path d="M16 2v4h4"/><path d="M8 10h8m-8 4h8m-8 4h4"/></symbol>
        <symbol id="icon-chevron-right" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></symbol>
        <symbol id="icon-chevron-down" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m6 9 6 6 6-6"/></symbol>
        <symbol id="icon-mail" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M7 9l5 3.5L17 9"/><path d="M2 17V7a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2Z"/></symbol>
    </svg>
    <div class="container">
        <header>
            <h1>JT Wazuh Manager <span style="font-size: 14px; color: #888; font-weight: normal;">v{{ version }}</span></h1>
            <div class="header-right">
                <div class="stats-bar" id="statsBar">
                    <div class="stat-item" onclick="filterByStatus('')" title="Show all agents"><div class="stat-value" id="totalAgents"><span>-</span></div><div class="stat-label">Total Agents</div></div>
                    <div class="stat-item active" onclick="filterByStatus('active')" title="Show active agents"><div class="stat-value" id="activeAgents"><span>-</span></div><div class="stat-label">Active</div></div>
                    <div class="stat-item disconnected" onclick="filterByStatus('disconnected')" title="Show disconnected agents"><div class="stat-value" id="disconnectedAgents"><span>-</span></div><div class="stat-label">Disconnected</div></div>
                    <div class="stat-item pending" onclick="filterByStatus('pending')" title="Show pending agents"><div class="stat-value" id="pendingAgents"><span>-</span></div><div class="stat-label">Pending</div></div>
                </div>
                <div class="user-info">
                    <div><span class="api-status connected">API Connected</span></div>
                    <div><strong>{{ username }}</strong></div>
                    <div id="sessionTimer" style="font-size:11px;color:#888;"></div>
                </div>
                <div class="header-buttons">
                    <button class="btn-settings" onclick="showSettingsModal()"><svg class="icon"><use href="#icon-settings"/></svg>Settings</button>
                    <a href="/logout" class="btn-logout"><svg class="icon"><use href="#icon-logout"/></svg>Logout</a>
                </div>
            </div>
        </header>

        <div class="tabs">
            <button class="tab active" data-tab="agents"><svg class="icon"><use href="#icon-agents"/></svg>Agents</button>
            <button class="tab" data-tab="groups"><svg class="icon"><use href="#icon-folder"/></svg>Groups</button>
            <button class="tab" data-tab="nodes"><svg class="icon"><use href="#icon-server"/></svg>Nodes</button>
            <button class="tab" data-tab="rules"><svg class="icon"><use href="#icon-tree"/></svg>Rules</button>
            <button class="tab" data-tab="packs"><svg class="icon"><use href="#icon-add-group"/></svg>Rule Packs</button>
            <button class="tab" data-tab="inventory"><svg class="icon"><use href="#icon-server"/></svg>Inventory</button>
            <button class="tab" data-tab="stats"><svg class="icon"><use href="#icon-stats"/></svg>Statistics</button>
            <button class="tab" data-tab="users"><svg class="icon"><use href="#icon-users"/></svg>API Users</button>
            <button class="tab" data-tab="logs"><svg class="icon"><use href="#icon-file"/></svg>Logs</button>
        </div>

        <!-- Agents Panel -->
        <div class="panel active" id="agents-panel">
            <div class="toolbar toolbar-row">
                <input type="text" id="agentSearch" placeholder="Search agents...">
                <div class="multi-select" id="statusFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('statusFilter')">Status <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="statusFilterDropdown">
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="active" onchange="onFilterChange()"><span class="multi-select-item-text">Active</span></div>
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="disconnected" onchange="onFilterChange()"><span class="multi-select-item-text">Disconnected</span></div>
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="pending" onchange="onFilterChange()"><span class="multi-select-item-text">Pending</span></div>
                        <div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="never_connected" onchange="onFilterChange()"><span class="multi-select-item-text">Never Connected</span></div>
                        <div class="multi-select-clear" onclick="clearFilter('statusFilter')">Clear</div>
                    </div>
                </div>
                <div class="multi-select" id="groupFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('groupFilter')">Group <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="groupFilterDropdown"></div>
                </div>
                <div class="multi-select" id="osFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('osFilter')">OS <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="osFilterDropdown"></div>
                </div>
                <div class="multi-select" id="versionFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('versionFilter')">Version <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="versionFilterDropdown"></div>
                </div>
                <div class="multi-select" id="nodeFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('nodeFilter')">Node <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="nodeFilterDropdown"></div>
                </div>
                <div class="multi-select" id="syncFilterWrap">
                    <div class="multi-select-btn" onclick="toggleMultiSelect('syncFilter')">Sync <svg class="icon"><use href="#icon-nav-arrow-down"/></svg></div>
                    <div class="multi-select-dropdown" id="syncFilterDropdown"></div>
                </div>
                <div class="toolbar-spacer"></div>
                <button class="btn btn-primary" onclick="refreshAgents()" title="Refresh agent list"><svg class="icon"><use href="#icon-refresh"/></svg></button>
                <div class="multi-select" id="columnsFilterWrap">
                    <button class="btn" onclick="toggleMultiSelect('columnsFilter')" title="Show/Hide Columns"><svg class="icon"><use href="#icon-column-settings"/></svg></button>
                    <div class="multi-select-dropdown" id="columnsFilterDropdown">
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'id')"><input type="checkbox" checked data-col="id"><span class="multi-select-item-text">ID</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'name')"><input type="checkbox" checked data-col="name"><span class="multi-select-item-text">Name</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'ip')"><input type="checkbox" checked data-col="ip"><span class="multi-select-item-text">IP</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'status')"><input type="checkbox" checked data-col="status"><span class="multi-select-item-text">Status</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'os')"><input type="checkbox" checked data-col="os"><span class="multi-select-item-text">OS</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'version')"><input type="checkbox" checked data-col="version"><span class="multi-select-item-text">Version</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'group')"><input type="checkbox" checked data-col="group"><span class="multi-select-item-text">Group</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'node_name')"><input type="checkbox" checked data-col="node_name"><span class="multi-select-item-text">Node</span></div>
                        <div class="multi-select-item" onclick="toggleColumnItem(event, this, 'synced')"><input type="checkbox" checked data-col="synced"><span class="multi-select-item-text">Sync</span></div>
                    </div>
                </div>
                <button class="btn" id="btnUpgradeProgress" style="background:#17a2b8;color:#fff;" onclick="showAllUpgradeProgress()" title="View upgrade progress"><svg class="icon"><use href="#icon-clock"/></svg></button>
                <div class="export-dropdown">
                    <button class="btn" onclick="toggleExportMenu()" title="Export to file"><svg class="icon"><use href="#icon-download"/></svg></button>
                    <div class="export-menu" id="exportMenu">
                        <div class="export-item" onclick="exportData('csv')">CSV</div>
                        <div class="export-item" onclick="exportData('tsv')">TSV</div>
                        <div class="export-item" onclick="exportData('json')">JSON</div>
                    </div>
                </div>
                <label class="toggle-switch-box" title="Show Queue DB column (loads from filesystem)">
                    <input type="checkbox" id="toggleQueueDB" onchange="toggleQueueDB()">
                    <span class="toggle-slider"></span>
                    <span class="toggle-label">Queue DB</span>
                </label>
                <label class="toggle-switch-box" title="Preview changes without executing">
                    <input type="checkbox" id="dryRunMode">
                    <span class="toggle-slider"></span>
                    <span class="toggle-label">Dry Run</span>
                </label>
                <button class="btn btn-sm" onclick="showRegisterAgentsModal()" title="Pre-register agents and get their keys"><svg class="icon"><use href="#icon-add-group"/></svg>Register Agents</button>
            </div>
            <div class="action-bar-container">
                <div class="distribution-bar" id="distributionBar">
                    <select id="distributionType" onchange="updateDistributionBar(true)">
                        <option value="status">Status</option>
                        <option value="os">OS</option>
                        <option value="version">Version</option>
                        <option value="group">Group</option>
                        <option value="node">Node</option>
                        <option value="sync">Sync</option>
                    </select>
                    <div class="distribution-chart" id="distributionChart"></div>
                </div>
                <div class="action-bar" id="actionBar">
                    <div class="selected-count" id="selectedCount">Selected: <span>0</span></div>
                    <button class="btn" id="btnClearSelection" onclick="clearSelection()" title="Clear selection"><svg class="icon"><use href="#icon-xmark"/></svg>Exit Selection</button>
                    <button class="btn btn-success" id="btnAddToGroup" onclick="showAddToGroupModal()"><svg class="icon"><use href="#icon-add-group"/></svg>Add to Group</button>
                    <button class="btn btn-warning" id="btnRemoveFromGroup" onclick="showRemoveFromGroupModal()"><svg class="icon"><use href="#icon-remove"/></svg>Remove from Group</button>
                    <button class="btn btn-primary" id="btnMoveToNode" onclick="showMoveToNodeModal()"><svg class="icon"><use href="#icon-move"/></svg>Move to Node</button>
                    <button class="btn btn-warning" id="btnRestart" onclick="restartSelected()"><svg class="icon"><use href="#icon-restart"/></svg>Restart</button>
                    <button class="btn btn-primary" id="btnReconnect" onclick="reconnectSelected()"><svg class="icon"><use href="#icon-link"/></svg>Reconnect</button>
                    <button class="btn" id="btnUpgrade" style="background:#fd7e14;color:#fff;" onclick="upgradeSelected()"><svg class="icon"><use href="#icon-upload"/></svg>Upgrade</button>
                    <button class="btn" id="btnActiveResponse" style="background:#00897b;color:#fff;" onclick="showActiveResponseModal()"><svg class="icon"><use href="#icon-bell"/></svg>Active Response</button>
                    <button class="btn" id="btnCleanQueueDB" style="background:#795548;color:#fff;" onclick="cleanQueueDBSelected()"><svg class="icon"><use href="#icon-trash"/></svg>Clean Queue DB</button>
                    <button class="btn btn-danger" id="btnDelete" onclick="deleteSelected()"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button>
                </div>
            </div>
            <div class="table-container">
                <table id="agentsTable">
                    <thead>
                        <tr>
                            <th class="checkbox-cell"><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                            <th></th>
                            <th class="sortable" data-sort="id" data-col="id" onclick="sortAgents('id')">ID<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="name" data-col="name" onclick="sortAgents('name')">Name<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="ip" data-col="ip" onclick="sortAgents('ip')">IP<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="status" data-col="status" onclick="sortAgents('status')">Status<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="os" data-col="os" onclick="sortAgents('os')">OS<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="version" data-col="version" onclick="sortAgents('version')">Version<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="group" data-col="group" onclick="sortAgents('group')">Group<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="node_name" data-col="node_name" onclick="sortAgents('node_name')">Node<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="synced" data-col="synced" onclick="sortAgents('synced')">Sync<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable queue-db-cell" data-sort="queue_size" data-col="queue_size" onclick="sortAgents('queue_size')" style="display:none">Queue DB<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                        </tr>
                    </thead>
                    <tbody id="agentsBody"></tbody>
                </table>
            </div>
            <div class="pagination-bar">
                <div class="pagination-info">
                    <span id="paginationInfo">Showing 0 - 0 of 0</span>
                </div>
                <div class="pagination-controls">
                    <label>Per page:
                        <select id="pageSizeSelect" onchange="changePageSize(this.value)">
                            <option value="50">50</option>
                            <option value="100" selected>100</option>
                            <option value="500">500</option>
                            <option value="1000">1000</option>
                            <option value="5000">5000</option>
                        </select>
                    </label>
                    <button class="btn" id="btnFirstPage" onclick="goToPage(1)">&laquo;</button>
                    <button class="btn" id="btnPrevPage" onclick="prevPage()">&lsaquo; Prev</button>
                    <span class="page-indicator">Page <input type="number" id="pageInput" min="1" value="1" onchange="goToPage(this.value)"> of <span id="totalPages">1</span></span>
                    <button class="btn" id="btnNextPage" onclick="nextPage()">Next &rsaquo;</button>
                    <button class="btn" id="btnLastPage" onclick="goToPage(999999)">&raquo;</button>
                </div>
            </div>
        </div>

        <!-- Groups Panel -->
        <div class="panel" id="groups-panel">
            <div class="toolbar">
                <button class="btn btn-success" onclick="showCreateGroupModal()"><svg class="icon"><use href="#icon-plus"/></svg>Create Group</button>
                <button class="btn btn-primary" onclick="refreshGroups()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="table-container">
                <table id="groupsTable">
                    <thead>
                        <tr>
                            <th class="sortable" data-sort="name" onclick="sortGroups('name')">Group Name<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th class="sortable" data-sort="count" style="text-align:center" onclick="sortGroups('count')">Agent Count<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                            <th>Agent Actions</th>
                            <th>Group Actions</th>
                        </tr>
                    </thead>
                    <tbody id="groupsBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Nodes Panel -->
        <div class="panel" id="nodes-panel">
            <div class="toolbar">
                <button class="btn" style="background:#607d8b;color:#fff;" onclick="showNodeConfigDiff()" title="Compare each node's ossec.conf against the master"><svg class="icon"><use href="#icon-file-code"/></svg>Config Diff</button>
                <button class="btn btn-primary" onclick="refreshNodes()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="table-container">
                <table id="nodesTable">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th style="text-align:center">Type</th>
                            <th style="text-align:center">Version</th>
                            <th>IP</th>
                            <th style="text-align:center">Agents</th>
                            <th>Services</th>
                            <th>Sync Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="nodesBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Rules Panel -->
        <div class="panel" id="rules-panel">
            <div class="toolbar" style="gap:8px;">
                <div class="rules-mode-toggle">
                    <button class="active" onclick="switchRulesMode('hierarchy')" id="rulesModeHierarchy"><svg class="icon"><use href="#icon-tree"/></svg>Hierarchy</button>
                    <button onclick="switchRulesMode('all')" id="rulesModeAll"><svg class="icon"><use href="#icon-file-text"/></svg>All Rules</button>
                    <button onclick="switchRulesMode('decoders')" id="rulesModeDecoders"><svg class="icon"><use href="#icon-file"/></svg>Decoders</button>
                    <button onclick="switchRulesMode('lists')" id="rulesModeLists"><svg class="icon"><use href="#icon-folder"/></svg>CDB Lists</button>
                    <button onclick="switchRulesMode('logtest')" id="rulesModeLogtest"><svg class="icon"><use href="#icon-search"/></svg>Log Test</button>
                </div>
                <span id="rulesHierarchyControls" style="display:contents;">
                    <div class="search-box" style="flex:1;max-width:400px;">
                        <input type="text" id="ruleIdSearch" placeholder="Rule ID (100001) or file name (zenarmor, adguard-rule.xml)" style="width:100%;padding:8px 12px;border:1px solid #333;border-radius:4px;background:#1a1a2e;color:#fff;" onkeydown="if(event.key==='Enter')searchRuleHierarchy()">
                    </div>
                    <button class="btn btn-primary" onclick="searchRuleHierarchy()"><svg class="icon"><use href="#icon-search"/></svg>Search</button>
                    <button class="btn" onclick="clearRuleSearch()"><svg class="icon"><use href="#icon-xmark"/></svg>Clear</button>
                    <button class="btn" onclick="expandAllRules()" title="Expand All"><svg class="icon"><use href="#icon-nav-arrow-down"/></svg>Expand</button>
                    <button class="btn" onclick="collapseAllRules()" title="Collapse All"><svg class="icon"><use href="#icon-nav-arrow-up"/></svg>Collapse</button>
                    <span id="ruleSearchStatus" style="margin-left:15px;color:#888;font-size:13px;"></span>
                </span>
                <span id="rulesAllControls" style="display:none;contents;">
                    <input type="text" id="rulesAllSearch" placeholder="Search rules..." style="padding:8px 12px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;min-width:200px;" oninput="filterAllRulesDebounced()">
                    <div class="rules-toolbar-filters">
                        <span style="color:#888;font-size:12px;">Level:</span>
                        <input type="number" id="rulesLevelMin" min="0" max="16" placeholder="Min" onchange="renderAllRules()">
                        <span style="color:#666;">-</span>
                        <input type="number" id="rulesLevelMax" min="0" max="16" placeholder="Max" onchange="renderAllRules()">
                        <select id="rulesFileFilter" onchange="renderAllRules()"><option value="">All Files</option></select>
                        <select id="rulesTypeFilter" onchange="renderAllRules()">
                            <option value="">All Types</option>
                            <option value="custom">Custom</option>
                            <option value="builtin">Built-in</option>
                        </select>
                    </div>
                    <button class="btn btn-primary btn-sm" onclick="loadAllRules()" title="Refresh"><svg class="icon"><use href="#icon-refresh"/></svg></button>
                    <span class="rules-content-search">
                        <input type="text" id="rulesContentSearch" placeholder="Search rule content..." onkeydown="if(event.key==='Enter')searchRulesContent()">
                        <select id="rulesContentMatch" title="Keyword mode">
                            <option value="all">Match all</option>
                            <option value="any">Match any</option>
                        </select>
                        <button class="btn btn-primary btn-sm" onclick="searchRulesContent()" title="Search inside every rule's XML"><svg class="icon"><use href="#icon-search"/></svg>Content</button>
                    </span>
                    <span id="rulesAllStatus" style="color:#888;font-size:13px;"></span>
                    <span id="rulesParseWarn" style="font-size:13px;"></span>
                </span>
                <span id="rulesDecoderControls" style="display:none;">
                    <input type="text" id="decoderSearch" placeholder="Search decoders..." style="padding:8px 12px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;min-width:220px;" onkeydown="if(event.key==='Enter')loadDecoders()">
                    <button class="btn btn-primary btn-sm" onclick="loadDecoders()"><svg class="icon"><use href="#icon-search"/></svg>Search</button>
                    <button class="btn btn-sm" onclick="document.getElementById('decoderSearch').value='';loadDecoders()"><svg class="icon"><use href="#icon-xmark"/></svg>Clear</button>
                    <span id="decoderStatus" style="color:#888;font-size:13px;"></span>
                </span>
                <span id="rulesListsControls" style="display:none;">
                    <button class="btn btn-primary btn-sm" onclick="loadCdbLists()" title="Refresh"><svg class="icon"><use href="#icon-refresh"/></svg></button>
                    <button class="btn btn-success btn-sm" onclick="editCdbList('')"><svg class="icon"><use href="#icon-add-group"/></svg>New List</button>
                    <span id="cdbStatus" style="color:#888;font-size:13px;"></span>
                </span>
                <button class="btn btn-sm" style="background:#00897b;color:#fff;margin-left:auto;" onclick="reloadClusterRuleset()" title="Apply rule changes on every cluster node without restarting"><svg class="icon"><use href="#icon-refresh"/></svg>Reload Ruleset</button>
                <span id="rulesLogtestControls" style="display:none;">
                    <span style="color:#888;font-size:12px;">Paste a log line and see which rule and decoder match it.</span>
                </span>
            </div>
            <!-- Hierarchy View -->
            <div id="rulesHierarchyView" style="flex:1;min-height:0;display:flex;flex-direction:column;overflow:hidden;">
                <div style="padding:10px 15px 0 15px;color:#888;font-size:12px;flex-shrink:0;">
                    Search by Rule ID to view the rule hierarchy (parent-child relationships via if_sid/if_matched_sid/if_group), or by rule file name to see everything that file contains. Click on a rule to view its XML content.
                </div>
                <div class="rules-content" style="padding:15px;">
                    <div id="ruleTreeContainer" style="min-height:200px;">
                        <div style="color:#888;text-align:center;padding:40px;">
                            <svg class="icon" style="width:48px;height:48px;opacity:0.5;margin-bottom:15px;"><use href="#icon-tree"/></svg>
                            <p>Enter a Rule ID to view its hierarchy and relationships, or a rule file name to list its rules.</p>
                            <p style="font-size:12px;margin-top:10px;">The tree will show parent rules (if_sid, if_matched_sid) and child rules.</p>
                        </div>
                    </div>
                </div>
            </div>
            <!-- Decoders View -->
            <div id="rulesDecoderView" style="display:none;flex:1;overflow:hidden;flex-direction:column;">
                <div class="table-container" style="flex:1;overflow-y:auto;min-height:0;">
                    <table id="decodersTable">
                        <thead><tr>
                            <th style="width:220px;">Name</th>
                            <th style="width:90px;">Position</th>
                            <th>Parent</th>
                            <th style="width:260px;">File</th>
                            <th style="width:70px;">Type</th>
                        </tr></thead>
                        <tbody id="decodersBody">
                            <tr><td colspan="5" style="text-align:center;color:#888;padding:40px;">Click Decoders to load.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <!-- CDB Lists View -->
            <div id="rulesListsView" style="display:none;flex:1;overflow:hidden;flex-direction:column;">
                <div class="table-container" style="flex:1;overflow-y:auto;min-height:0;">
                    <table id="cdbTable">
                        <thead><tr>
                            <th style="width:280px;">List</th>
                            <th>Path</th>
                            <th style="width:70px;">Type</th>
                            <th style="width:170px;">Actions</th>
                        </tr></thead>
                        <tbody id="cdbBody">
                            <tr><td colspan="4" style="text-align:center;color:#888;padding:40px;">Click CDB Lists to load.</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <!-- Log Test View -->
            <div id="rulesLogtestView" style="display:none;flex:1;overflow:auto;min-height:0;flex-direction:column;padding:15px;">
                <div style="display:flex;gap:10px;align-items:center;margin-bottom:10px;flex-wrap:wrap;">
                    <label style="color:#888;font-size:13px;">Format</label>
                    <select id="logtestFormat" style="padding:6px 8px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;">
                        <option value="syslog" selected>syslog</option>
                        <option value="json">json</option>
                        <option value="eventchannel">eventchannel</option>
                        <option value="audit">audit</option>
                        <option value="command">command</option>
                        <option value="full_command">full_command</option>
                        <option value="multi-line">multi-line</option>
                        <option value="snort-full">snort-full</option>
                        <option value="squid">squid</option>
                        <option value="iis">iis</option>
                        <option value="mysql_log">mysql_log</option>
                        <option value="postgresql_log">postgresql_log</option>
                    </select>
                    <label style="color:#888;font-size:13px;">Location</label>
                    <input type="text" id="logtestLocation" value="stdin" style="width:200px;padding:6px 8px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;">
                    <button class="btn btn-primary btn-sm" onclick="runLogtest()"><svg class="icon"><use href="#icon-search"/></svg>Run Test</button>
                    <button class="btn btn-sm" onclick="clearLogtest()"><svg class="icon"><use href="#icon-xmark"/></svg>Clear</button>
                    <span id="logtestStatus" style="color:#888;font-size:12px;"></span>
                </div>
                <textarea id="logtestEvent" placeholder="Paste one log line here" style="width:100%;height:110px;background:#0a0a15;color:#eee;border:1px solid #1a3a6e;border-radius:4px;padding:10px;font-family:monospace;font-size:12px;"></textarea>
                <div id="logtestResult" style="margin-top:12px;"></div>
            </div>
            <!-- All Rules View -->
            <div id="rulesAllView" style="display:none;flex:1;overflow:hidden;flex-direction:column;">
                <div class="table-container" style="flex:1;overflow-y:auto;min-height:0;">
                    <table id="rulesAllTable">
                        <thead>
                            <tr>
                                <th class="sortable" onclick="sortAllRules('id')" style="width:90px;">Rule ID <svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                                <th class="sortable" onclick="sortAllRules('level')" style="width:65px;">Level <svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                                <th class="sortable" onclick="sortAllRules('description')">Description <svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                                <th class="sortable" onclick="sortAllRules('group')" style="width:200px;">Groups <svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                                <th class="sortable" onclick="sortAllRules('file')" style="width:180px;">File <svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg></th>
                                <th style="width:70px;">Type</th>
                            </tr>
                        </thead>
                        <tbody id="rulesAllBody">
                            <tr><td colspan="6" style="text-align:center;color:#888;padding:40px;">Click "All Rules" to load all rules.</td></tr>
                        </tbody>
                    </table>
                </div>
                <div class="rules-pagination" id="rulesPagination">
                    <button onclick="rulesGoToPage(1)" title="First">&#171;</button>
                    <button onclick="rulesPrevPage()">&#8249; Prev</button>
                    <span id="rulesPaginationInfo">-</span>
                    <span>Page <input type="number" id="rulesPageInput" value="1" min="1" onchange="rulesGoToPage(parseInt(this.value))"> / <span id="rulesTotalPages">1</span></span>
                    <button onclick="rulesNextPage()">Next &#8250;</button>
                    <button onclick="rulesGoToPage(rulesTotalPagesNum)" title="Last">&#187;</button>
                    <select id="rulesPageSizeSelect" onchange="rulesChangePageSize(parseInt(this.value))">
                        <option value="50">50/page</option>
                        <option value="100" selected>100/page</option>
                        <option value="200">200/page</option>
                        <option value="500">500/page</option>
                    </select>
                </div>
            </div>
        </div>

        <!-- Stats Panel -->
        <div class="panel" id="packs-panel">
            <div class="toolbar" style="gap:8px;">
                <span style="color:#888;font-size:12px;">Rule series maintained by Jason Tools. Each pack bundles rules, decoders and CDB lists, and can be removed again.</span>
                <button class="btn btn-primary btn-sm" style="margin-left:auto;" onclick="refreshPacks()" title="Refresh"><svg class="icon"><use href="#icon-refresh"/></svg></button>
                <span id="packsStatus" style="color:#888;font-size:13px;"></span>
            </div>
            <div class="table-container" style="flex:1;overflow:auto;min-height:0;">
                <table id="packsTable">
                    <thead><tr>
                        <th style="width:230px;">Pack</th>
                        <th>Description</th>
                        <th style="width:120px;">Rule IDs</th>
                        <th style="width:80px;">Version</th>
                        <th style="width:110px;">Status</th>
                        <th style="width:200px;">Actions</th>
                    </tr></thead>
                    <tbody id="packsBody">
                        <tr><td colspan="6" style="text-align:center;color:#888;padding:40px;">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="panel" id="inventory-panel">
            <div class="toolbar" style="gap:8px;">
                <select id="invType" onchange="onInventoryTypeChange()" style="padding:8px 10px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;">
                    <option value="packages">Packages</option>
                    <option value="ports">Open Ports</option>
                    <option value="processes">Processes</option>
                    <option value="services">Services</option>
                    <option value="users">Local Users</option>
                    <option value="hotfixes">Hotfixes</option>
                    <option value="netiface">Network Interfaces</option>
                    <option value="os">Operating System</option>
                    <option value="browser_extensions">Browser Extensions</option>
                </select>
                <input type="text" id="invQuery" placeholder="Search across agents..." style="padding:8px 12px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;min-width:240px;" onkeydown="if(event.key==='Enter')runInventorySearch()">
                <select id="invScope" style="padding:8px 10px;border:1px solid #0f3460;background:#1a1a2e;color:#eee;border-radius:4px;">
                    <option value="active">Active agents</option>
                    <option value="all">All agents</option>
                    <option value="selected">Selected agents</option>
                </select>
                <button class="btn btn-primary" onclick="runInventorySearch()"><svg class="icon"><use href="#icon-search"/></svg>Search</button>
                <button class="btn" onclick="exportInventoryCsv()" title="Export results as CSV"><svg class="icon"><use href="#icon-download"/></svg>CSV</button>
                <span id="invStatus" style="color:#888;font-size:13px;"></span>
                <span id="invWarn" style="font-size:13px;"></span>
            </div>
            <div class="table-container" style="flex:1;overflow:auto;min-height:0;">
                <table id="invTable">
                    <thead><tr id="invHead"><th>Agent</th><th>Result</th></tr></thead>
                    <tbody id="invBody">
                        <tr><td colspan="2" style="text-align:center;color:#888;padding:40px;">Pick a category and search to see which agents match.</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="panel" id="stats-panel">
            <div class="toolbar">
                <button class="btn btn-primary" onclick="refreshStats()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="stats-content" id="statsContent"></div>
        </div>

        <!-- Users Panel -->
        <div class="panel" id="users-panel">
            <div class="toolbar">
                <button class="btn btn-success" onclick="showCreateUserModal()"><svg class="icon"><use href="#icon-plus"/></svg>Create User</button>
                <button class="btn btn-primary" onclick="refreshUsers()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            </div>
            <div class="table-container">
                <table id="usersTable">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Roles</th>
                            <th>Allow Run As</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="usersBody"></tbody>
                </table>
            </div>
        </div>

        <!-- Logs Panel -->
        <div class="panel" id="logs-panel">
            <div class="toolbar">
                <button class="btn btn-primary" onclick="refreshLogs()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
                <select id="logLines" onchange="refreshLogs()">
                    <option value="50">Last 50 lines</option>
                    <option value="100" selected>Last 100 lines</option>
                    <option value="200">Last 200 lines</option>
                    <option value="500">Last 500 lines</option>
                    <option value="1000">Last 1000 lines</option>
                </select>
                <button class="btn" onclick="downloadLogs()"><svg class="icon"><use href="#icon-download"/></svg>Download Full Log</button>
                <span style="margin-left:auto;color:#888;font-size:12px;">
                    <strong>Log file:</strong> <code id="logFilePath" style="color:#4fc3f7;">-</code>
                    <span id="logFileInfo" style="margin-left:10px;"></span>
                </span>
            </div>
            <div class="log-container" id="logContainer">
                <pre id="logContent" style="padding:15px;background:#0a0a15;border-radius:4px;font-size:12px;line-height:1.5;white-space:pre-wrap;word-wrap:break-word;">Click Refresh to load logs...</pre>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div class="modal" id="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Modal</h3>
                <button class="modal-close" onclick="closeModal()"><svg class="icon" style="width:20px;height:20px;"><use href="#icon-xmark"/></svg></button>
            </div>
            <div class="modal-body" id="modalBody"></div>
            <div class="modal-footer" id="modalFooter"></div>
        </div>
    </div>

    <!-- Footer -->
    <footer style="text-align:center;padding:5px;color:#555;font-size:12px;flex-shrink:0;">
        by <a href="https://github.com/jasoncheng7115/jt-wazuh-mgr" target="_blank" style="color:#666;text-decoration:none;">Jason Cheng (Jason Tools)</a>
    </footer>

    <!-- Toast Container -->
    <div class="toast-container" id="toastContainer"></div>

    <script>
        let agents = [];
        let groups = [];
        let selectedAgents = new Set();
        let sortColumn = 'id';
        let sortDirection = 'asc';
        let groupSortColumn = 'name';
        let groupSortDirection = 'asc';
        let queueSizes = {};
        let queueSizeNode = '';
        let queueOtherNodes = [];
        let queueLoadedNodes = [];
        let showQueueDB = false;  // Queue DB is disabled by default for performance
        let validNodeNames = [];  // List of valid node names in current cluster
        let managerVersion = '';  // Manager/master node version for comparison

        // Session timer - uses web session expiration (configurable, default 2hr)
        // JWT token is auto-refreshed before expiry to keep the session alive
        let apiTokenExp = {{ token_exp }};  // JWT token expiration timestamp
        const tokenIat = {{ token_iat }};  // JWT issued at timestamp
        const sessionExp = {{ session_exp }};  // Web session expiration timestamp
        let sessionTimerInterval = null;
        let isRefreshingToken = false;  // Prevent concurrent refresh requests
        let refreshFailCount = 0;       // Stop retrying after too many failures
        const maxRefreshFails = 3;      // Max consecutive failures before giving up

        function updateSessionTimer() {
            const timerEl = document.getElementById('sessionTimer');
            if (!timerEl || !sessionExp) return;

            const now = Math.floor(Date.now() / 1000);
            const remaining = sessionExp - now;

            // Auto-refresh JWT token when it's about to expire (< 2 min remaining)
            // but only if the web session is still valid and we haven't exceeded retry limit
            if (apiTokenExp && !isRefreshingToken && refreshFailCount < maxRefreshFails) {
                const tokenRemaining = apiTokenExp - now;
                if (tokenRemaining < 120 && remaining > 0) {
                    isRefreshingToken = true;
                    fetch('/api/session/refresh', { method: 'POST' })
                        .then(r => r.json())
                        .then(data => {
                            if (data.token_exp) {
                                apiTokenExp = data.token_exp;
                                refreshFailCount = 0;
                                console.log('[Session] JWT token refreshed, new expiry: ' + new Date(data.token_exp * 1000).toLocaleTimeString());
                            } else if (data.session_expired) {
                                // Session expired on server side, redirect to login
                                window.location.href = '/logout';
                            } else {
                                refreshFailCount++;
                                console.warn('[Session] Token refresh failed (' + refreshFailCount + '/' + maxRefreshFails + '):', data.error || 'unknown');
                                if (refreshFailCount >= maxRefreshFails) {
                                    console.error('[Session] Token refresh permanently failed, will not retry');
                                }
                            }
                        })
                        .catch(err => {
                            refreshFailCount++;
                            console.error('[Session] Token refresh error (' + refreshFailCount + '/' + maxRefreshFails + '):', err);
                        })
                        .finally(() => { isRefreshingToken = false; });
                }
            }

            if (remaining <= 0) {
                timerEl.innerHTML = '<span style="color:#e94560;">Session expired</span>';
                clearInterval(sessionTimerInterval);
                showToast('Session expired. Redirecting to login...', 'warning');
                setTimeout(() => { window.location.href = '/logout'; }, 2000);
                return;
            }

            const hrs = Math.floor(remaining / 3600);
            const mins = Math.floor((remaining % 3600) / 60);
            const secs = remaining % 60;
            const timeStr = (hrs > 0 ? hrs + ':' + String(mins).padStart(2, '0') : mins) + ':' + String(secs).padStart(2, '0');

            if (remaining <= 60) {
                timerEl.innerHTML = '<span style="color:#e94560;">Expires: ' + timeStr + '</span>';
            } else if (remaining <= 180) {
                timerEl.innerHTML = '<span style="color:#ffc107;">Expires: ' + timeStr + '</span>';
            } else {
                timerEl.textContent = 'Expires: ' + timeStr;
            }
        }

        // Start session timer on page load
        if (sessionExp) {
            updateSessionTimer();
            sessionTimerInterval = setInterval(updateSessionTimer, 1000);
        }

        // Column visibility - load from localStorage or use defaults
        const defaultColumns = { id: true, name: true, ip: true, status: true, os: true, version: true, group: true, node_name: true, synced: true };
        let visibleColumns = JSON.parse(localStorage.getItem('agentColumnsVisibility')) || { ...defaultColumns };

        // Initialize column visibility on page load
        function initColumnVisibility() {
            // Apply stored visibility to header checkboxes
            document.querySelectorAll('#columnsFilterDropdown input[data-col]').forEach(cb => {
                const col = cb.dataset.col;
                cb.checked = visibleColumns[col] !== false;
            });
            applyColumnVisibility();
        }

        // Toggle column visibility (for multi-select style)
        function toggleColumnItem(event, elem, col) {
            const checkbox = elem.querySelector('input[type="checkbox"]');
            // Only toggle if click was not directly on the checkbox (checkbox handles itself)
            if (event.target.tagName !== 'INPUT') {
                checkbox.checked = !checkbox.checked;
            }
            visibleColumns[col] = checkbox.checked;
            localStorage.setItem('agentColumnsVisibility', JSON.stringify(visibleColumns));
            applyColumnVisibility();
        }

        // Apply column visibility to table
        function applyColumnVisibility() {
            // Apply to headers
            document.querySelectorAll('#agentsTable th[data-col]').forEach(th => {
                const col = th.dataset.col;
                if (col === 'queue_size') return; // Queue DB has its own toggle
                th.style.display = visibleColumns[col] === false ? 'none' : '';
            });
            // Apply to body cells - re-render will handle this
            renderAgents();
        }

        // Pagination
        let currentPage = 1;
        let pageSize = 100;  // Default 100 items per page

        // Toast notification system
        function showToast(message, type = 'info', duration = 4000) {
            const container = document.getElementById('toastContainer');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            toast.innerHTML = `
                <span>${message}</span>
                <button class="toast-close" onclick="this.parentElement.remove()"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-xmark"/></svg></button>
            `;
            container.appendChild(toast);

            // Auto remove after duration
            setTimeout(() => {
                toast.style.animation = 'toastOut 0.3s ease-out forwards';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        function formatBytes(bytes) {
            if (!bytes || bytes === 0) return '-';
            const units = ['B', 'KB', 'MB', 'GB'];
            let i = 0;
            while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
            return bytes.toFixed(1) + ' ' + units[i];
        }

        function formatQueueSize(agent) {
            const entries = agent.queue_entries || [];

            if (entries.length > 0) {
                if (entries.length === 1) {
                    // Single node - show size with node name
                    const e = entries[0];
                    return `<div class="queue-entry"><span class="queue-size">${formatBytes(e.size)}</span><span class="queue-node">${escapeHtml(e.node)}</span></div>`;
                } else {
                    // Multiple nodes - show each entry aligned
                    return entries.map(e =>
                        `<div class="queue-entry"><span class="queue-size">${formatBytes(e.size)}</span><span class="queue-node">${escapeHtml(e.node)}</span></div>`
                    ).join('');
                }
            }

            // Check if agent is on a node we don't have queue data for
            const agentNode = agent.node_name || '';
            const otherNode = queueOtherNodes.find(n => n.name === agentNode);
            if (otherNode && agentNode !== queueSizeNode && !queueLoadedNodes.includes(agentNode)) {
                return `<a href="#" onclick="showSSHSetupTutorial('${escapeHtml(agentNode)}', '${escapeHtml(otherNode.ip)}'); return false;" style="color:#f39c12;text-decoration:underline;cursor:pointer;" title="SSH access required for ${escapeHtml(agentNode)}">SSH required</a>`;
            }

            return '-';
        }

        function formatNodeName(nodeName) {
            if (!nodeName) return '-';

            const escaped = escapeHtml(nodeName);

            // Check if this node exists in the current cluster
            if (validNodeNames.length > 0 && !validNodeNames.includes(nodeName)) {
                return `<span style="color:#e94560;text-decoration:line-through;" title="Node '${escaped}' no longer exists in cluster">${escaped}</span>`;
            }

            return escaped;
        }

        function formatGroupLabels(groupStr) {
            if (!groupStr || groupStr.trim() === '') return '-';
            const groups = groupStr.split(',').map(g => g.trim()).filter(g => g);
            if (groups.length === 0) return '-';
            return groups.map(g => `<span class="group-label">${escapeHtml(g)}</span>`).join(' ');
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

        // Format file size in human-readable format
        function formatFileSize(bytes) {
            if (!bytes || bytes === 0) return '0 B';
            const units = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(1024));
            const size = (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
            return size + ' ' + units[i];
        }

        // Parse a version string into numeric parts.
        // Accepts "4.14.7", "v4.14.7" and "Wazuh v4.14.7"; unparsable -> [0].
        function parseVersion(ver) {
            const m = String(ver == null ? '' : ver).match(/(\\d+(?:\\.\\d+)*)/);
            return m ? m[1].split('.').map(Number) : [0];
        }

        // Compare version strings (e.g., "4.14.7" vs "4.9.0").
        // Returns: -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
        // Parts are compared as NUMBERS, so 4.14.7 correctly ranks above 4.9.0
        // (a plain string compare would get this backwards).
        function compareVersions(v1, v2) {
            const a = parseVersion(v1), b = parseVersion(v2);
            const len = Math.max(a.length, b.length);
            for (let i = 0; i < len; i++) {
                const p1 = a[i] || 0, p2 = b[i] || 0;
                if (p1 < p2) return -1;
                if (p1 > p2) return 1;
            }
            return 0;
        }

        // Format agent version with color coding
        function formatAgentVersion(version) {
            if (!version) return '-';
            const v = escapeHtml(version);
            if (!managerVersion) return v;
            const cmp = compareVersions(version, managerVersion);
            if (cmp < 0) {
                // Older than manager - show in orange/warning color
                return `<span style="color:#fd7e14;" title="Older than manager (${managerVersion})">${v}</span>`;
            } else if (cmp > 0) {
                // Newer than manager - show in cyan (unusual)
                return `<span style="color:#17a2b8;" title="Newer than manager (${managerVersion})">${v}</span>`;
            }
            // Same version - normal color (green)
            return `<span style="color:#28a745;">${v}</span>`;
        }

        // Tab switching
        function switchToTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            const targetTab = document.querySelector(`.tab[data-tab="${tabName}"]`);
            if (targetTab) {
                targetTab.classList.add('active');
                document.getElementById(tabName + '-panel').classList.add('active');

                // Auto-refresh data for the tab
                if (tabName === 'agents') refreshAgents();
                else if (tabName === 'stats') {
                    refreshStats();
                    if (agents.length === 0) refreshAgents();
                }
                else if (tabName === 'nodes') refreshNodes();
                else if (tabName === 'groups') refreshGroups();
                else if (tabName === 'users') refreshUsers();
                else if (tabName === 'logs') refreshLogs();
                else if (tabName === 'packs') refreshPacks();
            }
        }

        function showNodeManagement() {
            switchToTab('nodes');
        }

        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                switchToTab(tab.dataset.tab);
            });
        });

        // API calls
        let isBackendConnected = true;

        function updateConnectionStatus(connected) {
            isBackendConnected = connected;
            const statusEl = document.querySelector('.api-status');
            if (statusEl) {
                if (connected) {
                    statusEl.textContent = 'API Connected';
                    statusEl.className = 'api-status connected';
                } else {
                    statusEl.textContent = 'Connection Lost';
                    statusEl.className = 'api-status disconnected';
                }
            }
        }

        function getConnectionErrorHtml(retryFunc) {
            return `
                <div class="connection-error">
                    <div class="error-icon"><svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4m0 4h.01"/></svg></div>
                    <div class="error-title">Backend Service Unavailable</div>
                    <div class="error-message">The backend server is not running or connection lost.<br>Please check if the service is started.</div>
                    <button class="retry-btn" onclick="${retryFunc}"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:middle;margin-right:6px;"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>Retry</button>
                </div>
            `;
        }

        async function api(endpoint, method = 'GET', data = null) {
            const options = { method, headers: { 'Content-Type': 'application/json' } };
            if (data) options.body = JSON.stringify(data);
            try {
                const res = await fetch('/api' + endpoint, options);
                if (res.status === 401) {
                    window.location.href = '/login';
                    return null;
                }
                const json = await res.json();
                // Handle session expired from API response
                if (json && json.session_expired) {
                    showToast('Session expired. Redirecting to login...', 'warning');
                    setTimeout(() => { window.location.href = '/login'; }, 1500);
                    return null;
                }
                // Connection restored
                if (!isBackendConnected) {
                    updateConnectionStatus(true);
                    showToast('Connection restored', 'success');
                }
                return json;
            } catch (err) {
                // Network error - backend is likely down
                if (err.name === 'TypeError' || err.message.includes('Failed to fetch') || err.message.includes('NetworkError')) {
                    updateConnectionStatus(false);
                    throw new Error('BACKEND_UNAVAILABLE');
                }
                throw err;
            }
        }

        // Load agents
        async function refreshAgents() {
            const body = document.getElementById('agentsBody');
            body.innerHTML = '<tr><td colspan="20" class="loading"><div class="spinner"></div>Loading...</td></tr>';

            try {
                // Also load valid node names and manager version if not already loaded
                if (validNodeNames.length === 0) {
                    const nodesData = await api('/nodes');
                    if (nodesData && nodesData.nodes) {
                        validNodeNames = nodesData.nodes.filter(n => n.status !== 'not_in_cluster').map(n => n.name);
                        // Get master node version as the manager version
                        const masterNode = nodesData.nodes.find(n => n.type === 'master') || nodesData.nodes[0];
                        if (masterNode && masterNode.version) {
                            managerVersion = masterNode.version.replace(/^v|^Wazuh /i, '');
                            console.log('Manager version detected:', managerVersion, 'from', masterNode.version);
                        }
                    }
                }

                const agentData = await api('/agents');
                if (!agentData) return;

                if (agentData.error) {
                    body.innerHTML = `<tr><td colspan="20" class="loading" style="color:#e94560;">Error: ${agentData.error}</td></tr>`;
                    showToast('Failed to load agents: ' + agentData.error, 'error');
                    return;
                }

                agents = agentData.agents || [];

                // Only load queue sizes if enabled (to avoid filesystem reads on every refresh)
                if (showQueueDB) {
                    await loadQueueSizes();
                }

                updateFilterOptions();
                renderAgents();
                updateStats();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="20">${getConnectionErrorHtml('refreshAgents()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="20" class="loading" style="color:#e94560;">Error loading agents: ${escapeHtml(err.message)}</td></tr>`;
                    showToast('Error loading agents: ' + err.message, 'error');
                }
                console.error('refreshAgents error:', err);
            }
        }

        // Load queue DB sizes separately (filesystem operation)
        async function loadQueueSizes() {
            const queueData = await api('/agents/queue-size');
            if (queueData && queueData.queue_sizes) {
                queueSizes = queueData.queue_sizes;  // Now an object with arrays: {agent_id: [{size, node}, ...]}
                queueSizeNode = queueData.local_node || '';
                queueOtherNodes = queueData.other_nodes || [];
                queueLoadedNodes = queueData.loaded_nodes || [];
                const loadedNodes = queueLoadedNodes;
                const failedNodes = queueData.ssh_failed_nodes || [];

                agents.forEach(a => {
                    const qInfoList = queueSizes[a.id];  // Array of {size, node}
                    if (qInfoList && qInfoList.length > 0) {
                        // Store all entries for display
                        a.queue_entries = qInfoList;
                        // Calculate total size for sorting
                        a.queue_size = qInfoList.reduce((sum, q) => sum + (q.size || 0), 0);
                    } else {
                        a.queue_entries = [];
                        a.queue_size = 0;
                    }
                });

                // Show appropriate message based on results
                if (failedNodes.length > 0) {
                    console.warn(`Queue DB SSH failed nodes: ${failedNodes.join(', ')}`);
                }
                if (loadedNodes.length > 1) {
                    showToast(`Queue DB loaded from all nodes: ${loadedNodes.join(', ')}`, 'success', 4000);
                } else if (loadedNodes.length === 1) {
                    showToast(`Queue DB loaded from ${loadedNodes[0]}`, 'success', 3000);
                }
            }
        }

        // Toggle Queue DB column visibility
        async function toggleQueueDB() {
            const checkbox = document.getElementById('toggleQueueDB');
            showQueueDB = checkbox.checked;

            // Update column visibility
            updateQueueDBColumn();

            // Load queue sizes if just enabled
            if (showQueueDB && Object.keys(queueSizes).length === 0) {
                await loadQueueSizes();
                renderAgents();
            } else {
                renderAgents();
            }
        }

        // Show/hide Queue DB column in table
        function updateQueueDBColumn() {
            const queueHeader = document.querySelector('th[data-sort="queue_size"]');
            if (queueHeader) {
                queueHeader.style.display = showQueueDB ? '' : 'none';
            }
        }

        // Multi-select functions
        function toggleMultiSelect(filterId) {
            const dropdown = document.getElementById(filterId + 'Dropdown');
            const btn = dropdown.previousElementSibling;
            const isOpen = dropdown.classList.contains('show');

            // Close all dropdowns first
            document.querySelectorAll('.multi-select-dropdown').forEach(d => d.classList.remove('show'));
            document.querySelectorAll('.multi-select-btn').forEach(b => b.classList.remove('active'));

            if (!isOpen) {
                dropdown.classList.add('show');
                btn.classList.add('active');
            }
        }

        function getFilterValues(filterId) {
            const dropdown = document.getElementById(filterId + 'Dropdown');
            const checked = dropdown.querySelectorAll('input[type="checkbox"]:checked');
            return Array.from(checked).map(cb => cb.value);
        }

        function updateFilterButton(filterId) {
            const values = getFilterValues(filterId);
            const btn = document.querySelector('#' + filterId + 'Wrap .multi-select-btn');
            const labels = { statusFilter: 'Status', groupFilter: 'Group', osFilter: 'OS', versionFilter: 'Version', nodeFilter: 'Node', syncFilter: 'Sync' };
            const arrowIcon = '<svg class="icon"><use href="#icon-nav-arrow-down"/></svg>';
            if (values.length === 0) {
                btn.innerHTML = labels[filterId] + ' ' + arrowIcon;
            } else {
                btn.innerHTML = labels[filterId] + ' <span class="filter-badge">' + values.length + '</span> ' + arrowIcon;
            }
        }

        function clearFilter(filterId) {
            const dropdown = document.getElementById(filterId + 'Dropdown');
            dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            updateFilterButton(filterId);
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function onFilterChange() {
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function toggleCheckbox(item, event) {
            // Don't toggle if clicking directly on checkbox (it handles itself)
            if (event && event.target.type === 'checkbox') return;
            const cb = item.querySelector('input[type="checkbox"]');
            if (cb) {
                cb.checked = !cb.checked;
                onFilterChange();
            }
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.multi-select')) {
                document.querySelectorAll('.multi-select-dropdown').forEach(d => d.classList.remove('show'));
                document.querySelectorAll('.multi-select-btn').forEach(b => b.classList.remove('active'));
            }
            if (!e.target.closest('.export-dropdown')) {
                const exportMenu = document.getElementById('exportMenu');
                if (exportMenu) exportMenu.classList.remove('show');
            }
        });

        function renderAgents() {
            const search = document.getElementById('agentSearch').value.toLowerCase();
            const statusValues = getFilterValues('statusFilter');
            const groupValues = getFilterValues('groupFilter');
            const osValues = getFilterValues('osFilter');
            const versionValues = getFilterValues('versionFilter');
            const nodeValues = getFilterValues('nodeFilter');
            const syncValues = getFilterValues('syncFilter');

            let filtered = agents.filter(a => {
                // Search all columns
                if (search) {
                    const searchFields = [
                        a.id, a.name, a.ip, a.status, a.os, a.version, a.group, a.node_name, a.synced
                    ].map(f => (f || '').toLowerCase());
                    if (!searchFields.some(f => f.includes(search))) return false;
                }
                if (statusValues.length > 0 && !statusValues.includes(a.status.toLowerCase().replace(' ', '_'))) return false;
                // Group can be comma-separated list, check if any selected group matches
                if (groupValues.length > 0) {
                    const agentGroups = (a.group || '').split(',').map(g => g.trim()).filter(g => g);
                    // Handle "(no group)" filter
                    const hasNoGroup = !a.group || a.group.trim() === '';
                    const matchesNoGroup = groupValues.includes('(no group)') && hasNoGroup;
                    const matchesGroup = groupValues.some(g => g !== '(no group)' && agentGroups.includes(g));
                    if (!matchesNoGroup && !matchesGroup) return false;
                }
                if (osValues.length > 0 && !osValues.includes(a.os || '')) return false;
                if (versionValues.length > 0 && !versionValues.includes(a.version || '')) return false;
                if (nodeValues.length > 0 && !nodeValues.includes(a.node_name || '')) return false;
                if (syncValues.length > 0 && !syncValues.includes(a.synced || 'unknown')) return false;
                return true;
            });

            // Apply sorting
            filtered.sort((a, b) => {
                let valA = a[sortColumn] || '';
                let valB = b[sortColumn] || '';

                // Handle numeric sorting for ID and queue_size
                if (sortColumn === 'id' || sortColumn === 'queue_size') {
                    valA = parseInt(valA) || 0;
                    valB = parseInt(valB) || 0;
                    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
                    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
                    return 0;
                }
                // Handle version sorting using semantic version comparison
                else if (sortColumn === 'version') {
                    const cmp = compareVersions(valA, valB);
                    return sortDirection === 'asc' ? cmp : -cmp;
                }
                // Default string sorting
                else {
                    valA = String(valA).toLowerCase();
                    valB = String(valB).toLowerCase();
                    if (valA < valB) return sortDirection === 'asc' ? -1 : 1;
                    if (valA > valB) return sortDirection === 'asc' ? 1 : -1;
                    return 0;
                }
            });

            // Pagination
            const totalFiltered = filtered.length;
            const totalPages = Math.ceil(totalFiltered / pageSize) || 1;

            // Ensure currentPage is valid
            if (currentPage > totalPages) currentPage = totalPages;
            if (currentPage < 1) currentPage = 1;

            const startIndex = (currentPage - 1) * pageSize;
            const endIndex = Math.min(startIndex + pageSize, totalFiltered);
            const paged = filtered.slice(startIndex, endIndex);

            // Update pagination UI
            updatePaginationUI(startIndex, endIndex, totalFiltered, totalPages);

            const body = document.getElementById('agentsBody');
            // Helper to conditionally show/hide column
            const colStyle = (col) => visibleColumns[col] === false ? 'display:none' : '';

            body.innerHTML = paged.map(a => {
                const isInactive = a.status && a.status.toLowerCase() !== 'active';
                const rowDim = isInactive ? ' style="opacity:0.6"' : '';
                return `
                <tr${rowDim}>
                    <td class="checkbox-cell"><input type="checkbox" value="${escapeHtml(a.id)}" onchange="toggleAgent('${escapeHtml(a.id)}')" ${selectedAgents.has(a.id) ? 'checked' : ''}></td>
                    <td><button class="btn btn-sm btn-icon" onclick="showAgentDetails('${escapeHtml(a.id)}')" title="View Details"><svg class="icon"><use href="#icon-search"/></svg></button></td>
                    <td style="${colStyle('id')}">${escapeHtml(a.id)}</td>
                    <td style="${colStyle('name')}; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(a.name)}">${escapeHtml(a.name)}</td>
                    <td style="${colStyle('ip')}; white-space: nowrap;">${escapeHtml(a.ip)}</td>
                    <td style="${colStyle('status')}"><span class="status status-${getStatusClass(a.status)}">${escapeHtml(a.status)}</span></td>
                    <td style="${colStyle('os')}; white-space: nowrap;">${escapeHtml(a.os) || '-'}</td>
                    <td style="${colStyle('version')}">${formatAgentVersion(a.version)}</td>
                    <td style="${colStyle('group')}; max-width: 200px; max-height: 32px; overflow: hidden; line-height: 16px;" title="${escapeHtml(a.group)}">${formatGroupLabels(a.group)}</td>
                    <td style="${colStyle('node_name')}">${formatNodeName(a.node_name)}</td>
                    <td style="${colStyle('synced')}"><span class="sync-status sync-${a.synced === 'synced' ? 'ok' : (a.synced === 'not synced' ? 'pending' : 'unknown')}">${escapeHtml(a.synced) || '-'}</span></td>
                    <td class="queue-db-cell" style="display:${showQueueDB ? '' : 'none'}">${formatQueueSize(a)}</td>
                </tr>`;
            }).join('');
        }

        // Pagination functions
        function updatePaginationUI(start, end, total, totalPages) {
            document.getElementById('paginationInfo').textContent =
                total > 0 ? `Showing ${start + 1} - ${end} of ${total}` : 'No results';
            document.getElementById('totalPages').textContent = totalPages;
            document.getElementById('pageInput').value = currentPage;
            document.getElementById('pageInput').max = totalPages;

            // Enable/disable buttons
            document.getElementById('btnFirstPage').disabled = currentPage <= 1;
            document.getElementById('btnPrevPage').disabled = currentPage <= 1;
            document.getElementById('btnNextPage').disabled = currentPage >= totalPages;
            document.getElementById('btnLastPage').disabled = currentPage >= totalPages;
        }

        function changePageSize(newSize) {
            pageSize = parseInt(newSize);
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function goToPage(page) {
            currentPage = parseInt(page);
            renderAgents();
        }

        function prevPage() {
            if (currentPage > 1) {
                currentPage--;
                renderAgents();
            }
        }

        function nextPage() {
            currentPage++;
            renderAgents();
        }

        async function showAgentDetails(agentId) {
            showModal('Agent Details', '<div class="loading"><div class="spinner"></div>Loading...</div>', '');

            try {
                const data = await api(`/agents/${agentId}`);
                if (!data || data.error) {
                    document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">' + ((data && data.error) || 'Failed to load agent details') + '</div>';
                    return;
                }

                const a = data.agent || {};
                const formatDate = (d) => {
                    if (!d) return '-';
                    // Handle Unix timestamp (seconds) - if number is small enough to be seconds
                    if (typeof d === 'number' && d < 9999999999) {
                        d = d * 1000;  // Convert to milliseconds
                    }
                    const date = new Date(d);
                    // Check if valid date
                    if (isNaN(date.getTime())) return '-';
                    // Use 24-hour format
                    return date.toLocaleString('zh-TW', { hour12: false });
                };
                const formatBytes = (b) => {
                    if (!b) return '-';
                    const units = ['B', 'KB', 'MB', 'GB'];
                    let i = 0;
                    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
                    return b.toFixed(1) + ' ' + units[i];
                };

                // Format queue DB sizes for modal (may have multiple nodes)
                const queueEntries = queueSizes[a.id] || [];
                let queueSizeDisplay = '-';
                if (queueEntries.length === 1) {
                    queueSizeDisplay = `${formatBytes(queueEntries[0].size)} <span style="color:#888;font-size:11px">(on ${queueEntries[0].node})</span>`;
                } else if (queueEntries.length > 1) {
                    queueSizeDisplay = queueEntries.map(e =>
                        `${formatBytes(e.size)} <span style="color:#888;font-size:11px">(on ${e.node})</span>`
                    ).join('<br>');
                }

                const html = `
                    <table style="width:100%">
                        <tr><td style="color:#aaa;width:40%">ID</td><td><strong>${a.id || '-'}</strong></td></tr>
                        <tr><td style="color:#aaa">Name</td><td><strong>${a.name || '-'}</strong></td></tr>
                        <tr><td style="color:#aaa">IP</td><td>${a.ip || '-'}</td></tr>
                        <tr><td style="color:#aaa">Status</td><td><span class="status status-${getStatusClass(a.status || '')}">${a.status || '-'}</span></td></tr>
                        <tr><td style="color:#aaa">Manager</td><td>${a.manager || '-'}</td></tr>
                        <tr><td style="color:#aaa">Node</td><td>${a.node_name || '-'}</td></tr>
                        <tr><td style="color:#aaa">Version</td><td>${a.version || '-'}</td></tr>
                        <tr><td style="color:#aaa">OS</td><td>${(a.os && a.os.name) || (a.os && a.os.platform) || '-'} ${(a.os && a.os.version) || ''}</td></tr>
                        <tr><td style="color:#aaa">OS Architecture</td><td>${(a.os && a.os.arch) || '-'}</td></tr>
                        <tr><td style="color:#aaa">Groups</td><td>${(a.group || []).join(', ') || '-'}</td></tr>
                        <tr><td style="color:#aaa">Registration Date</td><td>${formatDate(a.dateAdd)}</td></tr>
                        <tr><td style="color:#aaa">Last Keep Alive</td><td>${formatDate(a.lastKeepAlive)}</td></tr>
                        <tr><td style="color:#aaa">Queue DB Size</td><td>${queueSizeDisplay}</td></tr>
                        <tr><td style="color:#aaa">Config Sum</td><td style="font-family:monospace;font-size:11px">${a.configSum || '-'}</td></tr>
                        <tr><td style="color:#aaa">Merged Sum</td><td style="font-family:monospace;font-size:11px">${a.mergedSum || '-'}</td></tr>
                    </table>
                `;

                document.getElementById('modalBody').innerHTML = html;
                document.getElementById('modalFooter').innerHTML =
                    '<button class="btn" onclick="showAgentRuntimeConfig(\\'' + escapeHtml(a.id) + '\\')" title="Configuration the agent is actually running"><svg class="icon"><use href="#icon-file"/></svg>Running Config</button>' +
                    '<button class="btn" onclick="showAgentKey(\\'' + escapeHtml(a.id) + '\\')" title="Enrollment key for re-registering this agent"><svg class="icon"><use href="#icon-link"/></svg>Agent Key</button>' +
                    '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>';
            } catch (e) {
                document.getElementById('modalBody').innerHTML = `<div class="alert alert-error">Error: ${e.message}</div>`;
            }
        }

        // What the agent actually applied, merged group config included. Answers
        // "did my agent.conf reach this agent" in a way the stored file cannot.
        const AGENT_CONFIG_SECTIONS = [
            ['agent', 'client', 'Manager connection'],
            ['agent', 'buffer', 'Event buffer'],
            ['agent', 'labels', 'Labels'],
            ['syscheck', 'syscheck', 'File integrity'],
            ['rootcheck', 'rootcheck', 'Rootcheck'],
            ['logcollector', 'localfile', 'Log collection'],
            ['wmodules', 'wmodules', 'Modules'],
        ];

        async function showAgentRuntimeConfig(agentId, component, configuration) {
            const comp = component || 'agent';
            const conf = configuration || 'client';
            const options = AGENT_CONFIG_SECTIONS.map(([c, cf, label]) =>
                '<option value="' + c + '|' + cf + '"' + (c === comp && cf === conf ? ' selected' : '') + '>' + label + '</option>').join('');
            const header =
                '<div style="margin-bottom:10px;">Section: <select id="agentConfigSection" style="background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;" ' +
                'onchange="const v=this.value.split(\\'|\\');showAgentRuntimeConfig(\\'' + agentId + '\\', v[0], v[1]);">' + options + '</select></div>';
            showModal('Running Config - Agent ' + agentId,
                header + '<div id="agentRuntimeBody"><div class="loading"><div class="spinner"></div>Loading...</div></div>',
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
            const result = await api('/agents/' + agentId + '/runtime-config?component=' + encodeURIComponent(comp) + '&configuration=' + encodeURIComponent(conf));
            const target = document.getElementById('agentRuntimeBody');
            if (!target) return;
            if (!result || result.error) {
                target.innerHTML = '<div class="alert alert-error">' + escapeHtml((result && result.error) || 'Failed to load') +
                    '<div style="margin-top:6px;color:#888;font-size:12px;">The agent must be active for this to work.</div></div>';
                return;
            }
            const cfg = result.config || {};
            if (!Object.keys(cfg).length) {
                target.innerHTML = '<div style="color:#888;padding:20px;text-align:center;">This section is not configured on the agent.</div>';
                return;
            }
            target.innerHTML = '<pre style="background:#0a0a15;padding:15px;border-radius:4px;font-size:12px;max-height:55vh;overflow:auto;">' +
                escapeHtml(JSON.stringify(cfg, null, 2)) + '</pre>';
        }

        async function showAgentKey(agentId) {
            const result = await api('/agents/' + agentId + '/key');
            if (!result || result.error) {
                showToast((result && result.error) || 'Failed to load the agent key', 'error');
                return;
            }
            showModal('Agent Key - ' + agentId,
                '<p style="color:#888;font-size:12px;margin-bottom:10px;">Use this key to re-register the agent with <code>manage_agents</code>. Treat it as a secret.</p>' +
                '<textarea readonly id="agentKeyText" style="width:100%;height:110px;background:#0a0a15;color:#eee;border:1px solid #1a3a6e;border-radius:4px;padding:10px;font-family:monospace;font-size:12px;">' +
                escapeHtml(result.key || '') + '</textarea>',
                '<button class="btn" data-copy="' + escapeHtml(result.key || '') + '" onclick="copyToClipboard(this)"><svg class="icon"><use href="#icon-copy"/></svg>Copy</button>' +
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>');
        }

        function getStatusClass(status) {
            status = status.toLowerCase();
            if (status.includes('active')) return 'active';
            if (status.includes('disconnected')) return 'disconnected';
            if (status.includes('pending')) return 'pending';
            return 'never';
        }

        function sortAgents(column) {
            // Toggle direction if same column
            if (sortColumn === column) {
                sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                sortColumn = column;
                sortDirection = 'asc';
            }

            // Update header styles
            document.querySelectorAll('th.sortable').forEach(th => {
                th.classList.remove('asc', 'desc');
                if (th.dataset.sort === column) {
                    th.classList.add(sortDirection);
                }
            });

            renderAgents();
        }

        function toggleAgent(id) {
            if (selectedAgents.has(id)) selectedAgents.delete(id);
            else selectedAgents.add(id);
            updateSelectedUI();
        }

        function toggleSelectAll() {
            const checked = document.getElementById('selectAll').checked;
            document.querySelectorAll('#agentsBody input[type="checkbox"]').forEach(cb => {
                cb.checked = checked;
                if (checked) selectedAgents.add(cb.value);
                else selectedAgents.delete(cb.value);
            });
            updateSelectedUI();
        }

        function clearSelection() {
            selectedAgents.clear();
            document.querySelectorAll('#agentsBody input[type="checkbox"]').forEach(cb => { cb.checked = false; });
            const selectAll = document.getElementById('selectAll');
            if (selectAll) { selectAll.checked = false; selectAll.indeterminate = false; }
            updateSelectedUI();
        }

        function updateSelectedUI() {
            const count = selectedAgents.size;
            const actionBar = document.getElementById('actionBar');
            const countEl = document.getElementById('selectedCount');

            if (count > 0) {
                actionBar.classList.add('visible');
            } else {
                actionBar.classList.remove('visible');
            }
            countEl.querySelector('span').textContent = count;
        }

        async function updateStats() {
            // Always calculate from loaded agents for accuracy
            updateStatsFromAgents();
        }

        function updateStatValue(elementId, newValue) {
            const el = document.getElementById(elementId);
            const span = el.querySelector('span');
            const currentValue = span.textContent;

            if (currentValue !== String(newValue)) {
                // Value changed, animate
                span.classList.remove('slide-in');
                void span.offsetWidth; // Trigger reflow to restart animation
                span.textContent = newValue;
                span.classList.add('slide-in');
            }
        }

        function updateStatsFromAgents() {
            // Calculate stats from loaded agents
            if (!agents || agents.length === 0) {
                updateStatValue('totalAgents', '0');
                updateStatValue('activeAgents', '0');
                updateStatValue('disconnectedAgents', '0');
                updateStatValue('pendingAgents', '0');
                return;
            }

            const total = agents.length;
            const active = agents.filter(a => a.status && a.status.toLowerCase() === 'active').length;
            const disconnected = agents.filter(a => a.status && a.status.toLowerCase() === 'disconnected').length;
            const pending = agents.filter(a => a.status && a.status.toLowerCase() === 'pending').length;

            updateStatValue('totalAgents', total);
            updateStatValue('activeAgents', active);
            updateStatValue('disconnectedAgents', disconnected);
            updateStatValue('pendingAgents', pending);

            // Update distribution bar
            updateDistributionBar();
        }

        // Distribution bar colors (dark colors for white text readability)
        const distributionColors = {
            status: { 'active': '#2e7d32', 'disconnected': '#c62828', 'pending': '#f57c00', 'never_connected': '#616161' },
            os: ['#1565c0', '#7b1fa2', '#c62828', '#2e7d32', '#ad1457', '#00838f', '#558b2f', '#d84315', '#4527a0', '#00695c'],
            version: ['#1565c0', '#2e7d32', '#ef6c00', '#c62828', '#6a1b9a', '#00838f', '#558b2f', '#d84315'],
            group: ['#1565c0', '#2e7d32', '#ef6c00', '#c62828', '#6a1b9a', '#00838f', '#558b2f', '#d84315', '#4527a0', '#00695c'],
            node: ['#303f9f', '#00695c', '#9e9d24', '#d84315', '#5d4037'],
            sync: { 'synced': '#2e7d32', 'not synced': '#ef6c00', 'unknown': '#616161' }
        };

        // Simplify OS name for display
        function simplifyOsName(os) {
            if (!os) return 'Unknown';
            const osLower = os.toLowerCase();
            if (osLower.includes('ubuntu')) return 'Ubuntu';
            if (osLower.includes('debian')) return 'Debian';
            if (osLower.includes('centos')) return 'CentOS';
            if (osLower.includes('red hat') || osLower.includes('rhel')) return 'RHEL';
            if (osLower.includes('rocky')) return 'Rocky';
            if (osLower.includes('alma')) return 'AlmaLinux';
            if (osLower.includes('fedora')) return 'Fedora';
            if (osLower.includes('suse') || osLower.includes('sles')) return 'SUSE';
            if (osLower.includes('oracle')) return 'Oracle Linux';
            if (osLower.includes('amazon')) return 'Amazon Linux';
            if (osLower.includes('windows server')) return 'Windows Server';
            if (osLower.includes('windows 11')) return 'Windows 11';
            if (osLower.includes('windows 10')) return 'Windows 10';
            if (osLower.includes('windows')) return 'Windows';
            if (osLower.includes('macos') || osLower.includes('mac os')) return 'macOS';
            if (osLower.includes('freebsd') || osLower.includes('bsd')) return 'BSD';
            if (osLower.includes('arch')) return 'Arch';
            if (osLower.includes('gentoo')) return 'Gentoo';
            if (osLower.includes('alpine')) return 'Alpine';
            if (osLower.includes('proxmox')) return 'Proxmox';
            if (osLower.includes('univention')) return 'Univention';
            // Return first word or truncated name
            const parts = os.split(' ');
            return parts[0].length > 15 ? parts[0].substring(0, 12) + '...' : parts[0];
        }

        function updateDistributionBar(animate = false) {
            const chart = document.getElementById('distributionChart');
            const type = document.getElementById('distributionType').value;

            if (animate) {
                chart.classList.remove('animating');
                void chart.offsetWidth; // Trigger reflow
                chart.classList.add('animating');
            } else {
                chart.classList.remove('animating');
            }

            if (!agents || agents.length === 0) {
                chart.innerHTML = '<div style="color:#666;padding:0 10px;font-size:11px;">No data</div>';
                return;
            }

            // Calculate distribution based on type
            const counts = {};
            agents.forEach(a => {
                let key;
                switch(type) {
                    case 'status':
                        key = (a.status || 'unknown').toLowerCase();
                        break;
                    case 'os':
                        key = simplifyOsName(a.os);
                        break;
                    case 'version':
                        key = a.version || 'Unknown';
                        break;
                    case 'group':
                        // Count each group separately (agent can be in multiple groups)
                        const groups = (a.group || '').split(',').map(g => g.trim()).filter(g => g);
                        if (groups.length === 0) {
                            key = '(no group)';
                            counts[key] = (counts[key] || 0) + 1;
                        } else {
                            groups.forEach(g => { counts[g] = (counts[g] || 0) + 1; });
                        }
                        return; // Already counted
                    case 'node':
                        key = a.node_name || 'Unknown';
                        break;
                    case 'sync':
                        key = a.synced || 'unknown';
                        break;
                    default:
                        key = 'unknown';
                }
                counts[key] = (counts[key] || 0) + 1;
            });

            // Sort by count descending
            const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
            const total = agents.length;

            // Build chart segments
            let chartHtml = '';
            const colorMap = distributionColors[type];

            sorted.forEach(([name, count], index) => {
                const pct = (count / total * 100);
                const color = typeof colorMap === 'object' && !Array.isArray(colorMap)
                    ? (colorMap[name] || colorMap[name.replace(' ', '_')] || '#666')
                    : colorMap[index % colorMap.length];

                // Always show label, CSS will truncate if too long
                const label = `<span>${name} (${count})</span>`;
                chartHtml += `<div class="distribution-segment" style="width:${pct}%;background:${color}" title="${name}: ${count} (${pct.toFixed(1)}%)" onclick="filterByDistribution('${type}','${escapeHtml(name)}')">${label}</div>`;
            });

            chart.innerHTML = chartHtml;
        }

        function filterByDistribution(type, value) {
            // Clear all filters first
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
            });

            // Apply the selected filter
            let filterId;
            switch(type) {
                case 'status': filterId = 'statusFilter'; break;
                case 'os': filterId = 'osFilter'; break;
                case 'version': filterId = 'versionFilter'; break;
                case 'group': filterId = 'groupFilter'; break;
                case 'node': filterId = 'nodeFilter'; break;
                case 'sync': filterId = 'syncFilter'; break;
            }

            if (filterId) {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    // For OS, we need to match simplified name to full name
                    if (type === 'os') {
                        dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                            if (simplifyOsName(cb.value) === value) cb.checked = true;
                        });
                    } else {
                        dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                            if (cb.value === value || cb.value.toLowerCase() === value.toLowerCase()) cb.checked = true;
                        });
                    }
                }
            }

            // Update filter buttons and render
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.getElementById('agentSearch').value = '';
            currentPage = 1;
            renderAgents();
        }

        function filterByStatus(status) {
            // Switch to Agents tab
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="agents"]').classList.add('active');
            document.getElementById('agents-panel').classList.add('active');

            // Clear all filters
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
                }
            });

            // Set the status filter if provided
            if (status) {
                const statusDropdown = document.getElementById('statusFilterDropdown');
                statusDropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    if (cb.value === status) cb.checked = true;
                });
            }

            // Update all filter buttons and render
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.getElementById('agentSearch').value = '';
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function filterByNode(nodeName) {
            // Switch to Agents tab
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
            document.querySelector('[data-tab="agents"]').classList.add('active');
            document.getElementById('agents-panel').classList.add('active');

            // Clear all filters
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
                }
            });

            // Set the node filter if provided
            if (nodeName) {
                const nodeDropdown = document.getElementById('nodeFilterDropdown');
                nodeDropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    if (cb.value === nodeName) cb.checked = true;
                });
            }

            // Update all filter buttons and render
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.getElementById('agentSearch').value = '';
            currentPage = 1;  // Reset to first page
            renderAgents();
        }

        function updateFilterOptions() {
            // Save current filter selections before rebuilding
            const savedFilters = {};
            ['groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                savedFilters[filterId] = getFilterValues(filterId);
            });

            // Get unique values for each filter
            const groupSet = new Set();
            const osSet = new Set();
            const versionSet = new Set();
            const nodeSet = new Set();
            const syncSet = new Set();

            agents.forEach(a => {
                // Split groups
                if (a.group) {
                    a.group.split(',').forEach(g => groupSet.add(g.trim()));
                } else {
                    groupSet.add('(no group)');
                }
                if (a.os) osSet.add(a.os);
                if (a.version) versionSet.add(a.version);
                if (a.node_name) nodeSet.add(a.node_name);
                // Add sync status (handle empty as 'unknown')
                const syncVal = a.synced || 'unknown';
                syncSet.add(syncVal);
            });

            // Ensure common sync statuses are always available
            syncSet.add('synced');
            syncSet.add('not synced');

            // Helper to create dropdown items with preserved selections
            const createItems = (values, filterId, sortFn = null) => {
                const sorted = sortFn ? [...values].sort(sortFn) : [...values].sort();
                const savedValues = savedFilters[filterId] || [];
                return sorted.map(v => {
                    const isChecked = savedValues.includes(v) ? ' checked' : '';
                    return `<div class="multi-select-item" onclick="toggleCheckbox(this, event)"><input type="checkbox" value="${v}"${isChecked} onchange="onFilterChange()"><span class="multi-select-item-text">${v}</span></div>`;
                }).join('') + `<div class="multi-select-clear" onclick="clearFilter('${filterId}')">Clear</div>`;
            };

            // Version sort function (high to low)
            const versionSort = (a, b) => {
                // Sort descending (high to low) via the shared comparator
                return -compareVersions(a, b);
            };

            // Update Group filter
            document.getElementById('groupFilterDropdown').innerHTML = createItems(groupSet, 'groupFilter');

            // Update OS filter
            document.getElementById('osFilterDropdown').innerHTML = createItems(osSet, 'osFilter');

            // Update Version filter (sorted high to low)
            document.getElementById('versionFilterDropdown').innerHTML = createItems(versionSet, 'versionFilter', versionSort);

            // Update Node filter
            document.getElementById('nodeFilterDropdown').innerHTML = createItems(nodeSet, 'nodeFilter');

            // Update Sync filter
            document.getElementById('syncFilterDropdown').innerHTML = createItems(syncSet, 'syncFilter');

            // Update filter button labels to reflect restored selections
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
        }

        // Groups
        async function refreshGroups() {
            const body = document.getElementById('groupsBody');
            body.innerHTML = '<tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>';

            try {
                const data = await api('/groups');
                if (!data) return;
                groups = data.groups || [];
                renderGroups();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="4">${getConnectionErrorHtml('refreshGroups()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="4" class="loading" style="color:#e94560;">Error loading groups: ${escapeHtml(err.message)}</td></tr>`;
                }
            }
        }

        function sortGroups(column) {
            // Toggle direction if same column
            if (groupSortColumn === column) {
                groupSortDirection = groupSortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                groupSortColumn = column;
                groupSortDirection = 'asc';
            }

            // Update header styles
            document.querySelectorAll('#groupsTable th.sortable').forEach(th => {
                th.classList.remove('asc', 'desc');
                if (th.dataset.sort === column) {
                    th.classList.add(groupSortDirection);
                }
            });

            renderGroups();
        }

        function renderGroups() {
            const body = document.getElementById('groupsBody');

            // Sort groups
            const sorted = [...groups].sort((a, b) => {
                let valA, valB;
                if (groupSortColumn === 'count') {
                    valA = a.count || 0;
                    valB = b.count || 0;
                } else {
                    valA = (a.name || '').toLowerCase();
                    valB = (b.name || '').toLowerCase();
                }
                if (valA < valB) return groupSortDirection === 'asc' ? -1 : 1;
                if (valA > valB) return groupSortDirection === 'asc' ? 1 : -1;
                return 0;
            });

            body.innerHTML = sorted.map(g => {
                const safeName = escapeHtml(g.name);
                const jsName = g.name.replace(/'/g, "\\'").replace(/"/g, '\\"');
                return `
                <tr>
                    <td>${safeName}</td>
                    <td style="text-align:center"><a href="#" onclick="showGroupAgents('${jsName}');return false;" style="color:#4fc3f7;text-decoration:none;cursor:pointer;" title="View agents in this group">${g.count || 0}</a></td>
                    <td>
                        <div class="btn-wrap">
                            <button class="btn btn-sm" style="background:#607d8b;color:#fff;" onclick="showGroupFiles('${jsName}')" title="Files in this group's directory"><svg class="icon"><use href="#icon-file"/></svg>Files</button>
                            <button class="btn btn-sm btn-success" onclick="showImportCsvModal('${jsName}')"><svg class="icon"><use href="#icon-upload"/></svg>Import CSV</button>
                            <button class="btn btn-sm" style="background:#17a2b8;color:#fff;" onclick="exportGroupAgentsCsv('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-download"/></svg>Export CSV</button>
                            <button class="btn btn-sm btn-warning" onclick="showMoveGroupAgentsModal('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-move"/></svg>Move Agents</button>
                            <button class="btn btn-sm" style="background:#9c27b0;" onclick="setExclusiveGroup('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-exclusive"/></svg>Only This</button>
                            <button class="btn btn-sm btn-danger" onclick="removeAllFromGroup('${jsName}')" ${g.count ? '' : 'disabled'}><svg class="icon"><use href="#icon-remove"/></svg>Remove All</button>
                        </div>
                    </td>
                    <td>
                        <div class="btn-wrap">
                            <button class="btn btn-sm btn-primary" onclick="showGroupAgentConfModal('${jsName}')"><svg class="icon"><use href="#icon-file-code"/></svg>agent.conf</button>
                            <button class="btn btn-sm" style="background:#6f42c1;color:#fff;" onclick="showRenameGroupModal('${jsName}')"><svg class="icon"><use href="#icon-rename"/></svg>Rename</button>
                            <button class="btn btn-sm btn-danger" onclick="deleteGroup('${jsName}')"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button>
                        </div>
                    </td>
                </tr>
            `;}).join('');
        }

        // Nodes
        let nodeServices = {};  // Store service status per node

        let nodeSyncStatus = {};  // Store sync status per node
        let syncStatusLoading = false;  // Track if sync status is being loaded
        let nodeArchives = {};  // Store archives file info per node

        async function refreshNodes() {
            const body = document.getElementById('nodesBody');

            // Clear cached data to force fresh load
            nodeServices = {};
            nodeSyncStatus = {};
            nodeArchives = {};

            // Step 1: Load nodes
            body.innerHTML = '<tr><td colspan="9" class="loading"><div class="spinner"></div>Loading nodes...</td></tr>';

            try {
                const nodesData = await api('/nodes');

                if (!nodesData) return;
                const nodes = nodesData.nodes || [];

                // Store valid node names for use in agent table
                validNodeNames = nodes.filter(n => n.status !== 'not_in_cluster').map(n => n.name);

                if (nodes.length === 0) {
                    body.innerHTML = '<tr><td colspan="9" class="loading">Cluster not configured or not running</td></tr>';
                    return;
                }

                // Render nodes first (without services/sync)
                renderNodes(nodes);

                // Step 2: Load services in background
                body.querySelector('.loading-status')?.remove();
                const loadingRow = document.createElement('tr');
                loadingRow.className = 'loading-status-row';
                loadingRow.innerHTML = '<td colspan="9" style="padding:8px;color:#888;font-size:12px;text-align:center;"><span class="icon-spin" style="display:inline-block;margin-right:6px;">⟳</span>Loading services...</td>';
                body.appendChild(loadingRow);

                const servicesData = await api('/nodes/services');
                if (servicesData && !servicesData.error) {
                    nodeServices = servicesData.services || {};
                    renderNodes(nodes);
                }

                // Step 3: Load sync status
                loadingRow.innerHTML = '<td colspan="9" style="padding:8px;color:#888;font-size:12px;text-align:center;"><span class="icon-spin" style="display:inline-block;margin-right:6px;">⟳</span>Loading sync status...</td>';
                syncStatusLoading = true;
                renderNodes(nodes);  // Re-render to show loading indicator

                const syncData = await api('/nodes/sync-status');
                syncStatusLoading = false;
                if (syncData && !syncData.error) {
                    nodeSyncStatus = syncData.sync_status || {};
                }
                renderNodes(nodes);

                // Step 4: Load logs info (archives and alerts) for each node (in parallel)
                loadingRow.innerHTML = '<td colspan="9" style="padding:8px;color:#888;font-size:12px;text-align:center;"><span class="icon-spin" style="display:inline-block;margin-right:6px;">⟳</span>Loading logs info...</td>';

                const logsPromises = nodes.map(n =>
                    api('/nodes/' + encodeURIComponent(n.name) + '/logs-info')
                        .then(data => {
                            if (data && !data.error) {
                                nodeArchives[n.name] = data.files || {};
                            }
                        })
                        .catch(() => {})
                );
                await Promise.all(logsPromises);
                renderNodes(nodes);

                // Remove loading row
                body.querySelector('.loading-status-row')?.remove();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="9">${getConnectionErrorHtml('refreshNodes()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="9" class="loading" style="color:#e94560;">Error loading nodes: ${escapeHtml(err.message)}</td></tr>`;
                }
            }
        }

        function renderNodes(nodes) {
            const body = document.getElementById('nodesBody');
            body.innerHTML = nodes.map(n => {
                const safeName = escapeHtml(n.name);
                const jsName = n.name.replace(/'/g, "\\'").replace(/"/g, '\\"');
                const services = nodeServices[n.name] || null;
                let servicesHtml = '<span style="color:#888">-</span>';
                if (services) {
                    servicesHtml = '<div class="service-status">' + services.map(s =>
                        `<span class="service-indicator"><span class="dot ${escapeHtml(s.status)}"></span>${escapeHtml(s.name)}</span>`
                    ).join('') + '</div>';
                }

                // Sync status (only for worker nodes)
                let syncHtml = '<span style="color:#888">-</span>';
                if (n.type === 'worker') {
                    const sync = nodeSyncStatus[n.name];
                    if (sync && sync.length > 0) {
                        syncHtml = '<div class="service-status">' + sync.map(s => {
                            const statusClass = s.status === 'synced' ? 'running' :
                                               s.status === 'in_progress' ? 'pending' :
                                               s.status === 'unknown' ? 'unknown' : 'stopped';
                            const clickable = s.status !== 'unknown' ? `onclick="showSyncDetail('${jsName}', '${escapeHtml(s.name)}', '${escapeHtml(s.path)}')"` : '';
                            return `<span class="service-indicator sync-item" title="${escapeHtml(s.path)}" ${clickable}><span class="dot ${statusClass}"></span>${escapeHtml(s.name)}</span>`;
                        }).join('') + '</div>';
                    } else if (syncStatusLoading) {
                        // Show loading indicator while sync status is being fetched
                        syncHtml = '<span style="color:#888;font-size:12px;"><span class="icon-spin" style="display:inline-block;margin-right:4px;">⟳</span>Loading...</span>';
                    } else {
                        syncHtml = '<span style="color:#888">-</span>';
                    }
                } else {
                    // Master node - show as reference source with blue indicators
                    const syncItems = ['Rules', 'Decoders', 'Groups', 'Keys', 'Lists', 'SCA'];
                    syncHtml = '<div class="service-status">' + syncItems.map(item =>
                        `<span class="service-indicator sync-source" title="Reference source"><span class="dot source"></span>${item}</span>`
                    ).join('') + '</div>';
                }

                // Only show cluster.key download for master node
                const clusterKeyBtn = n.type === 'master' ?
                    `<button class="btn btn-sm" style="background:#6f42c1;color:#fff;" onclick="downloadFile('${jsName}', 'cluster-key')" title="Download cluster.key for worker nodes"><svg class="icon"><use href="#icon-download"/></svg>cluster.key</button>` : '';

                // Log viewer buttons - only show if file exists
                const logs = nodeArchives[n.name] || {};
                // Archives buttons
                const archivesLogBtn = logs.archives_log && logs.archives_log.exists ?
                    `<button class="btn btn-sm" style="background:#20c997;color:#fff;" onclick="showLogViewerModal('${jsName}', 'archives', 'log')" title="View archives.log (${formatFileSize(logs.archives_log.size)})"><svg class="icon"><use href="#icon-file-text"/></svg>archives.log</button>` : '';
                const archivesJsonBtn = logs.archives_json && logs.archives_json.exists ?
                    `<button class="btn btn-sm" style="background:#17a2b8;color:#fff;" onclick="showLogViewerModal('${jsName}', 'archives', 'json')" title="View archives.json (${formatFileSize(logs.archives_json.size)})"><svg class="icon"><use href="#icon-file-code"/></svg>archives.json</button>` : '';
                // Alerts buttons
                const alertsLogBtn = logs.alerts_log && logs.alerts_log.exists ?
                    `<button class="btn btn-sm" style="background:#e91e63;color:#fff;" onclick="showLogViewerModal('${jsName}', 'alerts', 'log')" title="View alerts.log (${formatFileSize(logs.alerts_log.size)})"><svg class="icon"><use href="#icon-bell"/></svg>alerts.log</button>` : '';
                const alertsJsonBtn = logs.alerts_json && logs.alerts_json.exists ?
                    `<button class="btn btn-sm" style="background:#9c27b0;color:#fff;" onclick="showLogViewerModal('${jsName}', 'alerts', 'json')" title="View alerts.json (${formatFileSize(logs.alerts_json.size)})"><svg class="icon"><use href="#icon-bell"/></svg>alerts.json</button>` : '';

                const isDisconnected = n.status === 'disconnected';
                const isNotInCluster = n.status === 'not_in_cluster';
                const isDimmed = isDisconnected || isNotInCluster;
                const statusBadge = isDisconnected ? ' <span class="badge badge-disconnected">disconnected</span>' :
                                    isNotInCluster ? ' <span class="badge badge-not-in-cluster">not in cluster</span>' : '';
                const rowStyle = isDimmed ? ' style="opacity:0.7"' : '';

                return `<tr${rowStyle}>
                    <td>${safeName}${statusBadge}${n.hostname ? `<br><span style="color:#888;">(${escapeHtml(n.hostname)})</span>` : ''}</td>
                    <td style="text-align:center"><span class="badge ${n.type === 'master' ? 'badge-master' : 'badge-worker'}">${escapeHtml(n.type)}</span></td>
                    <td style="text-align:center">${escapeHtml(n.version)}</td>
                    <td>${escapeHtml(n.ip)}</td>
                    <td style="text-align:center">${n.count ? `<a href="#" onclick="filterByNode('${jsName}'); return false;" style="color:#4fc3f7;text-decoration:none;font-weight:bold;" title="View agents on this node">${n.count}</a>` : "-"}</td>
                    <td>${servicesHtml}</td>
                    <td>${syncHtml}</td>
                    <td>
                        <div class="btn-wrap">
                            <button class="btn btn-sm btn-success" onclick="restartNodeServices('${jsName}')" title="Restart Wazuh Manager services on this node"><svg class="icon"><use href="#icon-restart"/></svg>Restart</button>
                            <button class="btn btn-sm btn-warning" onclick="reconnectNodeAgents('${jsName}')" title="Force all agents on this node to reconnect"><svg class="icon"><use href="#icon-link"/></svg>Reconnect</button>
                            <button class="btn btn-sm btn-primary" onclick="showConfigModal('${jsName}')" title="View/Edit ossec.conf configuration file"><svg class="icon"><use href="#icon-file-code"/></svg>ossec.conf</button>
                            <button class="btn btn-sm" style="background:#00897b;color:#fff;" onclick="showDaemonStats('${jsName}')" title="analysisd / remoted queue counters"><svg class="icon"><use href="#icon-stats"/></svg>Health</button>
                            ${n.type === 'master' ? `<button class="btn btn-sm" style="background:#7b1fa2;color:#fff;" onclick="showEmailAlertsModal('${jsName}')" title="Manage email alert rules"><svg class="icon"><use href="#icon-mail"/></svg>Email Alerts</button>` : ''}
                            ${archivesLogBtn}
                            ${archivesJsonBtn}
                            ${alertsLogBtn}
                            ${alertsJsonBtn}
                            ${clusterKeyBtn}
                            <button class="btn btn-sm" style="background:#fd7e14;color:#fff;" onclick="showUpgradeFiles('${jsName}')" title="Manage WPK upgrade files on this node"><svg class="icon"><use href="#icon-package"/></svg>WPK Files</button>
                        </div>
                    </td>
                </tr>`;
            }).join('');
        }

        // Show sync detail modal
        async function showSyncDetail(nodeName, itemName, itemPath) {
            showModal('Sync Detail: ' + itemName, '<div class="loading"><div class="spinner"></div>Loading comparison...</div>', '', true);

            try {
                const data = await api('/nodes/' + encodeURIComponent(nodeName) + '/sync-detail?item=' + encodeURIComponent(itemName) + '&path=' + encodeURIComponent(itemPath));

                if (!data || data.error) {
                    document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">' + (data ? data.error : 'Failed to load') + '</div>';
                    return;
                }

                let statusBadge = '';
                if (data.status === 'synced') {
                    statusBadge = '<span style="background:#00c853;color:#fff;padding:4px 12px;border-radius:4px;font-weight:bold;">Synced</span>';
                } else if (data.status === 'not_synced') {
                    statusBadge = '<span style="background:#e94560;color:#fff;padding:4px 12px;border-radius:4px;font-weight:bold;">Not Synced</span>';
                } else {
                    statusBadge = '<span style="background:#888;color:#fff;padding:4px 12px;border-radius:4px;font-weight:bold;">Unknown</span>';
                }

                let html = `
                    <div style="margin-bottom:15px;">
                        <div style="display:flex;align-items:center;gap:15px;margin-bottom:10px;">
                            <strong style="font-size:16px;">${escapeHtml(itemName)}</strong>
                            ${statusBadge}
                        </div>
                        <div style="color:#888;font-size:13px;">
                            <strong>Path:</strong> <code style="background:#0f3460;padding:2px 6px;border-radius:3px;">${escapeHtml(itemPath)}</code>
                        </div>
                        <div style="color:#888;font-size:13px;margin-top:5px;">
                            <strong>Worker Node:</strong> ${escapeHtml(nodeName)}
                        </div>
                    </div>
                `;

                if (data.status === 'synced') {
                    html += '<div class="alert alert-success">All files are synchronized between master and worker.</div>';
                    if (data.file_count !== undefined) {
                        html += '<div style="color:#aaa;font-size:13px;">Total files: ' + data.file_count + '</div>';
                    }
                } else if (data.status === 'not_synced') {
                    html += '<div class="alert alert-warning" style="background:#ffc10722;border-color:#ffc107;">Files are different between master and worker.</div>';

                    if (data.master_only && data.master_only.length > 0) {
                        html += '<h4 style="margin:15px 0 10px;color:#4fc3f7;">Only on Master (' + data.master_only.length + ')</h4>';
                        html += '<div style="max-height:150px;overflow-y:auto;background:#0a0a1a;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;">';
                        html += data.master_only.map(f => '<div style="color:#00c853;">+ ' + escapeHtml(f) + '</div>').join('');
                        html += '</div>';
                    }

                    if (data.worker_only && data.worker_only.length > 0) {
                        html += '<h4 style="margin:15px 0 10px;color:#4fc3f7;">Only on Worker (' + data.worker_only.length + ')</h4>';
                        html += '<div style="max-height:150px;overflow-y:auto;background:#0a0a1a;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;">';
                        html += data.worker_only.map(f => '<div style="color:#e94560;">- ' + escapeHtml(f) + '</div>').join('');
                        html += '</div>';
                    }

                    if (data.different && data.different.length > 0) {
                        html += '<h4 style="margin:15px 0 10px;color:#4fc3f7;">Different Content (' + data.different.length + ')</h4>';
                        html += '<div style="max-height:150px;overflow-y:auto;background:#0a0a1a;padding:10px;border-radius:4px;font-family:monospace;font-size:12px;">';
                        html += data.different.map(f => '<div style="color:#ffc107;">~ ' + escapeHtml(f) + '</div>').join('');
                        html += '</div>';
                    }
                }

                document.getElementById('modalBody').innerHTML = html;
            } catch (err) {
                document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">Error: ' + escapeHtml(err.message) + '</div>';
            }
        }

        // Stats
        let statsData = null;
        let statsSortState = {
            by_status: { col: 'count', dir: 'desc' },
            by_group: { col: 'count', dir: 'desc' },
            by_network: { col: 'name', dir: 'asc' },
            by_os: { col: 'name', dir: 'asc' },
            by_version: { col: 'name', dir: 'desc' }
        };

        function sortStatsData(data, section, col, dir) {
            const arr = [...data];
            arr.sort((a, b) => {
                let va, vb, cmp;
                if (col === 'name') {
                    // Get the name field based on section
                    const nameKey = section === 'by_status' ? 'status' :
                                   section === 'by_group' ? 'group' :
                                   section === 'by_network' ? 'network' :
                                   section === 'by_os' ? 'os' : 'version';
                    // Use version comparison for by_version section
                    if (section === 'by_version') {
                        cmp = compareVersions(a[nameKey], b[nameKey]);
                        return dir === 'asc' ? cmp : -cmp;
                    }
                    va = (a[nameKey] || '').toLowerCase();
                    vb = (b[nameKey] || '').toLowerCase();
                } else if (col === 'count') {
                    va = a.count;
                    vb = b.count;
                } else if (col === 'percentage') {
                    va = a.percentage;
                    vb = b.percentage;
                }
                if (va < vb) return dir === 'asc' ? -1 : 1;
                if (va > vb) return dir === 'asc' ? 1 : -1;
                return 0;
            });
            return arr;
        }

        function sortStats(section, col) {
            if (!statsData) return;
            const state = statsSortState[section];
            if (state.col === col) {
                state.dir = state.dir === 'asc' ? 'desc' : 'asc';
            } else {
                state.col = col;
                state.dir = col === 'name' ? 'asc' : 'desc';
            }
            renderStats();
        }

        function renderStats() {
            if (!statsData) return;
            const content = document.getElementById('statsContent');
            const sortIcons = '<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg>';

            function getSortClass(section, col) {
                const state = statsSortState[section];
                if (state.col === col) return state.dir;
                return '';
            }

            function renderTable(section, title, nameCol, nameKey, note = '') {
                const state = statsSortState[section];
                const data = sortStatsData(statsData[section] || [], section, state.col, state.dir);
                return `
                    <h3 style="margin-top:20px">${title}</h3>
                    ${note ? `<p style="color:#888;font-size:12px;margin:5px 0 10px 0;font-style:italic;">${note}</p>` : ''}
                    <table>
                        <thead><tr>
                            <th class="sortable ${getSortClass(section, 'name')}" style="width:50%" onclick="sortStats('${section}','name')">${nameCol}${sortIcons}</th>
                            <th class="sortable ${getSortClass(section, 'count')}" style="width:25%;text-align:right" onclick="sortStats('${section}','count')">Count${sortIcons}</th>
                            <th class="sortable ${getSortClass(section, 'percentage')}" style="width:25%;text-align:right" onclick="sortStats('${section}','percentage')">%${sortIcons}</th>
                        </tr></thead>
                        <tbody>${data.map(item => `<tr><td>${item[nameKey]}</td><td style="text-align:right">${item.count}</td><td style="text-align:right">${item.percentage.toFixed(1)}%</td></tr>`).join('')}</tbody>
                    </table>
                `;
            }

            content.innerHTML =
                renderTable('by_status', 'By Status', 'Status', 'status').replace('style="margin-top:20px"', '') +
                renderTable('by_group', 'By Group', 'Group', 'group', '* Agents can belong to multiple groups, so percentages may exceed 100%') +
                renderTable('by_network', 'By Network Segment', 'Network', 'network') +
                renderTable('by_os', 'By OS', 'OS', 'os') +
                renderTable('by_version', 'By Agent Version', 'Version', 'version');
        }

        async function refreshStats() {
            const content = document.getElementById('statsContent');
            content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

            try {
                const data = await api('/stats/report');
                if (!data) return;

                if (data.error) {
                    content.innerHTML = `<div class="alert alert-error">${data.error}</div>`;
                    return;
                }

                statsData = data;
                renderStats();
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    content.innerHTML = getConnectionErrorHtml('refreshStats()');
                } else {
                    content.innerHTML = `<div class="alert alert-error">Error loading statistics: ${escapeHtml(err.message)}</div>`;
                }
            }
        }

        // Modal functions
        function showModal(title, body, footer, wide = false) {
            document.getElementById('modalTitle').textContent = title;
            document.getElementById('modalBody').innerHTML = body;
            document.getElementById('modalFooter').innerHTML = footer;
            const modalContent = document.querySelector('.modal-content');
            if (wide) modalContent.classList.add('wide');
            else modalContent.classList.remove('wide');
            document.getElementById('modal').classList.add('show');
        }

        function closeModal() {
            document.getElementById('modal').classList.remove('show');
            const modalContent = document.querySelector('.modal-content');
            modalContent.classList.remove('wide', 'resizable');
            modalContent.style.width = '';
            modalContent.style.height = '';
            modalContent.style.maxWidth = '';
            modalContent.style.position = '';
        }

        // Custom confirm dialog (returns Promise)
        let confirmResolve = null;

        // Close modal on ESC key
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' && document.getElementById('modal').classList.contains('show')) {
                if (confirmResolve) { confirmResolve(false); confirmResolve = null; }
                closeModal();
            }
        });
        function showConfirm(message, isDanger = false) {
            return new Promise((resolve) => {
                confirmResolve = resolve;
                const body = '<p style="margin:0;font-size:15px;">' + message + '</p>';
                const btnClass = isDanger ? 'btn-danger' : 'btn-primary';
                const footer = '<button class="btn" onclick="confirmResolve(false);closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                    '<button class="btn ' + btnClass + '" onclick="confirmResolve(true);closeModal()"><svg class="icon"><use href="#icon-check"/></svg>Confirm</button>';
                showModal('Confirm', body, footer);
            });
        }

        function showAddToGroupModal() {
            const body = `
                <div class="form-group">
                    <label>Select Group</label>
                    <select id="targetGroup">${groups.map(g => `<option value="${g.name}">${g.name}</option>`).join('')}</select>
                </div>
                <p>Will add ${selectedAgents.size} agent(s) to the selected group.</p>
                ${document.getElementById('dryRunMode').checked ? '<div class="dry-run-notice">Dry Run Mode: No changes will be made</div>' : ''}
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="addToGroup()"><svg class="icon"><use href="#icon-add-group"/></svg>Add to Group</button>
            `;
            showModal('Add Agents to Group', body, footer);
        }

        async function addToGroup() {
            const group = document.getElementById('targetGroup').value;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + group + '/agents', 'POST', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            closeModal();
            if (result) {
                showToast(result.message || 'Agents added to group', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); refreshAgents(); }
            }
        }

        function showRemoveFromGroupModal() {
            // Get currently selected group from filter (if any)
            const selectedGroupFilters = getFilterValues('groupFilter');
            const preselectedGroup = selectedGroupFilters.length === 1 ? selectedGroupFilters[0] : '';

            const body = `
                <div class="form-group">
                    <label>Select Group</label>
                    <select id="targetGroup">${groups.map(g => `<option value="${g.name}"${g.name === preselectedGroup ? ' selected' : ''}>${g.name}</option>`).join('')}</select>
                </div>
                <p>Will remove ${selectedAgents.size} agent(s) from the selected group.</p>
                ${document.getElementById('dryRunMode').checked ? '<div class="dry-run-notice">Dry Run Mode: No changes will be made</div>' : ''}
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-warning" onclick="removeFromGroup()"><svg class="icon"><use href="#icon-remove"/></svg>Remove from Group</button>
            `;
            showModal('Remove Agents from Group', body, footer);
        }

        async function removeFromGroup() {
            const group = document.getElementById('targetGroup').value;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + group + '/agents', 'DELETE', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            closeModal();
            if (result) {
                showToast(result.message || 'Agents removed from group', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); refreshAgents(); }
            }
        }

        async function showMoveToNodeModal() {
            const body = `
                <div style="text-align:center;padding:30px;">
                    <svg class="icon" style="width:48px;height:48px;color:#ffc107;margin-bottom:15px;"><use href="#icon-move"/></svg>
                    <h3 style="color:#ffc107;margin-bottom:15px;">Under Development</h3>
                    <p style="color:#aaa;">Move to Node feature is still under development.</p>
                    <p style="color:#888;font-size:12px;margin-top:10px;">This feature will allow you to force agents to reconnect to a specific cluster node.</p>
                    <p style="color:#888;font-size:12px;margin-top:8px;">Will integrate with HAProxy LB to route agents to designated nodes.</p>
                </div>
            `;
            showModal('Move Agents to Node', body, '');
        }

        async function moveToNode() {
            // Function placeholder - feature under development
            showToast('This feature is still under development', 'warning');
        }

        async function restartSelected() {
            if (!await showConfirm('Restart ' + selectedAgents.size + ' agent(s)?')) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/agents/restart', 'POST', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            if (result) {
                showToast(result.message || 'Restart command sent', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); }
            }
        }

        async function reconnectSelected() {
            if (!await showConfirm('Reconnect ' + selectedAgents.size + ' agent(s)?')) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/agents/reconnect', 'POST', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            if (result) {
                showToast(result.message || 'Reconnect command sent', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); }
            }
        }

        async function deleteSelected() {
            if (!await showConfirm('DELETE ' + selectedAgents.size + ' agent(s)? This cannot be undone!', true)) return;
            // Second confirmation for safety
            if (!await showConfirm('⚠️ FINAL CONFIRMATION ⚠️\\n\\nAre you ABSOLUTELY sure you want to permanently delete ' + selectedAgents.size + ' agent(s)?\\n\\nThis action CANNOT be undone!', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/agents', 'DELETE', {
                agent_ids: Array.from(selectedAgents),
                dry_run: dryRun
            });
            if (result) {
                showToast(result.message || 'Agents deleted', 'success');
                if (!dryRun) { selectedAgents.clear(); updateSelectedUI(); refreshAgents(); }
            }
        }

        async function cleanQueueDBSelected() {
            const selectedList = Array.from(selectedAgents);
            const agentInfo = selectedList.map(id => {
                const a = agents.find(x => x.id === id);
                const entries = (a && a.queue_entries) || [];
                const sizeStr = entries.length > 0
                    ? entries.map(e => formatBytes(e.size) + ' on ' + e.node).join(', ')
                    : 'unknown size';
                return id + ' (' + (a ? a.name : '?') + ') - ' + sizeStr;
            }).join('\\n');

            if (!await showConfirm(
                'Clean Queue DB for ' + selectedAgents.size + ' agent(s)?\\n\\n' +
                'This will delete the queue DB files and restart the agents.\\n\\n' +
                agentInfo
            )) return;

            const dryRun = document.getElementById('dryRunMode').checked;
            // Build map of agent_id -> nodes that have queue DB files
            const agentNodes = {};
            selectedList.forEach(id => {
                const a = agents.find(x => x.id === id);
                const entries = (a && a.queue_entries) || [];
                agentNodes[id] = entries.map(e => e.node);
            });
            const result = await api('/agents/queue-db/clean', 'POST', {
                agent_ids: selectedList,
                agent_nodes: agentNodes,
                dry_run: dryRun
            });

            if (result) {
                if (result.details) {
                    showModal('Clean Queue DB Results', formatCleanResults(result), '');
                } else {
                    showToast(result.message || 'Queue DB cleaned', result.errors ? 'warning' : 'success');
                }
                if (!dryRun) {
                    if (showQueueDB) {
                        await loadQueueSizes();
                    }
                    selectedAgents.clear();
                    updateSelectedUI();
                    renderAgents();
                }
            }
        }

        function formatCleanResults(result) {
            const dryRunLabel = result.dry_run ? ' <span class="badge" style="background:#ff9800;">DRY-RUN</span>' : '';
            let html = '<div style="margin-bottom:12px;">' + escapeHtml(result.message) + dryRunLabel + '</div>';
            html += '<div style="max-height:400px;overflow-y:auto;">';
            html += '<table style="width:100%;border-collapse:collapse;">';
            html += '<thead><tr style="border-bottom:1px solid #333;">';
            html += '<th style="text-align:left;padding:6px;">Agent</th>';
            html += '<th style="text-align:left;padding:6px;">Node</th>';
            html += '<th style="text-align:left;padding:6px;">Status</th>';
            html += '</tr></thead><tbody>';

            (result.details || []).forEach(d => {
                const a = agents.find(x => x.id === d.agent_id);
                const agentLabel = d.agent_id + (a ? ' (' + escapeHtml(a.name) + ')' : '');
                if (d.deleted && d.deleted.length > 0) {
                    d.deleted.forEach(del => {
                        const status = del.dry_run
                            ? '<span style="color:#ff9800;">Would delete</span>'
                            : '<span style="color:#4caf50;">Deleted</span>';
                        html += '<tr style="border-bottom:1px solid #222;">';
                        html += '<td style="padding:6px;">' + escapeHtml(agentLabel) + '</td>';
                        html += '<td style="padding:6px;">' + escapeHtml(del.node) + '</td>';
                        html += '<td style="padding:6px;">' + status + '</td>';
                        html += '</tr>';
                    });
                }
                if (d.errors && d.errors.length > 0) {
                    d.errors.forEach(err => {
                        html += '<tr style="border-bottom:1px solid #222;">';
                        html += '<td style="padding:6px;">' + escapeHtml(agentLabel) + '</td>';
                        html += '<td style="padding:6px;">' + escapeHtml(err.node) + '</td>';
                        html += '<td style="padding:6px;"><span style="color:#f44336;">Error: ' + escapeHtml(err.error) + '</span></td>';
                        html += '</tr>';
                    });
                }
                if ((!d.deleted || d.deleted.length === 0) && (!d.errors || d.errors.length === 0)) {
                    html += '<tr style="border-bottom:1px solid #222;">';
                    html += '<td style="padding:6px;">' + escapeHtml(agentLabel) + '</td>';
                    html += '<td style="padding:6px;">-</td>';
                    html += '<td style="padding:6px;"><span style="color:#aaa;">No DB file found</span></td>';
                    html += '</tr>';
                }
            });

            html += '</tbody></table></div>';

            if (result.restart_result) {
                const data = result.restart_result.data || {};
                const affected = data.affected_items || [];
                const failed = data.failed_items || [];
                const borderColor = failed.length > 0 ? '#f44336' : '#4caf50';
                html += '<div style="margin-top:12px;padding:8px 12px;background:#1a1a2e;border-left:3px solid ' + borderColor + ';border-radius:4px;">';
                html += 'Agent restart: ' + affected.length + ' agent(s) restarted';
                if (failed.length > 0) {
                    html += ', <span style="color:#f44336;">' + failed.length + ' failed</span>';
                    html += '<div style="margin-top:6px;font-size:12px;color:#aaa;">';
                    failed.forEach(f => {
                        const fid = f.id || (f.error && f.error.code) || '?';
                        const fmsg = (f.error && f.error.message) || 'Unknown error';
                        html += '<div style="margin:2px 0;"><span style="color:#f44336;">&#x2716;</span> Agent ' + escapeHtml(String(fid)) + ': ' + escapeHtml(fmsg) + '</div>';
                    });
                    html += '</div>';
                }
                html += '</div>';
            }

            return html;
        }

        async function upgradeSelected() {
            // Get selected agents info
            const selectedList = Array.from(selectedAgents);
            const selectedAgentData = agents.filter(a => selectedList.includes(a.id));

            // Group by version for display
            const versionGroups = {};
            selectedAgentData.forEach(a => {
                const v = a.version || 'unknown';
                if (!versionGroups[v]) versionGroups[v] = [];
                versionGroups[v].push(a.name);
            });

            let versionSummary = Object.entries(versionGroups).map(([v, names]) =>
                `<div style="margin:5px 0;"><span class="badge">${escapeHtml(v)}</span> ${names.length} agent(s)</div>`
            ).join('');

            const dryRun = document.getElementById('dryRunMode').checked;
            const dryRunNotice = dryRun ?
                '<div class="dry-run-notice" style="margin-bottom:15px;">Dry Run Mode: No changes will be made</div>' : '';

            const body = `
                ${dryRunNotice}
                <div style="background:#1a1a2e;border-left:3px solid #fd7e14;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#aaa;font-size:12px;margin:0;">Upgrade will update agents to the latest available version from Wazuh repository. Make sure the manager has internet access or the WPK files are available locally.</p>
                </div>
                <p style="color:#aaa;margin-bottom:5px;">Selected Agents (${selectedList.length})</p>
                <div style="max-height:120px;overflow-y:auto;background:#1a1a2e;padding:10px;border-radius:4px;margin-bottom:15px;">
                    ${versionSummary}
                </div>
                <p style="color:#aaa;margin-bottom:5px;">Upgrade Options</p>
                <div style="background:#1a1a2e;padding:12px;border-radius:4px;margin-bottom:15px;">
                    <div style="margin-bottom:10px;"><input type="radio" name="upgradeType" value="latest" id="upgradeLatest" checked style="margin-right:8px;"><label for="upgradeLatest" style="cursor:pointer;"><span>Upgrade to manager version</span>${managerVersion ? ' (<span style="color:#4fc3f7;">v' + managerVersion + '</span>)' : ''}</label></div>
                    <div style="margin-bottom:10px;"><input type="radio" name="upgradeType" value="custom" id="upgradeCustom" style="margin-right:8px;"><label for="upgradeCustom" style="cursor:pointer;">Specify version:</label> <input type="text" id="customVersion" placeholder="e.g., 4.14.0" style="width:100px;margin-left:5px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;" onfocus="document.getElementById('upgradeCustom').checked=true;"></div>
                    <div><input type="radio" name="upgradeType" value="wpk" id="upgradeWpk" style="margin-right:8px;"><label for="upgradeWpk" style="cursor:pointer;">WPK file on the manager:</label>
                        <select id="upgradeWpkFile" style="margin-left:5px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;max-width:340px;" onfocus="document.getElementById('upgradeWpk').checked=true;">
                            <option value="">Loading...</option>
                        </select>
                        <div style="color:#888;font-size:11px;margin-top:4px;">Use this when the manager has no internet access.</div>
                    </div>
                </div>
                <div><input type="checkbox" id="upgradeForce" style="margin-right:8px;"><label for="upgradeForce" style="cursor:pointer;">Force upgrade (even if same version)</label></div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn" style="background:#fd7e14;color:#fff;" onclick="executeUpgrade()"><svg class="icon"><use href="#icon-upload"/></svg>Upgrade</button>
            `;
            showModal('Upgrade Agents', body, footer);
            loadUpgradeWpkOptions();
        }

        // Fill the WPK dropdown from the manager's upgrade directory
        async function loadUpgradeWpkOptions() {
            const select = document.getElementById('upgradeWpkFile');
            if (!select) return;
            const nodesData = await api('/nodes');
            const nodeList = (nodesData && nodesData.nodes) ? nodesData.nodes : [];
            const master = nodeList.find(n => n.type === 'master') || nodeList[0];
            if (!master) { select.innerHTML = '<option value="">No node available</option>'; return; }
            const node = master.name;
            const result = await api('/nodes/' + node + '/upgrade-files');
            const files = (result && result.files) ? result.files.filter(f => (f.name || '').endsWith('.wpk')) : [];
            if (!files.length) {
                select.innerHTML = '<option value="">No WPK files uploaded</option>';
                return;
            }
            select.innerHTML = files.map(f => '<option value="' + escapeHtml(f.name) + '">' + escapeHtml(f.name) + '</option>').join('');
        }

        async function executeUpgrade() {
            const selectedList = Array.from(selectedAgents);
            const upgradeType = document.querySelector('input[name="upgradeType"]:checked').value;
            const customVersion = document.getElementById('customVersion').value.trim();
            const force = document.getElementById('upgradeForce').checked;
            const dryRun = document.getElementById('dryRunMode').checked;

            if (upgradeType === 'custom' && !customVersion) {
                showToast('Please enter a version number', 'warning');
                return;
            }

            if (upgradeType === 'wpk') {
                const wpkFile = document.getElementById('upgradeWpkFile').value;
                if (!wpkFile) {
                    showToast('Please select a WPK file', 'warning');
                    return;
                }
                closeModal();
                if (!await showConfirm('Upgrade ' + selectedList.length + ' agent(s) using ' + wpkFile + '?', true)) return;
                showToast('Starting upgrade for ' + selectedList.length + ' agent(s)...', 'info');
                const wpkResult = await api('/agents/upgrade-custom', 'POST', {
                    agent_ids: selectedList, file_path: wpkFile
                });
                if (!wpkResult || wpkResult.error) {
                    showToast((wpkResult && wpkResult.error) || 'Upgrade failed', 'error');
                    return;
                }
                showToast(wpkResult.message || 'Upgrade queued', wpkResult.fail_count ? 'warning' : 'success');
                showUpgradeProgress(selectedList);
                return;
            }

            closeModal();

            if (!await showConfirm('Upgrade ' + selectedList.length + ' agent(s)' + (upgradeType === 'custom' ? ' to v' + customVersion : ' to latest version') + '?', true)) return;

            showToast('Starting upgrade for ' + selectedList.length + ' agent(s)...', 'info');

            const result = await api('/agents/upgrade', 'POST', {
                agent_ids: selectedList,
                version: upgradeType === 'custom' ? customVersion : null,
                force: force,
                dry_run: dryRun
            });

            if (result) {
                if (result.error) {
                    showToast('Upgrade failed: ' + result.error, 'error');
                } else {
                    const successCount = result.success_count || 0;
                    const failCount = result.fail_count || 0;
                    const failedAgents = result.failed_agents || [];

                    if (failCount > 0 && successCount === 0) {
                        // All failed - show error details in modal
                        showUpgradeErrorModal(failedAgents);
                    } else if (failCount > 0) {
                        // Partial success
                        showToast(`Upgrade: ${successCount} success, ${failCount} failed`, 'warning', 8000);
                        if (!dryRun) {
                            showUpgradeProgress(selectedList);
                        }
                    } else {
                        showToast(result.message || 'Upgrade initiated for ' + successCount + ' agent(s)', 'success');
                        if (!dryRun && successCount > 0) {
                            showUpgradeProgress(selectedList);
                        }
                    }
                }
            }
        }

        function showUpgradeErrorModal(failedAgents) {
            const agentMap = {};
            agents.forEach(a => { agentMap[a.id] = a; });

            // Check if any error is WPK related
            const hasWpkError = failedAgents.some(fa =>
                (fa.error && (fa.error.toLowerCase().includes('wpk') ||
                              fa.error.includes('Upgrade task not created') ||
                              fa.error.includes('/var/ossec/var/upgrade')))
            );

            let html = '<table style="width:100%;border-collapse:collapse;">';
            html += '<thead><tr style="background:#0f3460;"><th style="padding:10px;text-align:left;">Agent</th><th style="padding:10px;text-align:left;">Error</th></tr></thead>';
            html += '<tbody>';

            for (const fa of failedAgents) {
                const agent = agentMap[fa.id] || {};
                const agentName = agent.name || fa.id;
                const agentVersion = agent.version || '';
                const agentNode = agent.node_name || '';
                html += '<tr style="border-bottom:1px solid #1a3a6e;">';
                html += '<td style="padding:10px;"><span style="color:#0dcaf0;">' + escapeHtml(fa.id) + '</span><br><span style="color:#888;font-size:11px;">' + escapeHtml(agentName) + (agentVersion ? ' (' + agentVersion + ')' : '') + '</span></td>';
                // Format error message with line breaks for readability
                const errorHtml = escapeHtml(fa.error || 'Unknown error').replace(/\\n/g, '<br>');
                html += '<td style="padding:10px;color:#dc3545;white-space:pre-line;">' + errorHtml + '</td>';
                html += '</tr>';
            }

            html += '</tbody></table>';

            // Build hint section if WPK error detected
            let wpkHint = '';
            if (hasWpkError) {
                wpkHint = `
                    <div style="background:#1a1a2e;border-left:3px solid #fd7e14;padding:15px;margin-bottom:15px;border-radius:4px;">
                        <p style="color:#fd7e14;font-size:13px;font-weight:600;margin:0 0 10px 0;">WPK File Required</p>
                        <p style="color:#aaa;font-size:12px;margin:0 0 10px 0;">
                            The agent upgrade requires a WPK (Wazuh PacKage) file that is not available on the manager.
                            Please go to <strong>Node Management</strong> → select the node → <strong>Upgrade Files</strong> to:
                        </p>
                        <ul style="color:#aaa;font-size:12px;margin:0;padding-left:20px;">
                            <li>Upload the WPK file manually, or</li>
                            <li>Check if the WPK files exist for your target version</li>
                        </ul>
                        <p style="color:#888;font-size:11px;margin:10px 0 0 0;">
                            WPK files can be downloaded from: <a href="https://packages.wazuh.com/4.x/wpk/" target="_blank" style="color:#4fc3f7;">https://packages.wazuh.com/4.x/wpk/</a>
                        </p>
                    </div>
                `;
            }

            const body = `
                <div style="background:#1a1a2e;border-left:3px solid #dc3545;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#dc3545;font-size:14px;margin:0;">Upgrade failed for ${failedAgents.length} agent(s)</p>
                </div>
                ${wpkHint}
                <div style="max-height:350px;overflow-y:auto;">
                    ${html}
                </div>
            `;
            const footer = hasWpkError ? '<button class="btn" style="background:#fd7e14;color:#fff;" onclick="closeModal();showNodeManagement();">Go to Node Management</button>' : '';
            showModal('Upgrade Failed', body, footer);
        }

        let upgradeProgressInterval = null;
        let lastUpgradedAgentIds = [];  // Store recently upgraded agent IDs
        let upgradeHistoryCleared = false;  // Flag to track if history was manually cleared

        function showUpgradeProgress(agentIds) {
            // Store for later viewing and reset cleared flag
            lastUpgradedAgentIds = agentIds;
            upgradeHistoryCleared = false;
            const body = `
                <div style="background:#1a1a2e;border-left:3px solid #17a2b8;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#aaa;font-size:12px;margin:0;">Tracking upgrade progress for ${agentIds.length} agent(s). Status updates every 5 seconds.</p>
                </div>
                <div id="upgradeProgressContent" style="max-height:400px;overflow-y:auto;">
                    <div style="text-align:center;padding:30px;color:#888;">
                        <div class="spinner" style="margin:0 auto 15px;"></div>
                        Loading upgrade status...
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeUpgradeProgress()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>
                <button class="btn" onclick="refreshUpgradeProgress()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            `;
            showModal('Upgrade Progress', body, footer);

            // Store agent IDs for polling
            window.upgradeAgentIds = agentIds;

            // Initial fetch
            refreshUpgradeProgress();

            // Start polling every 5 seconds
            upgradeProgressInterval = setInterval(refreshUpgradeProgress, 5000);
        }

        function closeUpgradeProgress() {
            if (upgradeProgressInterval) {
                clearInterval(upgradeProgressInterval);
                upgradeProgressInterval = null;
            }
            closeModal();
            refreshAgents();
        }

        async function refreshUpgradeProgress() {
            const agentIds = window.upgradeAgentIds || [];
            if (!agentIds.length) return;

            try {
                const resp = await fetch('/api/agents/upgrade-result?agent_ids=' + agentIds.join(','));
                const data = await resp.json();

                if (data.error) {
                    document.getElementById('upgradeProgressContent').innerHTML =
                        '<div style="color:#dc3545;padding:20px;">Error: ' + escapeHtml(data.error) + '</div>';
                    return;
                }

                const results = data.results || [];
                let html = '<table style="width:100%;border-collapse:collapse;">';
                html += '<thead><tr style="background:#0f3460;"><th style="padding:10px;text-align:left;">Agent</th><th style="padding:10px;text-align:left;">Status</th><th style="padding:10px;text-align:left;">Details</th></tr></thead>';
                html += '<tbody>';

                // Get agent names from cache
                const agentMap = {};
                agents.forEach(a => { agentMap[a.id] = a.name; });

                // Track completion
                let completedCount = 0;
                let failedCount = 0;

                for (const agentId of agentIds) {
                    const result = results.find(r => r.agent_id === agentId);
                    const agentName = agentMap[agentId] || agentId;

                    let status = 'Pending';
                    let statusColor = '#888';
                    let statusIcon = 'clock';
                    let iconSpin = false;
                    let details = '';

                    if (result) {
                        const s = result.status.toLowerCase();
                        if (s === 'updated' || s === 'done' || s === 'success') {
                            status = 'Updated';
                            statusColor = '#28a745';
                            statusIcon = 'check';
                            completedCount++;
                        } else if (s === 'updating' || s === 'in progress' || s === 'downloading') {
                            status = s.charAt(0).toUpperCase() + s.slice(1);
                            statusColor = '#17a2b8';
                            statusIcon = 'refresh';
                            iconSpin = true;
                        } else if (s === 'error' || s === 'failed') {
                            status = 'Failed';
                            statusColor = '#dc3545';
                            statusIcon = 'xmark';
                            details = result.error || '';
                            failedCount++;
                            completedCount++;
                        } else {
                            status = s.charAt(0).toUpperCase() + s.slice(1);
                        }
                    }

                    const iconClass = iconSpin ? 'icon icon-spin' : 'icon';
                    html += '<tr style="border-bottom:1px solid #1a3a6e;">';
                    html += '<td style="padding:10px;"><span style="color:#0dcaf0;">' + escapeHtml(agentId) + '</span><br><span style="color:#888;font-size:11px;">' + escapeHtml(agentName) + '</span></td>';
                    html += '<td style="padding:10px;"><span style="color:' + statusColor + ';"><svg class="' + iconClass + '" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-' + statusIcon + '"/></svg>' + status + '</span></td>';
                    html += '<td style="padding:10px;color:#888;font-size:12px;">' + escapeHtml(details) + '</td>';
                    html += '</tr>';
                }

                html += '</tbody></table>';

                // Summary
                const remaining = agentIds.length - completedCount;
                let summary = '<div style="padding:15px;background:#0a0a15;border-radius:4px;margin-top:15px;">';
                summary += '<span style="color:#28a745;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-check"/></svg>' + (completedCount - failedCount) + ' Updated</span>';
                if (failedCount > 0) {
                    summary += '<span style="color:#dc3545;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-xmark"/></svg>' + failedCount + ' Failed</span>';
                }
                if (remaining > 0) {
                    summary += '<span style="color:#888;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-clock"/></svg>' + remaining + ' In Progress</span>';
                }
                summary += '</div>';

                document.getElementById('upgradeProgressContent').innerHTML = html + summary;

                // Stop polling if all done
                if (remaining === 0 && upgradeProgressInterval) {
                    clearInterval(upgradeProgressInterval);
                    upgradeProgressInterval = null;
                }

            } catch (e) {
                console.error('Failed to fetch upgrade progress:', e);
            }
        }

        async function showAllUpgradeProgress() {
            // If history was cleared and no new upgrades, show empty state
            if (upgradeHistoryCleared && lastUpgradedAgentIds.length === 0) {
                const body = `
                    <div style="text-align:center;padding:40px;color:#888;">
                        <svg class="icon" style="width:48px;height:48px;margin-bottom:15px;opacity:0.5;"><use href="#icon-check"/></svg>
                        <p>No recent upgrade tasks.</p>
                        <p style="font-size:12px;color:#666;">Upgrade history has been cleared.</p>
                    </div>
                `;
                showModal('Upgrade Progress', body, '');
                return;
            }

            // Use stored agent IDs if available, otherwise fetch all
            const useAgentIds = lastUpgradedAgentIds.length > 0;
            const agentCount = useAgentIds ? lastUpgradedAgentIds.length : 'all';

            // Show modal with loading state
            const body = `
                <div style="background:#1a1a2e;border-left:3px solid #17a2b8;padding:10px 15px;margin-bottom:15px;border-radius:4px;">
                    <p style="color:#aaa;font-size:12px;margin:0;">${useAgentIds ? `Showing upgrade progress for ${agentCount} recent agent(s).` : 'Showing all recent upgrade tasks from Wazuh API.'}</p>
                </div>
                <div id="allUpgradeProgressContent" style="max-height:400px;overflow-y:auto;">
                    <div style="text-align:center;padding:30px;color:#888;">
                        <div class="spinner" style="margin:0 auto 15px;"></div>
                        Loading upgrade tasks...
                    </div>
                </div>
            `;
            const footer = `
                <button class="btn" onclick="clearUpgradeHistory()" title="Clear history"><svg class="icon"><use href="#icon-trash"/></svg></button>
                <button class="btn btn-primary" onclick="showAllUpgradeProgress()"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
            `;
            showModal('Upgrade Progress', body, footer);

            // Fetch upgrade results (with agent filter if available)
            try {
                const url = useAgentIds
                    ? '/api/agents/upgrade-result?agent_ids=' + lastUpgradedAgentIds.join(',')
                    : '/api/agents/upgrade-result';
                const resp = await fetch(url);
                const data = await resp.json();

                const container = document.getElementById('allUpgradeProgressContent');
                if (!container) return;

                if (data.error) {
                    container.innerHTML = '<div style="color:#dc3545;padding:20px;">Error: ' + escapeHtml(data.error) + '</div>';
                    return;
                }

                const results = data.results || [];
                if (results.length === 0) {
                    container.innerHTML = '<div style="text-align:center;padding:30px;color:#888;">No recent upgrade tasks found.</div>';
                    return;
                }

                // Build table
                const agentMap = {};
                agents.forEach(a => { agentMap[a.id] = a; });

                let html = '<table style="width:100%;border-collapse:collapse;">';
                html += '<thead><tr style="background:#0f3460;"><th style="padding:10px;text-align:left;">Agent</th><th style="padding:10px;text-align:left;">Status</th><th style="padding:10px;text-align:left;">Time</th></tr></thead>';
                html += '<tbody>';

                let updatedCount = 0, failedCount = 0, inProgressCount = 0;

                for (const result of results) {
                    const agent = agentMap[result.agent_id] || {};
                    const agentName = agent.name || result.agent_id;

                    let status = result.status || 'Unknown';
                    let statusColor = '#888';
                    let statusIcon = 'clock';

                    const s = status.toLowerCase();
                    if (s === 'updated' || s === 'done' || s === 'success') {
                        statusColor = '#28a745';
                        statusIcon = 'check';
                        updatedCount++;
                    } else if (s === 'updating' || s === 'in progress' || s === 'downloading') {
                        statusColor = '#17a2b8';
                        statusIcon = 'refresh';
                        inProgressCount++;
                    } else if (s === 'error' || s === 'failed') {
                        statusColor = '#dc3545';
                        statusIcon = 'xmark';
                        failedCount++;
                    } else if (s === 'legacy') {
                        statusColor = '#ffc107';
                        statusIcon = 'clock';
                    }

                    const timeStr = result.update_time || result.create_time || '';

                    html += '<tr style="border-bottom:1px solid #1a3a6e;">';
                    html += '<td style="padding:10px;"><span style="color:#0dcaf0;">' + escapeHtml(result.agent_id) + '</span><br><span style="color:#888;font-size:11px;">' + escapeHtml(agentName) + '</span></td>';
                    html += '<td style="padding:10px;"><span style="color:' + statusColor + ';"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-' + statusIcon + '"/></svg>' + escapeHtml(status) + '</span>';
                    if (result.error) {
                        html += '<br><span style="color:#888;font-size:11px;">' + escapeHtml(result.error) + '</span>';
                    }
                    html += '</td>';
                    html += '<td style="padding:10px;color:#888;font-size:12px;">' + escapeHtml(timeStr) + '</td>';
                    html += '</tr>';
                }

                html += '</tbody></table>';

                // Summary
                let summary = '<div style="padding:15px;background:#0a0a15;border-radius:4px;margin-top:15px;">';
                summary += '<span style="margin-right:15px;">Total: ' + results.length + '</span>';
                if (updatedCount > 0) summary += '<span style="color:#28a745;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-check"/></svg>' + updatedCount + ' Updated</span>';
                if (failedCount > 0) summary += '<span style="color:#dc3545;margin-right:15px;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-xmark"/></svg>' + failedCount + ' Failed</span>';
                if (inProgressCount > 0) summary += '<span style="color:#17a2b8;"><svg class="icon" style="width:14px;height:14px;vertical-align:middle;margin-right:5px;"><use href="#icon-clock"/></svg>' + inProgressCount + ' In Progress</span>';
                summary += '</div>';

                container.innerHTML = html + summary;

            } catch (e) {
                console.error('Failed to fetch upgrade progress:', e);
                const container = document.getElementById('allUpgradeProgressContent');
                if (container) {
                    container.innerHTML = '<div style="color:#dc3545;padding:20px;">Error: ' + e.message + '</div>';
                }
            }
        }

        function clearUpgradeHistory() {
            lastUpgradedAgentIds = [];
            upgradeHistoryCleared = true;
            showToast('Upgrade history cleared', 'info');
            closeModal();
        }

        function showCreateGroupModal() {
            const body = `
                <div class="form-group">
                    <label>Group Name</label>
                    <input type="text" id="newGroupName" placeholder="Enter group name">
                </div>
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="createGroup()"><svg class="icon"><use href="#icon-plus"/></svg>Create</button>
            `;
            showModal('Create Group', body, footer);
        }

        async function createGroup() {
            const name = document.getElementById('newGroupName').value;
            if (!name) { showToast('Please enter a group name', 'warning'); return; }
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups', 'POST', { name, dry_run: dryRun });
            closeModal();
            if (result) {
                showToast(result.message || 'Group created', 'success');
                if (!dryRun) refreshGroups();
            }
        }

        async function deleteGroup(name) {
            if (!await showConfirm('Delete group "' + name + '"?', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + name, 'DELETE', { dry_run: dryRun });
            if (result) {
                showToast(result.message || 'Group deleted', 'success');
                if (!dryRun) refreshGroups();
            }
        }

        let renameFromGroup = '';
        function showRenameGroupModal(groupName) {
            renameFromGroup = groupName;
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            const dryRunNotice = document.getElementById('dryRunMode').checked ?
                '<div class="dry-run-notice">Dry Run Mode: No changes will be made</div>' : '';
            const body = `
                <div class="form-group">
                    <label>Current Name</label>
                    <input type="text" value="${groupName}" disabled style="background:#0a0a15;">
                </div>
                <div class="form-group">
                    <label>New Name</label>
                    <input type="text" id="newGroupNameInput" placeholder="Enter new group name">
                </div>
                <p style="color:#888;font-size:12px;margin-top:10px;">
                    This will: 1) Create new group, 2) Move ${count} agent(s) to new group, 3) Delete old group
                </p>
                ${dryRunNotice}
            `;
            const footer = `
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-primary" onclick="renameGroup()"><svg class="icon"><use href="#icon-rename"/></svg>Rename</button>
            `;
            showModal('Rename Group', body, footer);
            setTimeout(() => document.getElementById('newGroupNameInput').focus(), 100);
        }

        async function renameGroup() {
            const newName = document.getElementById('newGroupNameInput').value.trim();
            if (!newName) { showToast('Please enter a new group name', 'warning'); return; }
            if (newName === renameFromGroup) { showToast('New name is the same as current name', 'warning'); return; }
            if (groups.find(g => g.name === newName)) { showToast('Group "' + newName + '" already exists', 'warning'); return; }

            const dryRun = document.getElementById('dryRunMode').checked;
            closeModal();
            showToast('Renaming group...', 'info');

            const result = await api('/groups/rename', 'POST', {
                old_name: renameFromGroup,
                new_name: newName,
                dry_run: dryRun
            });

            if (result) {
                if (result.error) {
                    showToast(result.error, 'error');
                } else {
                    showToast(result.message || 'Group renamed successfully', 'success');
                    if (!dryRun) { refreshGroups(); refreshAgents(); }
                }
            }
        }

        async function removeAllFromGroup(groupName) {
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            if (!await showConfirm('Remove all ' + count + ' agent(s) from group "' + groupName + '"?', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + groupName + '/agents/all', 'DELETE', { dry_run: dryRun });
            if (result) {
                showToast(result.message || 'All agents removed from group', 'success');
                if (!dryRun) { refreshGroups(); refreshAgents(); }
            }
        }

        async function setExclusiveGroup(groupName) {
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            if (!await showConfirm(
                'Set "' + groupName + '" as exclusive group for ' + count + ' agent(s)?\\n\\n' +
                'This will REMOVE these agents from ALL other groups.', true)) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + groupName + '/exclusive', 'POST', { dry_run: dryRun });
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'Agents now only belong to this group', 'success');
                    if (!dryRun) { refreshGroups(); refreshAgents(); }
                }
            }
        }

        let moveFromGroup = '';
        function showMoveGroupAgentsModal(groupName) {
            moveFromGroup = groupName;
            const group = groups.find(g => g.name === groupName);
            const count = group ? group.count : 0;
            const otherGroups = groups.filter(g => g.name !== groupName);
            const options = otherGroups.map(g => '<option value="' + g.name + '">' + g.name + ' (' + g.count + ' agents)</option>').join('');
            const body = '<div class="form-group">' +
                '<label>Move ' + count + ' agent(s) from "' + groupName + '" to:</label>' +
                '<select id="moveTargetGroup">' + options + '</select>' +
                '</div>' +
                '<p style="color:#888;font-size:12px;">Note: Agents will be added to the target group and removed from "' + groupName + '".</p>';
            const footer = '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                '<button class="btn btn-primary" onclick="moveGroupAgents()"><svg class="icon"><use href="#icon-move"/></svg>Move</button>';
            showModal('Move Agents to Another Group', body, footer);
        }

        async function moveGroupAgents() {
            const targetGroup = document.getElementById('moveTargetGroup').value;
            if (!targetGroup) { showToast('Please select a target group', 'warning'); return; }
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/groups/' + moveFromGroup + '/move', 'POST', {
                target_group: targetGroup,
                dry_run: dryRun
            });
            closeModal();
            if (result) {
                showToast(result.message || 'Agents moved successfully', 'success');
                if (!dryRun) { refreshGroups(); refreshAgents(); }
            }
        }

        // CSV Import functions
        let importTargetGroup = '';
        let pendingImportData = [];

        function showImportCsvModal(groupName) {
            importTargetGroup = groupName;
            const body = '<div class="form-group">' +
                '<label>Select CSV file to import agents into group "' + groupName + '"</label>' +
                '<input type="file" id="csvFileInput" accept=".csv" style="margin-top:10px;">' +
                '</div>' +
                '<div style="background:#1a1a2e;padding:12px;border-radius:4px;margin-top:15px;font-size:12px;">' +
                '<p style="color:#4fc3f7;margin:0 0 8px 0;font-weight:bold;">CSV Format Rules:</p>' +
                '<ul style="color:#aaa;margin:0;padding-left:20px;line-height:1.8;">' +
                '<li>Must have at least one column: <b style="color:#fff;">ID</b>, <b style="color:#fff;">Name</b> (or Hostname), or <b style="color:#fff;">IP</b> (or Address)</li>' +
                '<li>Column order does not matter</li>' +
                '<li>If multiple match columns exist, leftmost takes priority</li>' +
                '<li>Other columns will be ignored</li>' +
                '<li>First row must be header</li>' +
                '</ul></div>' +
                '<p style="margin-top:10px;"><a href="#" onclick="downloadCsvTemplate(); return false;" style="color:#4fc3f7;">Download CSV Template</a></p>';
            const footer = '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                '<button class="btn btn-primary" onclick="previewCsvImport()"><svg class="icon"><use href="#icon-eye"/></svg>Preview</button>';
            showModal('Import Agents from CSV', body, footer);
        }

        function downloadCsvTemplate() {
            const template = 'ID,Name,IP' + String.fromCharCode(10) + '001,agent-example,192.168.1.100' + String.fromCharCode(10) + '002,another-agent,192.168.1.101';
            const blob = new Blob([template], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'agent_import_template.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            showToast('Template downloaded', 'success');
        }

        function exportGroupAgentsCsv(groupName) {
            // Filter agents by group
            const groupAgents = agents.filter(a => {
                if (!a.group) return false;
                const groups = a.group.split(',').map(g => g.trim());
                return groups.includes(groupName);
            });

            if (groupAgents.length === 0) {
                showToast('No agents in this group', 'warning');
                return;
            }

            // Build CSV with same columns as import template: ID, Name, IP
            let csv = 'ID,Name,IP' + String.fromCharCode(10);
            groupAgents.forEach(a => {
                const id = (a.id || '').replace(/"/g, '""');
                const name = (a.name || '').replace(/"/g, '""');
                const ip = (a.ip || '').replace(/"/g, '""');
                csv += '"' + id + '","' + name + '","' + ip + '"' + String.fromCharCode(10);
            });

            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = groupName + '_agents.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
            showToast('Exported ' + groupAgents.length + ' agents to CSV', 'success');
        }

        async function previewCsvImport() {
            const fileInput = document.getElementById('csvFileInput');
            if (!fileInput.files || fileInput.files.length === 0) {
                showToast('Please select a CSV file', 'warning');
                return;
            }

            const file = fileInput.files[0];
            const text = await file.text();
            const lines = text.trim().split(/\\r?\\n/);

            if (lines.length < 2) {
                showToast('CSV file is empty or has no data rows', 'warning');
                return;
            }

            // Parse header - support multiple column name variations
            const header = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/[_-]/g, ''));

            // Find matching columns (first/leftmost match wins)
            let idIndex = -1, nameIndex = -1, ipIndex = -1;
            const idNames = ['id', 'agentid', 'agent'];
            const nameNames = ['name', 'hostname', 'agentname', 'host'];
            const ipNames = ['ip', 'address', 'ipaddress', 'addr'];

            for (let i = 0; i < header.length; i++) {
                const h = header[i];
                if (idIndex === -1 && idNames.includes(h)) idIndex = i;
                if (nameIndex === -1 && nameNames.includes(h)) nameIndex = i;
                if (ipIndex === -1 && ipNames.includes(h)) ipIndex = i;
            }

            if (idIndex === -1 && nameIndex === -1 && ipIndex === -1) {
                showToast('CSV must have at least one of: ID, Name/Hostname, IP/Address columns', 'error');
                return;
            }

            // Determine priority: leftmost matching column
            const matchCols = [];
            if (idIndex >= 0) matchCols.push({ type: 'id', idx: idIndex });
            if (nameIndex >= 0) matchCols.push({ type: 'name', idx: nameIndex });
            if (ipIndex >= 0) matchCols.push({ type: 'ip', idx: ipIndex });
            matchCols.sort((a, b) => a.idx - b.idx);
            const primaryMatch = matchCols[0].type;

            // Parse data rows
            const importData = [];
            for (let i = 1; i < lines.length; i++) {
                const cols = lines[i].split(',').map(c => c.trim().replace(/^"|"$/g, ''));
                if (cols.length === 0 || (cols.length === 1 && !cols[0])) continue;
                importData.push({
                    id: idIndex >= 0 && cols[idIndex] ? cols[idIndex] : null,
                    name: nameIndex >= 0 && cols[nameIndex] ? cols[nameIndex] : null,
                    ip: ipIndex >= 0 && cols[ipIndex] ? cols[ipIndex] : null,
                    primaryMatch: primaryMatch
                });
            }

            if (importData.length === 0) {
                showToast('No valid data rows found in CSV', 'warning');
                return;
            }

            // Store for later import
            pendingImportData = importData;

            // Call API with preview mode to get matching info
            showToast('Analyzing CSV data...', 'info');
            const result = await api('/groups/' + importTargetGroup + '/import', 'POST', {
                agents: importData,
                dry_run: true
            });

            if (!result) {
                showToast('Failed to analyze CSV', 'error');
                return;
            }

            // Show preview modal
            let previewHtml = '<div style="margin-bottom:15px;">' +
                '<div style="display:flex;gap:20px;flex-wrap:wrap;">' +
                '<div style="background:#00c85333;padding:10px 15px;border-radius:6px;text-align:center;min-width:100px;">' +
                '<div style="font-size:24px;font-weight:bold;color:#00c853;">' + (result.added ? result.added.length : 0) + '</div>' +
                '<div style="font-size:12px;color:#aaa;">Will be added</div></div>' +
                '<div style="background:#ffc10733;padding:10px 15px;border-radius:6px;text-align:center;min-width:100px;">' +
                '<div style="font-size:24px;font-weight:bold;color:#ffc107;">' + (result.already_in_group ? result.already_in_group.length : 0) + '</div>' +
                '<div style="font-size:12px;color:#aaa;">Already in group</div></div>' +
                '<div style="background:#e9456033;padding:10px 15px;border-radius:6px;text-align:center;min-width:100px;">' +
                '<div style="font-size:24px;font-weight:bold;color:#e94560;">' + (result.not_found ? result.not_found.length : 0) + '</div>' +
                '<div style="font-size:12px;color:#aaa;">Not found</div></div>' +
                '</div></div>';

            previewHtml += '<div style="max-height:300px;overflow-y:auto;background:#0a0a15;border-radius:4px;padding:10px;">';

            if (result.added && result.added.length > 0) {
                previewHtml += '<div style="margin-bottom:10px;"><span style="color:#00c853;font-weight:bold;">Will be added:</span><div style="margin-top:5px;padding-left:10px;color:#ccc;font-size:13px;">' +
                    result.added.map(a => '<div>' + escapeHtml(a) + '</div>').join('') + '</div></div>';
            }
            if (result.already_in_group && result.already_in_group.length > 0) {
                previewHtml += '<div style="margin-bottom:10px;"><span style="color:#ffc107;font-weight:bold;">Already in group (will skip):</span><div style="margin-top:5px;padding-left:10px;color:#888;font-size:13px;">' +
                    result.already_in_group.map(a => '<div>' + escapeHtml(a) + '</div>').join('') + '</div></div>';
            }
            if (result.not_found && result.not_found.length > 0) {
                previewHtml += '<div style="margin-bottom:10px;"><span style="color:#e94560;font-weight:bold;">Not found (no matching agent):</span><div style="margin-top:5px;padding-left:10px;color:#888;font-size:13px;">' +
                    result.not_found.map(a => '<div>' + escapeHtml(a) + '</div>').join('') + '</div></div>';
            }
            previewHtml += '</div>';

            const canImport = result.added && result.added.length > 0;
            const footer = '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                (canImport ? '<button class="btn btn-success" onclick="confirmCsvImport()"><svg class="icon"><use href="#icon-check"/></svg>Confirm Import (' + result.added.length + ')</button>' : '');

            showModal('Import Preview - ' + importTargetGroup, previewHtml, footer);
        }

        async function confirmCsvImport() {
            if (pendingImportData.length === 0) {
                showToast('No data to import', 'warning');
                return;
            }

            closeModal();
            showToast('Importing agents...', 'info');

            const result = await api('/groups/' + importTargetGroup + '/import', 'POST', {
                agents: pendingImportData,
                dry_run: false
            });

            pendingImportData = [];

            if (result) {
                const addedCount = result.added ? result.added.length : 0;
                if (addedCount > 0) {
                    showToast('Successfully added ' + addedCount + ' agent(s) to group', 'success');
                    refreshGroups();
                    refreshAgents();
                } else {
                    showToast('No agents were added', 'warning');
                }
            }
        }

        async function reconnectNodeAgents(nodeName) {
            if (!await showConfirm('Reconnect all agents on node "' + nodeName + '"?')) return;
            const dryRun = document.getElementById('dryRunMode').checked;
            const result = await api('/nodes/' + nodeName + '/reconnect', 'POST', { dry_run: dryRun });
            if (result) showToast(result.message || 'Reconnect command sent', 'success');
        }

        // Config Editor
        let configEditor = null;
        let currentConfigNode = null;
        let configEditMode = false;
        let configContent = '';

        async function showConfigModal(nodeName) {
            currentConfigNode = nodeName;
            configEditMode = false;
            showToast('Loading config...', 'info');

            const result = await api('/nodes/' + nodeName + '/config');
            if (!result || result.error) {
                // Check if this is a remote node error - show SSH setup tutorial
                if (result && result.is_remote) {
                    showSSHSetupTutorial(nodeName, result.node_ip || '');
                    return;
                }
                showToast(result ? result.error : 'Failed to load config', 'error');
                return;
            }

            configContent = result.content || '';

            const body = `
                <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;">
                    <div><strong>File:</strong> <code>${escapeHtml(result.path) || '/var/ossec/etc/ossec.conf'}</code></div>
                    <div id="configToolbar" style="display:none;gap:8px;">
                        <button class="btn btn-sm" onclick="configEditor && configEditor.undo()"><svg class="icon"><use href="#icon-undo"/></svg>Undo</button>
                        <button class="btn btn-sm" onclick="configEditor && configEditor.redo()"><svg class="icon"><use href="#icon-redo"/></svg>Redo</button>
                    </div>
                </div>
                <div id="configEditorContainer" style="border:1px solid #444;border-radius:4px;overflow:auto;flex:1;min-height:300px;height:60vh;">
                    <textarea id="configEditorArea">${escapeHtml(configContent)}</textarea>
                </div>
                <div id="configSaveResult" style="margin-top:10px;"></div>
            `;
            const footer = `
                <button class="btn" onclick="downloadConfigFromModal()" title="Download ossec.conf"><svg class="icon"><use href="#icon-download"/></svg>Download</button>
                <button class="btn" onclick="validateNodeConfig()" title="Check the config before restarting"><svg class="icon"><use href="#icon-check"/></svg>Validate</button>
                <button class="btn" onclick="reloadNodeRuleset()" title="Reload the ruleset without restarting"><svg class="icon"><use href="#icon-refresh"/></svg>Reload Ruleset</button>
                <button id="configEditBtn" class="btn btn-primary" onclick="toggleConfigEditMode()"><svg class="icon"><use href="#icon-edit"/></svg>Edit</button>
                <button id="configCancelBtn" class="btn" onclick="cancelConfigEdit()" style="display:none;"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button id="configSaveBtn" class="btn btn-success" onclick="saveConfig()" style="display:none;"><svg class="icon"><use href="#icon-save"/></svg>Save</button>
            `;
            showModal('ossec.conf - ' + nodeName, body, footer, true);

            // Make modal resizable
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                modalContent.classList.add('resizable');
            }

            // Initialize CodeMirror in read-only mode
            setTimeout(() => {
                const textarea = document.getElementById('configEditorArea');
                const container = document.getElementById('configEditorContainer');
                if (textarea && typeof CodeMirror !== 'undefined') {
                    configEditor = CodeMirror.fromTextArea(textarea, {
                        mode: 'xml',
                        theme: 'dracula',
                        lineNumbers: true,
                        lineWrapping: true,
                        indentUnit: 2,
                        tabSize: 2,
                        readOnly: true
                    });
                    configEditor.setSize('100%', '100%');

                    // Update editor size when modal is resized
                    if (container) {
                        const resizeObserver = new ResizeObserver(() => {
                            configEditor.refresh();
                        });
                        resizeObserver.observe(container);
                    }
                }
            }, 100);
        }

        async function validateNodeConfig(nodeName) {
            const node = nodeName || currentConfigNode;
            if (!node) return;
            const target = document.getElementById('configSaveResult');
            if (target) target.innerHTML = '<span style="color:#888;">Validating...</span>';
            const result = await api('/nodes/' + node + '/config/validate');
            if (!result || result.error) {
                const msg = (result && result.error) || 'Validation failed';
                if (target) target.innerHTML = '<div class="alert alert-error">' + escapeHtml(msg) + '</div>';
                else showToast(msg, 'error');
                return false;
            }
            if (result.valid) {
                if (target) target.innerHTML = '<div class="alert alert-success">Configuration is valid</div>';
                showToast('Configuration is valid', 'success');
                return true;
            }
            const details = (result.details || []).map(d => escapeHtml(d)).join('<br>');
            const html = '<div class="alert alert-error">Configuration is invalid' +
                (details ? '<div style="margin-top:6px;font-family:monospace;font-size:12px;">' + details + '</div>' : '') + '</div>';
            if (target) target.innerHTML = html; else showToast('Configuration is invalid', 'error');
            return false;
        }

        async function reloadNodeRuleset(nodeName) {
            const node = nodeName || currentConfigNode;
            if (!node) return;
            if (!await showConfirm('Reload the ruleset on "' + node + '"? Running services are not restarted.')) return;
            const result = await api('/nodes/' + node + '/reload-ruleset', 'PUT');
            if (!result || result.error) {
                showToast((result && result.error) || 'Reload failed', 'error');
                return;
            }
            showToast('Ruleset reloaded on ' + node, 'success');
        }

        function toggleConfigEditMode() {
            configEditMode = true;
            const editBtn = document.getElementById('configEditBtn');
            const saveBtn = document.getElementById('configSaveBtn');
            const cancelBtn = document.getElementById('configCancelBtn');
            const toolbar = document.getElementById('configToolbar');

            // Switch to edit mode
            if (configEditor) {
                configEditor.setOption('readOnly', false);
                configEditor.focus();
            }
            editBtn.style.display = 'none';
            cancelBtn.style.display = '';
            saveBtn.style.display = '';
            toolbar.style.display = 'flex';
            showToast('Edit mode enabled', 'info');
        }

        function cancelConfigEdit() {
            configEditMode = false;
            const editBtn = document.getElementById('configEditBtn');
            const saveBtn = document.getElementById('configSaveBtn');
            const cancelBtn = document.getElementById('configCancelBtn');
            const toolbar = document.getElementById('configToolbar');

            // Revert content and switch to view mode
            if (configEditor) {
                configEditor.setValue(configContent);  // Restore original content
                configEditor.setOption('readOnly', true);
            }
            editBtn.style.display = '';
            cancelBtn.style.display = 'none';
            saveBtn.style.display = 'none';
            toolbar.style.display = 'none';
            showToast('Edit cancelled', 'info');
        }

        function downloadConfigFromModal() {
            if (!currentConfigNode) return;
            // Create download from current content
            const content = configEditor ? configEditor.getValue() : configContent;
            const blob = new Blob([content], { type: 'application/xml' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = currentConfigNode + '_ossec.conf';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Downloaded ' + currentConfigNode + '_ossec.conf', 'success');
        }

        async function saveConfig() {
            if (!configEditor || !currentConfigNode) return;

            const content = configEditor.getValue();
            if (!content.trim()) {
                showToast('Config cannot be empty', 'error');
                return;
            }

            const resultDiv = document.getElementById('configSaveResult');
            resultDiv.innerHTML = '<span style="color:#888;">Saving...</span>';

            const result = await api('/nodes/' + currentConfigNode + '/config', 'PUT', { content: content });

            if (!result) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Failed to save config</span>';
                return;
            }

            if (result.error) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Error: ' + result.error + '</span>';
                return;
            }

            let msg = '<span style="color:#4ade80;">Config saved successfully!</span>';
            if (result.backup_path) {
                msg += '<br><span style="color:#888;font-size:12px;">Backup: ' + result.backup_path + '</span>';
            }
            msg += '<br><br><span style="color:#f39c12;font-weight:bold;">Remember to restart services for changes to take effect!</span>';
            resultDiv.innerHTML = msg;

            showToast('Config saved! Remember to restart services.', 'success', 5000);
        }

        // ========== Email Alerts Management ==========
        let emailAlertsData = [];       // Current email alerts array
        let emailAlertsNodeName = '';   // Current node name
        let emailAlertsGlobal = {};     // Global email settings
        let emailAlertsGlobalConfigured = false;
        let emailAlertEditIndex = -1;   // -1 = new, >=0 = editing

        async function showEmailAlertsModal(nodeName) {
            emailAlertsNodeName = nodeName;
            emailAlertsData = [];
            emailAlertEditIndex = -1;
            showToast('Loading email alerts...', 'info');

            const result = await api('/nodes/' + nodeName + '/email-alerts');
            if (!result || result.error) {
                showToast(result ? result.error : 'Failed to load email alerts', 'error');
                return;
            }

            emailAlertsData = result.alerts || [];
            emailAlertsGlobal = result.global_email || {};
            emailAlertsGlobalConfigured = result.global_email_configured || false;

            renderEmailAlertsModal();
        }

        function renderEmailAlertsModal() {
            // Global email status
            let globalHtml = '';
            if (!emailAlertsGlobalConfigured) {
                globalHtml = `<div style="background:#e94560;color:#fff;padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;">
                    <strong>⚠ Global Email Not Configured</strong> — Please configure email_notification, smtp_server, email_from, email_to in the &lt;global&gt; section of ossec.conf first.
                </div>`;
            } else {
                globalHtml = `<div style="background:#1a2332;border:1px solid #333;padding:10px 14px;border-radius:6px;margin-bottom:14px;font-size:13px;">
                    <strong style="color:#4fc3f7;">Global Email Settings</strong><br>
                    <span style="color:#888;">SMTP:</span> ${escapeHtml(emailAlertsGlobal.smtp_server || '-')}
                    &nbsp;&nbsp;<span style="color:#888;">From:</span> ${escapeHtml(emailAlertsGlobal.email_from || '-')}
                    &nbsp;&nbsp;<span style="color:#888;">Default To:</span> ${escapeHtml(emailAlertsGlobal.email_to || '-')}
                </div>`;
            }

            // Worker nodes info
            const workerNodes = validNodeNames.filter(n => n !== emailAlertsNodeName);
            const syncBtnHtml = workerNodes.length > 0
                ? `<button class="btn btn-sm" style="background:#ff9800;color:#fff;margin-left:8px;" onclick="syncEmailAlertsToWorkers()" title="Sync current email alerts config to all worker nodes"><svg class="icon"><use href="#icon-upload"/></svg>Sync to All Workers</button>`
                : '';

            // Table
            let tableHtml = '';
            if (emailAlertsData.length === 0) {
                tableHtml = `<div style="color:#888;text-align:center;padding:30px 0;">No email alert rules configured. Click "Add Rule" to create one.</div>`;
            } else {
                tableHtml = `<div style="overflow-x:auto;"><table class="data-table" style="width:100%;font-size:13px;">
                    <thead><tr>
                        <th>Recipient</th>
                        <th>Rule ID</th>
                        <th>Level</th>
                        <th>Group</th>
                        <th>Event Location</th>
                        <th>Format</th>
                        <th>Options</th>
                        <th style="width:80px;">Actions</th>
                    </tr></thead>
                    <tbody>${emailAlertsData.map((a, i) => {
                        const emails = (a.email_to || []).join(', ');
                        const opts = [];
                        if (a.do_not_delay) opts.push('no_delay');
                        if (a.do_not_group) opts.push('no_group');
                        return `<tr>
                            <td>${escapeHtml(emails)}</td>
                            <td>${escapeHtml(a.rule_id || '')}</td>
                            <td style="text-align:center;">${a.level || ''}</td>
                            <td>${escapeHtml(a.group || '')}</td>
                            <td>${escapeHtml(a.event_location || '')}</td>
                            <td>${escapeHtml(a.format || '')}</td>
                            <td>${opts.join(', ') || '-'}</td>
                            <td>
                                <button class="btn btn-sm btn-primary" onclick="showEmailAlertForm(${i})" title="Edit"><svg class="icon"><use href="#icon-edit"/></svg></button>
                                <button class="btn btn-sm btn-danger" onclick="deleteEmailAlert(${i})" title="Delete"><svg class="icon"><use href="#icon-trash"/></svg></button>
                            </td>
                        </tr>`;
                    }).join('')}</tbody>
                </table></div>`;
            }

            // Edit form (hidden by default)
            const formHtml = `<div id="emailAlertFormArea" style="display:none;margin-top:14px;background:#1a2332;border:1px solid #444;border-radius:6px;padding:16px;">
                <h4 style="margin:0 0 12px 0;color:#4fc3f7;" id="emailAlertFormTitle">Add Rule</h4>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                    <div class="form-group" style="grid-column:1/3;">
                        <label>Recipient Email * <span style="color:#888;font-size:11px;">(separate multiple with commas)</span></label>
                        <input type="text" id="eaEmailTo" placeholder="security@example.com, admin@example.com">
                    </div>
                    <div class="form-group">
                        <label>Rule ID <span style="color:#888;font-size:11px;">(separate multiple with commas, e.g. 5710, 5711)</span></label>
                        <input type="text" id="eaRuleId" placeholder="5710, 5711">
                    </div>
                    <div class="form-group">
                        <label>Min Level <span style="color:#888;font-size:11px;">(1-16)</span></label>
                        <input type="number" id="eaLevel" min="1" max="16" placeholder="">
                    </div>
                    <div class="form-group">
                        <label>Group</label>
                        <input type="text" id="eaGroup" placeholder="authentication_failed">
                    </div>
                    <div class="form-group">
                        <label>Event Location</label>
                        <input type="text" id="eaEventLocation" placeholder="">
                    </div>
                    <div class="form-group">
                        <label>Format</label>
                        <select id="eaFormat">
                            <option value="">Default</option>
                            <option value="default">default</option>
                            <option value="full">full</option>
                            <option value="sms">sms</option>
                        </select>
                    </div>
                    <div class="form-group" style="display:flex;align-items:center;gap:16px;padding-top:20px;">
                        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;"><input type="checkbox" id="eaDoNotDelay"> do_not_delay</label>
                        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;"><input type="checkbox" id="eaDoNotGroup"> do_not_group</label>
                    </div>
                </div>
                <div style="margin-top:12px;text-align:right;display:flex;justify-content:flex-end;align-items:center;gap:8px;">
                    <button class="btn" onclick="hideEmailAlertForm()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                    <button class="btn btn-success" onclick="saveEmailAlert()"><svg class="icon"><use href="#icon-save"/></svg>Save</button>
                </div>
                <div id="emailAlertFormResult" style="margin-top:8px;"></div>
            </div>`;

            const body = globalHtml + `
                <div style="margin-bottom:10px;">
                    <button class="btn btn-sm btn-success" onclick="showEmailAlertForm(-1)"><svg class="icon"><use href="#icon-plus"/></svg>Add Rule</button>
                    ${syncBtnHtml}
                </div>
            ` + tableHtml + formHtml;

            showModal('Email Alerts - ' + emailAlertsNodeName, body, '', true);
        }

        function showEmailAlertForm(index) {
            emailAlertEditIndex = index;
            const form = document.getElementById('emailAlertFormArea');
            const title = document.getElementById('emailAlertFormTitle');
            if (!form) return;

            form.style.display = 'block';
            document.getElementById('emailAlertFormResult').innerHTML = '';

            if (index >= 0 && index < emailAlertsData.length) {
                // Edit mode
                const a = emailAlertsData[index];
                title.textContent = 'Edit Rule #' + (index + 1);
                document.getElementById('eaEmailTo').value = (a.email_to || []).join(', ');
                document.getElementById('eaRuleId').value = a.rule_id || '';
                document.getElementById('eaLevel').value = a.level || '';
                document.getElementById('eaGroup').value = a.group || '';
                document.getElementById('eaEventLocation').value = a.event_location || '';
                document.getElementById('eaFormat').value = a.format || '';
                document.getElementById('eaDoNotDelay').checked = !!a.do_not_delay;
                document.getElementById('eaDoNotGroup').checked = !!a.do_not_group;
            } else {
                // New mode
                title.textContent = 'Add Rule';
                document.getElementById('eaEmailTo').value = '';
                document.getElementById('eaRuleId').value = '';
                document.getElementById('eaLevel').value = '';
                document.getElementById('eaGroup').value = '';
                document.getElementById('eaEventLocation').value = '';
                document.getElementById('eaFormat').value = '';
                document.getElementById('eaDoNotDelay').checked = false;
                document.getElementById('eaDoNotGroup').checked = false;
            }

            // Scroll form into view
            form.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        function hideEmailAlertForm() {
            const form = document.getElementById('emailAlertFormArea');
            if (form) form.style.display = 'none';
            emailAlertEditIndex = -1;
        }

        async function saveEmailAlert() {
            const resultDiv = document.getElementById('emailAlertFormResult');
            // Validate
            const emailToStr = document.getElementById('eaEmailTo').value.trim();
            if (!emailToStr) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Recipient email is required</span>';
                return;
            }

            const emailTo = emailToStr.split(',').map(e => e.trim()).filter(e => e);
            const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            for (const e of emailTo) {
                if (!emailPattern.test(e)) {
                    resultDiv.innerHTML = '<span style="color:#e94560;">Invalid email format: ' + escapeHtml(e) + '</span>';
                    return;
                }
            }

            const ruleId = document.getElementById('eaRuleId').value.trim();
            if (ruleId && !/^[0-9,\s]+$/.test(ruleId)) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Rule ID can only contain numbers and commas</span>';
                return;
            }

            const levelStr = document.getElementById('eaLevel').value.trim();
            let level = null;
            if (levelStr) {
                level = parseInt(levelStr, 10);
                if (isNaN(level) || level < 1 || level > 16) {
                    resultDiv.innerHTML = '<span style="color:#e94560;">Level must be between 1 and 16</span>';
                    return;
                }
            }

            const alert = {
                email_to: emailTo,
                rule_id: ruleId,
                level: level,
                group: document.getElementById('eaGroup').value.trim(),
                event_location: document.getElementById('eaEventLocation').value.trim(),
                format: document.getElementById('eaFormat').value,
                do_not_delay: document.getElementById('eaDoNotDelay').checked,
                do_not_group: document.getElementById('eaDoNotGroup').checked
            };

            // Update the array
            const newAlerts = [...emailAlertsData];
            if (emailAlertEditIndex >= 0 && emailAlertEditIndex < newAlerts.length) {
                newAlerts[emailAlertEditIndex] = alert;
            } else {
                newAlerts.push(alert);
            }

            resultDiv.innerHTML = '<span style="color:#888;">Saving...</span>';

            const result = await api('/nodes/' + emailAlertsNodeName + '/email-alerts', 'PUT', { alerts: newAlerts });
            if (!result) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Failed to save</span>';
                return;
            }
            if (result.error) {
                resultDiv.innerHTML = '<span style="color:#e94560;">' + escapeHtml(result.error).replace(/\\n/g, '<br>') + '</span>';
                return;
            }

            emailAlertsData = newAlerts;
            showToast('Email alert rule saved! Remember to restart services for changes to take effect.', 'success', 5000);
            renderEmailAlertsModal();
        }

        async function deleteEmailAlert(index) {
            if (index < 0 || index >= emailAlertsData.length) return;
            const alert = emailAlertsData[index];
            const desc = (alert.email_to || []).join(', ') + (alert.rule_id ? ' (Rule: ' + alert.rule_id + ')' : '');
            const confirmed = await showConfirm('Are you sure you want to delete this rule?<br><br><code>' + escapeHtml(desc) + '</code>', true);
            if (!confirmed) return;

            const newAlerts = emailAlertsData.filter((_, i) => i !== index);

            showToast('Deleting...', 'info');
            const result = await api('/nodes/' + emailAlertsNodeName + '/email-alerts', 'PUT', { alerts: newAlerts });
            if (!result || result.error) {
                showToast(result ? result.error : 'Failed to delete', 'error');
                return;
            }

            emailAlertsData = newAlerts;
            showToast('Email alert rule deleted', 'success');
            renderEmailAlertsModal();
        }

        async function syncEmailAlertsToWorkers() {
            const workerNodes = validNodeNames.filter(n => n !== emailAlertsNodeName);
            if (workerNodes.length === 0) {
                showToast('No worker nodes to sync', 'warning');
                return;
            }

            const confirmed = await showConfirm(
                'Sync current email alerts config to the following worker nodes?<br><br>' +
                workerNodes.map(n => '<code>' + escapeHtml(n) + '</code>').join('<br>') +
                '<br><br><span style="color:#f39c12;">Each node&apos;s ossec.conf will be backed up before modification.</span>',
                false
            );
            if (!confirmed) return;

            showToast('Syncing...', 'info');
            let successCount = 0;
            let failedNodes = [];

            for (const workerName of workerNodes) {
                const result = await api('/nodes/' + workerName + '/email-alerts', 'PUT', { alerts: emailAlertsData });
                if (result && result.success) {
                    successCount++;
                } else {
                    failedNodes.push(workerName + ': ' + (result ? result.error : 'Failed'));
                }
            }

            if (failedNodes.length === 0) {
                showToast('Successfully synced to ' + successCount + ' worker node(s)! Remember to restart services.', 'success', 6000);
            } else {
                showToast('Sync completed: ' + successCount + ' succeeded, ' + failedNodes.length + ' failed', 'warning', 8000);
                console.warn('Sync failed nodes:', failedNodes);
            }
        }

        // Log Viewer Modal (for archives and alerts)
        let currentLogNode = null;
        let currentLogCategory = null;  // 'archives' or 'alerts'
        let currentLogType = null;  // 'log' or 'json'
        let currentLogLines = 100;
        let logViewerEditor = null;
        let jsonExpandState = {};  // Track expanded lines: {lineNum: {original, expandedCount}}

        async function showLogViewerModal(nodeName, category, logType) {
            currentLogNode = nodeName;
            currentLogCategory = category;
            currentLogType = logType;
            currentLogLines = 100;
            jsonExpandState = {};
            showToast('Loading ' + category + '...', 'info');

            const result = await api('/nodes/' + nodeName + '/logs/' + category + '/' + logType + '?lines=' + currentLogLines);
            if (!result || result.error) {
                if (result && result.is_remote) {
                    showSSHSetupTutorial(nodeName, '');
                    return;
                }
                showToast(result ? result.error : 'Failed to load ' + category, 'error');
                return;
            }

            const fileName = category + '.' + logType;
            const fileSize = formatFileSize(result.size || 0);

            const body = `
                <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                    <div>
                        <strong>File:</strong> <code>${escapeHtml(result.path) || '/var/ossec/logs/' + category + '/' + fileName}</code>
                        <span style="margin-left:15px;color:#888;">Size: <strong>${fileSize}</strong></span>
                    </div>
                    <div style="display:flex;align-items:center;gap:10px;">
                        <label style="color:#888;font-size:13px;display:flex;align-items:center;gap:4px;cursor:pointer;">
                            <input type="checkbox" id="logWrapToggle" onchange="toggleLogWrap()" style="cursor:pointer;">
                            Wrap
                        </label>
                        <label style="color:#888;font-size:13px;">Lines:</label>
                        <select id="logLinesSelect" onchange="refreshLogViewerContent()" style="background:#1a1a2e;color:#eee;border:1px solid #444;padding:4px 8px;border-radius:4px;">
                            <option value="100" selected>Last 100</option>
                            <option value="500">Last 500</option>
                            <option value="1000">Last 1,000</option>
                            <option value="5000">Last 5,000</option>
                            <option value="10000">Last 10,000</option>
                        </select>
                        <button class="btn btn-sm btn-primary" onclick="refreshLogViewerContent()" title="Refresh content"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>
                    </div>
                </div>
                <div id="logViewerContainer" style="border:1px solid #444;border-radius:4px;overflow:auto;flex:1;min-height:0;">
                    <textarea id="logViewerArea">${escapeHtml(result.content || '')}</textarea>
                </div>
            `;
            const footer = `<button class="btn" onclick="downloadLogFromModal()" title="Download ${fileName}"><svg class="icon"><use href="#icon-download"/></svg>Download</button>`;
            showModal(fileName + ' - ' + nodeName, body, footer, true);

            // Make modal resizable
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                modalContent.classList.add('resizable');
            }

            // Initialize CodeMirror in read-only mode
            setTimeout(() => {
                const textarea = document.getElementById('logViewerArea');
                const container = document.getElementById('logViewerContainer');
                if (textarea && typeof CodeMirror !== 'undefined') {
                    const mode = currentLogType === 'json' ? {name: 'javascript', json: true} : 'wazuh-alerts';
                    const gutters = currentLogType === 'json' ? ['json-gutter', 'CodeMirror-linenumbers'] : ['CodeMirror-linenumbers'];
                    logViewerEditor = CodeMirror.fromTextArea(textarea, {
                        mode: mode,
                        theme: 'dracula',
                        lineNumbers: true,
                        lineWrapping: false,
                        readOnly: true,
                        scrollbarStyle: 'native',
                        gutters: gutters
                    });

                    // Set height based on container
                    const containerHeight = container ? container.clientHeight : 400;
                    logViewerEditor.setSize('100%', Math.max(containerHeight, 400) + 'px');

                    // Update editor size when modal is resized
                    if (container) {
                        const resizeObserver = new ResizeObserver(() => {
                            const newHeight = container.clientHeight || 400;
                            logViewerEditor.setSize('100%', Math.max(newHeight, 400) + 'px');
                            logViewerEditor.refresh();
                        });
                        resizeObserver.observe(container);
                    }

                    // Add JSON expand markers
                    if (currentLogType === 'json') {
                        addJsonExpandMarkers();
                    }

                    // Scroll to bottom
                    logViewerEditor.scrollIntoView({line: logViewerEditor.lineCount() - 1, ch: 0});
                }
            }, 100);
        }

        function addJsonExpandMarkers() {
            if (!logViewerEditor) return;
            const lineCount = logViewerEditor.lineCount();
            for (let i = 0; i < lineCount; i++) {
                const line = logViewerEditor.getLine(i);
                if (line && (line.trim().startsWith('{') || line.trim().startsWith('['))) {
                    const marker = document.createElement('span');
                    marker.className = 'json-expand-marker';
                    marker.innerHTML = '<svg><use href="#icon-chevron-right"/></svg>';
                    marker.title = 'Expand JSON';
                    marker.onclick = (function(lineNum) {
                        return function(e) {
                            e.stopPropagation();
                            toggleJsonExpand(lineNum);
                        };
                    })(i);
                    logViewerEditor.setGutterMarker(i, 'json-gutter', marker);
                }
            }
        }

        function highlightJson(json) {
            return json.replace(/("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*")(\s*:)?|(\b(?:true|false)\b)|(\bnull\b)|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}\[\],:])/g,
                function(match, str, colon, bool, nil, num, bracket) {
                    if (str) {
                        if (colon) {
                            return '<span class="json-key">' + escapeHtml(str) + '</span>:';
                        }
                        return '<span class="json-string">' + escapeHtml(str) + '</span>';
                    }
                    if (bool) return '<span class="json-boolean">' + bool + '</span>';
                    if (nil) return '<span class="json-null">' + nil + '</span>';
                    if (num) return '<span class="json-number">' + num + '</span>';
                    if (bracket) return '<span class="json-bracket">' + bracket + '</span>';
                    return match;
                });
        }

        function toggleJsonExpand(lineNum) {
            if (!logViewerEditor) return;
            const state = jsonExpandState[lineNum];
            if (state) {
                // Collapse: remove widget
                if (state.widget) {
                    state.widget.clear();
                }
                const marker = document.createElement('span');
                marker.className = 'json-expand-marker';
                marker.innerHTML = '<svg><use href="#icon-chevron-right"/></svg>';
                marker.title = 'Expand JSON';
                marker.onclick = (function(ln) {
                    return function(e) { e.stopPropagation(); toggleJsonExpand(ln); };
                })(lineNum);
                logViewerEditor.setGutterMarker(lineNum, 'json-gutter', marker);
                delete jsonExpandState[lineNum];
            } else {
                // Expand: add widget below line
                const lineContent = logViewerEditor.getLine(lineNum);
                try {
                    const parsed = JSON.parse(lineContent.trim());
                    const formatted = JSON.stringify(parsed, null, 2);
                    const widgetEl = document.createElement('div');
                    widgetEl.className = 'json-expanded-widget';
                    widgetEl.innerHTML = highlightJson(formatted);
                    const widget = logViewerEditor.addLineWidget(lineNum, widgetEl, {coverGutter: false, noHScroll: false});
                    jsonExpandState[lineNum] = { widget: widget };
                    const marker = document.createElement('span');
                    marker.className = 'json-expand-marker expanded';
                    marker.innerHTML = '<svg><use href="#icon-chevron-down"/></svg>';
                    marker.title = 'Collapse JSON';
                    marker.onclick = (function(ln) {
                        return function(e) { e.stopPropagation(); toggleJsonExpand(ln); };
                    })(lineNum);
                    logViewerEditor.setGutterMarker(lineNum, 'json-gutter', marker);
                } catch (e) {
                    showToast('Invalid JSON', 'error');
                }
            }
        }

        function rebuildJsonMarkers() {
            if (!logViewerEditor || currentLogType !== 'json') return;
            // Clear all widgets
            for (const lineNum in jsonExpandState) {
                if (jsonExpandState[lineNum].widget) {
                    jsonExpandState[lineNum].widget.clear();
                }
            }
            const lineCount = logViewerEditor.lineCount();
            for (let i = 0; i < lineCount; i++) {
                logViewerEditor.setGutterMarker(i, 'json-gutter', null);
            }
            jsonExpandState = {};
            addJsonExpandMarkers();
        }

        function toggleLogWrap() {
            if (!logViewerEditor) return;
            const checkbox = document.getElementById('logWrapToggle');
            const wrap = checkbox ? checkbox.checked : false;
            logViewerEditor.setOption('lineWrapping', wrap);
        }

        async function refreshLogViewerContent() {
            if (!currentLogNode || !currentLogCategory || !currentLogType) return;

            const select = document.getElementById('logLinesSelect');
            if (select) {
                currentLogLines = parseInt(select.value) || 100;
            }

            showToast('Refreshing...', 'info');
            const result = await api('/nodes/' + currentLogNode + '/logs/' + currentLogCategory + '/' + currentLogType + '?lines=' + currentLogLines);

            if (!result || result.error) {
                showToast(result ? result.error : 'Failed to refresh', 'error');
                return;
            }

            // Clear existing widgets
            for (const lineNum in jsonExpandState) {
                if (jsonExpandState[lineNum].widget) {
                    jsonExpandState[lineNum].widget.clear();
                }
            }
            jsonExpandState = {};
            if (logViewerEditor) {
                logViewerEditor.setValue(result.content || '');
                if (currentLogType === 'json') {
                    setTimeout(function() { addJsonExpandMarkers(); }, 50);
                }
                // Scroll to bottom
                setTimeout(function() {
                    logViewerEditor.scrollIntoView({line: logViewerEditor.lineCount() - 1, ch: 0});
                }, 60);
            }
            showToast('Content refreshed (' + currentLogLines + ' lines)', 'success');
        }

        function downloadLogFromModal() {
            if (!currentLogNode || !currentLogCategory || !currentLogType) return;
            const fileName = currentLogCategory + '.' + currentLogType;
            const content = logViewerEditor ? logViewerEditor.getValue() : '';
            const mimeType = currentLogType === 'json' ? 'application/json' : 'text/plain';
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = currentLogNode + '_' + fileName;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            showToast('Downloaded ' + currentLogNode + '_' + fileName, 'success');
        }

        // SSH Setup Tutorial
        function copyToClipboard(btn) {
            const text = btn.getAttribute('data-copy');
            if (!text) return;

            navigator.clipboard.writeText(text).then(() => {
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<svg class="icon" style="width:14px;height:14px;color:#4ade80;"><use href="#icon-check"/></svg>';
                showToast('Copied to clipboard', 'success', 1500);
                setTimeout(() => { btn.innerHTML = originalHtml; }, 1500);
            }).catch((err) => {
                // Fallback for older browsers or non-secure contexts
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.style.position = 'fixed';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                textarea.select();
                try {
                    document.execCommand('copy');
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = '<svg class="icon" style="width:14px;height:14px;color:#4ade80;"><use href="#icon-check"/></svg>';
                    showToast('Copied to clipboard', 'success', 1500);
                    setTimeout(() => { btn.innerHTML = originalHtml; }, 1500);
                } catch (e) {
                    showToast('Failed to copy to clipboard', 'error');
                }
                document.body.removeChild(textarea);
            });
        }

        // Settings Modal
        async function showSettingsModal() {
            showModal('Settings', '<div class="loading"><div class="spinner"></div>Loading...</div>', '');

            try {
                const data = await api('/settings');
                if (!data) {
                    document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">Failed to load settings</div>';
                    return;
                }

                const sshEnabled = data.ssh_enabled || false;
                const sshNodes = data.ssh_nodes || {};
                const sshNodesCount = Object.keys(sshNodes).length;
                // Pre-compute SSH guide node info for the Setup Guide button
                const sshGuideNode = sshNodesCount > 0 ? Object.keys(sshNodes)[0] : 'worker-node';
                const sshGuideIp = sshNodesCount > 0 ? ((Object.values(sshNodes)[0] || {}).host || (Object.values(sshNodes)[0] || {}).ip || 'WORKER_IP') : 'WORKER_IP';

                const body = `
                    <div style="display:flex;flex-direction:column;gap:20px;">
                        <div style="background:#0f3460;padding:15px;border-radius:8px;">
                            <h4 style="color:#4fc3f7;margin:0 0 15px 0;">API Connection</h4>
                            <table style="width:100%;font-size:14px;">
                                <tr><td style="color:#888;padding:5px 8px;width:120px;">Host</td><td style="color:#eee;padding:5px 8px;">{{ host }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Port</td><td style="color:#eee;padding:5px 8px;">{{ port }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Username</td><td style="color:#eee;padding:5px 8px;">{{ username }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">SSL Verify</td><td style="color:#eee;padding:5px 8px;">${data.api_verify_ssl ? '<span style="color:#4ade80;">Enabled</span>' : '<span style="color:#ffc107;">Disabled</span>'}</td></tr>
                            </table>
                        </div>

                        <div style="background:#0f3460;padding:15px;border-radius:8px;">
                            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;">
                                <h4 style="color:#4fc3f7;margin:0;">SSH Configuration</h4>
                                <button onclick="closeModal(); showSSHSetupTutorial('${escapeHtml(sshGuideNode)}', '${escapeHtml(sshGuideIp)}')" style="background:#1a1a2e;border:1px solid #4fc3f7;border-radius:4px;padding:4px 10px;cursor:pointer;color:#4fc3f7;font-size:12px;display:flex;align-items:center;gap:5px;" title="SSH Setup Guide"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-info"/></svg> Setup Guide</button>
                            </div>
                            <table style="width:100%;font-size:14px;">
                                <tr><td style="color:#888;padding:5px 8px;width:120px;">Status</td><td style="padding:5px 8px;">${sshEnabled ? '<span style="color:#4ade80;">Enabled</span>' : '<span style="color:#888;">Disabled</span>'}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Key File</td><td style="color:#eee;padding:5px 8px;">${data.ssh_key_file || '<span style="color:#666;">Not configured</span>'}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Configured Nodes</td><td style="color:#eee;padding:5px 8px;">${sshNodesCount > 0 ? sshNodesCount + ' node(s)' : '<span style="color:#666;">None</span>'}</td></tr>
                            </table>
                            ${sshNodesCount > 0 ? '<div style="margin-top:10px;padding:10px;background:#1a1a2e;border-radius:4px;font-size:12px;color:#aaa;">' + Object.entries(sshNodes).map(([name, cfg]) => name + ' → ' + (cfg.host || cfg.ip || '?') + ':' + (cfg.port || 22)).join('<br>') + '</div>' : ''}
                            ${!sshEnabled ? '<p style="color:#888;font-size:12px;margin:10px 0 0 0;">SSH is required for remote node config editing and service management.</p>' : ''}
                        </div>

                        <div style="background:#0f3460;padding:15px;border-radius:8px;">
                            <h4 style="color:#4fc3f7;margin:0 0 15px 0;">About</h4>
                            <table style="width:100%;font-size:14px;">
                                <tr><td style="color:#888;padding:5px 8px;width:120px;">Version</td><td style="color:#eee;padding:5px 8px;">v{{ version }}</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Author</td><td style="color:#eee;padding:5px 8px;">Jason Cheng</td></tr>
                                <tr><td style="color:#888;padding:5px 8px;">Repository</td><td style="padding:5px 8px;"><a href="https://github.com/jasoncheng7115/jt-wazuh-mgr" target="_blank" style="color:#4fc3f7;">GitHub</a></td></tr>
                            </table>
                        </div>
                    </div>
                `;

                showModal('Settings', body, '');
            } catch (e) {
                document.getElementById('modalBody').innerHTML = '<div class="alert alert-error">Error loading settings: ' + e.message + '</div>';
            }
        }

        async function showSSHSetupTutorial(nodeName, nodeIp) {
            // Get config file path from settings
            let configFilePath = 'config.yaml';
            try {
                const settings = await api('/settings');
                if (settings && settings.config_file_path) {
                    configFilePath = settings.config_file_path;
                }
            } catch (e) { /* ignore */ }

            const cmd1 = 'ssh-keygen -t ed25519 -f /root/.ssh/wazuh_cluster_key -N ""';
            const cmd2 = 'ssh-copy-id -i /root/.ssh/wazuh_cluster_key.pub root@' + nodeIp;
            const cmd3 = 'ssh -i /root/.ssh/wazuh_cluster_key root@' + nodeIp + ' "hostname"';
            const cmd4 = 'ssh:\\n  enabled: true\\n  key_file: /root/.ssh/wazuh_cluster_key\\n  nodes:\\n    ' + nodeName + ':\\n      host: ' + nodeIp + '\\n      user: root';

            const codeBlockStyle = 'background:#0d0d1a;padding:12px;border-radius:6px;overflow-x:auto;color:#4ade80;font-size:13px;display:flex;justify-content:space-between;align-items:center;gap:10px;';
            const copyBtnStyle = 'background:transparent;border:1px solid #444;border-radius:4px;padding:4px 8px;cursor:pointer;color:#888;flex-shrink:0;display:flex;align-items:center;';

            const body = `
                <div style="line-height:1.8;">
                    <div style="background:#1f2d1f;padding:15px;border-radius:8px;margin-bottom:15px;border-left:4px solid #4ade80;">
                        <strong style="color:#4ade80;">Optional Setup</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            SSH configuration is <strong>optional</strong>. Only needed if you want to edit worker node configs
                            or restart services remotely from this web interface.
                        </p>
                    </div>

                    <div style="background:#1a1a2e;padding:15px;border-radius:8px;margin-bottom:20px;border-left:4px solid #4fc3f7;">
                        <strong style="color:#4fc3f7;">Why SSH Setup?</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            Wazuh API does not provide access to raw config files on worker nodes.
                            To enable remote config editing, you need to set up SSH key-based authentication
                            from the master node to worker nodes.
                        </p>
                    </div>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 1: Generate SSH Key on Master Node</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Run this on the <strong>master node</strong> (as root):</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(cmd1)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd1)}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 2: Copy Public Key to Worker Node</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Copy the public key to <strong>${escapeHtml(nodeName)}</strong> (${escapeHtml(nodeIp)}):</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(cmd2)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd2)}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>
                    <p style="color:#888;font-size:12px;margin-top:5px;">Or manually append the public key to <code>/root/.ssh/authorized_keys</code> on the worker node.</p>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 3: Test SSH Connection</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Verify passwordless SSH works:</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;word-break:break-all;">${escapeHtml(cmd3)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd3)}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>

                    <h4 style="color:#4fc3f7;margin:20px 0 10px 0;">Step 4: Configure This Tool</h4>
                    <p style="color:#aaa;margin-bottom:10px;">Add SSH settings to <code style="color:#4ade80;">${escapeHtml(configFilePath)}</code>:</p>
                    <div style="${codeBlockStyle}">
                        <code style="white-space:pre-wrap;">${escapeHtml(cmd4)}</code>
                        <button style="${copyBtnStyle}" data-copy="${escapeHtml(cmd4).replace(/\\n/g, '&#10;')}" onclick="copyToClipboard(this)" title="Copy to clipboard"><svg class="icon" style="width:14px;height:14px;"><use href="#icon-copy"/></svg></button>
                    </div>

                    <div style="background:#2d2d1f;padding:15px;border-radius:8px;margin-top:15px;border-left:4px solid #ffc107;">
                        <strong style="color:#ffc107;">Important</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            After modifying <code>config.yaml</code>, you must <strong>restart this tool</strong> for changes to take effect.
                        </p>
                    </div>

                    <div style="background:#2d1f1f;padding:15px;border-radius:8px;margin-top:15px;border-left:4px solid #e94560;">
                        <strong style="color:#e94560;">Security Note</strong>
                        <p style="margin:10px 0 0 0;color:#aaa;">
                            Ensure proper file permissions on SSH keys (600 for private key).
                            Consider using a dedicated service account instead of root for production environments.
                        </p>
                    </div>
                </div>
            `;
            showModal('SSH Setup Guide - ' + escapeHtml(nodeName), body, '', true);
        }

        // Group Config Editor
        let groupConfigEditor = null;
        let currentConfigGroup = null;

        let groupConfigEditMode = false;

        async function showGroupAgentConfModal(groupName) {
            currentConfigGroup = groupName;
            groupConfigEditMode = false;
            showToast('Loading agent.conf...', 'info');

            const result = await api('/groups/' + encodeURIComponent(groupName) + '/config');
            if (!result || result.error) {
                showToast(result ? result.error : 'Failed to load config', 'error');
                return;
            }

            renderGroupAgentConfModal(groupName, result.content, result.path);
        }

        function renderGroupAgentConfModal(groupName, content, filePath) {
            const isEdit = groupConfigEditMode;
            const body = `
                <div style="margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                    <div><strong>File:</strong> <code>${escapeHtml(filePath) || '/var/ossec/etc/shared/' + escapeHtml(groupName) + '/agent.conf'}</code></div>
                    <div style="display:flex;gap:8px;" id="groupConfigToolbar">
                        ${isEdit ? `
                            <button class="btn btn-sm" onclick="groupConfigEditor && groupConfigEditor.undo()"><svg class="icon"><use href="#icon-undo"/></svg>Undo</button>
                            <button class="btn btn-sm" onclick="groupConfigEditor && groupConfigEditor.redo()"><svg class="icon"><use href="#icon-redo"/></svg>Redo</button>
                        ` : ''}
                    </div>
                </div>
                <div id="groupConfigEditorContainer" style="border:1px solid #444;border-radius:4px;overflow:auto;flex:1;min-height:300px;height:60vh;">
                    <textarea id="groupConfigEditorArea">${escapeHtml(content) || ''}</textarea>
                </div>
                ${isEdit ? `<p style="color:#888;font-size:12px;margin-top:10px;">This config will be applied to all agents in group "${escapeHtml(groupName)}".</p>` : ''}
                <div id="groupConfigSaveResult" style="margin-top:10px;"></div>
            `;
            const footer = isEdit ? `
                <button class="btn" onclick="switchGroupConfigMode(false)"><svg class="icon"><use href="#icon-eye"/></svg>View</button>
                <button class="btn" onclick="downloadGroupConfig('${groupName.replace(/'/g, "\\'")}')"><svg class="icon"><use href="#icon-download"/></svg>Download</button>
                <button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="saveGroupConfig()"><svg class="icon"><use href="#icon-save"/></svg>Save</button>
            ` : `
                <button class="btn btn-primary" onclick="switchGroupConfigMode(true)"><svg class="icon"><use href="#icon-edit"/></svg>Edit</button>
                <button class="btn" onclick="downloadGroupConfig('${groupName.replace(/'/g, "\\'")}')"><svg class="icon"><use href="#icon-download"/></svg>Download</button>
            `;

            showModal('agent.conf - ' + escapeHtml(groupName), body, footer, true);

            // Make modal resizable
            const modalContent = document.querySelector('.modal-content');
            if (modalContent) {
                modalContent.classList.add('resizable');
            }

            // Initialize CodeMirror
            setTimeout(() => {
                const textarea = document.getElementById('groupConfigEditorArea');
                const container = document.getElementById('groupConfigEditorContainer');
                if (textarea && typeof CodeMirror !== 'undefined') {
                    groupConfigEditor = CodeMirror.fromTextArea(textarea, {
                        mode: 'xml',
                        theme: 'dracula',
                        lineNumbers: true,
                        lineWrapping: true,
                        indentUnit: 2,
                        tabSize: 2,
                        readOnly: !isEdit
                    });
                    groupConfigEditor.setSize('100%', '100%');

                    // Update editor size when modal is resized
                    if (container) {
                        const resizeObserver = new ResizeObserver(() => {
                            groupConfigEditor.refresh();
                        });
                        resizeObserver.observe(container);
                    }
                }
            }, 100);
        }

        function switchGroupConfigMode(editMode) {
            if (!groupConfigEditor || !currentConfigGroup) return;
            const content = groupConfigEditor.getValue();
            groupConfigEditMode = editMode;
            renderGroupAgentConfModal(currentConfigGroup, content, null);
        }

        async function saveGroupConfig() {
            if (!groupConfigEditor || !currentConfigGroup) return;

            const content = groupConfigEditor.getValue();
            const resultDiv = document.getElementById('groupConfigSaveResult');
            resultDiv.innerHTML = '<span style="color:#888;">Saving...</span>';

            const result = await api('/groups/' + encodeURIComponent(currentConfigGroup) + '/config', 'PUT', { content: content });

            if (!result) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Failed to save config</span>';
                return;
            }

            if (result.error) {
                resultDiv.innerHTML = '<span style="color:#e94560;">Error: ' + escapeHtml(result.error) + '</span>';
                return;
            }

            let msg = '<span style="color:#4ade80;">Config saved successfully!</span>';
            if (result.backup_path) {
                msg += '<br><span style="color:#888;font-size:12px;">Backup: ' + escapeHtml(result.backup_path) + '</span>';
            }
            msg += '<br><br><span style="color:#f39c12;">Agents will receive updated config on next keepalive.</span>';
            resultDiv.innerHTML = msg;

            showToast('Group config saved!', 'success', 5000);
        }

        function downloadGroupConfig(groupName) {
            window.open('/api/groups/' + encodeURIComponent(groupName) + '/config/download', '_blank');
        }

        async function restartNodeServices(nodeName) {
            if (!await showConfirm('Restart all Wazuh services on node "' + nodeName + '"? This may briefly interrupt monitoring.', true)) return;

            // Show waiting modal
            const modalBody = `
                <div style="text-align:center;padding:20px;">
                    <div class="spinner" style="margin:0 auto 20px;"></div>
                    <div id="restartStatus" style="color:#4fc3f7;font-size:16px;margin-bottom:10px;">Sending restart command...</div>
                    <div id="restartProgress" style="color:#888;font-size:13px;"></div>
                </div>
            `;
            showModal('Restarting ' + nodeName, modalBody, '', false);

            const updateStatus = (status, progress) => {
                const statusEl = document.getElementById('restartStatus');
                const progressEl = document.getElementById('restartProgress');
                if (statusEl) statusEl.textContent = status;
                if (progressEl) progressEl.textContent = progress || '';
            };

            const result = await api('/nodes/' + nodeName + '/restart', 'POST');

            if (!result) {
                closeModal();
                showToast('Failed to restart services', 'error');
                return;
            }

            if (result.error) {
                closeModal();
                if (result.is_remote) {
                    showSSHSetupTutorial(nodeName, result.node_ip || '');
                    return;
                }
                showToast('Error: ' + result.error, 'error');
                return;
            }

            // Wait for node to come back up
            updateStatus('Services restarting...', 'Waiting for node to come back online');

            let attempts = 0;
            const maxAttempts = 30;  // 30 attempts * 2 seconds = 60 seconds max
            const checkInterval = 2000;

            const checkNodeStatus = async () => {
                attempts++;
                updateStatus('Waiting for services...', `Checking status (${attempts}/${maxAttempts})`);

                try {
                    const statusResult = await api('/nodes/' + nodeName + '/services');
                    if (statusResult && !statusResult.error && statusResult.services) {
                        // Check if all critical services are running
                        const runningCount = statusResult.services.filter(s => s.status === 'running').length;
                        const totalCount = statusResult.services.length;

                        if (runningCount > 0) {
                            updateStatus('Services starting...', `${runningCount}/${totalCount} services running`);

                            // Consider success if most services are running
                            if (runningCount >= totalCount * 0.8) {
                                closeModal();
                                showToast('Services restarted successfully on ' + nodeName, 'success');
                                refreshNodes();
                                return;
                            }
                        }
                    }
                } catch (e) {
                    // Node might still be restarting, continue waiting
                }

                if (attempts < maxAttempts) {
                    setTimeout(checkNodeStatus, checkInterval);
                } else {
                    closeModal();
                    showToast('Restart command sent. Node may still be starting up.', 'warning');
                    refreshNodes();
                }
            };

            // Start checking after initial delay
            setTimeout(checkNodeStatus, 3000);
        }

        async function downloadFile(nodeName, fileType) {
            const url = '/api/nodes/' + nodeName + '/download/' + fileType;
            try {
                const response = await fetch(url);
                if (!response.ok) {
                    const data = await response.json();
                    // Check if this is a remote node error - show SSH setup tutorial
                    if (data.is_remote) {
                        showSSHSetupTutorial(nodeName, data.node_ip || '');
                        return;
                    }
                    showToast(data.error || 'Download failed', 'error');
                    return;
                }
                // Trigger download
                const blob = await response.blob();
                const filename = fileType === 'config' ? nodeName + '_ossec.conf' : nodeName + '_cluster.key';
                const a = document.createElement('a');
                a.href = URL.createObjectURL(blob);
                a.download = filename;
                a.click();
                URL.revokeObjectURL(a.href);
            } catch (e) {
                showToast('Download failed: ' + e.message, 'error');
            }
        }

        let upgradeFilesData = [];
        let upgradeFilesSortCol = 'version';
        let upgradeFilesSortAsc = false;
        let upgradeFilesNodeName = '';
        let upgradeFilesManagerVersion = '';

        async function showUpgradeFiles(nodeName) {
            upgradeFilesNodeName = nodeName;
            const body = `<div id="upgradeFilesContent"><div class="loading"><div class="spinner"></div>Loading...</div></div>`;
            showModal('Agent Upgrade Files - ' + nodeName, body, '');
            // Make modal wider and resizable
            const modalContent = document.querySelector('.modal-content');
            modalContent.classList.add('resizable');
            modalContent.style.width = '1000px';
            modalContent.style.height = '600px';
            modalContent.style.maxWidth = '95vw';
            modalContent.style.position = 'relative';

            await loadUpgradeFiles(nodeName);
        }

        async function loadUpgradeFiles(nodeName) {
            const content = document.getElementById('upgradeFilesContent');
            content.style.height = '100%';
            content.innerHTML = '<div class="loading"><div class="spinner"></div>Loading...</div>';

            const data = await api('/nodes/' + nodeName + '/upgrade-files');

            if (!data) {
                content.innerHTML = '<div style="color:#e94560;">Failed to load upgrade files</div>';
                return;
            }

            if (data.error) {
                if (data.is_remote) {
                    showSSHSetupTutorial(nodeName, data.node_ip || '');
                    return;
                }
                content.innerHTML = '<div style="color:#e94560;">Error: ' + escapeHtml(data.error) + '</div>';
                return;
            }

            upgradeFilesManagerVersion = data.manager_version || '';
            const files = data.files || [];

            // Parse and store files data
            upgradeFilesData = files.map(f => {
                const match = f.name.match(/wazuh_agent_v([\d.]+)_(\w+)/);
                return {
                    name: f.name,
                    version: match ? match[1] : '-',
                    platform: match ? match[2] : '-',
                    size: f.size
                };
            });
            // Default sort by version descending (newest first)
            upgradeFilesSortCol = 'version';
            upgradeFilesSortAsc = false;

            renderUpgradeFilesTable(data.path);
        }

        function renderUpgradeFilesTable(path) {
            const content = document.getElementById('upgradeFilesContent');

            // Format file size
            function formatSize(bytes) {
                if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
                if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
                if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
                return bytes + ' B';
            }

            // Sort data
            const sorted = [...upgradeFilesData].sort((a, b) => {
                let valA = a[upgradeFilesSortCol];
                let valB = b[upgradeFilesSortCol];
                if (upgradeFilesSortCol === 'size') {
                    return upgradeFilesSortAsc ? valA - valB : valB - valA;
                }
                if (upgradeFilesSortCol === 'version') {
                    // Version comparison (e.g., 4.13.0 vs 4.12.0)
                    const partsA = valA.split('.').map(Number);
                    const partsB = valB.split('.').map(Number);
                    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
                        const diff = (partsA[i] || 0) - (partsB[i] || 0);
                        if (diff !== 0) return upgradeFilesSortAsc ? diff : -diff;
                    }
                    return 0;
                }
                return upgradeFilesSortAsc ? valA.localeCompare(valB) : valB.localeCompare(valA);
            });

            // Generate sort indicator (same style as agents table)
            function sortClass(col) {
                if (upgradeFilesSortCol !== col) return '';
                return upgradeFilesSortAsc ? 'asc' : 'desc';
            }
            const sortIcons = '<svg class="sort-icon sort-asc"><use href="#icon-nav-arrow-up"/></svg><svg class="sort-icon sort-desc"><use href="#icon-nav-arrow-down"/></svg>';

            let tableRows = '';
            if (sorted.length === 0) {
                tableRows = '<tr><td colspan="5" style="text-align:center;color:#888;padding:20px;">No WPK files found</td></tr>';
            } else {
                tableRows = sorted.map(f => `<tr>
                    <td style="font-family:monospace;font-size:12px;">${escapeHtml(f.name)}</td>
                    <td style="text-align:center;">${f.version}</td>
                    <td style="text-align:center;">${f.platform}</td>
                    <td style="text-align:right;white-space:nowrap;">${formatSize(f.size)}</td>
                    <td style="text-align:center;"><button class="btn btn-sm btn-danger" onclick="deleteUpgradeFile('${escapeHtml(f.name).replace(/'/g, "\\'")}')"><svg class="icon"><use href="#icon-trash"/></svg></button></td>
                </tr>`).join('');
            }

            const versionInfo = upgradeFilesManagerVersion ?
                `<span style="background:#0f3460;padding:4px 10px;border-radius:4px;margin-left:10px;">Manager: <strong style="color:#4fc3f7;">v${escapeHtml(upgradeFilesManagerVersion)}</strong></span>` : '';

            content.innerHTML = `
                <div style="display:flex;flex-direction:column;height:100%;">
                    <div style="background:#1a1a2e;border-left:3px solid #4fc3f7;padding:10px 15px;margin-bottom:15px;border-radius:4px;flex-shrink:0;">
                        <p style="color:#aaa;font-size:12px;margin:0;">These WPK packages are automatically downloaded from Wazuh official site when an agent connected to this node requests an upgrade. You can also manually upload WPK files for offline environments.</p>
                    </div>
                    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;flex-wrap:wrap;gap:10px;flex-shrink:0;">
                        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                            <span style="color:#888;">Path: <code style="background:#1a1a2e;padding:4px 8px;border-radius:4px;">${escapeHtml(path)}</code></span>
                            ${versionInfo}
                        </div>
                        <div style="display:flex;gap:8px;flex-wrap:wrap;">
                            <a href="https://documentation.wazuh.com/current/user-manual/agent/agent-management/remote-upgrading/wpk-files/wpk-list.html" target="_blank" class="btn btn-sm" style="background:#17a2b8;color:#fff;text-decoration:none;"><svg class="icon"><use href="#icon-link"/></svg>Official WPK List</a>
                            <button class="btn btn-sm btn-success" onclick="document.getElementById('wpkFileInput').click()"><svg class="icon"><use href="#icon-upload"/></svg>Upload WPK</button>
                            <input type="file" id="wpkFileInput" accept=".wpk" style="display:none;" onchange="uploadWpkFile(this)">
                        </div>
                    </div>
                    <div style="flex:1;overflow-y:auto;min-height:150px;">
                        <table style="table-layout:auto;width:100%;" id="upgradeFilesTable">
                            <thead><tr>
                                <th class="sortable ${sortClass('name')}" style="text-align:left;" onclick="sortUpgradeFiles('name','${path}')">Filename${sortIcons}</th>
                                <th class="sortable ${sortClass('version')}" style="width:80px;text-align:center;" onclick="sortUpgradeFiles('version','${path}')">Version${sortIcons}</th>
                                <th class="sortable ${sortClass('platform')}" style="width:100px;text-align:center;" onclick="sortUpgradeFiles('platform','${path}')">Platform${sortIcons}</th>
                                <th class="sortable ${sortClass('size')}" style="width:80px;text-align:right;" onclick="sortUpgradeFiles('size','${path}')">Size${sortIcons}</th>
                                <th style="width:50px;text-align:center;">Del</th>
                            </tr></thead>
                            <tbody>${tableRows}</tbody>
                        </table>
                    </div>
                    <p style="color:#888;margin-top:15px;font-size:12px;flex-shrink:0;">Total: ${upgradeFilesData.length} file(s)</p>
                </div>
            `;
        }

        function sortUpgradeFiles(col, path) {
            if (upgradeFilesSortCol === col) {
                upgradeFilesSortAsc = !upgradeFilesSortAsc;
            } else {
                upgradeFilesSortCol = col;
                upgradeFilesSortAsc = true;
            }
            renderUpgradeFilesTable(path);
        }

        async function uploadWpkFile(input) {
            if (!input.files || input.files.length === 0) return;

            const file = input.files[0];
            if (!file.name.endsWith('.wpk')) {
                showToast('Only .wpk files are allowed', 'error');
                input.value = '';
                return;
            }

            showToast('Uploading ' + file.name + '...', 'info');

            const formData = new FormData();
            formData.append('file', file);

            try {
                const response = await fetch('/api/nodes/' + upgradeFilesNodeName + '/upgrade-files', {
                    method: 'POST',
                    body: formData
                });

                const data = await response.json();

                if (data.error) {
                    if (data.is_remote) {
                        showSSHSetupTutorial(upgradeFilesNodeName, data.node_ip || '');
                    } else {
                        showToast('Upload failed: ' + data.error, 'error');
                    }
                } else {
                    showToast(data.message || 'File uploaded successfully', 'success');
                    // Reload file list
                    await loadUpgradeFiles(upgradeFilesNodeName);
                }
            } catch (e) {
                showToast('Upload failed: ' + e.message, 'error');
            }

            input.value = '';
        }

        async function deleteUpgradeFile(filename) {
            if (!await showConfirm('Delete "' + filename + '"?', true)) return;

            showToast('Deleting ' + filename + '...', 'info');

            const response = await fetch('/api/nodes/' + upgradeFilesNodeName + '/upgrade-files/' + encodeURIComponent(filename), {
                method: 'DELETE'
            });

            const data = await response.json();

            if (data.error) {
                if (data.is_remote) {
                    showSSHSetupTutorial(upgradeFilesNodeName, data.node_ip || '');
                } else {
                    showToast('Delete failed: ' + data.error, 'error');
                }
            } else {
                showToast(data.message || 'File deleted successfully', 'success');
                // Reload file list
                await loadUpgradeFiles(upgradeFilesNodeName);
            }
        }

        // User Management functions
        let apiUsers = [];
        let availableRoles = [];

        async function refreshUsers() {
            const body = document.getElementById('usersBody');
            body.innerHTML = '<tr><td colspan="4" class="loading"><div class="spinner"></div>Loading...</td></tr>';

            try {
                const data = await api('/users');
                if (!data) return;

                if (data.error) {
                    body.innerHTML = '<tr><td colspan="4" class="loading" style="color:#e94560;">Error: ' + data.error + '</td></tr>';
                    return;
                }

                apiUsers = data.users || [];
                availableRoles = data.roles || [];

                // Show warning if roles couldn't be fetched
                if (data.roles_warning) {
                    showToast(data.roles_warning, 'warning', 6000);
                }

                if (apiUsers.length === 0) {
                    body.innerHTML = '<tr><td colspan="4" class="loading">No users found</td></tr>';
                    return;
                }

                body.innerHTML = apiUsers.map(u => {
                    const roles = (u.roles || []).map(r => `<span class="badge">${r}</span>`).join(' ');
                    const isSystem = u.username === 'wazuh' || u.username === 'wazuh-wui';
                    let userNote = '';
                    if (u.username === 'wazuh') userNote = " <span style='color:#888;font-size:11px;'>(system - API admin)</span>";
                    else if (u.username === 'wazuh-wui') userNote = " <span style='color:#888;font-size:11px;'>(system - Dashboard)</span>";
                    else userNote = " <span style='color:#888;font-size:11px;'>(API user)</span>";
                    const actionBtns = isSystem ?
                        '<div class="btn-wrap"><span style="display:inline-block;padding:4px 8px;color:#888;font-size:12px;">Protected</span></div>' :
                        `<div class="btn-wrap"><button class="btn btn-sm btn-warning" onclick="showEditUserRolesModal('${u.username}')"><svg class="icon"><use href="#icon-edit"/></svg>Edit Roles</button>
                         <button class="btn btn-sm btn-danger" onclick="deleteUser('${u.username}')"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button></div>`;
                    return `<tr>
                        <td>${u.username}${userNote}</td>
                        <td>${roles || "<span style='color:#888'>none</span>"}</td>
                        <td>${u.allow_run_as ? "Yes" : "No"}</td>
                        <td>${actionBtns}</td>
                    </tr>`;
                }).join('');
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    body.innerHTML = `<tr><td colspan="4">${getConnectionErrorHtml('refreshUsers()')}</td></tr>`;
                } else {
                    body.innerHTML = `<tr><td colspan="4" class="loading" style="color:#e94560;">Error loading users: ${escapeHtml(err.message)}</td></tr>`;
                }
            }
        }

        function showCreateUserModal() {
            let roleOptions;
            let roleNote = '';
            if (availableRoles.length === 0) {
                roleOptions = '<span style="color:#888;font-style:italic;">Roles will be assigned after creation using "Edit Roles"</span>';
                roleNote = '<p style="color:#f39c12;font-size:12px;margin-top:5px;">Note: Use "Edit Roles" button after creating user to assign roles.</p>';
            } else {
                roleOptions = availableRoles.map(r =>
                    `<div class="multi-select-item" onclick="toggleCheckbox(this, event)">
                    <input type="checkbox" value="${r.name}"><span class="multi-select-item-text">${r.name}</span></div>`
                ).join('');
            }

            const body = `<div class="form-group">
                <label>Username</label>
                <input type="text" id="newUsername" placeholder="Enter username">
                </div>
                <div class="form-group">
                <label>Password</label>
                <input type="password" id="newPassword" placeholder="Enter password">
                <p style="color:#888;font-size:11px;margin-top:5px;">Must contain: uppercase, lowercase, number, special char, min 8 chars</p>
                </div>
                <div class="form-group">
                <label>Roles (optional)</label>
                <div id="roleCheckboxes" style="max-height:200px;overflow-y:auto;background:#1a1a2e;padding:10px;border-radius:4px;">${roleOptions}</div>
                ${roleNote}
                </div>`;
            const footer = `<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-success" onclick="createUser()"><svg class="icon"><use href="#icon-plus"/></svg>Create</button>`;
            showModal('Create API User', body, footer);
        }

        async function createUser() {
            const username = document.getElementById('newUsername').value.trim();
            const password = document.getElementById('newPassword').value;

            if (!username) { showToast('Username is required', 'warning'); return; }
            if (!password) { showToast('Password is required', 'warning'); return; }

            // Validate password meets Wazuh requirements
            const pwdRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).{8,}$/;
            if (!pwdRegex.test(password)) {
                showToast('Password must contain: uppercase, lowercase, number, special char, min 8 chars', 'warning');
                return;
            }

            const selectedRoles = [];
            document.querySelectorAll('#roleCheckboxes input[type="checkbox"]:checked').forEach(cb => {
                selectedRoles.push(cb.value);  // Role names (strings)
            });

            const result = await api('/users', 'POST', {
                username: username,
                password: password,
                role_names: selectedRoles  // Send role names for CLI
            });

            closeModal();
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'User created', 'success');
                    refreshUsers();
                }
            }
        }

        function showEditUserRolesModal(username) {
            const user = apiUsers.find(u => u.username === username);
            const userRoleIds = (user && user.role_ids) || [];

            const roleOptions = availableRoles.map(r => {
                const checked = userRoleIds.includes(r.id) ? 'checked' : '';
                return `<div class="multi-select-item" onclick="toggleCheckbox(this, event)">
                    <input type="checkbox" value="${r.id}" ${checked}><span class="multi-select-item-text">${r.name}</span></div>`;
            }).join('');

            const body = `<div class="form-group">
                <label>Roles for user "${username}"</label>
                <div id="roleCheckboxes" style="max-height:200px;overflow-y:auto;background:#1a1a2e;padding:10px;border-radius:4px;">${roleOptions}</div>
                </div>`;
            const footer = `<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>
                <button class="btn btn-primary" onclick="updateUserRoles('${username}')"><svg class="icon"><use href="#icon-save"/></svg>Save</button>`;
            showModal('Edit User Roles', body, footer);
        }

        async function updateUserRoles(username) {
            const selectedRoles = [];
            document.querySelectorAll('#roleCheckboxes input[type="checkbox"]:checked').forEach(cb => {
                selectedRoles.push(parseInt(cb.value));
            });

            const result = await api('/users/' + username + '/roles', 'PUT', {
                role_ids: selectedRoles
            });

            closeModal();
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'Roles updated', 'success');
                    refreshUsers();
                }
            }
        }

        async function deleteUser(username) {
            if (!await showConfirm('Delete user "' + username + '"?', true)) return;

            const result = await api('/users/' + username, 'DELETE');
            if (result) {
                if (result.error) {
                    showToast('Error: ' + result.error, 'error');
                } else {
                    showToast(result.message || 'User deleted', 'success');
                    refreshUsers();
                }
            }
        }

        // Log functions
        function highlightLog(text) {
            if (!text) return '';
            return text
                .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')  // Escape HTML
                .replace(/^(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})/gm, '<span style="color:#888">$1</span>')  // Timestamp
                .replace(/\\[INFO\\]/g, '<span style="color:#4fc3f7;font-weight:bold">[INFO]</span>')
                .replace(/\\[WARNING\\]/g, '<span style="color:#ffc107;font-weight:bold">[WARNING]</span>')
                .replace(/\\[ERROR\\]/g, '<span style="color:#e94560;font-weight:bold">[ERROR]</span>')
                .replace(/\\[DEBUG\\]/g, '<span style="color:#9e9e9e">[DEBUG]</span>')
                .replace(/(LOGIN SUCCESS:)/g, '<span style="color:#4ade80">$1</span>')
                .replace(/(LOGIN FAILED:)/g, '<span style="color:#f87171">$1</span>')
                .replace(/(SERVER START:)/g, '<span style="color:#60a5fa">$1</span>')
                .replace(/(USER DELETE:?|USER CREATE:?|USER ROLES UPDATE:?)/g, '<span style="color:#c084fc">$1</span>')
                .replace(/(GROUP |AGENT )/g, '<span style="color:#34d399">$1</span>')
                .replace(/(user=\\w+|operator=\\w+)/g, '<span style="color:#fbbf24">$1</span>')
                .replace(/(from=[\\d\\.]+)/g, '<span style="color:#94a3b8">$1</span>');
        }

        async function refreshLogs() {
            const lines = document.getElementById('logLines').value;
            const content = document.getElementById('logContent');
            content.innerHTML = '<span style="color:#888">Loading...</span>';

            try {
                const data = await api('/logs?lines=' + lines);
                if (!data) {
                    content.innerHTML = '<span style="color:#e94560">Failed to load logs</span>';
                    return;
                }

                if (data.error) {
                    content.innerHTML = '<span style="color:#e94560">Error: ' + escapeHtml(data.error) + '</span>';
                    return;
                }

                content.innerHTML = highlightLog(data.content) || '<span style="color:#888">No log entries</span>';

                // Update path and info
                if (data.path) {
                    document.getElementById('logFilePath').textContent = data.path;
                }
                if (data.total_lines !== undefined) {
                    document.getElementById('logFileInfo').textContent =
                        `(showing ${data.showing || 0} of ${data.total_lines} lines)`;
                }

                // Scroll to bottom after content renders
                setTimeout(function() {
                    content.scrollTop = content.scrollHeight;
                }, 50);
            } catch (err) {
                if (err.message === 'BACKEND_UNAVAILABLE') {
                    content.innerHTML = getConnectionErrorHtml('refreshLogs()').replace('class="connection-error"', 'class="connection-error" style="padding:30px 20px;"');
                } else {
                    content.innerHTML = '<span style="color:#e94560">Error loading logs: ' + escapeHtml(err.message) + '</span>';
                }
            }
        }

        function downloadLogs() {
            window.open('/api/logs/download', '_blank');
        }

        // Rules functions
        let rulesCache = {};
        let allRulesData = [];
        let allRulesParseErrors = [];
        let rulesContentQuery = '';
        let decodersData = [], decodersLoaded = false;
        let cdbListsData = [], cdbListsLoaded = false;
        let logtestToken = '';
        let allRulesLoaded = false;
        let rulesMode = 'hierarchy';
        let rulesSortColumn = 'id';
        let rulesSortDirection = 'asc';
        let rulesCurrentPage = 1;
        let rulesPageSize = 100;
        let rulesTotalPagesNum = 1;
        let _rulesFilterTimer = null;

        async function searchRuleHierarchy() {
            const ruleId = document.getElementById('ruleIdSearch').value.trim();
            if (!ruleId) {
                showToast('Enter a rule ID, or part of a rule file name', 'warning');
                return;
            }

            const container = document.getElementById('ruleTreeContainer');
            const status = document.getElementById('ruleSearchStatus');
            container.innerHTML = '<div class="loading"><div class="spinner"></div>Searching rules...</div>';
            status.textContent = '';

            try {
                const data = await api('/rules/hierarchy?rule_id=' + encodeURIComponent(ruleId));
                if (!data || data.error) {
                    container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">' +
                        escapeHtml((data && data.error) || 'Rule not found') + '</div>';
                    return;
                }

                rulesCache = data.all_rules || {};
                renderRuleTree(data, ruleId);
                const ruleCount = Object.keys(data.all_rules || {}).length;
                if (data.mode === 'file') {
                    const files = (data.matched_files || []).length;
                    status.textContent = 'Found ' + ruleCount + ' rules in ' + files + ' file' +
                        (files === 1 ? '' : 's') + (data.truncated ? ' (more files matched, showing the first 20)' : '');
                } else {
                    status.textContent = 'Found ' + ruleCount + ' related rules';
                }
            } catch (err) {
                container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">Error: ' +
                    escapeHtml(err.message) + '</div>';
            }
        }

        function renderRuleTree(data, targetRuleId) {
            const container = document.getElementById('ruleTreeContainer');
            const hierarchy = data.hierarchy || [];
            const targetRule = data.target_rule;
            const byFile = data.mode === 'file';

            if (!byFile && !targetRule) {
                container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">Rule not found</div>';
                return;
            }
            if (byFile && !hierarchy.length) {
                container.innerHTML = '<div style="color:#e94560;text-align:center;padding:20px;">No rule file matched</div>';
                return;
            }

            let html = '<div class="rule-tree"><ul>';
            html += renderRuleNode(hierarchy, targetRuleId, 0);
            html += '</ul></div>';

            container.innerHTML = html;

            // Add enter key listener
            document.getElementById('ruleIdSearch').onkeypress = function(e) {
                if (e.key === 'Enter') searchRuleHierarchy();
            };
        }

        function renderRuleNode(nodes, targetRuleId, depth) {
            if (!nodes || nodes.length === 0) return '';

            let html = '';
            for (const node of nodes) {
                const isTarget = node.id === targetRuleId;
                const isParent = depth < getTargetDepth(nodes, targetRuleId, 0);
                const hasChildren = node.children && node.children.length > 0;
                const isGroup = node.is_group === true;
                const isMore = node.is_more === true;
                const isFile = node.is_file === true;
                const levelClass = node.level === 0 ? 'zero' : (node.level >= 12 ? 'high' : (node.level >= 6 ? 'medium' : 'low'));
                let nodeClass = isTarget ? 'highlight' : (isParent ? 'parent' : 'child');
                if (isGroup) nodeClass = 'group';
                if (isMore) nodeClass = 'more';

                html += '<li>';

                if (isFile) {
                    // File node: the rule file itself, with its rules nested beneath
                    html += '<div class="rule-node group" style="cursor:pointer;" onclick="toggleRuleExpand(this.parentElement)">';
                    if (hasChildren) {
                        html += '<span class="rule-expand"><svg class="icon" style="width:16px;height:16px;"><use href="#icon-nav-arrow-down"/></svg></span>';
                    }
                    html += '<span class="rule-id" style="font-family:monospace;">' + escapeHtml(node.id) + '</span>';
                    html += '<span class="rule-desc">' + escapeHtml(node.description || '') + '</span>';
                    if (node.is_custom) {
                        html += '<span class="rule-level low" style="margin-left:8px;">custom</span>';
                    }
                    html += '</div>';
                } else if (isMore) {
                    // Just show text for "more" indicator
                    html += '<div class="rule-node ' + nodeClass + '">';
                    html += '<span class="rule-id">' + escapeHtml(node.id) + '</span>';
                    html += '</div>';
                } else if (isGroup) {
                    // Group node - clickable to show member rules
                    const memberRulesJson = node.member_rules ? JSON.stringify(node.member_rules) : '[]';
                    const groupName = node.group_name || '';
                    html += '<div class="rule-node ' + nodeClass + '" onclick="toggleGroupContent(this, ' + escapeHtml(memberRulesJson) + ', \\'' + escapeHtml(groupName) + '\\')" style="cursor:pointer;">';
                    if (hasChildren) {
                        html += '<span class="rule-expand" onclick="event.stopPropagation();toggleRuleExpand(this.parentElement.parentElement)"><svg class="icon" style="width:16px;height:16px;"><use href="#icon-nav-arrow-down"/></svg></span>';
                    }
                    html += '<span class="rule-id">' + escapeHtml(node.id) + '</span>';
                    html += '<span class="rule-desc">' + escapeHtml(node.description || '') + '</span>';
                    html += '</div>';
                    html += '<div class="rule-content" id="group-content-' + escapeHtml(groupName) + '"></div>';
                } else {
                    // Regular rule node
                    html += '<div class="rule-node ' + nodeClass + '" onclick="toggleRuleContent(this, \\'' + escapeHtml(node.id) + '\\')">';
                    if (hasChildren) {
                        html += '<span class="rule-expand" onclick="event.stopPropagation();toggleRuleExpand(this.parentElement.parentElement)"><svg class="icon" style="width:16px;height:16px;"><use href="#icon-nav-arrow-down"/></svg></span>';
                    }
                    html += '<span class="rule-id">' + escapeHtml(node.id) + '</span>';
                    html += '<span class="rule-level ' + levelClass + '">L' + node.level + '</span>';
                    if (node.is_custom) {
                        html += '<span class="rule-custom-badge">Custom</span>';
                    }
                    if (node.if_group) {
                        html += '<span class="rule-if-group-badge">if_group: ' + escapeHtml(node.if_group) + '</span>';
                    }
                    html += '<span class="rule-desc">' + escapeHtml(node.description || '') + '</span>';
                    html += '<span class="rule-file' + (node.is_custom ? ' custom' : '') + '">' + escapeHtml(node.file || '') + '</span>';
                    html += '</div>';
                    html += '<div class="rule-content" id="rule-content-' + escapeHtml(node.id) + '"></div>';
                }

                if (hasChildren) {
                    html += '<ul>' + renderRuleNode(node.children, targetRuleId, depth + 1) + '</ul>';
                }
                html += '</li>';
            }
            return html;
        }

        function getTargetDepth(nodes, targetRuleId, currentDepth) {
            for (const node of nodes) {
                if (node.id === targetRuleId) return currentDepth;
                if (node.children) {
                    const childDepth = getTargetDepth(node.children, targetRuleId, currentDepth + 1);
                    if (childDepth >= 0) return childDepth;
                }
            }
            return -1;
        }

        function toggleRuleExpand(li) {
            li.classList.toggle('collapsed');
        }

        async function toggleRuleContent(nodeEl, ruleId) {
            const contentEl = document.getElementById('rule-content-' + ruleId);
            if (!contentEl) return;

            if (contentEl.classList.contains('show')) {
                contentEl.classList.remove('show');
                return;
            }

            // Load content if not cached
            if (!contentEl.querySelector('code')) {
                contentEl.innerHTML = '<span style="color:#888">Loading...</span>';
                try {
                    const data = await api('/rules/' + encodeURIComponent(ruleId));
                    if (data && data.content) {
                        contentEl.innerHTML = '<button class="rule-copy-btn" onclick="copyRuleContent(this, \\'' + ruleId + '\\')">Copy</button><code>' + highlightXml(data.content) + '</code>';
                        contentEl.dataset.rawContent = data.content;
                    } else {
                        contentEl.innerHTML = '<span style="color:#888">No content available</span>';
                    }
                } catch (err) {
                    contentEl.innerHTML = '<span style="color:#e94560">Error loading rule</span>';
                }
            }

            contentEl.classList.add('show');
        }

        async function toggleGroupContent(nodeEl, memberRules, groupName) {
            const contentEl = document.getElementById('group-content-' + groupName);
            if (!contentEl) return;

            if (contentEl.classList.contains('show')) {
                contentEl.classList.remove('show');
                return;
            }

            // Load content if not cached
            if (!contentEl.querySelector('code')) {
                contentEl.innerHTML = '<span style="color:#888">Loading member rules...</span>';
                try {
                    let html = '';
                    for (const ruleId of memberRules) {
                        const data = await api('/rules/' + encodeURIComponent(ruleId));
                        if (data && data.content) {
                            html += '<div style="margin-bottom:15px;border-bottom:1px solid #333;padding-bottom:15px;">';
                            html += '<div style="color:#5dade2;font-weight:bold;margin-bottom:8px;">Rule ' + ruleId + '</div>';
                            html += '<code>' + highlightXml(data.content) + '</code>';
                            html += '</div>';
                        }
                    }
                    if (html) {
                        contentEl.innerHTML = html;
                    } else {
                        contentEl.innerHTML = '<span style="color:#888">No member rule content available</span>';
                    }
                } catch (err) {
                    contentEl.innerHTML = '<span style="color:#e94560">Error loading rules</span>';
                }
            }

            contentEl.classList.add('show');
        }

        function clearRuleSearch() {
            document.getElementById('ruleIdSearch').value = '';
            document.getElementById('ruleSearchStatus').textContent = '';
            document.getElementById('ruleTreeContainer').innerHTML = '<div style="color:#888;text-align:center;padding:40px;">' +
                '<svg class="icon" style="width:48px;height:48px;opacity:0.5;margin-bottom:15px;"><use href="#icon-tree"/></svg>' +
                '<p>Enter a Rule ID to view its hierarchy and relationships.</p>' +
                '<p style="font-size:12px;margin-top:10px;">The tree will show parent rules (if_sid, if_matched_sid) and child rules.</p>' +
                '</div>';
            rulesCache = {};
        }

        async function copyRuleContent(btn, ruleId) {
            const contentEl = document.getElementById('rule-content-' + ruleId);
            if (!contentEl || !contentEl.dataset.rawContent) return;

            try {
                await navigator.clipboard.writeText(contentEl.dataset.rawContent);
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                    btn.textContent = 'Copy';
                    btn.classList.remove('copied');
                }, 2000);
            } catch (err) {
                showToast('Failed to copy to clipboard', 'error');
            }
        }

        function highlightXml(xml) {
            // Escape HTML first
            let escaped = escapeHtml(xml);
            // Highlight comments
            escaped = escaped.replace(/(&lt;!--[\s\S]*?--&gt;)/g, '<span class="xml-comment">$1</span>');
            // Highlight tags (including < and </ as part of tag color)
            escaped = escaped.replace(/(&lt;\/?)([\w:-]+)/g, '<span class="xml-tag">$1$2</span>');
            escaped = escaped.replace(/([\w:-]+)(=)(&quot;[^&]*&quot;)/g, '<span class="xml-attr">$1</span>$2<span class="xml-value">$3</span>');
            // Highlight closing bracket
            escaped = escaped.replace(/(\/?&gt;)/g, '<span class="xml-tag">$1</span>');
            return escaped;
        }

        function expandAllRules() {
            // Expand all collapsed tree nodes
            document.querySelectorAll('#ruleTreeContainer li.collapsed').forEach(li => {
                li.classList.remove('collapsed');
            });
            // Also show all rule content that has been loaded
            document.querySelectorAll('#ruleTreeContainer .rule-content').forEach(el => {
                if (el.innerHTML && el.innerHTML.trim()) {
                    el.classList.add('show');
                }
            });
        }

        function collapseAllRules() {
            // Collapse all tree nodes that have children
            document.querySelectorAll('#ruleTreeContainer li').forEach(li => {
                if (li.querySelector(':scope > ul')) {
                    li.classList.add('collapsed');
                }
            });
            // Also hide all rule content
            document.querySelectorAll('#ruleTreeContainer .rule-content.show').forEach(el => {
                el.classList.remove('show');
            });
        }

        // ============ All Rules Functions ============

        // mode -> [button id, controls id, view id, controls display, loader]
        const RULES_MODES = {
            hierarchy: ['rulesModeHierarchy', 'rulesHierarchyControls', 'rulesHierarchyView', 'contents', null],
            all:       ['rulesModeAll',       'rulesAllControls',       'rulesAllView',       'contents', () => { if (!allRulesLoaded) loadAllRules(); }],
            decoders:  ['rulesModeDecoders',  'rulesDecoderControls',   'rulesDecoderView',   'contents', () => { if (!decodersLoaded) loadDecoders(); }],
            lists:     ['rulesModeLists',     'rulesListsControls',     'rulesListsView',     'contents', () => { if (!cdbListsLoaded) loadCdbLists(); }],
            logtest:   ['rulesModeLogtest',   'rulesLogtestControls',   'rulesLogtestView',   'contents', null],
        };

        function switchRulesMode(mode) {
            if (!RULES_MODES[mode]) mode = 'hierarchy';
            rulesMode = mode;
            for (const [name, [btnId, controlsId, viewId, display]] of Object.entries(RULES_MODES)) {
                const active = name === mode;
                const btn = document.getElementById(btnId);
                const controls = document.getElementById(controlsId);
                const view = document.getElementById(viewId);
                if (btn) btn.classList.toggle('active', active);
                if (controls) controls.style.display = active ? display : 'none';
                if (view) view.style.display = active ? 'flex' : 'none';
            }
            const loader = RULES_MODES[mode][4];
            if (loader) loader();
        }

        async function loadAllRules() {
            const tbody = document.getElementById('rulesAllBody');
            const status = document.getElementById('rulesAllStatus');
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;"><div class="loading"><div class="spinner"></div>Loading all rules...</div></td></tr>';
            status.textContent = '';

            try {
                const data = await api('/rules');
                if (!data || data.error) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#e94560;padding:30px;">' + escapeHtml((data && data.error) || 'Failed to load rules') + '</td></tr>';
                    return;
                }

                allRulesData = data.rules || [];
                allRulesLoaded = true;
                allRulesParseErrors = data.parse_errors || [];

                // Some rule files may be unreadable XML (Wazuh's own ruleset has
                // shipped such files). Say so instead of silently hiding rules.
                const warn = document.getElementById('rulesParseWarn');
                if (allRulesParseErrors.length) {
                    const n = allRulesParseErrors.length;
                    warn.innerHTML = '<a href="#" onclick="showRuleParseErrors();return false;" ' +
                        'style="color:#fd7e14;text-decoration:none;" ' +
                        'title="Click for details">&#9888; ' + n +
                        (n === 1 ? ' rule file could not be parsed' : ' rule files could not be parsed') + '</a>';
                } else {
                    warn.innerHTML = '';
                }

                // Back to the full list: drop any content-search marker
                rulesContentQuery = '';
                populateRulesFileFilter();

                status.textContent = allRulesData.length + ' rules loaded';
                rulesCurrentPage = 1;
                renderAllRules();
            } catch (err) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#e94560;padding:30px;">Error: ' + escapeHtml(err.message) + '</td></tr>';
            }
        }

        // Rule files are synced to workers by the cluster, but each node keeps its
        // own in-memory ruleset until told to reload. Reload every node at once.
        async function reloadClusterRuleset() {
            if (!await showConfirm('Reload the ruleset on every cluster node? Running services are not restarted.')) return;
            showToast('Reloading ruleset...', 'info');
            const result = await api('/cluster/reload-ruleset', 'POST');
            if (!result || result.error) {
                showToast((result && result.error) || 'Reload failed', 'error');
                return;
            }
            const rows = (result.nodes || []).map(n =>
                '<tr><td style="padding:6px 10px;">' + escapeHtml(n.node) + '</td>' +
                '<td style="padding:6px 10px;color:' + (n.ok ? '#28a745' : '#e94560') + ';">' +
                (n.ok ? 'reloaded' : 'failed') + '</td>' +
                '<td style="padding:6px 10px;color:#888;font-size:11px;">' +
                escapeHtml((n.warnings || []).join('; ')) + '</td></tr>').join('');
            showModal('Reload Ruleset',
                '<div class="alert ' + (result.fail_count ? 'alert-error' : 'alert-success') + '">' +
                escapeHtml(result.message || '') + '</div>' +
                '<div style="overflow-x:auto;"><table class="data-table" style="width:100%;font-size:13px;">' +
                '<thead><tr><th style="text-align:left;padding:6px 10px;">Node</th>' +
                '<th style="text-align:left;padding:6px 10px;">Result</th>' +
                '<th style="text-align:left;padding:6px 10px;">Warnings</th></tr></thead><tbody>' +
                rows + '</tbody></table></div>' +
                ((result.errors && result.errors.length) ?
                    '<div style="margin-top:10px;color:#e94560;font-size:12px;">' +
                    result.errors.map(e => escapeHtml(e)).join('<br>') + '</div>' : ''),
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>');
        }

        // ---------- Decoders ----------
        async function loadDecoders() {
            const tbody = document.getElementById('decodersBody');
            const status = document.getElementById('decoderStatus');
            const search = (document.getElementById('decoderSearch').value || '').trim();
            tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:30px;"><div class="loading"><div class="spinner"></div>Loading decoders...</div></td></tr>';
            const data = await api('/decoders' + (search ? '?search=' + encodeURIComponent(search) : ''));
            if (!data || data.error) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#e94560;padding:30px;">' + escapeHtml((data && data.error) || 'Failed to load decoders') + '</td></tr>';
                return;
            }
            decodersData = data.decoders || [];
            decodersLoaded = true;
            status.textContent = decodersData.length + ' decoders';
            if (!decodersData.length) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#888;padding:30px;">No decoders match.</td></tr>';
                return;
            }
            tbody.innerHTML = decodersData.map(d => {
                const file = d.filename || '';
                return '<tr>' +
                    '<td><a class="rule-id-link" onclick="showDecoderFile(\\'' + escapeHtml(file) + '\\')">' + escapeHtml(d.name || '') + '</a></td>' +
                    '<td>' + escapeHtml(String(d.position !== undefined ? d.position : '')) + '</td>' +
                    '<td>' + escapeHtml(d.parent || '') + '</td>' +
                    '<td' + (d.is_custom ? ' style="color:#f39c12;"' : '') + '>' + escapeHtml(file) + '</td>' +
                    '<td><span class="rule-type-badge ' + (d.is_custom ? 'custom' : 'builtin') + '">' + (d.is_custom ? 'Custom' : 'Built-in') + '</span></td>' +
                    '</tr>';
            }).join('');
        }

        async function showDecoderFile(filename) {
            if (!filename) return;
            showModal('Decoder - ' + filename, '<div class="loading"><div class="spinner"></div>Loading...</div>',
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
            const data = await api('/decoders/file?filename=' + encodeURIComponent(filename));
            const body = document.getElementById('modalBody');
            if (!body) return;
            if (!data || data.error) {
                body.innerHTML = '<div class="alert alert-error">' + escapeHtml((data && data.error) || 'Failed to load') + '</div>';
                return;
            }
            body.innerHTML = '<pre style="background:#0a0a15;padding:15px;border-radius:4px;font-size:12px;max-height:60vh;overflow:auto;"><code>' +
                highlightXml(escapeHtml(data.content || '')) + '</code></pre>';
        }

        // ---------- CDB lists ----------
        async function loadCdbLists() {
            const tbody = document.getElementById('cdbBody');
            const status = document.getElementById('cdbStatus');
            tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:30px;"><div class="loading"><div class="spinner"></div>Loading lists...</div></td></tr>';
            const data = await api('/lists');
            if (!data || data.error) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#e94560;padding:30px;">' + escapeHtml((data && data.error) || 'Failed to load lists') + '</td></tr>';
                return;
            }
            cdbListsData = data.lists || [];
            cdbListsLoaded = true;
            status.textContent = cdbListsData.length + ' lists';
            if (!cdbListsData.length) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#888;padding:30px;">No CDB lists found.</td></tr>';
                return;
            }
            tbody.innerHTML = cdbListsData.map(l => {
                const name = l.filename || '';
                return '<tr>' +
                    '<td><a class="rule-id-link" onclick="editCdbList(\\'' + escapeHtml(name) + '\\')">' + escapeHtml(name) + '</a></td>' +
                    '<td style="color:#888;">' + escapeHtml(l.relative_dirname || '') + '</td>' +
                    '<td><span class="rule-type-badge ' + (l.is_custom ? 'custom' : 'builtin') + '">' + (l.is_custom ? 'Custom' : 'Built-in') + '</span></td>' +
                    '<td><button class="btn btn-sm" onclick="editCdbList(\\'' + escapeHtml(name) + '\\')"><svg class="icon"><use href="#icon-edit"/></svg>Edit</button>' +
                    '<button class="btn btn-sm btn-danger" style="margin-left:6px;" onclick="deleteCdbList(\\'' + escapeHtml(name) + '\\')"><svg class="icon"><use href="#icon-trash"/></svg>Delete</button></td>' +
                    '</tr>';
            }).join('');
        }

        async function editCdbList(filename) {
            const isNew = !filename;
            let content = '';
            if (!isNew) {
                const data = await api('/lists/file?filename=' + encodeURIComponent(filename));
                if (!data || data.error) {
                    showToast((data && data.error) || 'Failed to load the list', 'error');
                    return;
                }
                content = data.content || '';
            }
            const body =
                '<p style="color:#888;font-size:12px;margin-bottom:10px;">One <code>key:value</code> pair per line. The ruleset must be reloaded before changes take effect.</p>' +
                '<div style="margin-bottom:10px;">Name <input type="text" id="cdbName" value="' + escapeHtml(filename || '') + '"' +
                (isNew ? '' : ' readonly') + ' style="width:280px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;"></div>' +
                '<textarea id="cdbContent" style="width:100%;height:45vh;background:#0a0a15;color:#eee;border:1px solid #1a3a6e;border-radius:4px;padding:10px;font-family:monospace;font-size:12px;">' +
                escapeHtml(content) + '</textarea>' +
                '<div id="cdbSaveResult" style="margin-top:10px;"></div>';
            showModal(isNew ? 'New CDB List' : 'CDB List - ' + filename, body,
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                '<button class="btn btn-success" onclick="saveCdbList()"><svg class="icon"><use href="#icon-save"/></svg>Save</button>', true);
        }

        async function saveCdbList() {
            const name = (document.getElementById('cdbName').value || '').trim();
            const content = document.getElementById('cdbContent').value;
            const target = document.getElementById('cdbSaveResult');
            if (!name) {
                target.innerHTML = '<div class="alert alert-error">A list name is required</div>';
                return;
            }
            const result = await api('/lists/file', 'PUT', { filename: name, content: content });
            if (!result || result.error) {
                target.innerHTML = '<div class="alert alert-error">' + escapeHtml((result && result.error) || 'Save failed') + '</div>';
                return;
            }
            closeModal();
            showToast(result.message || 'List saved', 'success', 6000);
            loadCdbLists();
        }

        async function deleteCdbList(filename) {
            if (!await showConfirm('Delete CDB list "' + filename + '"?', true)) return;
            const result = await api('/lists/file?filename=' + encodeURIComponent(filename), 'DELETE');
            if (!result || result.error) {
                showToast((result && result.error) || 'Delete failed', 'error');
                return;
            }
            showToast(result.message || 'List deleted', 'success');
            loadCdbLists();
        }

        // ---------- Log test ----------
        async function runLogtest() {
            const event = (document.getElementById('logtestEvent').value || '').trim();
            const target = document.getElementById('logtestResult');
            const status = document.getElementById('logtestStatus');
            if (!event) {
                showToast('Paste a log line first', 'warning');
                return;
            }
            target.innerHTML = '<div class="loading"><div class="spinner"></div>Testing...</div>';
            const result = await api('/logtest', 'POST', {
                event: event,
                log_format: document.getElementById('logtestFormat').value,
                location: (document.getElementById('logtestLocation').value || 'stdin').trim(),
                token: logtestToken || undefined
            });
            if (!result || result.error) {
                target.innerHTML = '<div class="alert alert-error">' + escapeHtml((result && result.error) || 'Log test failed') + '</div>';
                return;
            }
            logtestToken = result.token || logtestToken;
            status.textContent = logtestToken ? 'session ' + logtestToken : '';
            const out = result.output || {};
            const rule = out.rule || null;
            const decoder = out.decoder || {};
            let html = '';
            if (rule) {
                const level = rule.level !== undefined ? rule.level : '-';
                const levelClass = level === 0 ? 'zero' : (level >= 12 ? 'high' : (level >= 6 ? 'medium' : 'low'));
                html += '<div style="background:#0a0a15;padding:15px;border-radius:4px;border-left:3px solid #28a745;margin-bottom:12px;">' +
                    '<div style="margin-bottom:6px;">Matched rule <a class="rule-id-link" onclick="browseToRuleHierarchy(\\'' + escapeHtml(String(rule.id)) + '\\')">' + escapeHtml(String(rule.id)) + '</a> ' +
                    '<span class="rule-level ' + levelClass + '">' + escapeHtml(String(level)) + '</span></div>' +
                    '<div style="color:#eee;">' + escapeHtml(rule.description || '') + '</div>' +
                    (rule.groups && rule.groups.length ? '<div class="rules-group-tags" style="margin-top:8px;">' + rule.groups.map(g => '<span class="rules-group-tag">' + escapeHtml(g) + '</span>').join('') + '</div>' : '') +
                    '</div>';
            } else {
                html += '<div style="background:#0a0a15;padding:15px;border-radius:4px;border-left:3px solid #888;margin-bottom:12px;color:#888;">No rule matched this log line.</div>';
            }
            html += '<div style="background:#0a0a15;padding:15px;border-radius:4px;margin-bottom:12px;">' +
                '<div style="color:#888;font-size:12px;margin-bottom:4px;">Decoder</div>' +
                '<div>' + escapeHtml(decoder.name || 'none') + (decoder.parent ? ' (parent: ' + escapeHtml(decoder.parent) + ')' : '') + '</div></div>';
            const fields = out.data || {};
            if (Object.keys(fields).length) {
                html += '<div style="background:#0a0a15;padding:15px;border-radius:4px;margin-bottom:12px;">' +
                    '<div style="color:#888;font-size:12px;margin-bottom:4px;">Extracted fields</div>' +
                    '<pre style="margin:0;font-size:12px;">' + escapeHtml(JSON.stringify(fields, null, 2)) + '</pre></div>';
            }
            if (result.messages && result.messages.length) {
                html += '<div style="background:#0a0a15;padding:15px;border-radius:4px;">' +
                    '<div style="color:#888;font-size:12px;margin-bottom:4px;">Messages</div><pre style="margin:0;font-size:12px;">' +
                    escapeHtml(result.messages.join('\\n')) + '</pre></div>';
            }
            target.innerHTML = html;
        }

        async function clearLogtest() {
            document.getElementById('logtestEvent').value = '';
            document.getElementById('logtestResult').innerHTML = '';
            document.getElementById('logtestStatus').textContent = '';
            if (logtestToken) {
                await api('/logtest/session/' + encodeURIComponent(logtestToken), 'DELETE');
                logtestToken = '';
            }
        }

        // ---------- Inventory (cross-agent syscollector) ----------
        let inventoryRows = [], inventoryColumns = [];

        function onInventoryTypeChange() {
            document.getElementById('invBody').innerHTML =
                '<tr><td colspan="2" style="text-align:center;color:#888;padding:40px;">Press Search to query this category.</td></tr>';
            document.getElementById('invStatus').textContent = '';
            document.getElementById('invWarn').innerHTML = '';
        }

        function invCell(row, column) {
            // columns may be dotted paths such as local.port
            return column.split('.').reduce((acc, key) => (acc == null ? acc : acc[key]), row);
        }

        async function runInventorySearch() {
            const type = document.getElementById('invType').value;
            const query = (document.getElementById('invQuery').value || '').trim();
            const scope = document.getElementById('invScope').value;
            const body = document.getElementById('invBody');
            const status = document.getElementById('invStatus');
            const warn = document.getElementById('invWarn');
            let agents = scope;
            if (scope === 'selected') {
                if (!selectedAgents.size) {
                    showToast('No agents selected on the Agents tab', 'warning');
                    return;
                }
                agents = Array.from(selectedAgents).join(',');
            }
            warn.innerHTML = '';
            status.textContent = '';
            body.innerHTML = '<tr><td colspan="2" style="text-align:center;padding:30px;"><div class="loading"><div class="spinner"></div>Querying agents...</div></td></tr>';
            const data = await api('/inventory/search?type=' + encodeURIComponent(type) +
                '&q=' + encodeURIComponent(query) + '&agents=' + encodeURIComponent(agents));
            if (!data || data.error) {
                body.innerHTML = '<tr><td colspan="2" style="text-align:center;color:#e94560;padding:30px;">' +
                    escapeHtml((data && data.error) || 'Search failed') + '</td></tr>';
                return;
            }
            inventoryRows = data.rows || [];
            inventoryColumns = data.columns || [];
            const head = document.getElementById('invHead');
            head.innerHTML = '<th style="width:170px;">Agent</th>' +
                inventoryColumns.map(c => '<th>' + escapeHtml(c) + '</th>').join('');
            status.textContent = data.total + ' results from ' + data.agents_matched + ' of ' +
                data.agents_queried + ' agents';
            const notes = [];
            if (data.truncated) notes.push('results truncated at ' + data.max_rows);
            if (data.agents_failed && data.agents_failed.length) notes.push(data.agents_failed.length + ' agents returned no data');
            warn.innerHTML = notes.length ? '<span style="color:#fd7e14;">&#9888; ' + escapeHtml(notes.join('; ')) + '</span>' : '';
            if (!inventoryRows.length) {
                body.innerHTML = '<tr><td colspan="' + (inventoryColumns.length + 1) +
                    '" style="text-align:center;color:#888;padding:30px;">No agent matched.</td></tr>';
                return;
            }
            body.innerHTML = inventoryRows.map(r =>
                '<tr><td><span style="color:#0dcaf0;">' + escapeHtml(r.agent_id) + '</span> ' +
                escapeHtml(r.agent_name || '') + '</td>' +
                inventoryColumns.map(c => {
                    const v = invCell(r, c);
                    return '<td>' + escapeHtml(v === undefined || v === null ? '' : String(v)) + '</td>';
                }).join('') + '</tr>').join('');
        }

        // The manifests are bilingual. Pick the reader's language rather than always
        // showing Chinese, which left English-speaking operators with a table they
        // could not read.
        function packLang(en, zh) {
            try {
                if (localStorage.getItem('jtwz_lang') === 'zh-TW' && zh) return zh;
            } catch (e) { /* localStorage unavailable */ }
            return en || zh || '';
        }

        function exportInventoryCsv() {
            if (!inventoryRows.length) {
                showToast('Nothing to export', 'warning');
                return;
            }
            const header = ['agent_id', 'agent_name'].concat(inventoryColumns);
            const escapeCsv = (v) => '"' + String(v === undefined || v === null ? '' : v).replace(/"/g, '""') + '"';
            const lines = [header.join(',')];
            inventoryRows.forEach(r => {
                lines.push([escapeCsv(r.agent_id), escapeCsv(r.agent_name)]
                    .concat(inventoryColumns.map(c => escapeCsv(invCell(r, c)))).join(','));
            });
            const blob = new Blob([lines.join('\\n')], { type: 'text/csv' });
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            link.download = 'inventory_' + document.getElementById('invType').value + '.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(link.href);
        }

        // ossec.conf is not synced by the cluster, so a worker can silently miss a
        // list declaration and ignore every rule that uses it. Nothing else surfaces this.
        async function showNodeConfigDiff() {
            showModal('Node Config Diff', '<div class="loading"><div class="spinner"></div>Comparing nodes...</div>',
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
            const data = await api('/nodes/config-diff');
            const body = document.getElementById('modalBody');
            if (!body) return;
            if (!data || data.error) {
                body.innerHTML = '<div class="alert alert-error">' + escapeHtml((data && data.error) || 'Failed to compare') + '</div>';
                return;
            }
            let html = '<p style="color:#888;font-size:12px;margin-bottom:12px;">ossec.conf is not synchronised by the cluster. ' +
                'Compared against the master <strong>' + escapeHtml(data.reference) + '</strong>: ' +
                escapeHtml(data.nodes.join(', ')) + '</p>';
            if (!data.differences.length) {
                html += '<div class="alert alert-success">All nodes match the master in the sections that affect detection.</div>';
            } else {
                html += '<div class="alert alert-error">' + data.diff_count + ' difference(s) found</div>';
                for (const d of data.differences) {
                    html += '<div style="background:#0a0a15;padding:12px;border-radius:4px;margin-bottom:10px;">' +
                        '<div style="color:#4fc3f7;margin-bottom:6px;">' + escapeHtml(d.node) +
                        ' &mdash; section <code>' + escapeHtml(d.section) + '</code></div>';
                    if (d.missing_on_node.length) {
                        html += '<div style="color:#e94560;font-size:12px;margin-bottom:4px;">Missing on this node (present on master):</div>' +
                            '<ul style="margin:0 0 8px 18px;font-family:monospace;font-size:12px;color:#eee;">' +
                            d.missing_on_node.map(i => '<li>' + escapeHtml(i) + '</li>').join('') + '</ul>';
                    }
                    if (d.extra_on_node.length) {
                        html += '<div style="color:#fd7e14;font-size:12px;margin-bottom:4px;">Only on this node:</div>' +
                            '<ul style="margin:0 0 0 18px;font-family:monospace;font-size:12px;color:#eee;">' +
                            d.extra_on_node.map(i => '<li>' + escapeHtml(i) + '</li>').join('') + '</ul>';
                    }
                    html += '</div>';
                }
            }
            if (data.errors && Object.keys(data.errors).length) {
                html += '<div class="alert alert-error">' +
                    Object.entries(data.errors).map(([n, e]) => escapeHtml(n) + ': ' + escapeHtml(e)).join('<br>') + '</div>';
            }
            body.innerHTML = html;
        }

        // ---------- Rule packs ----------
        let packsData = [];

        async function refreshPacks() {
            const body = document.getElementById('packsBody');
            const status = document.getElementById('packsStatus');
            body.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;"><div class="loading"><div class="spinner"></div>Loading...</div></td></tr>';
            const data = await api('/packs');
            if (!data || data.error) {
                body.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#e94560;padding:30px;">' +
                    escapeHtml((data && data.error) || 'Failed to load packs') + '</td></tr>';
                return;
            }
            packsData = data.packs || [];
            const installed = packsData.filter(p => p.installed).length;
            status.textContent = packsData.length + ' packs, ' + installed + ' installed';
            if (!packsData.length) {
                body.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#888;padding:30px;">No packs available.</td></tr>';
                return;
            }
            body.innerHTML = packsData.map(p => {
                const badge = p.installed
                    ? '<span class="rule-type-badge custom">Installed</span>'
                    : '<span class="rule-type-badge builtin">Not installed</span>';
                const update = p.update_available
                    ? ' <span style="color:#fd7e14;font-size:11px;">update ' + escapeHtml(p.installed_version || '') + ' &rarr; ' + escapeHtml(p.version) + '</span>'
                    : '';
                const actions =
                    '<button class="btn btn-sm" onclick="showPackDetail(\\'' + escapeHtml(p.id) + '\\')"><svg class="icon"><use href="#icon-file-text"/></svg>Details</button>' +
                    (p.installed
                        ? '<button class="btn btn-sm btn-danger" style="margin-left:6px;" onclick="uninstallPack(\\'' + escapeHtml(p.id) + '\\')"><svg class="icon"><use href="#icon-trash"/></svg>Remove</button>'
                        : '<button class="btn btn-sm btn-success" style="margin-left:6px;" onclick="installPack(\\'' + escapeHtml(p.id) + '\\')"><svg class="icon"><use href="#icon-download"/></svg>Install</button>');
                return '<tr>' +
                    '<td><strong>' + escapeHtml(packLang(p.name, p.name_zh)) + '</strong><br>' +
                        '<span style="color:#888;font-size:11px;font-family:monospace;">' + escapeHtml(p.id) + '</span></td>' +
                    '<td style="font-size:12px;color:#ccc;">' + escapeHtml(packLang(p.summary, p.summary_zh)) + '</td>' +
                    '<td style="font-family:monospace;font-size:12px;">' + escapeHtml(p.rule_id_range) + '</td>' +
                    '<td>' + escapeHtml(p.version) + update + '</td>' +
                    '<td>' + badge + '</td>' +
                    '<td>' + actions + '</td></tr>';
            }).join('');
        }

        async function showPackDetail(packId) {
            showModal('Pack Details', '<div class="loading"><div class="spinner"></div>Loading...</div>',
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
            const d = await api('/packs/' + encodeURIComponent(packId));
            const body = document.getElementById('modalBody');
            if (!body) return;
            if (!d || d.error) {
                body.innerHTML = '<div class="alert alert-error">' + escapeHtml((d && d.error) || 'Failed to load') + '</div>';
                return;
            }
            const m = d.manifest || {};
            document.getElementById('modalTitle').textContent = (packLang(m.name, m.name_zh) || packId);
            let html =
                '<div style="background:#0a0a15;padding:12px;border-radius:4px;margin-bottom:12px;">' +
                '<div style="color:#ccc;margin-bottom:6px;">' + escapeHtml(packLang(m.summary, m.summary_zh)) + '</div>' +
                '<div style="color:#888;font-size:12px;">' +
                'ID <code>' + escapeHtml(m.id || '') + '</code> &nbsp; version ' + escapeHtml(m.version || '') +
                ' &nbsp; rules ' + d.rule_count + ' &nbsp; ID range ' + escapeHtml(m.rule_id_range || '') +
                '<br>' + escapeHtml(m.author || '') + ' &nbsp; ' + escapeHtml(m.license || '') + '</div></div>';
            // manifests carry both notes (English) and notes_zh; show the reader's own language
            let packNotes = m.notes || [];
            try {
                if (localStorage.getItem('jtwz_lang') === 'zh-TW' && m.notes_zh && m.notes_zh.length) {
                    packNotes = m.notes_zh;
                }
            } catch (e) { /* localStorage unavailable */ }
            if (!packNotes.length) packNotes = m.notes_zh || [];
            if (packNotes.length) {
                html += '<div style="margin-bottom:12px;"><div style="color:#888;font-size:12px;margin-bottom:4px;">Notes</div>' +
                    '<ul style="margin:0 0 0 18px;font-size:12px;color:#ccc;">' +
                    packNotes.map(n => '<li style="margin-bottom:3px;">' + escapeHtml(n) + '</li>').join('') + '</ul></div>';
            }
            if (d.conflicts && d.conflicts.length) {
                html += '<div class="alert alert-error">Rule ID conflict with rules already installed: ' +
                    d.conflicts.slice(0, 10).map(c => escapeHtml(c.rule) + ' (' + escapeHtml(c.file) + ')').join(', ') + '</div>';
            }
            html += '<div style="overflow-x:auto;"><table class="data-table" style="width:100%;font-size:12px;">' +
                '<thead><tr><th style="text-align:left;padding:6px 10px;">Type</th>' +
                '<th style="text-align:left;padding:6px 10px;">File</th>' +
                '<th style="text-align:left;padding:6px 10px;">Installs to</th>' +
                '<th style="text-align:right;padding:6px 10px;">Size</th></tr></thead><tbody>' +
                (d.files || []).map(f =>
                    '<tr><td style="padding:6px 10px;">' + escapeHtml(f.type) + '</td>' +
                    '<td style="padding:6px 10px;font-family:monospace;">' + escapeHtml(f.name) + '</td>' +
                    '<td style="padding:6px 10px;font-family:monospace;color:#888;">' + escapeHtml(f.dest) + '</td>' +
                    '<td style="padding:6px 10px;text-align:right;">' + formatFileSize(f.size) + '</td></tr>').join('') +
                '</tbody></table></div>';
            body.innerHTML = html;
            const footer = document.getElementById('modalFooter');
            if (footer) {
                footer.innerHTML =
                    (d.installed
                        ? '<button class="btn btn-danger" onclick="closeModal();uninstallPack(\\'' + escapeHtml(packId) + '\\')"><svg class="icon"><use href="#icon-trash"/></svg>Remove</button>'
                        : '<button class="btn btn-success" onclick="closeModal();installPack(\\'' + escapeHtml(packId) + '\\')"><svg class="icon"><use href="#icon-download"/></svg>Install</button>') +
                    '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>';
            }
        }

        async function installPack(packId, force) {
            if (!force && !await showConfirm('Install pack "' + packId + '"? Files are backed up and rolled back if the ruleset fails to validate.')) return;
            showToast('Installing...', 'info');
            const result = await api('/packs/' + encodeURIComponent(packId) + '/install', 'POST', force ? { force: true } : {});
            if (!result || result.error) {
                if (result && result.conflicts) {
                    if (await showConfirm('Rule ID conflict: ' + result.conflicts.slice(0, 8).join(', ') +
                            '. Install anyway and overwrite?', true)) {
                        return installPack(packId, true);
                    }
                    return;
                }
                showToast((result && result.error) || 'Install failed', 'error', 8000);
                return;
            }
            showToast(result.message || 'Installed', 'success', 8000);
            refreshPacks();
        }

        async function uninstallPack(packId, force) {
            if (!force && !await showConfirm('Remove pack "' + packId + '"? Files it replaced are restored.', true)) return;
            const result = await api('/packs/' + encodeURIComponent(packId), 'DELETE', force ? { force: true } : {});
            if (!result || result.error) {
                if (result && result.modified) {
                    if (await showConfirm('These files were edited after installation: ' +
                            result.modified.join(', ') + '. Remove them anyway?', true)) {
                        return uninstallPack(packId, true);
                    }
                    return;
                }
                showToast((result && result.error) || 'Remove failed', 'error', 8000);
                return;
            }
            showToast(result.message || 'Removed', 'success', 8000);
            refreshPacks();
        }

        // ---------- Node daemon health ----------
        async function showDaemonStats(nodeName) {
            showModal('Health - ' + nodeName, '<div class="loading"><div class="spinner"></div>Loading...</div>',
                '<button class="btn" onclick="showDaemonStats(\\'' + nodeName + '\\')"><svg class="icon"><use href="#icon-refresh"/></svg>Refresh</button>' +
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
            const data = await api('/nodes/' + nodeName + '/daemon-stats');
            const body = document.getElementById('modalBody');
            if (!body) return;
            if (!data || data.error) {
                body.innerHTML = '<div class="alert alert-error">' + escapeHtml((data && data.error) || 'Failed to load') + '</div>';
                return;
            }
            const daemons = data.daemons || [];
            if (!daemons.length) {
                body.innerHTML = '<div style="color:#888;padding:20px;text-align:center;">No daemon statistics returned.</div>';
                return;
            }
            body.innerHTML = daemons.map(d => {
                const name = d.name || d.daemon || 'daemon';
                const metrics = d.metrics || d;
                return '<div style="background:#0a0a15;padding:15px;border-radius:4px;margin-bottom:12px;">' +
                    '<div style="color:#4fc3f7;margin-bottom:8px;">' + escapeHtml(name) + '</div>' +
                    '<pre style="margin:0;font-size:12px;max-height:40vh;overflow:auto;">' +
                    escapeHtml(JSON.stringify(metrics, null, 2)) + '</pre></div>';
            }).join('') +
            ((data.errors && data.errors.length) ?
                '<div class="alert alert-error">' + data.errors.map(e => escapeHtml(e)).join('<br>') + '</div>' : '');
        }

        // ---------- Group files ----------
        async function showGroupFiles(groupName) {
            showModal('Group Files - ' + groupName, '<div class="loading"><div class="spinner"></div>Loading...</div>',
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
            const data = await api('/groups/' + encodeURIComponent(groupName) + '/files');
            const body = document.getElementById('modalBody');
            if (!body) return;
            if (!data || data.error) {
                body.innerHTML = '<div class="alert alert-error">' + escapeHtml((data && data.error) || 'Failed to load') + '</div>';
                return;
            }
            const files = data.files || [];
            if (!files.length) {
                body.innerHTML = '<div style="color:#888;padding:20px;text-align:center;">This group has no files.</div>';
                return;
            }
            body.innerHTML = '<div style="overflow-x:auto;"><table class="data-table" style="width:100%;font-size:13px;">' +
                '<thead><tr><th style="text-align:left;padding:6px 10px;">File</th><th style="text-align:left;padding:6px 10px;">Hash</th><th style="width:90px;"></th></tr></thead><tbody>' +
                files.map(f => {
                    const fn = f.filename || '';
                    return '<tr><td style="padding:6px 10px;font-family:monospace;">' + escapeHtml(fn) + '</td>' +
                        '<td style="padding:6px 10px;color:#888;font-family:monospace;font-size:11px;">' + escapeHtml(f.hash || '') + '</td>' +
                        '<td style="padding:6px 10px;"><button class="btn btn-sm" onclick="showGroupFileContent(\\'' + escapeHtml(groupName) + '\\', \\'' + escapeHtml(fn) + '\\')">View</button></td></tr>';
                }).join('') + '</tbody></table></div>';
        }

        async function showGroupFileContent(groupName, filename) {
            const data = await api('/groups/' + encodeURIComponent(groupName) + '/files/' + encodeURIComponent(filename));
            if (!data || data.error) {
                showToast((data && data.error) || 'Failed to load the file', 'error');
                return;
            }
            showModal(filename + ' - ' + groupName,
                '<pre style="background:#0a0a15;padding:15px;border-radius:4px;font-size:12px;max-height:60vh;overflow:auto;"><code>' +
                highlightXml(escapeHtml(data.content || '')) + '</code></pre>',
                '<button class="btn" onclick="showGroupFiles(\\'' + escapeHtml(groupName) + '\\')"><svg class="icon"><use href="#icon-nav-arrow-up"/></svg>Back</button>' +
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>', true);
        }

        // ---------- Active response ----------
        const AR_PRESETS = [
            ['firewall-drop', 'Block an IP with the local firewall', true],
            ['restart-wazuh', 'Restart the Wazuh agent', false],
            ['host-deny', 'Add the IP to hosts.deny', true],
            ['disable-account', 'Disable a user account', true],
        ];

        function showActiveResponseModal() {
            const count = selectedAgents.size;
            if (!count) {
                showToast('Select at least one agent', 'warning');
                return;
            }
            const options = AR_PRESETS.map(([cmd, desc]) =>
                '<option value="' + cmd + '">' + cmd + ' - ' + desc + '</option>').join('');
            const body =
                '<div style="background:#1a1a2e;border-left:3px solid #00897b;padding:10px 15px;margin-bottom:15px;border-radius:4px;">' +
                '<p style="color:#aaa;font-size:12px;margin:0;">The command must be configured as an active response on the manager. A name starting with ! refers to a script.</p></div>' +
                '<p style="color:#aaa;margin-bottom:5px;">Target: ' + count + ' agent(s)</p>' +
                '<div style="margin-bottom:12px;">Command <select id="arCommand" style="margin-left:6px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;min-width:320px;">' +
                options + '<option value="__custom">Custom...</option></select></div>' +
                '<div style="margin-bottom:12px;">Custom command <input type="text" id="arCustom" placeholder="!my-script.sh" style="margin-left:6px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;width:260px;"></div>' +
                '<div>Arguments <input type="text" id="arArgs" placeholder="space separated, e.g. an IP" style="margin-left:6px;background:#0f3460;border:1px solid #1a3a6e;color:#eee;padding:6px 10px;border-radius:4px;width:320px;"></div>';
            showModal('Active Response', body,
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Cancel</button>' +
                '<button class="btn" style="background:#00897b;color:#fff;" onclick="runActiveResponse()"><svg class="icon"><use href="#icon-bell"/></svg>Send</button>');
        }

        async function runActiveResponse() {
            const picked = document.getElementById('arCommand').value;
            const custom = (document.getElementById('arCustom').value || '').trim();
            const command = picked === '__custom' ? custom : picked;
            const args = (document.getElementById('arArgs').value || '').trim();
            if (!command) {
                showToast('A command is required', 'warning');
                return;
            }
            const selectedList = Array.from(selectedAgents);
            const dryRun = document.getElementById('dryRunMode').checked;
            closeModal();
            if (!await showConfirm('Run "' + command + '" on ' + selectedList.length + ' agent(s)?', true)) return;
            const result = await api('/active-response', 'POST', {
                agent_ids: selectedList,
                command: command,
                arguments: args ? args.split(/\\s+/) : [],
                dry_run: dryRun
            });
            if (!result || result.error) {
                showToast((result && result.error) || 'Active response failed', 'error');
                return;
            }
            showToast(result.message || 'Command sent', result.fail_count ? 'warning' : 'success');
        }

        // ---------- Pre-register agents ----------
        function showRegisterAgentsModal() {
            showModal('Register Agents',
                '<p style="color:#888;font-size:12px;margin-bottom:10px;">One agent name per line. Each gets an ID and key you can use to enrol the machine later.</p>' +
                '<textarea id="registerNames" placeholder="web-01&#10;web-02" style="width:100%;height:150px;background:#0a0a15;color:#eee;border:1px solid #1a3a6e;border-radius:4px;padding:10px;font-family:monospace;font-size:12px;"></textarea>' +
                '<div id="registerResult" style="margin-top:12px;"></div>',
                '<button class="btn" onclick="closeModal()"><svg class="icon"><use href="#icon-xmark"/></svg>Close</button>' +
                '<button class="btn btn-success" onclick="runRegisterAgents()"><svg class="icon"><use href="#icon-add-group"/></svg>Register</button>', true);
        }

        async function runRegisterAgents() {
            const raw = (document.getElementById('registerNames').value || '').trim();
            const target = document.getElementById('registerResult');
            const names = raw.split(/\\r?\\n/).map(n => n.trim()).filter(n => n);
            if (!names.length) {
                target.innerHTML = '<div class="alert alert-error">Enter at least one name</div>';
                return;
            }
            target.innerHTML = '<div class="loading"><div class="spinner"></div>Registering...</div>';
            const result = await api('/agents/register', 'POST', { names: names });
            if (!result || result.error) {
                target.innerHTML = '<div class="alert alert-error">' + escapeHtml((result && result.error) || 'Registration failed') + '</div>';
                return;
            }
            const created = result.created || [], failed = result.failed || [];
            let html = '<div class="alert ' + (failed.length ? 'alert-error' : 'alert-success') + '">' + escapeHtml(result.message || '') + '</div>';
            if (created.length) {
                html += '<div style="overflow-x:auto;"><table class="data-table" style="width:100%;font-size:12px;">' +
                    '<thead><tr><th style="text-align:left;padding:6px;">ID</th><th style="text-align:left;padding:6px;">Name</th><th style="text-align:left;padding:6px;">Key</th></tr></thead><tbody>' +
                    created.map(c => '<tr><td style="padding:6px;">' + escapeHtml(c.id) + '</td><td style="padding:6px;">' + escapeHtml(c.name) +
                        '</td><td style="padding:6px;font-family:monospace;word-break:break-all;">' + escapeHtml(c.key) + '</td></tr>').join('') +
                    '</tbody></table></div>';
            }
            if (failed.length) {
                html += '<div style="margin-top:10px;color:#e94560;font-size:12px;">' +
                    failed.map(f => escapeHtml(f.name) + ': ' + escapeHtml(f.error)).join('<br>') + '</div>';
            }
            target.innerHTML = html;
            refreshAgents();
        }

        function showRuleParseErrors() {
            const rows = allRulesParseErrors.map(e =>
                '<tr><td style="padding:6px 10px;font-family:monospace;">' + escapeHtml(e.file) +
                '</td><td style="padding:6px 10px;color:#e94560;">' + escapeHtml(e.error) + '</td></tr>'
            ).join('');
            showModal('Rule Files That Could Not Be Parsed',
                '<p style="margin-bottom:12px;">These rule files contain XML the parser rejected, so their rules are ' +
                'not listed in this tab. This usually means the file itself is malformed &mdash; check it on the manager.</p>' +
                '<div style="overflow-x:auto;"><table class="data-table" style="width:100%;font-size:13px;">' +
                '<thead><tr><th style="text-align:left;padding:6px 10px;">File</th>' +
                '<th style="text-align:left;padding:6px 10px;">Error</th></tr></thead><tbody>' +
                rows + '</tbody></table></div>',
                '<button class="btn" onclick="closeModal()">Close</button>', true);
        }

        // Search the full XML body of every rule via the server (the table filter
        // above only sees id/level/description/file/groups).
        async function searchRulesContent() {
            const input = document.getElementById('rulesContentSearch');
            const q = (input.value || '').trim();
            const match = document.getElementById('rulesContentMatch').value;
            const tbody = document.getElementById('rulesAllBody');
            const status = document.getElementById('rulesAllStatus');
            if (!q) {
                showToast('Enter one or more keywords', 'error');
                input.focus();
                return;
            }
            tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;padding:30px;"><div class="loading"><div class="spinner"></div>Searching rule content...</div></td></tr>';
            try {
                const data = await api('/rules/search?q=' + encodeURIComponent(q) + '&match=' + encodeURIComponent(match));
                if (!data || data.error) {
                    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#e94560;padding:30px;">' + escapeHtml((data && data.error) || 'Search failed') + '</td></tr>';
                    return;
                }
                allRulesData = data.rules || [];
                allRulesLoaded = true;
                rulesContentQuery = (data.keywords || []).join(' ');
                populateRulesFileFilter();
                rulesCurrentPage = 1;
                renderAllRules();
                if (data.truncated) {
                    showToast('Too many matches, showing first ' + data.max_results, 'warning', 6000);
                }
            } catch (err) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#e94560;padding:30px;">Error: ' + escapeHtml(err.message) + '</td></tr>';
            }
        }

        function populateRulesFileFilter() {
            const fileFilter = document.getElementById('rulesFileFilter');
            const currentFile = fileFilter.value;
            const files = [...new Set(allRulesData.map(r => r.file).filter(f => f))].sort();
            fileFilter.innerHTML = '<option value="">All Files (' + files.length + ')</option>';
            files.forEach(f => {
                const opt = document.createElement('option');
                opt.value = f;
                opt.textContent = f;
                fileFilter.appendChild(opt);
            });
            if (currentFile && files.includes(currentFile)) fileFilter.value = currentFile;
        }

        function getFilteredRulesAll() {
            const search = (document.getElementById('rulesAllSearch').value || '').toLowerCase().trim();
            const levelMin = parseInt(document.getElementById('rulesLevelMin').value);
            const levelMax = parseInt(document.getElementById('rulesLevelMax').value);
            const fileFilter = document.getElementById('rulesFileFilter').value;
            const typeFilter = document.getElementById('rulesTypeFilter').value;

            return allRulesData.filter(r => {
                if (search) {
                    const fields = [r.id, String(r.level), r.description || '', r.file || '', r.group || ''].join(' ').toLowerCase();
                    if (!fields.includes(search)) return false;
                }
                if (!isNaN(levelMin) && r.level < levelMin) return false;
                if (!isNaN(levelMax) && r.level > levelMax) return false;
                if (fileFilter && r.file !== fileFilter) return false;
                if (typeFilter === 'custom' && !r.is_custom) return false;
                if (typeFilter === 'builtin' && r.is_custom) return false;
                return true;
            });
        }

        function renderAllRules() {
            const tbody = document.getElementById('rulesAllBody');
            if (!allRulesLoaded) return;

            let filtered = getFilteredRulesAll();

            // Sort
            const col = rulesSortColumn;
            const dir = rulesSortDirection === 'asc' ? 1 : -1;
            filtered.sort((a, b) => {
                let va, vb;
                if (col === 'id') {
                    va = parseInt(a.id) || 0;
                    vb = parseInt(b.id) || 0;
                    return (va - vb) * dir;
                } else if (col === 'level') {
                    return (a.level - b.level) * dir;
                } else {
                    va = (a[col] || '').toLowerCase();
                    vb = (b[col] || '').toLowerCase();
                    return va < vb ? -dir : va > vb ? dir : 0;
                }
            });

            // Paginate
            const total = filtered.length;
            rulesTotalPagesNum = Math.max(1, Math.ceil(total / rulesPageSize));
            if (rulesCurrentPage > rulesTotalPagesNum) rulesCurrentPage = rulesTotalPagesNum;
            const start = (rulesCurrentPage - 1) * rulesPageSize;
            const pageData = filtered.slice(start, start + rulesPageSize);

            // Update sort indicators
            document.querySelectorAll('#rulesAllTable th.sortable').forEach(th => {
                th.classList.remove('asc', 'desc');
            });
            const sortIdx = {'id':0,'level':1,'description':2,'group':3,'file':4}[rulesSortColumn];
            if (sortIdx !== undefined) {
                const th = document.querySelectorAll('#rulesAllTable th.sortable')[sortIdx];
                if (th) th.classList.add(rulesSortDirection);
            }

            if (pageData.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:#888;padding:30px;">No rules match the current filters.</td></tr>';
            } else {
                let html = '';
                for (const r of pageData) {
                    const levelClass = r.level === 0 ? 'zero' : (r.level >= 12 ? 'high' : (r.level >= 6 ? 'medium' : 'low'));
                    const typeClass = r.is_custom ? 'custom' : 'builtin';
                    const typeLabel = r.is_custom ? 'Custom' : 'Built-in';
                    const groups = (r.group || '').split(',').map(g => g.trim()).filter(g => g);
                    let groupsHtml = '';
                    if (groups.length > 0) {
                        const showGroups = groups.slice(0, 4);
                        groupsHtml = '<div class="rules-group-tags">' + showGroups.map(g => '<span class="rules-group-tag">' + escapeHtml(g) + '</span>').join('');
                        if (groups.length > 4) groupsHtml += '<span class="rules-group-tag" style="background:#333;color:#888;">+' + (groups.length - 4) + '</span>';
                        groupsHtml += '</div>';
                    }
                    const fileClass = r.is_custom ? ' style="color:#f39c12;"' : '';
                    html += '<tr>' +
                        '<td><a class="rule-id-link" onclick="browseToRuleHierarchy(\\'' + escapeHtml(r.id) + '\\')">' + escapeHtml(r.id) + '</a></td>' +
                        '<td><span class="rule-level ' + levelClass + '">' + r.level + '</span></td>' +
                        '<td style="max-width:400px;" title="' + escapeHtml(r.description || '') + '"><div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + escapeHtml(r.description || '') + '</div>' +
                            (r.snippet ? '<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#888;font-size:11px;font-family:monospace;margin-top:2px;" title="' + escapeHtml(r.snippet) + '">' + escapeHtml(r.snippet) + '</div>' : '') + '</td>' +
                        '<td>' + groupsHtml + '</td>' +
                        '<td' + fileClass + '>' + escapeHtml(r.file || '') + '</td>' +
                        '<td><span class="rule-type-badge ' + typeClass + '">' + typeLabel + '</span></td>' +
                        '</tr>';
                }
                tbody.innerHTML = html;
            }

            // Update pagination
            const endIdx = Math.min(start + rulesPageSize, total);
            document.getElementById('rulesPaginationInfo').textContent = total > 0 ? (start + 1) + '-' + endIdx + ' of ' + total : '0 rules';
            document.getElementById('rulesPageInput').value = rulesCurrentPage;
            document.getElementById('rulesPageInput').max = rulesTotalPagesNum;
            document.getElementById('rulesTotalPages').textContent = rulesTotalPagesNum;
            document.getElementById('rulesAllStatus').textContent =
                rulesContentQuery ? total + ' matched: ' + rulesContentQuery
                                  : total + ' / ' + allRulesData.length + ' rules';
        }

        function sortAllRules(column) {
            if (rulesSortColumn === column) {
                rulesSortDirection = rulesSortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                rulesSortColumn = column;
                rulesSortDirection = 'asc';
            }
            renderAllRules();
        }

        function rulesGoToPage(page) {
            rulesCurrentPage = Math.max(1, Math.min(page || 1, rulesTotalPagesNum));
            renderAllRules();
        }
        function rulesPrevPage() { rulesGoToPage(rulesCurrentPage - 1); }
        function rulesNextPage() { rulesGoToPage(rulesCurrentPage + 1); }
        function rulesChangePageSize(size) {
            rulesPageSize = size;
            rulesCurrentPage = 1;
            renderAllRules();
        }

        function filterAllRulesDebounced() {
            clearTimeout(_rulesFilterTimer);
            _rulesFilterTimer = setTimeout(() => {
                rulesCurrentPage = 1;
                renderAllRules();
            }, 300);
        }

        function browseToRuleHierarchy(ruleId) {
            switchRulesMode('hierarchy');
            document.getElementById('ruleIdSearch').value = ruleId;
            searchRuleHierarchy();
        }

        // Export functions
        function toggleExportMenu() {
            const menu = document.getElementById('exportMenu');
            menu.classList.toggle('show');
        }

        function getFilteredAgents() {
            const search = document.getElementById('agentSearch').value.toLowerCase();
            const statusValues = getFilterValues('statusFilter');
            const groupValues = getFilterValues('groupFilter');
            const osValues = getFilterValues('osFilter');
            const versionValues = getFilterValues('versionFilter');
            const nodeValues = getFilterValues('nodeFilter');

            return agents.filter(a => {
                if (search) {
                    const searchFields = [
                        a.id, a.name, a.ip, a.status, a.os, a.version, a.group, a.node_name
                    ].map(f => (f || '').toLowerCase());
                    if (!searchFields.some(f => f.includes(search))) return false;
                }
                if (statusValues.length > 0 && !statusValues.includes(a.status.toLowerCase().replace(' ', '_'))) return false;
                if (groupValues.length > 0) {
                    const agentGroups = (a.group || '').split(',').map(g => g.trim()).filter(g => g);
                    // Handle "(no group)" filter
                    const hasNoGroup = !a.group || a.group.trim() === '';
                    const matchesNoGroup = groupValues.includes('(no group)') && hasNoGroup;
                    const matchesGroup = groupValues.some(g => g !== '(no group)' && agentGroups.includes(g));
                    if (!matchesNoGroup && !matchesGroup) return false;
                }
                if (osValues.length > 0 && !osValues.includes(a.os || '')) return false;
                if (versionValues.length > 0 && !versionValues.includes(a.version || '')) return false;
                if (nodeValues.length > 0 && !nodeValues.includes(a.node_name || '')) return false;
                return true;
            });
        }

        function exportData(format) {
            document.getElementById('exportMenu').classList.remove('show');

            const filtered = getFilteredAgents();
            if (filtered.length === 0) {
                showToast('No data to export', 'warning');
                return;
            }

            const columns = ['id', 'name', 'ip', 'status', 'os', 'version', 'group', 'node_name', 'synced'];
            const headers = ['ID', 'Name', 'IP', 'Status', 'OS', 'Version', 'Group', 'Node', 'Sync'];
            let content, filename, mimeType;

            if (format === 'json') {
                const exportData = filtered.map(a => {
                    const obj = {};
                    columns.forEach((col, i) => obj[headers[i]] = a[col] || '');
                    return obj;
                });
                content = JSON.stringify(exportData, null, 2);
                filename = 'agents.json';
                mimeType = 'application/json';
            } else {
                const separator = format === 'tsv' ? String.fromCharCode(9) : ',';
                const rows = [headers.join(separator)];
                filtered.forEach(a => {
                    const row = columns.map(col => {
                        let val = a[col] || '';
                        // Escape quotes and wrap in quotes if contains separator or quotes
                        if (format === 'csv' && (val.includes(',') || val.includes('"') || val.includes(String.fromCharCode(10)))) {
                            val = '"' + val.replace(/"/g, '""') + '"';
                        }
                        return val;
                    });
                    rows.push(row.join(separator));
                });
                content = rows.join(String.fromCharCode(10));
                filename = format === 'tsv' ? 'agents.tsv' : 'agents.csv';
                mimeType = format === 'tsv' ? 'text/tab-separated-values' : 'text/csv';
            }

            // Download file
            const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);

            showToast(`Exported ${filtered.length} agents to ${filename}`, 'success');
        }

        function showGroupAgents(groupName) {
            // Clear search field
            document.getElementById('agentSearch').value = '';
            // Clear all filters first
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(filterId => {
                const dropdown = document.getElementById(filterId + 'Dropdown');
                if (dropdown) {
                    dropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => cb.checked = false);
                }
            });
            // Set the group filter - find checkbox by iterating (avoid template literal in querySelector)
            const groupDropdown = document.getElementById('groupFilterDropdown');
            let found = false;
            if (groupDropdown) {
                groupDropdown.querySelectorAll('input[type="checkbox"]').forEach(cb => {
                    if (cb.value === groupName) {
                        cb.checked = true;
                        found = true;
                    }
                });
            }
            // If group not in dropdown (e.g., has 0 agents), add it temporarily
            if (!found && groupDropdown) {
                const item = document.createElement('div');
                item.className = 'multi-select-item';
                item.innerHTML = '<input type="checkbox" value="' + groupName + '" onchange="onFilterChange()" checked><span class="multi-select-item-text">' + groupName + '</span>';
                item.onclick = function(e) { toggleCheckbox(this, e); };
                groupDropdown.insertBefore(item, groupDropdown.firstChild);
            }
            ['statusFilter', 'groupFilter', 'osFilter', 'versionFilter', 'nodeFilter', 'syncFilter'].forEach(updateFilterButton);
            document.querySelector('[data-tab="agents"]').click();
            currentPage = 1;
            renderAgents();
        }

        // Event listeners
        document.getElementById('agentSearch').addEventListener('input', () => {
            currentPage = 1;  // Reset to first page on search
            renderAgents();
        });

        // Initial load
        initColumnVisibility();
        refreshAgents();
        refreshGroups();

        // Auto-refresh stats every 10 seconds (only stats, not the table)
        setInterval(async () => {
            try {
                const data = await api('/stats/summary');
                if (data && data.summary && !data.summary.error) {
                    const s = data.summary;
                    // Only update if we have valid data (total_agents should be a positive number)
                    const total = s.total_agents;
                    if (typeof total === 'number' && total > 0) {
                        updateStatValue('totalAgents', total);
                        updateStatValue('activeAgents', s.status_breakdown?.Active || 0);
                        updateStatValue('disconnectedAgents', s.status_breakdown?.Disconnected || 0);
                        updateStatValue('pendingAgents', s.status_breakdown?.Pending || 0);
                    }
                }
            } catch (e) { /* ignore */ }
        }, 10000);
    </script>
</body>
</html>
'''

# === BEGIN i18n auto-embed (generated by tools/build_i18n.py) ===
_I18N_SCRIPT = r"""
<script>
/* ==========================================================================
 * JT Wazuh Manager - Client-side i18n engine
 * Source language is English (as authored in the templates). When the user
 * selects Traditional Chinese (zh-TW), visible text nodes and selected
 * attributes are translated in place using the I18N dictionary below.
 *
 * Design notes:
 *  - Only TEXT NODES and the placeholder/title attributes are translated.
 *    Element `value` attributes and <option value="..."> are never touched,
 *    so form/logic values stay in English.
 *  - Switching language reloads the page so reverting to English is exact
 *    (the server always emits English; we re-translate on load if needed).
 *  - A MutationObserver re-translates content rendered dynamically by the
 *    app's JavaScript (tables, modals, toasts) while in zh-TW mode.
 *  - Strings with interpolated values are handled by I18N_PATTERNS (regex).
 * ======================================================================== */
(function () {
  'use strict';

  var I18N = {
    'zh-TW': {
      // --- App / header / nav ---
      // NOTE: the product name "JT Wazuh Manager" is intentionally NOT translated.
      'Login with your Wazuh credentials': '請使用您的 Wazuh 帳號登入',
      'Wazuh API Username': 'Wazuh API 使用者名稱',
      'Username': '使用者名稱',
      'Password': '密碼',
      'Login': '登入',
      'Logout': '登出',
      'Settings': '設定',
      'API Host': 'API 主機',
      'API Port': 'API 連接埠',
      'API Connected': 'API 已連線',
      'Connection Lost': '連線中斷',
      'API: ': 'API：',
      // --- Tabs ---
      'Agents': '代理程式',
      'Groups': '群組',
      'Nodes': '節點',
      'Rules': '規則',
      'Statistics': '統計',
      'API Users': 'API 使用者',
      'Logs': '記錄',
      // --- Stat bar ---
      'Total Agents': '代理程式總數',
      'Active': '已連線',
      'Disconnected': '已離線',
      'Pending': '等待中',
      'Never Connected': '從未連線',
      'Show all agents': '顯示所有代理程式',
      'Show active agents': '顯示已連線代理程式',
      'Show disconnected agents': '顯示已離線代理程式',
      'Show pending agents': '顯示等待中代理程式',
      // --- Agent toolbar / actions ---
      'Search agents...': '搜尋代理程式…',
      'Search rules...': '搜尋規則…',
      'Search': '搜尋',
      'Clear': '清除',
      'Refresh': '重新整理',
      'Refresh agent list': '重新整理代理程式列表',
      'Refresh content': '重新整理內容',
      'Show/Hide Columns': '顯示/隱藏欄位',
      'Export to file': '匯出為檔案',
      'View upgrade progress': '檢視升級進度',
      'Add to Group': '加入群組',
      'Remove from Group': '從群組移除',
      'Move to Node': '移動到節點',
      'Restart': '重新啟動',
      'Reconnect': '重新連線',
      'Upgrade': '升級',
      'Clean Queue DB': '清除 Queue DB',
      'Delete': '刪除',
      'Agent Actions': '代理程式操作',
      'Group Actions': '群組操作',
      'Dry Run': '模擬執行',
      'Preview changes without executing': '預覽變更但不實際執行',
      'Show Queue DB column (loads from filesystem)': '顯示 Queue DB 欄位（由檔案系統載入）',
      'Queue DB': 'Queue DB',
      // --- Table headers ---
      'Actions': '操作',
      'ID': 'ID',
      'Name': '名稱',
      'IP': 'IP',
      'Status': '狀態',
      'Group': '群組',
      'Node': '節點',
      'OS': '作業系統',
      'Version': '版本',
      'Type': '類型',
      'Description': '說明',
      'Level': '等級',
      'Level:': '等級：',
      'File': '檔案',
      'Roles': '角色',
      'Agent Count': '代理程式數量',
      'Group Name': '群組名稱',
      'Rule ID': '規則 ID',
      'Selected:': '已選取：',
      'Allow Run As': '允許 Run As',
      // --- Pagination ---
      'Per page:': '每頁筆數：',
      'Page': '頁',
      'of': '/',
      'First': '第一頁',
      'Last': '最後一頁',
      '‹ Prev': '‹ 上一頁',
      'Next ›': '下一頁 ›',
      '«': '«',
      '»': '»',
      '50/page': '50 筆/頁',
      '100/page': '100 筆/頁',
      '200/page': '200 筆/頁',
      '500/page': '500 筆/頁',
      'Showing 0 - 0 of 0': '顯示 0 - 0，共 0 筆',
      // --- Filters / selects ---
      'All Types': '所有類型',
      'All Files': '所有檔案',
      'All Rules': '所有規則',
      'Min': '最小',
      'Max': '最大',
      // --- Groups panel ---
      'Create Group': '建立群組',
      'Create User': '建立使用者',
      // --- Rules panel ---
      'Hierarchy': '階層',
      'Expand': '展開',
      'Collapse': '收合',
      'Expand All': '全部展開',
      'Collapse All': '全部收合',
      'Add Rule': '新增規則',
      'No rule file matched': '沒有符合的規則檔',
      'rules': '條規則',
      'Rule ID (100001) or file name (zenarmor, adguard-rule.xml)': '規則 ID（100001）或檔名（zenarmor、adguard-rule.xml）',
      'Click "All Rules" to load all rules.': '點選「所有規則」載入全部規則。',
      'Enter a Rule ID to view its hierarchy and relationships, or a rule file name to list its rules.': '輸入規則 ID 以檢視其階層與關聯，或輸入規則檔名以列出該檔的所有規則。',
      'The tree will show parent rules (if_sid, if_matched_sid) and child rules.': '樹狀圖會顯示父規則（if_sid、if_matched_sid）與子規則。',
      // --- Nodes panel ---
      'Services': '服務',
      'Sync': '同步',
      'Sync Status': '同步狀態',
      // --- Logs panel ---
      'Click Refresh to load logs...': '點選重新整理以載入記錄…',
      'Download Full Log': '下載完整記錄',
      'Last 50 lines': '最後 50 行',
      'Last 100 lines': '最後 100 行',
      'Last 200 lines': '最後 200 行',
      'Last 500 lines': '最後 500 行',
      'Last 1000 lines': '最後 1000 行',
      'Log file:': '記錄檔：',
      // --- Export formats ---
      'CSV': 'CSV',
      'JSON': 'JSON',
      'TSV': 'TSV',
      // --- Misc / footer ---
      'Session expired': 'Session 已過期',
      'Built-in': '內建',
      'Custom': '自訂',
      'by': '製作：',
      // (login "Session expires after N minutes" is handled by I18N_PATTERNS)
      // --- JS messages (dynamic, static text portion) ---
      'Loading...': '載入中…',
      'Loading': '載入中',
      'Loading config...': '載入設定中…',
      'Loading email alerts...': '載入電子郵件警示中…',
      'Restarting': '重新啟動中',
      'Restarting...': '重新啟動中…',
      'Services restarting...': '服務重新啟動中…',
      'Services starting...': '服務啟動中…',
      'Waiting for services...': '等待服務中…',
      'Importing agents...': '匯入代理程式中…',
      'Analyzing CSV data...': '分析 CSV 資料中…',
      'Config cannot be empty': '設定不可為空',
      'Config saved! Remember to restart services.': '設定已儲存！記得重新啟動服務。',
      'Group config saved!': '群組設定已儲存！',
      'Edit cancelled': '已取消編輯',
      'Edit mode enabled': '已啟用編輯模式',
      'Email alert rule deleted': '電子郵件警示規則已刪除',
      'Email alert rule saved! Remember to restart services for changes to take effect.': '電子郵件警示規則已儲存！請重新啟動服務以使變更生效。',
      'Download Failed': '下載失敗',
      'Download failed': '下載失敗',
      'Downloaded': '已下載',
      'Download ossec.conf': '下載 ossec.conf',
      'Exported': '已匯出',
      'Failed': '失敗',
      'Failed to load': '載入失敗',
      'Failed to load config': '載入設定失敗',
      'Failed to load email alerts': '載入電子郵件警示失敗',
      'Failed to delete': '刪除失敗',
      'Failed to analyze CSV': '分析 CSV 失敗',
      'Failed to restart services': '重新啟動服務失敗',
      'Reconnect command sent': '已送出重新連線指令',
      'Restart command sent. Node may still be starting up.': '已送出重新啟動指令，節點可能仍在啟動中。',
      'No agents were added': '未加入任何代理程式',
      'No data to import': '沒有可匯入的資料',
      'No valid data rows found in CSV': 'CSV 中找不到有效的資料列',
      'No worker nodes to sync': '沒有可同步的 Worker 節點',
      'Please select a CSV file': '請選擇一個 CSV 檔案',
      'CSV file is empty or has no data rows': 'CSV 檔案為空或沒有資料列',
      'CSV must have at least one of: ID, Name/Hostname, IP/Address columns': 'CSV 至少需包含其中一欄：ID、Name/Hostname、IP/Address',
      'Sync current email alerts config to all worker nodes': '將目前的電子郵件警示設定同步到所有 Worker 節點',
      'Error': '錯誤',
      'Confirm': '確認',
      'Cancel': '取消',
      'Close': '關閉',
      'Save': '儲存',
      'Edit': '編輯',
      'Yes': '是',
      'No': '否',
      'OK': '確定',
      // --- more dynamic toasts / dialogs ---
      'Connection restored': '連線已恢復',
      'Copied to clipboard': '已複製到剪貼簿',
      'Failed to copy to clipboard': '複製到剪貼簿失敗',
      'Deleting...': '刪除中…',
      'Refreshing...': '重新整理中…',
      'Syncing...': '同步中…',
      'Renaming group...': '重新命名群組中…',
      'Loading agent.conf...': '載入 agent.conf 中…',
      'Loading...': '載入中…',
      'Invalid JSON': 'JSON 格式無效',
      'New name is the same as current name': '新名稱與目前名稱相同',
      'No agents in this group': '此群組沒有代理程式',
      'No data to export': '沒有可匯出的資料',
      'Only .wpk files are allowed': '僅允許 .wpk 檔案',
      'Password is required': '密碼為必填',
      'Username is required': '使用者名稱為必填',
      'Group name is required': '群組名稱為必填',
      // --- Upgrade modal / progress ---
      'Upgrade Agents': '升級代理程式',
      'Upgrade will update agents to the latest available version from Wazuh repository. Make sure the manager has internet access or the WPK files are available locally.': '升級會將代理程式更新為 Wazuh 套件庫中最新的可用版本。請確認 Manager 可連上網際網路，或 WPK 檔案已存放於本機。',
      'Upgrade to manager version': '升級至 Manager 版本',
      'Upgrade Failed': '升級失敗',
      'Updated': '已更新',
      'Updating': '更新中',
      'Downloading': '下載中',
      'In progress': '進行中',
      'In Progress': '進行中',
      'Legacy': '舊版',
      // --- Modal titles ---
      'Add Agents to Group': '將代理程式加入群組',
      'Remove Agents from Group': '從群組移除代理程式',
      'Move Agents to Another Group': '將代理程式移至其他群組',
      'Move Agents to Node': '將代理程式移至節點',
      'Clean Queue DB Results': '清除 Queue DB 結果',
      'Copied!': '已複製！',
      'This will delete the queue DB files and restart the agents.': '這會刪除 queue DB 檔案並重新啟動代理程式。',
      'This cannot be undone!': '此動作無法復原！',
      'DRY-RUN': '模擬執行',
      // --- v1.5 features: inventory, decoders, CDB lists, logtest, AR, enrolment ---
      'Inventory': '資產清單',
      'Packages': '套件',
      'Open Ports': '開放連接埠',
      'Processes': '處理程序',
      'Services': '服務',
      'Local Users': '本機使用者',
      'Hotfixes': '修補程式',
      'Network Interfaces': '網路介面',
      'Operating System': '作業系統',
      'Browser Extensions': '瀏覽器擴充功能',
      'Search across agents...': '跨代理程式搜尋…',
      'Active agents': '已連線的代理程式',
      'All agents': '所有代理程式',
      'Selected agents': '已選取的代理程式',
      'Export results as CSV': '將結果匯出為 CSV',
      'Pick a category and search to see which agents match.': '選擇類別並搜尋，即可看到符合的代理程式。',
      'Press Search to query this category.': '按「搜尋」查詢此類別。',
      'Querying agents...': '查詢代理程式中…',
      'No agent matched.': '沒有代理程式符合。',
      'Nothing to export': '沒有可匯出的內容',
      'No agents selected on the Agents tab': '「代理程式」分頁中沒有選取任何項目',
      'Decoders': '解碼器',
      'Search decoders...': '搜尋解碼器…',
      'Loading decoders...': '載入解碼器中…',
      'No decoders match.': '沒有符合的解碼器。',
      'Click Decoders to load.': '點擊「解碼器」載入。',
      'Position': '順序',
      'Parent': '父項',
      'CDB Lists': 'CDB 清單',
      'New List': '新增清單',
      'New CDB List': '新增 CDB 清單',
      'Loading lists...': '載入清單中…',
      'No CDB lists found.': '找不到任何 CDB 清單。',
      'Click CDB Lists to load.': '點擊「CDB 清單」載入。',
      'A list name is required': '請輸入清單名稱',
      'List': '清單',
      'Path': '路徑',
      'Hash': '雜湊值',
      'Log Test': '記錄測試',
      'Run Test': '執行測試',
      'Testing...': '測試中…',
      'Location': '來源位置',
      'Paste one log line here': '在此貼上一行記錄',
      'Paste a log line first': '請先貼上一行記錄',
      'Paste a log line and see which rule and decoder match it.': '貼上一行記錄，查看命中的規則與解碼器。',
      'Matched rule': '命中規則',
      'No rule matched this log line.': '沒有規則命中這行記錄。',
      'Extracted fields': '擷取到的欄位',
      'Messages': '訊息',
      'Validate': '驗證',
      'Validating...': '驗證中…',
      'Configuration is valid': '設定有效',
      'Configuration is invalid': '設定無效',
      'Check the config before restarting': '重新啟動前先檢查設定',
      'Reload Ruleset': '重新載入規則集',
      'Config Diff': '設定差異',
      // --- Rule packs ---
      'Rule Packs': '規則套件',
      'Pack Details': '套件詳細資訊',
      'Rule series maintained by Jason Tools. Each pack bundles rules, decoders and CDB lists, and can be removed again.': 'Jason Tools 維護的規則系列。每個套件包含規則、解碼器與 CDB 清單，安裝後可隨時移除。',
      'Pack': '套件',
      'Rule IDs': '規則 ID',
      'Installs to': '安裝位置',
      'Installed': '已安裝',
      'Not installed': '未安裝',
      'Install': '安裝',
      'Remove': '移除',
      'Details': '詳細資訊',
      'Notes': '注意事項',
      'Installing...': '安裝中…',
      'Install failed': '安裝失敗',
      'Remove failed': '移除失敗',
      'Failed to load packs': '載入套件失敗',
      'No packs available.': '沒有可用的套件。',
      'Version': '版本',
      'Status': '狀態',
      'Actions': '操作',
      'Node Config Diff': '節點設定差異',
      "Compare each node's ossec.conf against the master": '比對各節點的 ossec.conf 與 master 的差異',
      'Comparing nodes...': '比對節點中…',
      'Failed to compare': '比對失敗',
      'All nodes match the master in the sections that affect detection.': '所有節點在影響偵測的區段上都與 master 一致。',
      'Missing on this node (present on master):': '此節點缺少（master 上有）：',
      'Only on this node:': '僅此節點有：',
      'Apply rule changes on every cluster node without restarting': '套用規則變更到叢集所有節點, 不需重新啟動',
      'Reload the ruleset on every cluster node? Running services are not restarted.': '要在叢集所有節點重新載入規則集嗎？執行中的服務不會重新啟動。',
      'Reloading ruleset...': '重新載入規則集中…',
      'Reload failed': '重新載入失敗',
      'Node': '節點',
      'Result': '結果',
      'Warnings': '警告',
      'reloaded': '已重新載入',
      'failed': '失敗',
      'Reload the ruleset without restarting': '重新載入規則集而不重新啟動服務',
      'WPK file on the manager:': 'Manager 上的 WPK 檔案：',
      'Use this when the manager has no internet access.': '當 Manager 無法連上網際網路時使用。',
      'No WPK files uploaded': '尚未上傳 WPK 檔案',
      'No node available': '沒有可用的節點',
      'Please select a WPK file': '請選擇 WPK 檔案',
      'Running Config': '生效中的設定',
      'Configuration the agent is actually running': '代理程式實際套用的設定',
      'This section is not configured on the agent.': '代理程式上沒有設定此區段。',
      'The agent must be active for this to work.': '代理程式必須在連線狀態才能使用此功能。',
      'Agent Key': '代理程式金鑰',
      'Enrollment key for re-registering this agent': '用於重新註冊此代理程式的金鑰',
      'Health': '健康狀態',
      'analysisd / remoted queue counters': 'analysisd / remoted 佇列計數',
      'No daemon statistics returned.': '沒有回傳任何 daemon 統計資訊。',
      'Files': '檔案',
      'This group has no files.': '此群組沒有檔案。',
      'Back': '返回',
      'Active Response': '主動回應',
      'Command': '指令',
      'Custom command': '自訂指令',
      'Custom...': '自訂…',
      'Arguments': '參數',
      'Send': '傳送',
      'A command is required': '請輸入指令',
      'Select at least one agent': '請至少選取一個代理程式',
      'The command must be configured as an active response on the manager. A name starting with ! refers to a script.': '該指令必須已在 Manager 上設定為主動回應。名稱開頭為 ! 代表指令碼。',
      'space separated, e.g. an IP': '以空白分隔，例如 IP',
      'Register': '註冊',
      'Register Agents': '註冊代理程式',
      'Registering...': '註冊中…',
      'Pre-register agents and get their keys': '預先註冊代理程式並取得金鑰',
      'Enter at least one name': '請至少輸入一個名稱',
      'One agent name per line. Each gets an ID and key you can use to enrol the machine later.': '每行一個代理程式名稱。每個都會取得可供日後註冊該台機器的 ID 與金鑰。',
      'Result': '結果',
      'Key': '金鑰',
      // --- Batch selection / rule content search ---
      'Exit Selection': '離開選取',
      'Clear selection': '清除選取',
      'Search rule content...': '搜尋規則內容…',
      'Keyword mode': '關鍵字模式',
      'Match all': '全部符合',
      'Match any': '任一符合',
      'Content': '內容',
      "Search inside every rule's XML": '搜尋每條規則的 XML 內容',
      'Searching rule content...': '搜尋規則內容中…',
      'Enter one or more keywords': '請輸入一個以上的關鍵字',
      'Search failed': '搜尋失敗',
      'Are you sure you want to delete this rule?': '確定要刪除這條規則嗎？',
      'Sync current email alerts config to the following worker nodes?': '要將目前的電子郵件警示設定同步到下列 Worker 節點嗎？',
      'Force all agents on this node to reconnect': '強制此節點上的所有代理程式重新連線',
      'Restart Wazuh Manager services on this node': '重新啟動此節點上的 Wazuh Manager 服務',
      'SSH is required for remote node config editing and service management.': '遠端編輯節點設定與管理服務需要 SSH。',
      'This feature will allow you to force agents to reconnect to a specific cluster node.': '此功能可讓你強制代理程式重新連線到指定的叢集節點。',
      'Will integrate with HAProxy LB to route agents to designated nodes.': '將整合 HAProxy 負載平衡，把代理程式導向指定節點。',
      'Must contain: uppercase, lowercase, number, special char, min 8 chars': '必須包含：大寫、小寫、數字、特殊字元，且至少 8 個字元',
      'Rule Files That Could Not Be Parsed': '無法解析的規則檔',
      'Click for details': '點擊查看詳細資訊',
      'File': '檔案',
      'Error': '錯誤',
      'These rule files contain XML the parser rejected, so their rules are not listed in this tab. This usually means the file itself is malformed — check it on the manager.': '這些規則檔內含解析器無法讀取的 XML，因此其規則不會顯示在此分頁。通常代表該檔案本身格式有誤，請至 Manager 上檢查。',
      'Invalid group name': '群組名稱格式無效',
      'agent_ids is required and must be a non-empty list': '必須提供 agent_ids，且不可為空清單',
      'Password must contain: uppercase, lowercase, number, special char, min 8 chars': '密碼必須包含：大寫、小寫、數字、特殊字元，且至少 8 個字元',
      'Please enter a group name': '請輸入群組名稱',
      'Please enter a new group name': '請輸入新的群組名稱',
      'Enter a rule ID, or part of a rule file name': '請輸入規則 ID，或規則檔名的一部分',
      'Please enter a version number': '請輸入版本號',
      'Please select a target group': '請選擇目標群組',
      'Template downloaded': '範本已下載',
      'Upgrade history cleared': '升級記錄已清除',
      'Session expired. Redirecting to login...': 'Session 已過期，正在導向登入頁…',
      'This feature is still under development': '此功能仍在開發中',
      'Under Development': '開發中',
      // --- modal titles / section headings ---
      'About': '關於',
      'API Connection': 'API 連線',
      'SSH Configuration': 'SSH 設定',
      'Step 1: Generate SSH Key on Master Node': '步驟 1：在 Master 節點產生 SSH 金鑰',
      'Step 2: Copy Public Key to Worker Node': '步驟 2：複製公鑰到 Worker 節點',
      'Step 3: Test SSH Connection': '步驟 3：測試 SSH 連線',
      'Step 4: Configure This Tool': '步驟 4：設定本工具',
      // --- group action buttons ---
      'Import CSV': '匯入 CSV',
      'Export CSV': '匯出 CSV',
      'Download CSV Template': '下載 CSV 範本',
      'Move Agents': '移動代理程式',
      'Only This': '僅保留此群組',
      'Remove All': '全部移除',
      'Rename': '重新命名',
      'Select Group': '選擇群組',
      'Enter group name': '輸入群組名稱',
      'Enter new group name': '輸入新群組名稱',
      'Current Name': '目前名稱',
      'New Name': '新名稱',
      // --- node / WPK / config buttons ---
      'Download': '下載',
      'Upload WPK': '上傳 WPK',
      'Official WPK List': '官方 WPK 清單',
      'WPK Files': 'WPK 檔案',
      'WPK File Required': '需要 WPK 檔案',
      'Upgrade Files': '升級檔案',
      'Upgrade Options': '升級選項',
      'Upgrade Progress': '升級進度',
      'Email Alerts': '電子郵件警示',
      'Edit Roles': '編輯角色',
      'View': '檢視',
      'View Details': '檢視詳細',
      'Create': '建立',
      'Copy': '複製',
      'Copy to clipboard': '複製到剪貼簿',
      'Move': '移動',
      'Redo': '重做',
      'Undo': '復原',
      'Wrap': '自動換行',
      'Retry': '重試',
      'Clear history': '清除記錄',
      'Setup Guide': '設定指南',
      'Sync to All Workers': '同步到所有 Worker',
      'Go to Node Management': '前往節點管理',
      'Expand JSON': '展開 JSON',
      'Collapse JSON': '收合 JSON',
      'Preview': '預覽',
      'Format': '格式化',
      'View this rule': '檢視此規則',
      // --- table headers / field labels ---
      'Filename': '檔案名稱',
      'Platform': '平台',
      'Size': '大小',
      'Size:': '大小：',
      'Del': '刪除',
      'Author': '作者',
      'Time': '時間',
      'Format ': '格式',
      'Event Location': '事件位置',
      'Last Keep Alive': '最後連線時間',
      'Registration Date': '註冊日期',
      'OS Architecture': '作業系統架構',
      'Queue DB Size': 'Queue DB 大小',
      'Recipient': '收件者',
      'Recipient Email *': '收件者電子郵件 *',
      'Min Level': '最低等級',
      'Host': '主機',
      'Port': '連接埠',
      'Key File': '金鑰檔案',
      'SSL Verify': 'SSL 驗證',
      'Manager': 'Manager',
      'Manager:': 'Manager：',
      'Path:': '路徑：',
      'File:': '檔案：',
      'Lines:': '行數：',
      'From:': '寄件者：',
      'Default To:': '預設收件者：',
      'Roles (optional)': '角色（選用）',
      'Configured Nodes': '已設定的節點',
      'Agent': '代理程式',
      // --- status / sync badge VALUES (lowercase, display only; <option value> is never touched) ---
      'active': '已連線',
      'disconnected': '已離線',
      'pending': '等待中',
      'never_connected': '從未連線',
      'never connected': '從未連線',
      'connected': '已連線',
      'synced': '已同步',
      'syncing': '同步中',
      // --- sync items / status ---
      'Decoders': '解碼器',
      'Keys': '金鑰',
      'Lists': '清單',
      'Rename Group': '重新命名群組',
      'not in cluster': '不在叢集中',
      'not synced': '未同步',
      'Not Synced': '未同步',
      'Synced': '已同步',
      'Unknown': '未知',
      'SSH required': '需要 SSH',
      'Enabled': '已啟用',
      'Disabled': '已停用',
      'Protected': '受保護',
      'Default': '預設',
      'None': '無',
      'Not configured': '未設定',
      'Not found': '找不到',
      'master node': 'Master 節點',
      'Worker Node:': 'Worker 節點：',
      'Last Keep Alive:': '最後連線時間：',
      // --- modal titles / section headings ---
      'Node Management': '節點管理',
      'Global Email Settings': '全域電子郵件設定',
      'Global Email Not Configured': '全域電子郵件尚未設定',
      'SSH Setup Guide': 'SSH 設定指南',
      'Why SSH Setup?': '為什麼要設定 SSH？',
      'Why SSH Setup': '為什麼要設定 SSH',
      'Security Note': '安全提醒',
      'Important': '重要',
      'Optional Setup': '選用設定',
      'CSV Format Rules:': 'CSV 格式規則：',
      'Manage email alert rules': '管理電子郵件警示規則',
      'Manage WPK upgrade files on this node': '管理此節點上的 WPK 升級檔案',
      'Agent Details': '代理程式詳細資訊',
      'Details': '詳細資訊',
      // --- loading / status messages ---
      'Loading all rules...': '載入所有規則中…',
      'Loading comparison...': '載入比對中…',
      'Loading logs info...': '載入記錄資訊中…',
      'Loading member rules...': '載入成員規則中…',
      'Loading nodes...': '載入節點中…',
      'Loading services...': '載入服務中…',
      'Loading sync status...': '載入同步狀態中…',
      'Loading upgrade status...': '載入升級狀態中…',
      'Loading upgrade tasks...': '載入升級工作中…',
      'Searching rules...': '搜尋規則中…',
      'Saving...': '儲存中…',
      'Sending restart command...': '傳送重新啟動指令中…',
      'No content available': '無可用內容',
      'No data': '無資料',
      'No DB file found': '找不到 DB 檔案',
      'No log entries': '沒有記錄項目',
      'No member rule content available': '沒有可用的成員規則內容',
      'No recent upgrade tasks found.': '找不到最近的升級工作。',
      'No recent upgrade tasks.': '沒有最近的升級工作。',
      'No rules match the current filters.': '沒有符合目前篩選的規則。',
      'No users found': '找不到使用者',
      'No WPK files found': '找不到 WPK 檔案',
      'Showing all recent upgrade tasks from Wazuh API.': '顯示來自 Wazuh API 的所有最近升級工作。',
      'Config saved successfully!': '設定已成功儲存！',
      'Failed to load logs': '載入記錄失敗',
      'Failed to load settings': '載入設定失敗',
      'Failed to load upgrade files': '載入升級檔案失敗',
      'Failed to save': '儲存失敗',
      'Failed to save config': '儲存設定失敗',
      'Error loading rule': '載入規則錯誤',
      'Error loading rules': '載入規則錯誤',
      'Rule not found': '找不到規則',
      'Backend Service Unavailable': '後端服務無法使用',
      'The backend server is not running or connection lost.': '後端伺服器未執行或連線中斷。',
      'Please check if the service is started.': '請檢查服務是否已啟動。',
      'Cluster not configured or not running': '叢集未設定或未執行',
      'Move to Node feature is still under development.': '「移動到節點」功能仍在開發中。',
      'Loading agent details...': '載入代理程式詳細資訊中…',
      // --- descriptive / helper texts ---
      'View agents in this group': '檢視此群組的代理程式',
      'View agents on this node': '檢視此節點的代理程式',
      'View Queue DB on this node': '檢視此節點的 Queue DB',
      'View/Edit ossec.conf configuration file': '檢視／編輯 ossec.conf 設定檔',
      'Download cluster.key for worker nodes': '下載供 Worker 節點使用的 cluster.key',
      'Download cluster.key': '下載 cluster.key',
      'All files are synchronized between master and worker.': 'Master 與 Worker 間所有檔案皆已同步。',
      'Files are different between master and worker.': 'Master 與 Worker 間的檔案有差異。',
      'Agents will receive updated config on next keepalive.': '代理程式會在下次連線時收到更新後的設定。',
      'Remember to restart services for changes to take effect!': '請記得重新啟動服務以使變更生效！',
      'These WPK packages are automatically downloaded from Wazuh official site when an agent connected to this node requests an upgrade. You can also manually upload WPK files for offline environments.':
        '當連線到此節點的代理程式要求升級時，這些 WPK 套件會自動從 Wazuh 官方網站下載。你也可以為離線環境手動上傳 WPK 檔案。',
      'Force upgrade (even if same version)': '強制升級（即使版本相同）',
      'Specify version:': '指定版本：',
      'Dry Run Mode: No changes will be made': '模擬執行模式：不會進行任何變更',
      'Recipient email is required': '收件者電子郵件為必填',
      'Rule ID can only contain numbers and commas': '規則 ID 只能包含數字與逗號',
      'Level must be between 1 and 16': '等級必須介於 1 到 16 之間',
      'Enter a rule ID, or part of a rule file name': '請輸入規則 ID，或規則檔名的一部分',
      // --- API user modal ---
      'Create API User': '建立 API 使用者',
      'Edit User Roles': '編輯使用者角色',
      'Enter username': '輸入使用者名稱',
      'Enter password': '輸入密碼',
      'Username is required': '使用者名稱為必填',
      'Roles will be assigned after creation using "Edit Roles"': '建立後將透過「編輯角色」指派角色',
      // --- settings / SSH guide labels ---
      'API Connection': 'API 連線',
      'SSH Configuration': 'SSH 設定',
      'Configured': '已設定',
      'Not Configured': '未設定',
      'Reference source': '參考來源',
      'Repository': '原始碼倉庫',
      'About': '關於',
      'Total': '總計',
      'Status:': '狀態：',
      // --- CSV import modal ---
      'Import Agents from CSV': '從 CSV 匯入代理程式',
      'Column order does not matter': '欄位順序不影響',
      'If multiple match columns exist, leftmost takes priority': '若有多個可對應欄位，以最左邊優先',
      'Other columns will be ignored': '其他欄位將被忽略',
      'First row must be header': '第一列必須是標題列',
      'Must have at least one column:': '至少需包含一欄：',
      '(or Hostname), or': '（或 Hostname），或',
      '(or Address)': '（或 Address）',
      'Already in group': '已在群組中',
      'Already in group (will skip):': '已在群組中（將略過）：',
      'Not found (no matching agent):': '找不到（無相符的代理程式）：',
      'Will be added': '將被加入',
      'Will be added:': '將被加入：',
      'Would delete': '將刪除',
      'Deleted': '已刪除',
      // --- email alerts modal ---
      'No email alert rules configured. Click "Add Rule" to create one.': '尚未設定任何電子郵件警示規則。點選「新增規則」建立一筆。',
      '⚠ Global Email Not Configured': '⚠ 全域電子郵件尚未設定',
      'SMTP:': 'SMTP：',
      'Config Sum': '設定校驗值',
      'Merged Sum': '合併校驗值',
      'Recipient Email': '收件者電子郵件',
      'Level': '等級',
      '(separate multiple with commas)': '（多個以逗號分隔）',
      '(separate multiple with commas, e.g. 5710, 5711)': '（多個以逗號分隔，例如 5710, 5711）',
      '(API user)': '（API 使用者）',
      '(system - API admin)': '（系統 - API 管理員）',
      '(system - Dashboard)': '（系統 - Dashboard）',
      'for changes to take effect.': '以使變更生效。',
      'Upgrade history has been cleared.': '升級記錄已清除。',
      // --- WPK / upgrade helper ---
      'Check if the WPK files exist for your target version': '請確認目標版本的 WPK 檔案存在',
      'WPK files can be downloaded from:': 'WPK 檔案可從以下位置下載：',
      'Upload the WPK file manually, or': '手動上傳 WPK 檔案，或',
      'Options': '選項',
      // --- SSH setup guide ---
      'Add SSH settings to': '將 SSH 設定加入到',
      'After modifying': '修改後',
      'restart this tool': '重新啟動本工具',
      'Run this on the': '在以下位置執行：',
      'on the worker node.': '在 Worker 節點上。',
      'Copy the public key to': '複製公鑰到',
      'Or manually append the public key to': '或手動將公鑰附加到',
      'Verify passwordless SSH works:': '驗證免密碼 SSH 是否正常：',
      'SSH configuration is': 'SSH 設定為',
      // --- log line counts ---
      'Last 100': '最後 100',
      'Last 500': '最後 500',
      'Last 1,000': '最後 1,000',
      'Last 5,000': '最後 5,000',
      'Last 10,000': '最後 10,000',
      // --- Statistics tab ---
      'By Status': '依狀態',
      'By Group': '依群組',
      'By Node': '依節點',
      'By OS': '依作業系統',
      'By Version': '依版本',
      'By Agent Version': '依代理程式版本',
      'By Network Segment': '依網段',
      'Count': '數量',
      'Network': '網段',
      'Network Segment': '網段',
      '(no group)': '（無群組）',
      '(no node)': '（無節點）',
      '* Agents can belong to multiple groups, so percentages may exceed 100%': '* 代理程式可屬於多個群組，因此百分比總和可能超過 100%',
      // --- Rules tab helper ---
      'Search by Rule ID to view the rule hierarchy (parent-child relationships via if_sid/if_matched_sid/if_group), or by rule file name to see everything that file contains. Click on a rule to view its XML content.': '輸入規則 ID 以檢視規則階層（透過 if_sid／if_matched_sid／if_group 的父子關係），或輸入規則檔名以檢視該檔的完整內容。點選規則可檢視其 XML 內容。',
      'Summary': '摘要',
      'Report': '報表'
    }
  };

  // Patterns for interpolated strings: [regex, function(match)->translated]
  var I18N_PATTERNS = {
    'zh-TW': [
      [/^Expires:\s*(.+)$/, function (m) { return '到期：' + m[1]; }],
      [/^Session expires after\s+(\d+)\s+minutes?$/, function (m) { return 'Session 將於 ' + m[1] + ' 分鐘後過期'; }],
      [/^Showing\s+(\d+)\s*-\s*(\d+)\s+of\s+(\d+)$/, function (m) { return '顯示 ' + m[1] + ' - ' + m[2] + '，共 ' + m[3] + ' 筆'; }],
      [/^Page\s+(\d+)\s+of\s+(\d+)$/, function (m) { return '第 ' + m[1] + ' 頁，共 ' + m[2] + ' 頁'; }],
      [/^(\d+)\s+agents?\s+selected$/, function (m) { return '已選取 ' + m[1] + ' 個代理程式'; }],
      [/^Found\s+(\d+)\s+agents?$/, function (m) { return '找到 ' + m[1] + ' 個代理程式'; }],
      [/^Error:\s*(.+)$/, function (m) { return '錯誤：' + m[1]; }],
      [/^Invalid agent ID:\s*(.+)$/, function (m) { return '無效的代理程式 ID：' + m[1]; }],
      // --- Upgrade modal / progress (interpolated) ---
      [/^Selected Agents \((\d+)\)$/, function (m) { return '已選取的代理程式（' + m[1] + '）'; }],
      [/^(\d+) agent\(s\)$/, function (m) { return m[1] + ' 個代理程式'; }],
      [/^Showing upgrade progress for (\d+) recent agent\(s\)\.$/, function (m) { return '顯示最近 ' + m[1] + ' 個代理程式的升級進度。'; }],
      [/^Tracking upgrade progress for (\d+) agent\(s\)\. Status updates every 5 seconds\.$/, function (m) { return '正在追蹤 ' + m[1] + ' 個代理程式的升級進度，狀態每 5 秒更新一次。'; }],
      [/^Upgrade failed for (\d+) agent\(s\)$/, function (m) { return m[1] + ' 個代理程式升級失敗'; }],
      [/^Total: (\d+)$/, function (m) { return '總計：' + m[1]; }],
      [/^(\d+) Updated$/, function (m) { return m[1] + ' 個已更新'; }],
      [/^(\d+) Failed$/, function (m) { return m[1] + ' 個失敗'; }],
      [/^(\d+) In Progress$/, function (m) { return m[1] + ' 個進行中'; }],
      [/^Older than manager \((.+)\)$/, function (m) { return '比 Manager 版本舊（' + m[1] + '）'; }],
      [/^Newer than manager \((.+)\)$/, function (m) { return '比 Manager 版本新（' + m[1] + '）'; }],
      // --- Confirmation dialogs (interpolated) ---
      [/^Restart (\d+) agent\(s\)\?$/, function (m) { return '要重新啟動 ' + m[1] + ' 個代理程式嗎？'; }],
      [/^Reconnect (\d+) agent\(s\)\?$/, function (m) { return '要讓 ' + m[1] + ' 個代理程式重新連線嗎？'; }],
      [/^DELETE (\d+) agent\(s\)\? This cannot be undone!$/, function (m) { return '要刪除 ' + m[1] + ' 個代理程式嗎？此動作無法復原！'; }],
      [/^Upgrade (\d+) agent\(s\) to latest version\?$/, function (m) { return '要將 ' + m[1] + ' 個代理程式升級到最新版本嗎？'; }],
      [/^Upgrade (\d+) agent\(s\) to v(.+)\?$/, function (m) { return '要將 ' + m[1] + ' 個代理程式升級到 v' + m[2] + ' 嗎？'; }],
      [/^Clean Queue DB for (\d+) agent\(s\)\?([\s\S]*)$/, function (m) { return '要清除 ' + m[1] + ' 個代理程式的 Queue DB 嗎？' + m[2].replace('This will delete the queue DB files and restart the agents.', '這會刪除 queue DB 檔案並重新啟動代理程式。'); }],
      [/^Remove all (\d+) agent\(s\) from group "(.+)"\?$/, function (m) { return '要將全部 ' + m[1] + ' 個代理程式從群組「' + m[2] + '」移除嗎？'; }],
      [/^Move (\d+) agent\(s\) from "(.+)" to:$/, function (m) { return '將 ' + m[1] + ' 個代理程式從「' + m[2] + '」移動到：'; }],
      [/^Will add (\d+) agent\(s\) to the selected group\.$/, function (m) { return '將會把 ' + m[1] + ' 個代理程式加入所選群組。'; }],
      [/^Will remove (\d+) agent\(s\) from the selected group\.$/, function (m) { return '將會把 ' + m[1] + ' 個代理程式從所選群組移除。'; }],
      [/^This will: 1\) Create new group, 2\) Move (\d+) agent\(s\) to new group, 3\) Delete old group$/, function (m) { return '這會：1) 建立新群組，2) 將 ' + m[1] + ' 個代理程式移至新群組，3) 刪除舊群組'; }],
      [/^\u26a0\ufe0f FINAL CONFIRMATION \u26a0\ufe0f([\s\S]*?)permanently delete (\d+) agent\(s\)\?([\s\S]*)$/, function (m) { return '\u26a0\ufe0f 最終確認 \u26a0\ufe0f\n\n你確定要永久刪除 ' + m[2] + ' 個代理程式嗎？\n\n此動作無法復原！'; }],
      // --- Modal titles carrying a value ---
      [/^Sync Detail: (.+)$/, function (m) { return '同步詳細資訊：' + m[1]; }],
      [/^Email Alerts - (.+)$/, function (m) { return '電子郵件警示 - ' + m[1]; }],
      [/^Agent Upgrade Files - (.+)$/, function (m) { return '代理程式升級檔案 - ' + m[1]; }],
      [/^SSH Setup Guide - (.+)$/, function (m) { return 'SSH 設定指南 - ' + m[1]; }],
      [/^Edit Rule #(\d+)$/, function (m) { return '編輯規則 #' + m[1]; }],
      [/^Download (?!failed)(.+)$/, function (m) { return '下載 ' + m[1]; }],
      [/^Content refreshed \((\d+) lines\)$/, function (m) { return '內容已更新（' + m[1] + ' 行）'; }],
      [/^Sync completed: (\d+) succeeded, (\d+) failed$/, function (m) { return '同步完成：' + m[1] + ' 個成功，' + m[2] + ' 個失敗'; }],
      [/^Found (\d+) related rules?$/, function (m) { return '找到 ' + m[1] + ' 條相關規則'; }],
      [/^Found (\d+) rules? in (\d+) files?$/, function (m) { return '在 ' + m[2] + ' 個檔案中找到 ' + m[1] + ' 條規則'; }],
      [/^Found (\d+) rules? in (\d+) files? \(more files matched, showing the first 20\)$/, function (m) { return '在 ' + m[2] + ' 個檔案中找到 ' + m[1] + ' 條規則（尚有更多檔案符合，僅顯示前 20 個）'; }],
      [/^(\d+) rules$/, function (m) { return m[1] + ' 條規則'; }],
      // --- v1.5 (interpolated) ---
      [/^Health - (.+)$/, function (m) { return '健康狀態 - ' + m[1]; }],
      [/^Group Files - (.+)$/, function (m) { return '群組檔案 - ' + m[1]; }],
      [/^Decoder - (.+)$/, function (m) { return '解碼器 - ' + m[1]; }],
      [/^CDB List - (.+)$/, function (m) { return 'CDB 清單 - ' + m[1]; }],
      [/^Agent Key - (.+)$/, function (m) { return '代理程式金鑰 - ' + m[1]; }],
      [/^Running Config - Agent (.+)$/, function (m) { return '生效中的設定 - 代理程式 ' + m[1]; }],
      [/^Ruleset reloaded on (.+)$/, function (m) { return '已在 ' + m[1] + ' 重新載入規則集'; }],
      [/^Ruleset reloaded on (\\d+) node\\(s\\)$/, function (m) { return '已在 ' + m[1] + ' 個節點重新載入規則集'; }],
      [/^(\\d+) difference\\(s\\) found$/, function (m) { return '發現 ' + m[1] + ' 處差異'; }],
      [/^(\\d+) packs, (\\d+) installed$/, function (m) { return m[1] + ' 個套件，已安裝 ' + m[2] + ' 個'; }],
      [/^Install pack "(.+)"\\? Files are backed up and rolled back if the ruleset fails to validate\\.$/, function (m) { return '要安裝套件「' + m[1] + '」嗎？檔案會先備份，規則集驗證失敗時自動回滾。'; }],
      [/^Remove pack "(.+)"\\? Files it replaced are restored\\.$/, function (m) { return '要移除套件「' + m[1] + '」嗎？被它覆蓋的檔案會還原。'; }],
      [/^Installed (.+)\\. Reload the ruleset for it to take effect\\.$/, function (m) { return '已安裝 ' + m[1] + '，請重新載入規則集使其生效。'; }],
      [/^Removed (.+)\\. Reload the ruleset for it to take effect\\.$/, function (m) { return '已移除 ' + m[1] + '，請重新載入規則集使其生效。'; }],
      [/^Reload the ruleset on "(.+)"\? Running services are not restarted\.$/, function (m) { return '要在「' + m[1] + '」重新載入規則集嗎？執行中的服務不會重新啟動。'; }],
      [/^Command sent to (\d+) agent\(s\)$/, function (m) { return '指令已送出至 ' + m[1] + ' 個代理程式'; }],
      [/^Run "(.+)" on (\d+) agent\(s\)\?$/, function (m) { return '要在 ' + m[2] + ' 個代理程式上執行「' + m[1] + '」嗎？'; }],
      [/^Registered (\d+) of (\d+) agent\(s\)$/, function (m) { return '已註冊 ' + m[2] + ' 個中的 ' + m[1] + ' 個代理程式'; }],
      [/^(\d+) results from (\d+) of (\d+) agents$/, function (m) { return '共 ' + m[1] + ' 筆結果，來自 ' + m[3] + ' 台中的 ' + m[2] + ' 台代理程式'; }],
      [/^(\d+) decoders$/, function (m) { return m[1] + ' 個解碼器'; }],
      [/^(\d+) lists$/, function (m) { return m[1] + ' 個清單'; }],
      [/^Saved (.+)\. Reload the ruleset for it to take effect\.$/, function (m) { return '已儲存 ' + m[1] + '，請重新載入規則集使其生效。'; }],
      [/^Deleted (.+)$/, function (m) { return '已刪除 ' + m[1]; }],
      [/^Delete CDB list "(.+)"\?$/, function (m) { return '要刪除 CDB 清單「' + m[1] + '」嗎？'; }],
      [/^Upgrade (\d+) agent\(s\) using (.+)\?$/, function (m) { return '要用 ' + m[2] + ' 升級 ' + m[1] + ' 個代理程式嗎？'; }],
      [/^Custom upgrade queued for (\d+) agent\(s\)$/, function (m) { return '已為 ' + m[1] + ' 個代理程式排入自訂升級'; }],
      [/^Target: (\d+) agent\(s\)$/, function (m) { return '目標：' + m[1] + ' 個代理程式'; }],
      [/^(\d+) matched: (.+)$/, function (m) { return '符合 ' + m[1] + ' 條：' + m[2]; }],
      [/^Too many matches, showing first (\d+)$/, function (m) { return '符合數量過多，僅顯示前 ' + m[1] + ' 條'; }],
      [/^(\d+) rules loaded$/, function (m) { return '已載入 ' + m[1] + ' 條規則'; }],
      [/^Search keywords are required$/, function () { return '請輸入搜尋關鍵字'; }],
      [/^Search query is too long$/, function () { return '搜尋字串過長'; }],
      [/^\u26a0\s*(\d+)\s+rule files? could not be parsed$/, function (m) { return '\u26a0 ' + m[1] + ' 個規則檔無法解析'; }],
      [/^Error loading agents:\s*(.+)$/, function (m) { return '載入代理程式錯誤：' + m[1]; }],
      [/^Successfully synced to\s+(.+)$/, function (m) { return '已成功同步到 ' + m[1]; }],
      [/^Services restarted successfully on\s+(.+)$/, function (m) { return '已成功在 ' + m[1] + ' 重新啟動服務'; }],
      [/^Successfully added\s+(.+)$/, function (m) { return '已成功新增 ' + m[1]; }],
      [/^Starting upgrade for\s+(.+)$/, function (m) { return '開始升級 ' + m[1]; }],
      [/^Upgrade failed:\s*(.+)$/, function (m) { return '升級失敗：' + m[1]; }],
      [/^Upload failed:\s*(.+)$/, function (m) { return '上傳失敗：' + m[1]; }],
      [/^Delete failed:\s*(.+)$/, function (m) { return '刪除失敗：' + m[1]; }],
      [/^Download failed:\s*(.+)$/, function (m) { return '下載失敗：' + m[1]; }],
      [/^Failed to load agents:\s*(.+)$/, function (m) { return '載入代理程式失敗：' + m[1]; }],
      [/^Content refreshed\s*\((.+)\)$/, function (m) { return '內容已重新整理（' + m[1] + '）'; }],
      [/^Sync completed:\s*(.+)$/, function (m) { return '同步完成：' + m[1]; }],
      [/^Downloaded\s+(.+)$/, function (m) { return '已下載 ' + m[1]; }],
      [/^Exported\s+(.+)$/, function (m) { return '已匯出 ' + m[1]; }],
      // interpolated modal titles / labels
      [/^Agent Upgrade Files - (.+)$/, function (m) { return 'Agent 升級檔案 - ' + m[1]; }],
      [/^Email Alerts - (.+)$/, function (m) { return '電子郵件警示 - ' + m[1]; }],
      [/^Import Preview - (.+)$/, function (m) { return '匯入預覽 - ' + m[1]; }],
      [/^Edit Rule #(.+)$/, function (m) { return '編輯規則 #' + m[1]; }],
      [/^Total:\s*(\d+)\s*file\(s\)$/, function (m) { return '共 ' + m[1] + ' 個檔案'; }],
      [/^Total:\s*(\d+)\s*agents?$/, function (m) { return '共 ' + m[1] + ' 個代理程式'; }],
      [/^Manager:\s*(.+)$/, function (m) { return 'Manager：' + m[1]; }],
      [/^Path:\s*(.+)$/, function (m) { return '路徑：' + m[1]; }],
      [/^File:\s*(.+)$/, function (m) { return '檔案：' + m[1]; }],
      [/^Lines:\s*(.+)$/, function (m) { return '行數：' + m[1]; }],
      [/^Last Keep Alive:\s*(.+)$/, function (m) { return '最後連線時間：' + m[1]; }],
      [/^Total\s+(\d+)\s+rules?$/, function (m) { return '共 ' + m[1] + ' 條規則'; }],
      // interpolated modal subtitles / helpers
      [/^Roles for user "(.+)"$/, function (m) { return '使用者「' + m[1] + '」的角色'; }],
      [/^Select CSV file to import agents into group "(.+)"$/, function (m) { return '選擇 CSV 檔案以將代理程式匯入群組「' + m[1] + '」'; }],
      [/^This will: 1\) Create new group, 2\) Move (\d+) agents? to new group, 3\) Delete old group$/, function (m) { return '這會：1) 建立新群組，2) 將 ' + m[1] + ' 個代理程式移到新群組，3) 刪除舊群組'; }],
      [/^Delete user "(.+)"\?$/, function (m) { return '確定刪除使用者「' + m[1] + '」？'; }],
      [/^Delete group "(.+)"\?$/, function (m) { return '確定刪除群組「' + m[1] + '」？'; }],
      // distribution bar segments: "active (34)"
      [/^active \((\d+)\)$/, function (m) { return '已連線 (' + m[1] + ')'; }],
      [/^disconnected \((\d+)\)$/, function (m) { return '已離線 (' + m[1] + ')'; }],
      [/^pending \((\d+)\)$/, function (m) { return '等待中 (' + m[1] + ')'; }],
      [/^never_connected \((\d+)\)$/, function (m) { return '從未連線 (' + m[1] + ')'; }]
    ]
  };

  var LANG_KEY = 'jtwz_lang';
  var SUPPORTED = ['en', 'zh-TW'];
  var SKIP_TAGS = { SCRIPT: 1, STYLE: 1, TEXTAREA: 1, CODE: 1, PRE: 1, svg: 1, SVG: 1 };

  function getLang() {
    var l = localStorage.getItem(LANG_KEY);
    return SUPPORTED.indexOf(l) >= 0 ? l : 'en';
  }

  function translate(raw, lang) {
    if (!raw) return null;
    var key = raw.trim();
    if (!key) return null;
    var dict = I18N[lang];
    if (dict && Object.prototype.hasOwnProperty.call(dict, key)) {
      var v = dict[key];
      if (v === '') return null; // intentionally skip (handled by pattern)
      return raw.replace(key, v);
    }
    var pats = I18N_PATTERNS[lang] || [];
    for (var i = 0; i < pats.length; i++) {
      var mm = key.match(pats[i][0]);
      if (mm) return raw.replace(key, pats[i][1](mm));
    }
    return null;
  }

  function shouldSkip(node) {
    var p = node.parentNode;
    while (p && p.nodeType === 1) {
      if (SKIP_TAGS[p.tagName]) return true;
      if (p.hasAttribute && p.hasAttribute('data-noi18n')) return true;
      p = p.parentNode;
    }
    return false;
  }

  function translateTextNodes(root, lang) {
    var walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, null);
    var batch = [];
    var n;
    while ((n = walker.nextNode())) batch.push(n);
    for (var i = 0; i < batch.length; i++) {
      var node = batch[i];
      if (shouldSkip(node)) continue;
      var t = translate(node.nodeValue, lang);
      if (t !== null && t !== node.nodeValue) node.nodeValue = t;
    }
  }

  function translateAttrs(root, lang) {
    var els = root.nodeType === 1 ? [root] : [];
    var found = (root.querySelectorAll ? root.querySelectorAll('[placeholder],[title]') : []);
    for (var i = 0; i < found.length; i++) els.push(found[i]);
    for (var j = 0; j < els.length; j++) {
      var el = els[j];
      if (!el.getAttribute) continue;
      ['placeholder', 'title'].forEach(function (a) {
        if (el.hasAttribute(a)) {
          var t = translate(el.getAttribute(a), lang);
          if (t !== null) el.setAttribute(a, t);
        }
      });
    }
  }

  function translateTree(root, lang) {
    if (lang === 'en') return;
    translateTextNodes(root, lang);
    translateAttrs(root, lang);
  }

  function setLang(lang) {
    if (SUPPORTED.indexOf(lang) < 0) lang = 'en';
    localStorage.setItem(LANG_KEY, lang);
    location.reload();
  }
  window.jtwzSetLang = setLang;

  function injectStyle() {
    if (document.getElementById('jtwz-i18n-style')) return;
    var st = document.createElement('style');
    st.id = 'jtwz-i18n-style';
    st.textContent =
      '#langToggle svg{width:18px;height:18px;flex:0 0 auto}' +
      '.jtwz-lang-fab svg{width:16px;height:16px}' +
      '.jtwz-lang-fab{position:fixed;top:14px;right:16px;z-index:9999;display:inline-flex;align-items:center;gap:6px;' +
      'padding:7px 13px;background:#16213e;color:#4fc3f7;border:1px solid #4fc3f7;border-radius:8px;' +
      'font-size:13px;font-weight:600;cursor:pointer;font-family:inherit}' +
      '.jtwz-lang-fab:hover{background:#1a4a7a;color:#81d4fa}';
    (document.head || document.documentElement).appendChild(st);
  }

  var GLOBE = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" ' +
    'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>' +
    '<path d="M12 3c2.6 2.7 2.6 15.3 0 18M12 3c-2.6 2.7-2.6 15.3 0 18"/></svg>';

  function buildToggle() {
    injectStyle();
    var lang = getLang();
    var label = (lang === 'zh-TW') ? 'EN' : '中文';
    var btn = document.createElement('button');
    btn.id = 'langToggle';
    btn.type = 'button';
    btn.title = (lang === 'zh-TW') ? 'Switch to English' : '切換為繁體中文';
    btn.innerHTML = GLOBE + '<span>' + label + '</span>';
    btn.onclick = function () { setLang(lang === 'zh-TW' ? 'en' : 'zh-TW'); };
    var hb = document.querySelector('.header-buttons');
    if (hb) { btn.className = 'btn-settings'; hb.insertBefore(btn, hb.firstChild); }
    else { btn.className = 'jtwz-lang-fab'; document.body.appendChild(btn); }
  }

  function init() {
    var lang = getLang();
    document.documentElement.setAttribute('lang', lang === 'zh-TW' ? 'zh-TW' : 'en');
    buildToggle();
    if (lang !== 'en') {
      translateTree(document.body, lang);
      var obs = new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          var added = muts[i].addedNodes;
          for (var j = 0; j < added.length; j++) {
            var node = added[j];
            if (node.nodeType === 1) translateTree(node, lang);
            else if (node.nodeType === 3) {
              if (!shouldSkip(node)) {
                var t = translate(node.nodeValue, lang);
                if (t !== null && t !== node.nodeValue) node.nodeValue = t;
              }
            }
          }
        }
      });
      obs.observe(document.body, { childList: true, subtree: true });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

</script>
"""
LOGIN_TEMPLATE = LOGIN_TEMPLATE.replace('</body>', _I18N_SCRIPT + '</body>')
HTML_TEMPLATE = HTML_TEMPLATE.replace('</body>', _I18N_SCRIPT + '</body>')
# === END i18n auto-embed ===



class SessionExpiredException(Exception):
    """Raised when Wazuh API session/token has expired."""
    pass


class WazuhAPISession:
    """Wazuh API session manager."""

    # Class-level SSL setting (can be True, False, or path to CA cert)
    ssl_verify = os.environ.get('WAZUH_SSL_VERIFY', 'false').lower() not in ('false', '0', 'no')
    ssl_cert_path = os.environ.get('WAZUH_SSL_CERT', None)

    def __init__(self, host: str, port: int, username: str, password: str):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.base_url = f"https://{host}:{port}"
        self.token = None
        # Use cert path if provided, otherwise use boolean
        self._verify = self.ssl_cert_path if self.ssl_cert_path and os.path.exists(self.ssl_cert_path) else self.ssl_verify

    def authenticate(self) -> bool:
        """Authenticate and get token. Raises descriptive exceptions on failure."""
        try:
            response = http_requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
                verify=self._verify,
                timeout=30
            )
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('data', {}).get('token')
                return bool(self.token)
            elif response.status_code == 401:
                raise Exception("Invalid username or password")
            elif response.status_code == 403:
                raise Exception("Access forbidden - check user permissions")
            else:
                raise Exception(f"API returned status {response.status_code}")
        except http_requests.exceptions.ConnectionError:
            raise Exception(f"Cannot connect to Wazuh API at {self.host}:{self.port} - check if the service is running")
        except http_requests.exceptions.Timeout:
            raise Exception(f"Connection timeout - Wazuh API at {self.host}:{self.port} is not responding")
        except http_requests.exceptions.SSLError as e:
            raise Exception(f"SSL certificate error - {str(e)}")
        except Exception as e:
            if "Invalid username or password" in str(e) or "Cannot connect" in str(e) or "timeout" in str(e).lower():
                raise
            raise Exception(f"Connection failed: {str(e)}")

    def request(self, method: str, endpoint: str, data=None, params=None):
        """Make authenticated API request."""
        if not self.token:
            raise Exception("Not authenticated")

        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }

        try:
            response = http_requests.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                headers=headers,
                json=data,
                params=params,
                verify=self._verify,
                timeout=60
            )

            # Token expired - raise exception so it propagates up
            if response.status_code == 401:
                raise SessionExpiredException("Session expired. Please login again.")

            return response.json()
        except SessionExpiredException:
            raise  # Re-raise session expired
        except Exception as e:
            return {'error': str(e)}

    def request_raw(self, method: str, endpoint: str, body: str = None, params=None,
                    content_type: str = 'application/octet-stream'):
        """Request that sends/receives a plain body instead of JSON.

        Used for CDB lists, which Wazuh serves as text/plain and accepts as
        octet-stream. Returns (ok, text_or_error).
        """
        if not self.token:
            raise Exception("Not authenticated")
        headers = {'Authorization': f'Bearer {self.token}'}
        if body is not None:
            headers['Content-Type'] = content_type
        try:
            response = http_requests.request(
                method=method,
                url=f"{self.base_url}{endpoint}",
                headers=headers,
                data=body.encode('utf-8') if isinstance(body, str) else body,
                params=params,
                verify=self._verify,
                timeout=60,
            )
            if response.status_code == 401:
                raise SessionExpiredException("Session expired. Please login again.")
            if response.status_code >= 400:
                try:
                    payload = response.json()
                    detail = payload.get('detail') or payload.get('title') or payload.get('message')
                except Exception:
                    detail = response.text[:300]
                return False, detail or f'HTTP {response.status_code}'
            return True, response.text
        except SessionExpiredException:
            raise
        except Exception as e:
            return False, str(e)

    def get_agents(self, status=None, group=None, limit=10000):
        """Get agents list."""
        params = {'limit': limit, 'select': 'id,name,ip,status,os.platform,os.name,os.version,version,group,node_name,group_config_status'}
        if status:
            params['status'] = status
        if group:
            params['group'] = group
        result = self.request('GET', '/agents', params=params)
        items = result.get('data', {}).get('affected_items', [])
        # Flatten the response
        agents = []
        for item in items:
            # Clean version string: "Wazuh v4.14.0" -> "v4.14.0"
            version = item.get('version') or ''
            if version.startswith('Wazuh '):
                version = version[6:]  # Remove "Wazuh " prefix
            agent = {
                'id': item.get('id'),
                'name': item.get('name'),
                'ip': item.get('ip'),
                'status': item.get('status'),
                'os': (item.get('os', {}).get('name') or item.get('os', {}).get('platform', '')) + (' ' + item.get('os', {}).get('version', '') if item.get('os', {}).get('version') else ''),
                'version': version,
                'group': ','.join(item.get('group', [])) if item.get('group') else '',
                'node_name': item.get('node_name', ''),
                'synced': item.get('group_config_status', '')
            }
            agents.append(agent)
        return agents

    def get_groups(self):
        """Get groups list."""
        result = self.request('GET', '/groups')
        items = result.get('data', {}).get('affected_items', [])
        return [{'name': g.get('name'), 'count': g.get('count', 0)} for g in items]

    def get_nodes(self):
        """Get cluster nodes. Falls back to manager info if cluster not configured."""
        result = self.request('GET', '/cluster/nodes')
        items = result.get('data', {}).get('affected_items', [])

        # Get local hostname directly from system
        import socket
        local_hostname = socket.gethostname()

        # Get local cluster node name for matching
        try:
            local_info = self.request('GET', '/cluster/local/info')
            local_data = local_info.get('data', {}).get('affected_items', [])
            local_node = local_data[0] if local_data else {}
            local_node_name = local_node.get('node', '') or local_node.get('name', '')
        except:
            local_node_name = ''

        # Get agent counts per node
        agent_counts = {}
        try:
            agents_result = self.request('GET', '/agents', params={'select': 'node_name', 'limit': 100000})
            agents_data = agents_result.get('data', {}).get('affected_items', [])
            for agent in agents_data:
                node = agent.get('node_name', 'unknown')
                agent_counts[node] = agent_counts.get(node, 0) + 1
        except:
            pass

        if items:
            nodes = []
            for n in items:
                node_name = n.get('name', '')
                ip = n.get('ip', '')
                # If IP is localhost, use the configured API host
                if ip in ['localhost', '127.0.0.1', '']:
                    ip = f"{self.host} (API)"
                # Use hostname for local node (match by type=master or node name)
                is_local = n.get('type') == 'master' or node_name == local_node_name
                # For local node use system hostname, for remote nodes try to derive from node name
                if is_local:
                    hostname = local_hostname
                else:
                    # Try to get hostname from node name (e.g., "edr2-server" -> try to resolve)
                    # For now, we'll use the node name as a hint or show the IP
                    hostname = node_name.replace('-server', '') if '-server' in node_name else ''
                # Clean version string: "Wazuh v4.14.0" -> "v4.14.0"
                version = n.get('version') or ''
                if version.startswith('Wazuh '):
                    version = version[6:]
                nodes.append({
                    'name': node_name,
                    'hostname': hostname,
                    'type': n.get('type'),
                    'version': version,
                    'ip': ip,
                    'count': agent_counts.get(node_name, 0),
                    'status': n.get('status', 'connected'),
                })

            # Add entries for nodes referenced by agents but not in cluster
            known_names = {n['name'] for n in nodes}
            for node_name_key, cnt in agent_counts.items():
                if node_name_key and node_name_key != 'unknown' and node_name_key not in known_names:
                    nodes.append({
                        'name': node_name_key,
                        'hostname': '',
                        'type': 'worker',
                        'version': '',
                        'ip': '',
                        'count': cnt,
                        'status': 'not_in_cluster',
                    })

            return nodes

        # Fallback: get manager info for single-node setup
        try:
            manager_result = self.request('GET', '/manager/info')
            manager_data = manager_result.get('data', {}).get('affected_items', [])
            if manager_data:
                m = manager_data[0]
                # Clean version string
                version = m.get('version', '')
                if version.startswith('Wazuh '):
                    version = version[6:]
                node_name = local_node_name or 'manager'
                return [{
                    'name': node_name,
                    'hostname': local_hostname,
                    'type': 'master',
                    'version': version,
                    'ip': f"{self.host} (API)",
                    'count': agent_counts.get(node_name, sum(agent_counts.values())),
                    'status': 'connected',
                }]
        except:
            pass

        return []

    def add_agents_to_group(self, group_name: str, agent_ids: list):
        """Add agents to group."""
        params = {'group_id': group_name, 'agents_list': ','.join(agent_ids)}
        return self.request('PUT', '/agents/group', params=params)

    def remove_agents_from_group(self, group_name: str, agent_ids: list):
        """Remove agents from group."""
        params = {'group_id': group_name, 'agents_list': ','.join(agent_ids)}
        return self.request('DELETE', '/agents/group', params=params)

    def create_group(self, group_name: str):
        """Create a group."""
        return self.request('POST', '/groups', data={'group_id': group_name})

    def delete_group(self, group_name: str):
        """Delete a group."""
        params = {'groups_list': group_name}
        return self.request('DELETE', '/groups', params=params)

    def restart_agents(self, agent_ids: list):
        """Restart agents."""
        params = {'agents_list': ','.join(agent_ids)}
        return self.request('PUT', '/agents/restart', params=params)

    def reconnect_agents(self, agent_ids: list):
        """Force agents to reconnect."""
        params = {'agents_list': ','.join(agent_ids)}
        return self.request('PUT', '/agents/reconnect', params=params)

    def delete_agents(self, agent_ids: list):
        """Delete agents."""
        params = {'agents_list': ','.join(agent_ids), 'status': 'all', 'older_than': '0s'}
        return self.request('DELETE', '/agents', params=params)

    def get_agent_details(self, agent_id: str):
        """Get detailed agent information."""
        result = self.request('GET', f'/agents?agents_list={agent_id}')
        items = result.get('data', {}).get('affected_items', [])
        return items[0] if items else None

    def get_stats_summary(self):
        """Get agent statistics summary."""
        result = self.request('GET', '/agents/summary/status')

        # Handle error response (error != 0 means failure)
        if result.get('error') and result.get('error') != 0:
            return {'error': result['error']}

        # The data structure might vary - handle both cases
        data = result.get('data', {})

        # If data has 'affected_items', it's a different response format
        if 'affected_items' in data:
            data = data.get('affected_items', [{}])[0] if data.get('affected_items') else {}

        # Extract status counts - only sum numeric values
        status_values = {}
        for key, value in data.items():
            if isinstance(value, (int, float)):
                status_values[key] = value

        total = sum(status_values.values()) if status_values else 0
        active = status_values.get('active', 0)

        return {
            'total_agents': total,
            'active_agents': active,
            'active_percentage': round((active / total * 100) if total > 0 else 0, 1),
            'status_breakdown': {
                'Active': status_values.get('active', 0),
                'Disconnected': status_values.get('disconnected', 0),
                'Pending': status_values.get('pending', 0),
                'Never connected': status_values.get('never_connected', 0)
            }
        }

    # ============ User Management Methods ============

    def get_users(self):
        """Get all API users."""
        # First fetch all roles to create ID-to-name mapping
        all_roles = self.get_roles()
        role_id_to_name = {r['id']: r['name'] for r in all_roles}

        result = self.request('GET', '/security/users')
        users = result.get('data', {}).get('affected_items', [])
        parsed_users = []
        for u in users:
            roles = u.get('roles', [])
            # Handle both dict format and int format for roles
            role_names = []
            role_ids = []
            for r in roles:
                if isinstance(r, dict):
                    role_names.append(r.get('name', ''))
                    role_ids.append(r.get('id'))
                elif isinstance(r, int):
                    role_ids.append(r)
                    # Look up role name from ID
                    role_name = role_id_to_name.get(r, f'role_{r}')
                    role_names.append(role_name)
            parsed_users.append({
                'user_id': u.get('id'),
                'username': u.get('username'),
                'roles': role_names,
                'role_ids': role_ids,
                'allow_run_as': u.get('allow_run_as', False)
            })
        return parsed_users

    def get_roles(self):
        """Get all available roles."""
        result = self.request('GET', '/security/roles')
        roles = result.get('data', {}).get('affected_items', [])
        return [{'id': r.get('id'), 'name': r.get('name')} for r in roles]

    def create_user(self, username: str, password: str):
        """Create a new API user."""
        result = self.request('POST', '/security/users', data={
            'username': username,
            'password': password
        })
        if result.get('data', {}).get('affected_items'):
            return {'success': True}
        else:
            failed = result.get('data', {}).get('failed_items', [])
            if failed:
                error_msg = failed[0].get('error', {}).get('message', 'Unknown error')
                return {'error': error_msg}
            if result.get('error'):
                return {'error': result.get('error')}
            return {'error': 'Failed to create user'}

    def delete_user(self, username: str):
        """Delete an API user."""
        # First get user ID from username
        users = self.get_users()
        user_id = None
        for u in users:
            if u.get('username') == username:
                user_id = u.get('user_id')
                break

        if user_id is None:
            return {'error': f'User "{username}" not found'}

        result = self.request('DELETE', '/security/users', params={'user_ids': str(user_id)})
        if result.get('data', {}).get('affected_items'):
            return {'success': True}
        else:
            failed = result.get('data', {}).get('failed_items', [])
            if failed:
                error_msg = failed[0].get('error', {}).get('message', 'Unknown error')
                return {'error': error_msg}
            return {'error': 'Failed to delete user'}

    def assign_user_role(self, user_id: int, role_id: int):
        """Assign a role to a user."""
        result = self.request('POST', f'/security/users/{user_id}/roles', params={'role_ids': role_id})
        if result.get('error'):
            return {'error': result['error']}
        return {'success': True}

    def remove_user_role(self, user_id: int, role_id: int):
        """Remove a role from a user."""
        result = self.request('DELETE', f'/security/users/{user_id}/roles', params={'role_ids': role_id})
        if result.get('error'):
            return {'error': result['error']}
        return {'success': True}

    # ============ Service Status Methods ============

    def get_manager_status(self):
        """Get manager daemon status."""
        result = self.request('GET', '/manager/status')
        daemons = result.get('data', {}).get('affected_items', [])
        services = []
        if daemons:
            daemon_dict = daemons[0] if daemons else {}
            for daemon_name, status in daemon_dict.items():
                services.append({
                    'name': daemon_name,
                    'status': status.lower() if status else 'unknown'
                })
        return services

    def get_cluster_status(self):
        """Get cluster status."""
        result = self.request('GET', '/cluster/status')
        return result.get('data', {})

    def get_nodes_status(self):
        """Get status for all nodes individually."""
        result = {}
        nodes = self.get_nodes()

        for node in nodes:
            node_name = node.get('name', 'manager')
            node_type = node.get('type', 'master')

            try:
                # Try to get status for this specific node via cluster API
                api_result = self.request('GET', f'/cluster/{node_name}/status')
                daemons = api_result.get('data', {}).get('affected_items', [])

                services = []
                if daemons:
                    daemon_dict = daemons[0] if daemons else {}
                    for daemon_name, status in daemon_dict.items():
                        services.append({
                            'name': daemon_name,
                            'status': status.lower() if status else 'unknown'
                        })

                if services:
                    result[node_name] = services
                else:
                    result[node_name] = [{'name': 'Unknown', 'status': 'unknown'}]

            except Exception as e:
                # Fallback: if cluster API fails, try manager status for master node
                if node_type == 'master':
                    services = self.get_manager_status()
                    result[node_name] = services if services else [{'name': 'Unknown', 'status': 'unknown'}]
                else:
                    result[node_name] = [{'name': 'Remote', 'status': 'unknown'}]

        return result

    def get_agent_info(self, agent_id: str):
        """Get detailed info for a single agent.

        Args:
            agent_id: Agent ID

        Returns:
            Agent info dictionary or None
        """
        try:
            result = self.request('GET', f'/agents', params={'agents_list': agent_id})
            items = result.get('data', {}).get('affected_items', [])
            if items:
                return items[0]
            return None
        except Exception:
            return None

    def upgrade_agent(self, agent_id: str, version: str = None, force: bool = False, manager_version: str = None):
        """Upgrade an agent to specified version or latest.

        Args:
            agent_id: Agent ID
            version: Target version (None for latest/manager version)
            force: Force upgrade even if same version
            manager_version: Manager version to use when version is None

        Returns:
            Result dictionary with success or error
        """
        import logging
        logger = logging.getLogger('wazuh_mgr')

        try:
            # Pre-flight check: Get agent info to verify status
            agent_info = self.get_agent_info(agent_id)
            if not agent_info:
                return {'error': f'Agent {agent_id} not found'}

            agent_status = agent_info.get('status', 'unknown')
            agent_name = agent_info.get('name', agent_id)
            agent_version = agent_info.get('version', '')

            # Check if agent is in a valid state for upgrade
            if agent_status not in ['active', 'connected']:
                return {
                    'error': f'Agent must be active/connected to upgrade (current status: {agent_status})',
                    'agent_status': agent_status
                }

            # Build params using correct Wazuh API format
            # Endpoint: PUT /agents/upgrade?agents_list=xxx
            # NOT: PUT /agents/{id}/upgrade
            params = {
                'agents_list': agent_id
            }
            if force:
                params['force'] = 'true'

            # If no version specified, use manager version (more reliable than "latest")
            target_version = version
            if not target_version and manager_version:
                # Clean the manager version (remove 'v' prefix if present, remove 'Wazuh ' prefix)
                target_version = manager_version.replace('Wazuh ', '').replace('v', '').strip()

            # Use 'upgrade_version' parameter (not 'version')
            if target_version:
                params['upgrade_version'] = target_version

            # Print to terminal for debugging
            print(f"[UPGRADE] Agent {agent_id}: target_version={target_version}, params={params}")
            logger.info(f"Upgrade request: agent={agent_id} ({agent_name}) current_version={agent_version} target_version={target_version or 'latest'} force={force} params={params}")

            # Use the correct endpoint: PUT /agents/upgrade (not /agents/{id}/upgrade)
            result = self.request('PUT', '/agents/upgrade', params=params)
            print(f"[UPGRADE] Agent {agent_id} API response: {json.dumps(result)}")
            logger.info(f"Wazuh API upgrade response for agent {agent_id}: {json.dumps(result)}")

            # Check for errors in response
            if result.get('error'):
                error_msg = result.get('error')
                if isinstance(error_msg, dict):
                    error_msg = error_msg.get('message', str(error_msg))
                logger.warning(f"Upgrade error for agent {agent_id}: {error_msg}")
                return {'error': error_msg}

            # Check for failed_items
            if result.get('data', {}).get('failed_items'):
                failed = result['data']['failed_items']
                if failed:
                    error_info = failed[0].get('error', {})
                    if isinstance(error_info, dict):
                        error_code = error_info.get('code', 0)
                        error_msg = error_info.get('message', 'Unknown error')
                        # Provide more helpful messages for common errors
                        if error_code == 1810:
                            error_msg = f'WPK file not found. Please upload the WPK file for the target version to the manager\'s /var/ossec/var/upgrade/ directory.'
                        elif error_code == 1811:
                            error_msg = f'Agent version is already up to date or newer.'
                        elif 'WPK' in error_msg.upper() or 'wpk' in error_msg.lower():
                            error_msg = f'{error_msg}. Please check if the WPK file exists in /var/ossec/var/upgrade/'
                    else:
                        error_msg = str(error_info)
                    logger.warning(f"Upgrade failed_items for agent {agent_id}: {error_msg}")
                    return {'error': error_msg}

            # Check if there are affected_items (success)
            affected = result.get('data', {}).get('affected_items', [])
            if affected:
                print(f"[UPGRADE] Agent {agent_id}: SUCCESS - upgrade initiated")
                logger.info(f"Upgrade initiated for agent {agent_id}: {affected}")
                return {'success': True, 'result': result}
            else:
                # No affected items and no errors - Wazuh silently ignored the request
                # This typically means WPK not available or version mismatch
                print(f"[UPGRADE] Agent {agent_id}: FAILED - no affected_items in response")
                logger.warning(f"No affected_items in upgrade response for agent {agent_id}. Full response: {json.dumps(result)}")

                # Use the computed target version for error message
                target_v = target_version or 'latest'
                return {
                    'error': f'Upgrade task not created. Possible causes:\n'
                             f'1. WPK file for target version ({target_v}) not found in /var/ossec/var/upgrade/\n'
                             f'2. Agent already at target version\n'
                             f'3. Wazuh manager cannot download WPK automatically (check network/firewall)\n'
                             f'Please check the Upgrade Files in Node Management to verify WPK availability.',
                    'needs_wpk': True
                }

        except Exception as e:
            logger.error(f"Upgrade exception for agent {agent_id}: {str(e)}")
            return {'error': str(e)}

    def get_upgrade_result(self, agent_ids: list = None):
        """Get upgrade task results for agents.

        Args:
            agent_ids: List of agent IDs to check. If None, returns all.

        Returns:
            Dictionary with upgrade results per agent
        """
        try:
            params = {}
            if agent_ids:
                params['agents_list'] = ','.join(agent_ids)

            result = self.request('GET', '/agents/upgrade_result', params=params)

            # Handle Wazuh API error format (error in data.failed_items)
            if result.get('data', {}).get('failed_items'):
                failed = result['data']['failed_items']
                if failed:
                    # Log but don't treat as error - might be partial results
                    import logging
                    logging.getLogger('web_ui').debug(f"Upgrade result failed_items: {failed}")

            return result

        except Exception as e:
            return {'error': str(e)}


def create_app(max_login_attempts: int = 3, lockout_minutes: int = 30) -> 'Flask':
    """Create Flask application with login support.

    Args:
        max_login_attempts: Max failed login attempts before IP lockout
        lockout_minutes: IP lockout duration in minutes
    """
    if not HAS_FLASK:
        raise ImportError("Flask is required for web UI. Install with: pip install flask")

    if not HAS_REQUESTS:
        raise ImportError("requests is required for API calls. Install with: pip install requests")

    from datetime import datetime, timedelta

    app = Flask(__name__)
    app.secret_key = secrets.token_hex(32)

    # Security: Session cookie settings
    app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection
    web_session_timeout = get_config().web_session_timeout
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=web_session_timeout)  # Session timeout
    # Enable secure cookies if SSL is configured
    ssl_cert = os.environ.get('WEB_SSL_CERT')
    ssl_key = os.environ.get('WEB_SSL_KEY')
    if ssl_cert and ssl_key:
        app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS

    # Security response headers. The UI is built from inline <script>/<style>, so
    # 'unsafe-inline' cannot be dropped without rewriting the template; everything
    # else is locked down to self plus the one CDN that serves CodeMirror.
    CSP = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'"
    )

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault('Content-Security-Policy', CSP)
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('Referrer-Policy', 'no-referrer')
        response.headers.setdefault('Permissions-Policy',
                                    'geolocation=(), microphone=(), camera=(), payment=(), usb=()')
        response.headers.setdefault('Cross-Origin-Opener-Policy', 'same-origin')
        response.headers.setdefault('Cross-Origin-Resource-Policy', 'same-origin')
        response.headers.setdefault('Cache-Control', 'no-store')
        if os.environ.get('WEB_SSL_CERT') and os.environ.get('WEB_SSL_KEY'):
            response.headers.setdefault('Strict-Transport-Security',
                                        'max-age=31536000; includeSubDomains')
        # The Server header itself is handled by harden_wsgi_server(); setting it
        # here too would emit the header twice.
        return response

    # IP lockout tracking: {ip: {'attempts': count, 'locked_until': datetime}}
    ip_lockout = {}

    # Server-side credential store for JWT token refresh
    # Keyed by credential_id (stored in session), value = {host, port, username, password, session_exp}
    # Credentials are stored in server memory ONLY (never in cookie/client), cleared on logout/restart
    _credential_store = {}

    def _cleanup_expired_credentials():
        """Remove expired credential entries."""
        import time
        now = int(time.time())
        expired = [k for k, v in _credential_store.items() if v.get('session_exp', 0) < now]
        for k in expired:
            del _credential_store[k]

    def get_client_ip():
        """Get client IP address, considering proxies."""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        return request.remote_addr or 'unknown'

    def get_wazuh_api_token_timeout():
        """Get Wazuh API token timeout from api.yaml config file."""
        api_config_paths = [
            '/var/ossec/api/configuration/api.yaml',
            '/var/ossec/api/configuration/api.yml'
        ]
        for config_path in api_config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        import yaml
                        config = yaml.safe_load(f) or {}
                        # auth_token_exp_timeout is in seconds, default 900 (15 minutes)
                        return config.get('auth_token_exp_timeout', 900)
                except Exception:
                    pass
        return 900  # Default 15 minutes

    def is_ip_locked(ip):
        """Check if IP is currently locked."""
        if ip not in ip_lockout:
            return False, 0
        info = ip_lockout[ip]
        if info.get('locked_until'):
            remaining = (info['locked_until'] - datetime.now()).total_seconds()
            if remaining > 0:
                return True, int(remaining / 60) + 1
            else:
                # Lockout expired, reset
                del ip_lockout[ip]
        return False, 0

    def record_failed_login(ip):
        """Record a failed login attempt for an IP."""
        if ip not in ip_lockout:
            ip_lockout[ip] = {'attempts': 0, 'locked_until': None}
        ip_lockout[ip]['attempts'] += 1
        if ip_lockout[ip]['attempts'] >= max_login_attempts:
            ip_lockout[ip]['locked_until'] = datetime.now() + timedelta(minutes=lockout_minutes)
            return True
        return False

    def clear_failed_logins(ip):
        """Clear failed login attempts for an IP after successful login."""
        if ip in ip_lockout:
            del ip_lockout[ip]

    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'api_session' not in session:
                return jsonify({'error': 'Not authenticated'}), 401
            # Check web session expiration
            import time
            sess_data = session['api_session']
            session_exp = sess_data.get('session_exp', 0)
            if session_exp and int(time.time()) > session_exp:
                session.pop('api_session', None)
                return jsonify({'error': 'Session expired. Please login again.', 'session_expired': True}), 401
            return f(*args, **kwargs)
        return decorated_function

    def get_api_session() -> Optional[WazuhAPISession]:
        """Get API session from Flask session."""
        if 'api_session' not in session:
            return None
        sess_data = session['api_session']
        # Security: Create API session with token only (no password stored)
        api = WazuhAPISession(
            sess_data['host'],
            sess_data['port'],
            sess_data['username'],
            ''  # Password not stored for security
        )
        api.token = sess_data.get('token')
        return api

    def require_agent_ids(data):
        """Extract and validate agent_ids from a request body.

        Returns (agent_ids, None) on success, or (None, error_response) so the
        caller can `return err`. An absent or empty list is a client error.
        """
        agent_ids = data.get('agent_ids')
        if not isinstance(agent_ids, list) or not agent_ids:
            return None, (jsonify({'error': 'agent_ids is required and must be a non-empty list'}), 400)
        agent_ids = [str(a) for a in agent_ids]
        invalid = [a for a in agent_ids if not validate_agent_id(a)]
        if invalid:
            return None, (jsonify({'error': f'Invalid agent ID: {sanitize_for_log(invalid[0])}'}), 400)
        return agent_ids, None

    @app.route('/images/<path:filename>')
    def serve_image(filename):
        """Serve images from the images directory."""
        from flask import send_from_directory
        # Get the images directory path (relative to the main script)
        images_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'images')
        return send_from_directory(images_dir, filename)

    @app.route('/')
    def index():
        if 'api_session' not in session:
            return redirect(url_for('login'))
        sess_data = session['api_session']
        return render_template_string(
            HTML_TEMPLATE,
            username=sess_data['username'],
            host=sess_data['host'],
            port=sess_data['port'],
            token_exp=sess_data.get('token_exp', 0),
            token_iat=sess_data.get('token_iat', 0),
            session_exp=sess_data.get('session_exp', 0),
            version=VERSION
        )

    def issue_csrf_token():
        """Per-session token for the login form (the only cookie-authenticated
        HTML form in the app; the JSON API is covered by SameSite=Lax)."""
        token = session.get('csrf_token')
        if not token:
            token = secrets.token_urlsafe(32)
            session['csrf_token'] = token
        return token

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        host = request.form.get('host', 'localhost')
        port = request.form.get('port', '55000')
        username = request.form.get('username', '')

        # Check IP lockout
        client_ip = get_client_ip()
        locked, remaining_minutes = is_ip_locked(client_ip)
        if locked:
            error = f'IP locked due to too many failed attempts. Try again in {remaining_minutes} minute(s).'
            return render_template_string(
                LOGIN_TEMPLATE,
                error=error,
                host=host,
                port=port,
                username=username,
                token_timeout_minutes=web_session_timeout,
                csrf_token=issue_csrf_token(),
                version=VERSION
            )

        if request.method == 'POST':
            expected = session.get('csrf_token')
            supplied = request.form.get('csrf_token', '')
            if not expected or not secrets.compare_digest(str(expected), str(supplied)):
                logger.warning(f"LOGIN CSRF REJECT: from={sanitize_for_log(client_ip)}")
                session.pop('csrf_token', None)
                return render_template_string(
                    LOGIN_TEMPLATE,
                    error='Your session expired. Please try again.',
                    host=host, port=port, username=username,
                    token_timeout_minutes=web_session_timeout,
                    csrf_token=issue_csrf_token(),
                    version=VERSION
                ), 400
            password = request.form.get('password', '')
            try:
                port_int = int(port)
                api = WazuhAPISession(host, port_int, username, password)
                if api.authenticate():
                    clear_failed_logins(client_ip)  # Clear on successful login
                    # Security: Don't store password in session, only token
                    # Decode JWT to get actual expiration time
                    import time
                    import base64
                    token_exp = 0
                    token_iat = int(time.time())
                    try:
                        # JWT format: header.payload.signature
                        payload = api.token.split('.')[1]
                        # Add padding if needed
                        payload += '=' * (4 - len(payload) % 4)
                        decoded = json.loads(base64.urlsafe_b64decode(payload))
                        token_exp = decoded.get('exp', 0)
                        token_iat = decoded.get('iat', token_iat)
                    except Exception:
                        # Fallback to default 15 minutes if decode fails
                        token_exp = int(time.time()) + 900

                    session_exp = int(time.time()) + (web_session_timeout * 60)
                    # Store credentials in server-side memory for token refresh
                    # (never stored in session cookie - only credential_id is in cookie)
                    credential_id = secrets.token_hex(16)
                    _cleanup_expired_credentials()
                    _credential_store[credential_id] = {
                        'host': host,
                        'port': port_int,
                        'username': username,
                        'password': password,
                        'session_exp': session_exp
                    }

                    session['api_session'] = {
                        'host': host,
                        'port': port_int,
                        'username': username,
                        'token': api.token,
                        'token_exp': token_exp,  # Token expiration timestamp from JWT
                        'token_iat': token_iat,  # Token issued at timestamp
                        'session_exp': session_exp,  # Web session expiration timestamp
                        'credential_id': credential_id  # Reference to server-side credentials
                    }
                    session.permanent = True  # Use permanent session with timeout
                    logger.info(f"LOGIN SUCCESS: user={username} from={client_ip} api={host}:{port_int}")
                    return redirect(url_for('index'))
                else:
                    # Record failed attempt
                    just_locked = record_failed_login(client_ip)
                    logger.warning(f"LOGIN FAILED: user={username} from={client_ip} api={host}:{port_int}")
                    if just_locked:
                        logger.warning(f"IP LOCKED: {client_ip} due to too many failed attempts")
                        error = f'Too many failed attempts. IP locked for {lockout_minutes} minutes.'
                    else:
                        attempts_left = max_login_attempts - ip_lockout.get(client_ip, {}).get('attempts', 0)
                        error = f'Authentication failed. {attempts_left} attempt(s) remaining.'
            except ValueError:
                error = 'Invalid port number.'
            except Exception as e:
                error_msg = str(e)
                logger.warning(f"LOGIN ERROR: user={username} from={client_ip} api={host}:{port} error={error_msg}")
                # Only record failed attempt for auth errors, not connection errors
                if "Invalid username or password" in error_msg:
                    just_locked = record_failed_login(client_ip)
                    if just_locked:
                        error = f'Too many failed attempts. IP locked for {lockout_minutes} minutes.'
                    else:
                        attempts_left = max_login_attempts - ip_lockout.get(client_ip, {}).get('attempts', 0)
                        error = f'{error_msg}. {attempts_left} attempt(s) remaining.'
                else:
                    # Connection/API errors - show the descriptive message
                    error = error_msg

        return render_template_string(
            LOGIN_TEMPLATE,
            error=error,
            host=host,
            port=port,
            username=username,
            token_timeout_minutes=web_session_timeout,
            csrf_token=issue_csrf_token(),
            version=VERSION
        )

    @app.route('/logout')
    def logout():
        api_session = session.get('api_session', {})
        username = api_session.get('username', 'unknown')
        client_ip = get_client_ip()
        # Clean up server-side credentials
        credential_id = api_session.get('credential_id')
        if credential_id:
            _credential_store.pop(credential_id, None)
        logger.info(f"LOGOUT: user={username} from={client_ip}")
        session.pop('api_session', None)
        return redirect(url_for('login'))

    # Global error handler for session expired
    @app.errorhandler(SessionExpiredException)
    def handle_session_expired(e):
        return jsonify({'error': 'Session expired. Please login again.', 'session_expired': True}), 401

    @app.route('/api/session/refresh', methods=['POST'])
    @login_required
    def refresh_session_token():
        """Refresh JWT token by re-authenticating with stored credentials."""
        import time
        import base64
        try:
            sess_data = session['api_session']
            # Check web session is still valid
            session_exp = sess_data.get('session_exp', 0)
            if session_exp and int(time.time()) > session_exp:
                session.pop('api_session', None)
                return jsonify({'error': 'Session expired', 'session_expired': True}), 401

            # Look up stored credentials
            credential_id = sess_data.get('credential_id')
            if not credential_id or credential_id not in _credential_store:
                return jsonify({'error': 'No stored credentials for refresh'}), 401

            creds = _credential_store[credential_id]

            # Re-authenticate with stored credentials to get a new token
            api = WazuhAPISession(creds['host'], creds['port'], creds['username'], creds['password'])
            if api.authenticate():
                # Decode new JWT to get exp/iat
                token_exp = 0
                token_iat = int(time.time())
                try:
                    payload = api.token.split('.')[1]
                    payload += '=' * (4 - len(payload) % 4)
                    decoded = json.loads(base64.urlsafe_b64decode(payload))
                    token_exp = decoded.get('exp', 0)
                    token_iat = decoded.get('iat', token_iat)
                except Exception:
                    token_exp = int(time.time()) + 900

                # Update session with new token
                sess_data['token'] = api.token
                sess_data['token_exp'] = token_exp
                sess_data['token_iat'] = token_iat
                session['api_session'] = sess_data
                session.modified = True

                logger.info(f"TOKEN REFRESH: user={sess_data.get('username')} new_exp={token_exp}")
                return jsonify({'token_exp': token_exp})
            else:
                logger.warning(f"TOKEN REFRESH FAILED: user={sess_data.get('username')}")
                return jsonify({'error': 'Token refresh failed'}), 401
        except Exception as e:
            logger.error(f"TOKEN REFRESH ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents', methods=['GET'])
    @login_required
    def get_agents():
        try:
            api = get_api_session()
            agents = api.get_agents()
            return jsonify({'agents': agents})
        except SessionExpiredException:
            raise  # Let the error handler handle it
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/<agent_id>', methods=['GET'])
    @login_required
    def get_agent_detail(agent_id):
        if not validate_agent_id(agent_id):
            return jsonify({'error': 'Invalid agent ID'}), 400
        try:
            api = get_api_session()
            agent = api.get_agent_details(agent_id)
            if not agent:
                return jsonify({'error': 'Agent not found'}), 404
            return jsonify({'agent': agent})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/queue-size', methods=['GET'])
    @login_required
    def get_agents_queue_size():
        """Get queue database sizes for all agents from /var/ossec/queue/db/"""
        import socket
        import subprocess
        try:
            wazuh_path = '/var/ossec'
            queue_db_path = os.path.join(wazuh_path, 'queue', 'db')
            local_hostname = socket.gethostname()

            # Get cluster nodes info
            api = get_api_session()
            nodes = api.get_nodes()

            # Get SSH config
            config = get_config()

            # Determine local node name
            local_node_name = local_hostname
            other_nodes = []
            ssh_failed_nodes = []
            loaded_nodes = []

            for n in nodes:
                node_name = n.get('name', '')
                if (node_name == local_hostname or
                    node_name.replace('-server', '') == local_hostname or
                    local_hostname.replace('-server', '') == node_name.replace('-server', '')):
                    local_node_name = node_name
                else:
                    other_nodes.append({
                        'name': node_name,
                        'ip': n.get('ip', ''),
                        'type': n.get('type', '')
                    })

            queue_sizes = {}  # agent_id -> list of {size, node}

            # Helper function to add queue size entry
            def add_queue_entry(agent_id, size, node_name):
                if agent_id not in queue_sizes:
                    queue_sizes[agent_id] = []
                queue_sizes[agent_id].append({
                    'size': size,
                    'node': node_name
                })

            # Read local queue db
            if os.path.exists(queue_db_path):
                for db_file in glob.glob(os.path.join(queue_db_path, '*.db')):
                    filename = os.path.basename(db_file)
                    agent_id = filename.replace('.db', '')
                    try:
                        size = os.path.getsize(db_file)
                        add_queue_entry(agent_id, size, local_node_name)
                    except OSError:
                        pass
                loaded_nodes.append(local_node_name)

            # Try to read remote queue db via SSH
            for node in other_nodes:
                node_name = node['name']
                ssh_cfg = config.get_ssh_config_for_node(node_name)

                if ssh_cfg:
                    try:
                        # Get list of db files and their sizes from remote node
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=5',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"find {queue_db_path} -name '*.db' -exec stat --format='%n %s' {{}} \\; 2>/dev/null"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)

                        if result.returncode == 0 and result.stdout.strip():
                            for line in result.stdout.strip().split('\n'):
                                if line:
                                    parts = line.rsplit(' ', 1)
                                    if len(parts) == 2:
                                        filepath, size_str = parts
                                        filename = os.path.basename(filepath)
                                        agent_id = filename.replace('.db', '')
                                        try:
                                            size = int(size_str)
                                            add_queue_entry(agent_id, size, node_name)
                                        except ValueError:
                                            pass
                            loaded_nodes.append(node_name)
                        else:
                            logger.warning(f"SSH queue-size failed for {node_name}: returncode={result.returncode} stderr={result.stderr.strip()}")
                            ssh_failed_nodes.append(node_name)
                    except Exception as e:
                        logger.warning(f"SSH queue-size failed for {node_name}: {e}")
                        ssh_failed_nodes.append(node_name)
                else:
                    logger.warning(f"SSH queue-size skipped for {node_name}: no SSH config")
                    ssh_failed_nodes.append(node_name)

            # Build note message
            if ssh_failed_nodes:
                note = f"Queue sizes loaded from: {', '.join(loaded_nodes)}. Failed nodes: {', '.join(ssh_failed_nodes)}."
            else:
                note = f"Queue sizes loaded from all nodes: {', '.join(loaded_nodes)}."

            # Log for debugging
            for agent_id, entries in queue_sizes.items():
                for entry in entries:
                    logger.debug(f"Queue DB: agent={agent_id}, size={entry['size']} bytes, node={entry['node']}")

            return jsonify({
                'queue_sizes': queue_sizes,
                'path': queue_db_path,
                'local_node': local_node_name,
                'loaded_nodes': loaded_nodes,
                'other_nodes': other_nodes,
                'ssh_failed_nodes': ssh_failed_nodes,
                'has_other_nodes': len(other_nodes) > 0,
                'note': note
            })
        except Exception as e:
            return jsonify({'error': str(e), 'queue_sizes': {}}), 500

    def get_current_user():
        """Get current logged in username for logging."""
        api_session = session.get('api_session', {})
        return api_session.get('username', 'unknown')

    @app.route('/api/agents/queue-db/clean', methods=['POST'])
    @login_required
    def clean_agents_queue_db():
        """Delete queue DB files for specified agents and restart them."""
        import socket
        import subprocess

        try:
            data = request.get_json(silent=True) or {}
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            # agent_nodes: {agent_id: [node1, node2, ...]} - nodes that have queue DB for each agent
            agent_nodes = data.get('agent_nodes', {})

            # Validate agent IDs
            for aid in agent_ids:
                if not validate_agent_id(aid):
                    return jsonify({'error': f'Invalid agent ID: {aid}'}), 400

            user = get_current_user()
            logger.info(f"QUEUE_DB_CLEAN: user={user} agents={agent_ids} agent_nodes={agent_nodes} dry_run={dry_run}")

            wazuh_path = '/var/ossec'
            queue_db_path = os.path.join(wazuh_path, 'queue', 'db')
            local_hostname = socket.gethostname()

            # Get cluster nodes info
            api = get_api_session()
            nodes = api.get_nodes()
            config = get_config()

            # Determine local node name
            local_node_name = local_hostname

            for n in nodes:
                node_name = n.get('name', '')
                if (node_name == local_hostname or
                    node_name.replace('-server', '') == local_hostname or
                    local_hostname.replace('-server', '') == node_name.replace('-server', '')):
                    local_node_name = node_name
                    break

            results = []

            for aid in agent_ids:
                db_filename = f"{aid}.db"
                local_db_path = os.path.join(queue_db_path, db_filename)
                agent_result = {'agent_id': aid, 'deleted': [], 'errors': []}

                # Get target nodes for this agent (from frontend queue_entries data)
                target_nodes = agent_nodes.get(aid, [])

                # Delete local DB (only if local node is in target list, or no target info available)
                if not target_nodes or local_node_name in target_nodes:
                    if os.path.exists(local_db_path):
                        if dry_run:
                            agent_result['deleted'].append({'node': local_node_name, 'path': local_db_path, 'dry_run': True})
                        else:
                            try:
                                os.remove(local_db_path)
                                agent_result['deleted'].append({'node': local_node_name, 'path': local_db_path})
                                logger.info(f"QUEUE_DB_CLEAN: deleted {local_db_path} on {local_node_name}")
                            except Exception as e:
                                agent_result['errors'].append({'node': local_node_name, 'error': str(e)})

                # Delete remote node DB via SSH (only target nodes with queue DB)
                remote_targets = [n for n in target_nodes if n != local_node_name] if target_nodes else []
                for node_name in remote_targets:
                    ssh_cfg = config.get_ssh_config_for_node(node_name)
                    if not ssh_cfg:
                        agent_result['errors'].append({'node': node_name, 'error': 'SSH not configured'})
                        continue

                    remote_path = os.path.join(queue_db_path, db_filename)
                    if dry_run:
                        agent_result['deleted'].append({'node': node_name, 'path': remote_path, 'dry_run': True})
                    else:
                        try:
                            ssh_cmd = [
                                'ssh',
                                '-i', ssh_cfg['key_file'],
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'ConnectTimeout=5',
                                '-p', str(ssh_cfg['port']),
                                f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                                f"rm -f {remote_path}"
                            ]
                            result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
                            if result.returncode == 0:
                                agent_result['deleted'].append({'node': node_name, 'path': remote_path})
                                logger.info(f"QUEUE_DB_CLEAN: deleted {remote_path} on {node_name}")
                            else:
                                agent_result['errors'].append({'node': node_name, 'error': result.stderr.strip()})
                        except Exception as e:
                            agent_result['errors'].append({'node': node_name, 'error': str(e)})

                results.append(agent_result)

            # Restart agents to regenerate queue DB
            restart_result = None
            if not dry_run and agent_ids:
                try:
                    restart_result = api.restart_agents(agent_ids)
                    logger.info(f"QUEUE_DB_CLEAN: restarted agents {agent_ids}")
                except Exception as e:
                    logger.error(f"QUEUE_DB_CLEAN: restart failed: {e}")

            # Summary
            total_deleted = sum(len(r['deleted']) for r in results)
            total_errors = sum(len(r['errors']) for r in results)

            return jsonify({
                'message': f"{'[DRY-RUN] Would clean' if dry_run else 'Cleaned'} Queue DB for {len(agent_ids)} agent(s) ({total_deleted} file(s) {'would be ' if dry_run else ''}deleted, {total_errors} error(s))",
                'details': results,
                'restart_result': restart_result,
                'dry_run': dry_run,
                'errors': total_errors > 0
            })
        except Exception as e:
            logger.error(f"QUEUE_DB_CLEAN ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents', methods=['DELETE'])
    @login_required
    def delete_agents():
        try:
            data = request.get_json(silent=True) or {}
            agent_ids, err = require_agent_ids(data)
            if err:
                return err
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            if dry_run:
                logger.info(f"AGENT DELETE [DRY-RUN]: user={user} agents={agent_ids}")
                return jsonify({
                    'message': f"[DRY-RUN] Would delete {len(agent_ids)} agents",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.delete_agents(agent_ids)
            affected = len(result.get('data', {}).get('affected_items', []))
            logger.info(f"AGENT DELETE: user={user} agents={agent_ids} affected={affected}")
            return jsonify({
                'message': f"Deleted {affected}/{len(agent_ids)} agents",
                'result': result
            })
        except Exception as e:
            logger.error(f"AGENT DELETE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/restart', methods=['POST'])
    @login_required
    def restart_agents():
        try:
            data = request.get_json(silent=True) or {}
            agent_ids, err = require_agent_ids(data)
            if err:
                return err
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            if dry_run:
                logger.info(f"AGENT RESTART [DRY-RUN]: user={user} agents={agent_ids}")
                return jsonify({
                    'message': f"[DRY-RUN] Would restart {len(agent_ids)} agents",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.restart_agents(agent_ids)
            affected = len(result.get('data', {}).get('affected_items', []))
            logger.info(f"AGENT RESTART: user={user} agents={agent_ids} affected={affected}")
            return jsonify({
                'message': f"Restarted {affected}/{len(agent_ids)} agents",
                'result': result
            })
        except Exception as e:
            logger.error(f"AGENT RESTART ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/reconnect', methods=['POST'])
    @login_required
    def reconnect_agents():
        try:
            data = request.get_json(silent=True) or {}
            agent_ids, err = require_agent_ids(data)
            if err:
                return err
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            if dry_run:
                logger.info(f"AGENT RECONNECT [DRY-RUN]: user={user} agents={agent_ids}")
                return jsonify({
                    'message': f"[DRY-RUN] Would reconnect {len(agent_ids)} agents",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.reconnect_agents(agent_ids)
            affected = len(result.get('data', {}).get('affected_items', []))
            logger.info(f"AGENT RECONNECT: user={user} agents={agent_ids} affected={affected}")
            return jsonify({
                'message': f"Reconnected {affected}/{len(agent_ids)} agents",
                'result': result
            })
        except Exception as e:
            logger.error(f"AGENT RECONNECT ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/upgrade', methods=['POST'])
    @login_required
    def upgrade_agents():
        """Upgrade selected agents to a specified or latest version."""
        try:
            data = request.get_json(silent=True) or {}
            agent_ids, err = require_agent_ids(data)
            if err:
                return err
            version = data.get('version')  # None means use manager version
            force = data.get('force', False)
            dry_run = data.get('dry_run', False)

            user = get_current_user()
            api = get_api_session()

            # Get manager version to use as target when no version specified
            manager_version = None
            if not version:
                try:
                    nodes = api.get_nodes()
                    print(f"[UPGRADE] Nodes: {nodes}")
                    master_node = next((n for n in nodes if n.get('type') == 'master'), nodes[0] if nodes else None)
                    if master_node:
                        raw_version = master_node.get('version', '')
                        manager_version = raw_version.replace('Wazuh ', '').replace('v', '').strip()
                        print(f"[UPGRADE] Master node: {master_node.get('name')}, raw_version={raw_version}, manager_version={manager_version}")
                        logger.info(f"Manager version detected: {manager_version}")
                except Exception as e:
                    print(f"[UPGRADE] ERROR getting manager version: {e}")
                    logger.warning(f"Could not get manager version: {e}")

            version_str = f"v{version}" if version else f"v{manager_version}" if manager_version else "latest"

            if dry_run:
                logger.info(f"AGENT UPGRADE [DRY-RUN]: user={user} agents={agent_ids} version={version_str} force={force}")
                return jsonify({
                    'message': f"[DRY-RUN] Would upgrade {len(agent_ids)} agents to {version_str}",
                    'dry_run': True,
                    'success_count': len(agent_ids),
                    'fail_count': 0
                })

            # Upgrade agents one by one and collect results
            success_count = 0
            fail_count = 0
            failed_agents = []

            for agent_id in agent_ids:
                try:
                    result = api.upgrade_agent(agent_id, version=version, force=force, manager_version=manager_version)
                    if result.get('error'):
                        fail_count += 1
                        failed_agents.append({'id': agent_id, 'error': result.get('error')})
                    else:
                        success_count += 1
                except Exception as e:
                    fail_count += 1
                    failed_agents.append({'id': agent_id, 'error': str(e)})

            logger.info(f"AGENT UPGRADE: user={user} agents={agent_ids} version={version_str} force={force} success={success_count} fail={fail_count}")

            return jsonify({
                'message': f"Upgrade initiated: {success_count} success, {fail_count} failed",
                'success_count': success_count,
                'fail_count': fail_count,
                'failed_agents': failed_agents if failed_agents else None
            })
        except Exception as e:
            logger.error(f"AGENT UPGRADE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/upgrade-result', methods=['GET'])
    @login_required
    def get_upgrade_result():
        """Get upgrade task results for agents."""
        try:
            api = get_api_session()

            agent_ids = request.args.get('agent_ids', '').split(',') if request.args.get('agent_ids') else None
            if agent_ids:
                agent_ids = [aid.strip() for aid in agent_ids if aid.strip()]

            result = api.get_upgrade_result(agent_ids if agent_ids else None)
            logger.debug(f"Upgrade result API response: {result}")

            # Handle various Wazuh API error response formats
            if result.get('error'):
                error_info = result.get('error')
                # Error might be a dict with 'message' or just a string/code
                if isinstance(error_info, dict):
                    error_msg = error_info.get('message', str(error_info))
                else:
                    error_msg = str(error_info)

                # Wazuh returns error code 1 or "No task in DB" when no tasks found
                if error_msg in ['1', '2'] or 'no task' in error_msg.lower() or 'not found' in error_msg.lower():
                    return jsonify({'results': [], 'total': 0})

                logger.warning(f"Upgrade result error: {error_msg}")
                return jsonify({'error': error_msg}), 400

            # Check for failed_items in data (Wazuh API often puts errors here)
            data = result.get('data', {})
            failed_items = data.get('failed_items', [])
            if failed_items and not data.get('affected_items'):
                # All queries failed - likely no tasks for these agents
                error_msgs = []
                for fi in failed_items:
                    err = fi.get('error', {})
                    if isinstance(err, dict):
                        error_msgs.append(err.get('message', str(err)))
                    else:
                        error_msgs.append(str(err))
                # "No task in DB" or similar means no upgrade tasks - return empty
                if any('no task' in m.lower() or m in ['1', '2'] for m in error_msgs):
                    return jsonify({'results': [], 'total': 0})

            # Parse upgrade results
            items = data.get('affected_items', [])
            upgrade_results = []
            for item in items:
                upgrade_results.append({
                    'agent_id': str(item.get('agent', '')),
                    'task_id': item.get('task_id'),
                    'status': item.get('status', 'unknown'),
                    'error': item.get('error_message', ''),
                    'create_time': item.get('create_time', ''),
                    'update_time': item.get('update_time', '')
                })

            return jsonify({
                'results': upgrade_results,
                'total': len(upgrade_results)
            })
        except Exception as e:
            logger.error(f"GET UPGRADE RESULT ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups', methods=['GET'])
    @login_required
    def get_groups():
        try:
            api = get_api_session()
            groups = api.get_groups()
            return jsonify({'groups': groups})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups', methods=['POST'])
    @login_required
    def create_group():
        try:
            data = request.get_json(silent=True) or {}
            name = data.get('name')
            if not name:
                return jsonify({'error': 'Group name is required'}), 400
            if not validate_group_name(name):
                return jsonify({'error': 'Invalid group name'}), 400
            dry_run = data.get('dry_run', False)
            user = get_current_user()

            if dry_run:
                logger.info(f"GROUP CREATE [DRY-RUN]: user={user} group={name}")
                return jsonify({
                    'message': f"[DRY-RUN] Would create group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.create_group(name)
            logger.info(f"GROUP CREATE: user={user} group={name}")
            return jsonify({'success': True, 'message': f"Group '{name}' created", 'result': result})
        except Exception as e:
            logger.error(f"GROUP CREATE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>', methods=['DELETE'])
    @login_required
    def delete_group(name):
        # Validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            dry_run = data.get('dry_run', False)
            user = get_current_user()

            if dry_run:
                logger.info(f"GROUP DELETE [DRY-RUN]: user={user} group={name}")
                return jsonify({
                    'message': f"[DRY-RUN] Would delete group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.delete_group(name)
            logger.info(f"GROUP DELETE: user={user} group={name}")
            return jsonify({'success': True, 'message': f"Group '{name}' deleted", 'result': result})
        except Exception as e:
            logger.error(f"GROUP DELETE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/rename', methods=['POST'])
    @login_required
    def rename_group():
        """Rename a group by creating new, copying config, moving agents, deleting old."""
        import shutil
        try:
            data = request.get_json(silent=True) or {}
            old_name = data.get('old_name', '')
            new_name = data.get('new_name', '')
            dry_run = data.get('dry_run', False)
            user = get_current_user()

            if not old_name or not new_name:
                return jsonify({'error': 'Both old_name and new_name are required'}), 400

            # Validate group names
            if not validate_group_name(old_name) or not validate_group_name(new_name):
                return jsonify({'error': 'Invalid group name'}), 400

            if old_name == new_name:
                return jsonify({'error': 'New name is the same as old name'}), 400

            # Validate group names (security: prevent path traversal)
            if '/' in old_name or '\\' in old_name or '..' in old_name:
                return jsonify({'error': 'Invalid old group name'}), 400
            if '/' in new_name or '\\' in new_name or '..' in new_name:
                return jsonify({'error': 'Invalid new group name'}), 400

            api = get_api_session()

            # Get agents in old group
            agents = api.get_agents(group=old_name)
            agent_ids = [a.get('id') for a in agents if a.get('id')]
            agent_count = len(agent_ids)

            # Check if old group has config files
            old_group_path = f'/var/ossec/etc/shared/{old_name}'
            new_group_path = f'/var/ossec/etc/shared/{new_name}'
            has_config = os.path.exists(old_group_path)
            config_files = []
            if has_config:
                config_files = [f for f in os.listdir(old_group_path) if os.path.isfile(os.path.join(old_group_path, f))]

            if dry_run:
                logger.info(f"GROUP RENAME [DRY-RUN]: user={user} old={old_name} new={new_name} agents={agent_count}")
                steps = [
                    f"1. Create new group '{new_name}'",
                    f"2. Copy config files ({len(config_files)} files: {', '.join(config_files[:5])}{'...' if len(config_files) > 5 else ''})" if config_files else "2. No config files to copy",
                    f"3. Move {agent_count} agent(s) to '{new_name}'",
                    f"4. Delete old group '{old_name}'"
                ]
                return jsonify({
                    'message': f"[DRY-RUN] Would rename '{old_name}' to '{new_name}' ({agent_count} agents, {len(config_files)} config files)",
                    'steps': steps,
                    'dry_run': True
                })

            # Step 1: Create new group
            try:
                api.create_group(new_name)
                logger.info(f"GROUP RENAME: Created new group '{new_name}'")
            except Exception as e:
                if 'already exists' not in str(e).lower():
                    raise Exception(f"Failed to create new group: {e}")

            # Step 2: Copy config files from old group to new group
            copied_files = []
            if has_config and os.path.exists(new_group_path):
                try:
                    for filename in config_files:
                        src = os.path.join(old_group_path, filename)
                        dst = os.path.join(new_group_path, filename)
                        shutil.copy2(src, dst)
                        copied_files.append(filename)
                    logger.info(f"GROUP RENAME: Copied {len(copied_files)} config files to '{new_name}'")
                except Exception as e:
                    logger.warning(f"GROUP RENAME: Failed to copy some config files: {e}")

            # Step 3: Move agents to new group (if any)
            if agent_ids:
                try:
                    api.add_agents_to_group(new_name, agent_ids)
                    logger.info(f"GROUP RENAME: Moved {agent_count} agents to '{new_name}'")
                except Exception as e:
                    logger.error(f"GROUP RENAME: Failed to move agents: {e}")
                    # Try to clean up - delete the new group
                    try:
                        api.delete_group(new_name)
                    except:
                        pass
                    raise Exception(f"Failed to move agents: {e}")

            # Step 4: Delete old group
            try:
                api.delete_group(old_name)
                logger.info(f"GROUP RENAME: Deleted old group '{old_name}'")
            except Exception as e:
                logger.warning(f"GROUP RENAME: Failed to delete old group (agents already moved): {e}")

            logger.info(f"GROUP RENAME: user={user} old={old_name} new={new_name} agents={agent_count} configs={len(copied_files)}")
            return jsonify({
                'success': True,
                'message': f"Group renamed from '{old_name}' to '{new_name}' ({agent_count} agents moved, {len(copied_files)} config files copied)"
            })

        except Exception as e:
            logger.error(f"GROUP RENAME ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/agents', methods=['POST'])
    @login_required
    def add_agents_to_group(name):
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would add {len(agent_ids)} agents to group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.add_agents_to_group(name, agent_ids)

            # Log result for debugging
            print(f"[DEBUG] Add to group '{name}' agents={agent_ids}: {result}")

            # Check for errors in the result (error != 0 means failure)
            if result.get('error') and result.get('error') != 0:
                return jsonify({
                    'message': f"Error: {result.get('error')}",
                    'result': result
                }), 400

            data = result.get('data', {})
            affected = len(data.get('affected_items', []))
            failed = data.get('failed_items', [])
            total_failed = data.get('total_failed_items', 0)

            msg = f"Added {affected}/{len(agent_ids)} agents to '{name}'"

            # Parse failed items - id can be string or list
            if total_failed > 0 or failed:
                error_msgs = []
                for f in failed[:5]:
                    err_msg = f.get('error', {}).get('message', 'unknown error')
                    ids = f.get('id', [])
                    if isinstance(ids, list):
                        ids_str = ','.join(str(i) for i in ids[:3])
                    else:
                        ids_str = str(ids)
                    error_msgs.append(f"{ids_str}: {err_msg}")
                if error_msgs:
                    msg += f". Errors: {'; '.join(error_msgs)}"

            return jsonify({
                'message': msg,
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/agents', methods=['DELETE'])
    @login_required
    def remove_agents_from_group(name):
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            agent_ids = data.get('agent_ids', [])
            dry_run = data.get('dry_run', False)

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would remove {len(agent_ids)} agents from group '{name}'",
                    'dry_run': True
                })

            api = get_api_session()
            result = api.remove_agents_from_group(name, agent_ids)

            # Check for errors in the result (error != 0 means failure)
            if result.get('error') and result.get('error') != 0:
                return jsonify({
                    'message': f"Error: {result.get('error')}",
                    'result': result
                }), 400

            affected = len(result.get('data', {}).get('affected_items', []))
            failed = result.get('data', {}).get('failed_items', [])
            failed_count = len(failed)

            msg = f"Removed {affected}/{len(agent_ids)} agents from '{name}'"
            if failed_count > 0:
                errors = [f"{f.get('id', '?')}: {f.get('error', {}).get('message', 'unknown')}" for f in failed[:3]]
                msg += f". Failed: {', '.join(errors)}"

            return jsonify({
                'message': msg,
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/agents/all', methods=['DELETE'])
    @login_required
    def remove_all_agents_from_group(name):
        """Remove all agents from a group."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            dry_run = data.get('dry_run', False)

            api = get_api_session()
            # First get all agents in this group
            all_agents = api.get_agents()
            agents_in_group = [a for a in all_agents if name in (a.get('group') or '').split(',')]
            agent_ids = [a['id'] for a in agents_in_group]

            if len(agent_ids) == 0:
                return jsonify({'message': f"No agents in group '{name}'"})

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would remove {len(agent_ids)} agents from group '{name}'",
                    'dry_run': True
                })

            result = api.remove_agents_from_group(name, agent_ids)

            # Check for errors (error != 0 means failure)
            if result.get('error') and result.get('error') != 0:
                return jsonify({'message': f"Error: {result.get('error')}", 'result': result}), 400

            affected = len(result.get('data', {}).get('affected_items', []))
            return jsonify({
                'message': f"Removed {affected}/{len(agent_ids)} agents from group '{name}'",
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/exclusive', methods=['POST'])
    @login_required
    def set_exclusive_group(name):
        """Remove agents in this group from all other groups."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            dry_run = data.get('dry_run', False)

            api = get_api_session()
            # Get all agents in this group
            all_agents = api.get_agents()
            agents_in_group = [a for a in all_agents if name in (a.get('group') or '').split(',')]

            if len(agents_in_group) == 0:
                return jsonify({'message': f"No agents in group '{name}'"})

            # Find agents that belong to other groups
            affected_count = 0
            other_groups_removed = set()

            for agent in agents_in_group:
                agent_groups = [g.strip() for g in (agent.get('group') or '').split(',') if g.strip()]
                other_groups = [g for g in agent_groups if g != name]

                if other_groups:
                    if dry_run:
                        for g in other_groups:
                            other_groups_removed.add(g)
                        affected_count += 1
                    else:
                        # Remove agent from each other group
                        for other_group in other_groups:
                            api.remove_agents_from_group(other_group, [agent['id']])
                            other_groups_removed.add(other_group)
                        affected_count += 1

            if affected_count == 0:
                return jsonify({'message': f"All agents in '{name}' already belong only to this group"})

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would remove {affected_count} agent(s) from other groups: {', '.join(sorted(other_groups_removed))}",
                    'dry_run': True
                })

            return jsonify({
                'message': f"Removed {affected_count} agent(s) from other groups: {', '.join(sorted(other_groups_removed))}"
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/move', methods=['POST'])
    @login_required
    def move_group_agents(name):
        """Move all agents from one group to another."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            target_group = data.get('target_group')
            dry_run = data.get('dry_run', False)

            if not target_group:
                return jsonify({'error': 'Target group is required'}), 400

            # Validate target group name too
            if not validate_group_name(target_group):
                return jsonify({'error': 'Invalid target group name'}), 400

            api = get_api_session()
            # Get all agents in source group
            all_agents = api.get_agents()
            agents_in_group = [a for a in all_agents if name in (a.get('group') or '').split(',')]
            agent_ids = [a['id'] for a in agents_in_group]

            if len(agent_ids) == 0:
                return jsonify({'message': f"No agents in group '{name}'"})

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would move {len(agent_ids)} agents from '{name}' to '{target_group}'",
                    'dry_run': True
                })

            # Add agents to target group first
            add_result = api.add_agents_to_group(target_group, agent_ids)
            added = len(add_result.get('data', {}).get('affected_items', []))

            # Then remove from source group
            remove_result = api.remove_agents_from_group(name, agent_ids)
            removed = len(remove_result.get('data', {}).get('affected_items', []))

            return jsonify({
                'message': f"Moved {removed}/{len(agent_ids)} agents from '{name}' to '{target_group}'",
                'added': added,
                'removed': removed
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/import', methods=['POST'])
    @login_required
    def import_agents_to_group(name):
        """Import agents to a group from CSV data."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            agents_data = data.get('agents', [])
            dry_run = data.get('dry_run', False)

            if not agents_data:
                return jsonify({'error': 'No agents data provided'}), 400

            api = get_api_session()
            all_agents = api.get_agents()

            # Build lookup tables
            id_map = {a['id']: a for a in all_agents}
            name_map = {a['name'].lower(): a for a in all_agents}
            ip_map = {a['ip']: a for a in all_agents}

            added = []
            not_found = []
            already_in_group = []
            agent_ids_to_add = []

            for row in agents_data:
                agent = None
                identifier = None
                primary = row.get('primaryMatch', 'id')

                # Define match order based on primaryMatch (leftmost column in CSV)
                if primary == 'id':
                    match_order = ['id', 'name', 'ip']
                elif primary == 'name':
                    match_order = ['name', 'id', 'ip']
                else:  # ip
                    match_order = ['ip', 'id', 'name']

                # Try to find agent in priority order
                for match_type in match_order:
                    if agent:
                        break
                    if match_type == 'id' and row.get('id'):
                        agent = id_map.get(row['id'])
                        identifier = identifier or f"ID:{row['id']}"
                    elif match_type == 'name' and row.get('name'):
                        agent = name_map.get(row['name'].lower())
                        identifier = identifier or f"Name:{row['name']}"
                    elif match_type == 'ip' and row.get('ip'):
                        agent = ip_map.get(row['ip'])
                        identifier = identifier or f"IP:{row['ip']}"

                if not identifier:
                    continue

                if not agent:
                    not_found.append(identifier)
                    continue

                # Check if already in group
                current_groups = (agent.get('group') or '').split(',')
                current_groups = [g.strip() for g in current_groups if g.strip()]
                if name in current_groups:
                    already_in_group.append(f"{agent['id']} ({agent['name']})")
                    continue

                added.append(f"{agent['id']} ({agent['name']})")
                agent_ids_to_add.append(agent['id'])

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would add {len(agent_ids_to_add)} agents to group '{name}'",
                    'dry_run': True,
                    'added': added,
                    'not_found': not_found,
                    'already_in_group': already_in_group
                })

            # Actually add agents
            if agent_ids_to_add:
                api.add_agents_to_group(name, agent_ids_to_add)

            return jsonify({
                'message': f"Added {len(agent_ids_to_add)} agents to group '{name}'",
                'added': added,
                'not_found': not_found,
                'already_in_group': already_in_group
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/config', methods=['GET'])
    @login_required
    def get_group_config(name):
        """Get agent.conf for a group."""
        # Security: validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:

            config_path = f'/var/ossec/etc/shared/{name}/agent.conf'
            user = get_current_user()

            if not os.path.exists(config_path):
                # Return empty template if file doesn't exist
                default_content = '''<!-- agent.conf for group: ''' + name + ''' -->
<agent_config>
    <!-- Add your configuration here -->
    <!-- Example:
    <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/example.log</location>
    </localfile>
    -->
</agent_config>
'''
                return jsonify({
                    'content': default_content,
                    'path': config_path,
                    'exists': False
                })

            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()

            logger.info(f"Group config read: {config_path} by user '{user}'")
            return jsonify({
                'content': content,
                'path': config_path,
                'exists': True
            })

        except Exception as e:
            logger.error(f"Group config read error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/config', methods=['PUT'])
    @login_required
    def save_group_config(name):
        """Save agent.conf for a group."""
        # Security: validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            content = data.get('content', '')
            user = get_current_user()

            group_dir = f'/var/ossec/etc/shared/{name}'
            config_path = f'{group_dir}/agent.conf'

            # Check if group directory exists
            if not os.path.exists(group_dir):
                return jsonify({'error': f"Group '{name}' does not exist"}), 404

            # Create backup if file exists
            backup_path = None
            if os.path.exists(config_path):
                from datetime import datetime
                backup_dir = '/var/ossec/etc/backup'
                os.makedirs(backup_dir, exist_ok=True)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_path = f'{backup_dir}/agent.conf.{name}.{timestamp}.bak'
                import shutil
                shutil.copy2(config_path, backup_path)
                logger.info(f"Group config backup created: {backup_path}")

            # Save new content
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(content)

            # Set proper permissions (ossec:ossec)
            try:
                import pwd
                import grp
                uid = pwd.getpwnam('ossec').pw_uid
                gid = grp.getgrnam('ossec').gr_gid
                os.chown(config_path, uid, gid)
                os.chmod(config_path, 0o660)
            except:
                pass  # Ignore permission errors on non-Wazuh systems

            logger.info(f"Group config saved: {config_path} by user '{user}'")
            return jsonify({
                'success': True,
                'message': f"Config saved for group '{name}'",
                'backup_path': backup_path
            })

        except Exception as e:
            logger.error(f"Group config save error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/config/download', methods=['GET'])
    @login_required
    def download_group_config(name):
        """Download agent.conf for a group."""
        # Security: validate group name
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        from flask import Response
        try:

            config_path = f'/var/ossec/etc/shared/{name}/agent.conf'
            user = get_current_user()

            if not os.path.exists(config_path):
                return jsonify({'error': f"Config file not found for group '{name}'"}), 404

            with open(config_path, 'r', encoding='utf-8') as f:
                content = f.read()

            logger.info(f"Group config downloaded: {config_path} by user '{user}'")

            return Response(
                content,
                mimetype='application/xml',
                headers={
                    'Content-Disposition': f'attachment; filename=agent.conf.{name}'
                }
            )

        except Exception as e:
            logger.error(f"Group config download error: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes', methods=['GET'])
    @login_required
    def get_nodes():
        try:
            api = get_api_session()
            nodes = api.get_nodes()

            # Calculate agent count per node
            if nodes:
                agents = api.get_agents()
                node_counts = {}
                for agent in agents:
                    node_name = agent.get('node_name', '')
                    if node_name:
                        node_counts[node_name] = node_counts.get(node_name, 0) + 1

                # For single-node setup, assign all agents to that node
                if len(nodes) == 1:
                    nodes[0]['count'] = len(agents)
                else:
                    for node in nodes:
                        node['count'] = node_counts.get(node['name'], 0)

            return jsonify({'nodes': nodes})
        except Exception as e:
            return jsonify({'error': str(e), 'nodes': []})

    @app.route('/api/nodes/<name>/reconnect', methods=['POST'])
    @login_required
    def reconnect_node(name):
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            dry_run = data.get('dry_run', False)

            api = get_api_session()
            # Get agents on this node
            agents = api.get_agents()
            node_agents = [a['id'] for a in agents if a.get('node_name') == name]

            if dry_run:
                return jsonify({
                    'message': f"[DRY-RUN] Would reconnect {len(node_agents)} agents on node '{name}'",
                    'dry_run': True
                })

            if not node_agents:
                return jsonify({'message': f"No agents found on node '{name}'"})

            result = api.reconnect_agents(node_agents)
            affected = len(result.get('data', {}).get('affected_items', []))
            return jsonify({
                'message': f"Reconnected {affected}/{len(node_agents)} agents on '{name}'",
                'result': result
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/services', methods=['GET'])
    @login_required
    def get_nodes_services():
        """Get Wazuh service status for all nodes via API."""
        try:
            api = get_api_session()

            # Get nodes status via API
            nodes_status = api.get_nodes_status()

            # Friendly name mapping
            service_names = {
                'wazuh-modulesd': 'Modules',
                'wazuh-db': 'DB',
                'wazuh-execd': 'Exec',
                'wazuh-analysisd': 'Analysis',
                'wazuh-syscheckd': 'Syscheck',
                'wazuh-remoted': 'Remote',
                'wazuh-logcollector': 'Logcollect',
                'wazuh-monitord': 'Monitor',
                'wazuh-clusterd': 'Cluster',
                'wazuh-apid': 'API'
            }

            # Format services with friendly names
            result = {}
            for node_name, services in nodes_status.items():
                formatted_services = []
                for svc in services:
                    svc_name = svc.get('name', '')
                    friendly_name = service_names.get(svc_name, svc_name.replace('wazuh-', '').title())
                    formatted_services.append({
                        'name': friendly_name,
                        'status': svc.get('status', 'unknown')
                    })
                result[node_name] = formatted_services

            # Also get cluster status
            cluster_status = api.get_cluster_status()

            return jsonify({
                'services': result,
                'cluster': cluster_status
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/sync-status', methods=['GET'])
    @login_required
    def get_nodes_sync_status():
        """Get cluster sync status by comparing files between master and worker nodes."""
        import subprocess
        import hashlib
        import socket

        # Define sync items to check
        # type: 'dir' = compare all files in directory
        # type: 'file' = compare single file
        # type: 'subdirs' = only compare subdirectories (not root files)
        SYNC_ITEMS = [
            {'name': 'Rules', 'path': '/var/ossec/etc/rules/', 'type': 'dir'},
            {'name': 'Decoders', 'path': '/var/ossec/etc/decoders/', 'type': 'dir'},
            {'name': 'Groups', 'path': '/var/ossec/etc/shared/', 'type': 'subdirs'},  # Only compare group subdirs
            {'name': 'Keys', 'path': '/var/ossec/etc/client.keys', 'type': 'file'},
            {'name': 'Lists', 'path': '/var/ossec/etc/lists/', 'type': 'dir'},
            {'name': 'SCA', 'path': '/var/ossec/ruleset/sca/', 'type': 'dir'},
        ]

        def get_path_checksum(path, item_type, ssh_cmd=None):
            """Get checksum for a path (file or directory).

            item_type:
            - 'file': Compare single file
            - 'dir': Compare all files in directory recursively
            - 'subdirs': Only compare files within subdirectories (skip root-level files)
            """
            try:
                if item_type == 'file':
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'md5sum {path} 2>/dev/null || echo NOTFOUND'"
                    else:
                        cmd = f"md5sum {path} 2>/dev/null || echo NOTFOUND"
                elif item_type == 'subdirs':
                    # Only compare files within subdirectories, skip root-level files
                    # Find all directories first, then find files within them
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND'"
                    else:
                        cmd = f"find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND"
                else:
                    # For directories, get sorted list of files with their checksums
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND'"
                    else:
                        cmd = f"find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort || echo NOTFOUND"

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                output = result.stdout.strip()

                if not output or 'NOTFOUND' in output or result.returncode != 0:
                    return None

                # Hash the entire output to get a single checksum representing the directory state
                return hashlib.md5(output.encode()).hexdigest()
            except Exception as e:
                return None

        try:
            api = get_api_session()

            # Get cluster nodes
            nodes_result = api.request('GET', '/cluster/nodes')
            if nodes_result.get('error'):
                return jsonify({'error': nodes_result.get('error')}), 500

            nodes = nodes_result.get('data', {}).get('affected_items', [])

            # Find master and workers
            master_node = None
            worker_nodes = []
            for node in nodes:
                if node.get('type') == 'master':
                    master_node = node
                elif node.get('type') == 'worker':
                    worker_nodes.append(node)

            if not master_node:
                return jsonify({'sync_status': {}, 'message': 'No master node found'})

            if not worker_nodes:
                return jsonify({'sync_status': {}, 'message': 'No worker nodes found'})

            # Get master checksums (local)
            master_checksums = {}
            for item in SYNC_ITEMS:
                master_checksums[item['name']] = get_path_checksum(item['path'], item['type'])

            # Check each worker node
            sync_status = {}
            local_hostname = socket.gethostname()

            # Get SSH config from application config
            from .config import get_config
            config = get_config()

            for worker in worker_nodes:
                worker_name = worker.get('name', '')
                worker_ip = worker.get('ip', '')

                sync_items = []

                # Build SSH command for this worker using config
                ssh_cmd = None
                ssh_config = config.get_ssh_config_for_node(worker_name)

                if ssh_config:
                    # Use configured SSH settings
                    ssh_host = ssh_config.get('host', worker_ip)
                    ssh_port = ssh_config.get('port', 22)
                    ssh_user = ssh_config.get('user', 'root')
                    ssh_key = ssh_config.get('key_file', '')

                    if ssh_key:
                        ssh_cmd = f"ssh -i {ssh_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
                    else:
                        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
                elif worker_ip and worker_ip not in ['localhost', '127.0.0.1', local_hostname]:
                    # Fallback: try default SSH key location
                    default_key = '/root/.ssh/wazuh_cluster_key'
                    import os
                    if os.path.exists(default_key):
                        ssh_cmd = f"ssh -i {default_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{worker_ip}"
                    else:
                        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{worker_ip}"

                if ssh_cmd:
                    # Test SSH connection first
                    test_result = subprocess.run(
                        f"{ssh_cmd} 'echo OK' 2>/dev/null",
                        shell=True, capture_output=True, text=True, timeout=15
                    )
                    if 'OK' not in test_result.stdout:
                        # SSH not available, mark all as unknown
                        for item in SYNC_ITEMS:
                            sync_items.append({
                                'name': item['name'],
                                'path': item['path'],
                                'status': 'unknown'
                            })
                        sync_status[worker_name] = sync_items
                        continue
                else:
                    # No SSH available for this node
                    for item in SYNC_ITEMS:
                        sync_items.append({
                            'name': item['name'],
                            'path': item['path'],
                            'status': 'unknown'
                        })
                    sync_status[worker_name] = sync_items
                    continue

                # Compare each sync item
                for item in SYNC_ITEMS:
                    worker_checksum = get_path_checksum(item['path'], item['type'], ssh_cmd)
                    master_checksum = master_checksums.get(item['name'])

                    if master_checksum is None and worker_checksum is None:
                        status = 'synced'  # Both don't have it, considered synced
                    elif master_checksum is None or worker_checksum is None:
                        status = 'not_synced'  # One has it, one doesn't
                    elif master_checksum == worker_checksum:
                        status = 'synced'
                    else:
                        status = 'not_synced'

                    sync_items.append({
                        'name': item['name'],
                        'path': item['path'],
                        'status': status
                    })

                sync_status[worker_name] = sync_items

            return jsonify({'sync_status': sync_status})
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/sync-detail', methods=['GET'])
    @login_required
    def get_node_sync_detail(name):
        """Get detailed sync comparison for a specific item on a worker node."""
        import subprocess
        import socket

        # Validate node name
        if not validate_node_name(name):
            logger.warning(f"Invalid node name attempt: {sanitize_for_log(name)}")
            return jsonify({'error': 'Invalid node name'}), 400

        item_name = request.args.get('item', '')
        item_path = request.args.get('path', '')

        if not item_name or not item_path:
            return jsonify({'error': 'Missing item or path parameter'}), 400

        # Whitelist of allowed sync items (prevent arbitrary path access)
        ALLOWED_SYNC_ITEMS = {
            'Rules': '/var/ossec/etc/rules/',
            'Decoders': '/var/ossec/etc/decoders/',
            'Groups': '/var/ossec/etc/shared/',
            'Keys': '/var/ossec/etc/client.keys',
            'Lists': '/var/ossec/etc/lists/',
            'SCA': '/var/ossec/ruleset/sca/',
        }

        # Validate item_name is in whitelist
        if item_name not in ALLOWED_SYNC_ITEMS:
            logger.warning(f"Invalid sync item attempt: {sanitize_for_log(item_name)}")
            return jsonify({'error': 'Invalid sync item'}), 400

        # Validate item_path matches expected path for this item
        expected_path = ALLOWED_SYNC_ITEMS[item_name]
        if item_path != expected_path:
            logger.warning(f"Path mismatch for {item_name}: expected {expected_path}, got {sanitize_for_log(item_path)}")
            return jsonify({'error': 'Invalid path for sync item'}), 400

        # Determine type based on path and item name
        is_dir = item_path.endswith('/')
        # Groups need special handling - only compare subdirectories
        is_subdirs = (item_name == 'Groups')

        def get_file_list(path, ssh_cmd=None):
            """Get list of files with their md5sums."""
            try:
                if not is_dir:
                    # Single file
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'md5sum {path} 2>/dev/null'"
                    else:
                        cmd = f"md5sum {path} 2>/dev/null"
                elif is_subdirs:
                    # Only files in subdirectories (mindepth 2 skips root-level files)
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort'"
                    else:
                        cmd = f"find {path} -mindepth 2 -type f -exec md5sum {{}} \\; 2>/dev/null | sort"
                else:
                    # All files in directory
                    if ssh_cmd:
                        cmd = f"{ssh_cmd} 'find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort'"
                    else:
                        cmd = f"find {path} -type f -exec md5sum {{}} \\; 2>/dev/null | sort"

                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                output = result.stdout.strip()

                if not output:
                    return {}

                # Parse md5sum output: "checksum  filepath"
                files = {}
                for line in output.split('\n'):
                    if line.strip():
                        parts = line.split(None, 1)
                        if len(parts) == 2:
                            checksum, filepath = parts
                            # Remove base path for cleaner display
                            rel_path = filepath.replace(path, '').lstrip('/')
                            files[rel_path or os.path.basename(filepath)] = checksum
                return files
            except Exception as e:
                return {}

        try:
            api = get_api_session()

            # Get worker node info
            nodes_result = api.request('GET', '/cluster/nodes')
            if nodes_result.get('error'):
                return jsonify({'error': nodes_result.get('error')}), 500

            nodes = nodes_result.get('data', {}).get('affected_items', [])
            worker_node = None
            for node in nodes:
                if node.get('name') == name:
                    worker_node = node
                    break

            if not worker_node:
                return jsonify({'error': f'Node {name} not found'}), 404

            if worker_node.get('type') != 'worker':
                return jsonify({'error': 'Can only compare worker nodes'}), 400

            worker_ip = worker_node.get('ip', '')

            # Get SSH config
            from .config import get_config
            config = get_config()
            ssh_config = config.get_ssh_config_for_node(name)

            ssh_cmd = None
            local_hostname = socket.gethostname()

            if ssh_config:
                ssh_host = ssh_config.get('host', worker_ip)
                ssh_port = ssh_config.get('port', 22)
                ssh_user = ssh_config.get('user', 'root')
                ssh_key = ssh_config.get('key_file', '')

                if ssh_key:
                    ssh_cmd = f"ssh -i {ssh_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
                else:
                    ssh_cmd = f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -p {ssh_port} {ssh_user}@{ssh_host}"
            elif worker_ip and worker_ip not in ['localhost', '127.0.0.1', local_hostname]:
                default_key = '/root/.ssh/wazuh_cluster_key'
                if os.path.exists(default_key):
                    ssh_cmd = f"ssh -i {default_key} -o StrictHostKeyChecking=no -o ConnectTimeout=10 root@{worker_ip}"

            if not ssh_cmd:
                return jsonify({'error': 'SSH not configured for this node'}), 400

            # Get file lists from master and worker
            master_files = get_file_list(item_path)
            worker_files = get_file_list(item_path, ssh_cmd)

            # Compare
            master_only = []
            worker_only = []
            different = []

            all_files = set(master_files.keys()) | set(worker_files.keys())

            for f in sorted(all_files):
                m_checksum = master_files.get(f)
                w_checksum = worker_files.get(f)

                if m_checksum and not w_checksum:
                    master_only.append(f)
                elif w_checksum and not m_checksum:
                    worker_only.append(f)
                elif m_checksum != w_checksum:
                    different.append(f)

            if not master_only and not worker_only and not different:
                status = 'synced'
            else:
                status = 'not_synced'

            return jsonify({
                'status': status,
                'item': item_name,
                'path': item_path,
                'file_count': len(all_files),
                'master_only': master_only,
                'worker_only': worker_only,
                'different': different
            })
        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/config', methods=['GET'])
    @login_required
    def get_node_config(name):
        """Get ossec.conf for a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import socket

            # Default config path
            config_path = '/var/ossec/etc/ossec.conf'

            api = get_api_session()
            nodes = api.get_nodes()

            # Find the requested node
            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node by comparing hostname
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            if is_local:
                # Read local config file
                if not os.path.exists(config_path):
                    return jsonify({'error': f'Config file not found: {config_path}'}), 404

                with open(config_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                logger.info(f"Config read: {config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'content': content,
                    'path': config_path,
                    'node': name,
                    'is_local': True
                })
            else:
                # Remote worker node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    # Try to read config via SSH
                    try:
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"cat {config_path}"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0:
                            logger.info(f"Config read via SSH: {name}:{config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                            return jsonify({
                                'content': result.stdout,
                                'path': config_path,
                                'node': name,
                                'is_local': False,
                                'via_ssh': True
                            })
                        else:
                            error_msg = result.stderr.strip() or 'SSH command failed'
                            logger.warning(f"SSH read failed for {name}: {error_msg}")
                            return jsonify({
                                'error': f'SSH read failed: {error_msg}',
                                'is_remote': True,
                                'node_ip': target_node.get('ip', '')
                            }), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration. SSH is {"enabled" if config.ssh_enabled else "disabled"} but node "{name}" is not in the configured nodes list.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/config', methods=['PUT'])
    @login_required
    def save_node_config(name):
        """Save ossec.conf for a node with auto-backup."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import shutil
            import socket

            data = request.get_json(silent=True) or {}
            content = data.get('content', '')

            if not content or not content.strip():
                return jsonify({'error': 'Config content cannot be empty'}), 400

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            config_path = '/var/ossec/etc/ossec.conf'
            backup_dir = '/var/ossec/etc/backup'

            if is_local:
                # Ensure backup directory exists
                if not os.path.exists(backup_dir):
                    os.makedirs(backup_dir, mode=0o750)

                # Create backup with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_filename = f'ossec.conf.{timestamp}.bak'
                backup_path = os.path.join(backup_dir, backup_filename)

                # Backup current config
                if os.path.exists(config_path):
                    shutil.copy2(config_path, backup_path)
                    logger.info(f"Config backup created: {backup_path}")

                # Write new config
                with open(config_path, 'w', encoding='utf-8') as f:
                    f.write(content)

                logger.info(f"Config saved: {config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'success': True,
                    'message': 'Config saved successfully',
                    'backup_path': backup_path
                })
            else:
                # Remote node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Create backup command and save command
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        backup_path = f'{backup_dir}/ossec.conf.{timestamp}.bak'
                        remote_cmd = f"mkdir -p {backup_dir} && cp {config_path} {backup_path} 2>/dev/null; cat > {config_path}"

                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            remote_cmd
                        ]

                        result = subprocess.run(ssh_cmd, input=content, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0:
                            logger.info(f"Config saved via SSH: {name}:{config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                            return jsonify({
                                'success': True,
                                'message': f'Config saved to {name} via SSH',
                                'backup_path': backup_path,
                                'via_ssh': True
                            })
                        else:
                            error_msg = result.stderr.strip() or 'SSH command failed'
                            logger.warning(f"SSH save failed for {name}: {error_msg}")
                            return jsonify({'error': f'SSH save failed: {error_msg}'}), 400

                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH connection timed out'}), 400
                    except Exception as e:
                        logger.error(f"SSH save error for {name}: {str(e)}")
                        return jsonify({'error': f'SSH error: {str(e)}'}), 400
                else:
                    return jsonify({
                        'error': f'Cannot save config to remote node "{name}". SSH is not configured for this node.'
                    }), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"Config save failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    # ============ Email Alerts Helper Functions ============

    def parse_email_alerts_from_config(content):
        """Extract all <email_alerts> blocks from ossec.conf using regex + ElementTree."""
        import xml.etree.ElementTree as ET
        alerts = []
        pattern = re.compile(r'<email_alerts>\s*.*?\s*</email_alerts>', re.DOTALL)
        for match in pattern.finditer(content):
            block = match.group(0)
            try:
                root = ET.fromstring(block)
                alert = {
                    'email_to': [],
                    'rule_id': '',
                    'level': None,
                    'group': '',
                    'event_location': '',
                    'format': '',
                    'do_not_delay': False,
                    'do_not_group': False
                }
                for child in root:
                    tag = child.tag.strip()
                    text = (child.text or '').strip()
                    if tag == 'email_to':
                        alert['email_to'].append(text)
                    elif tag == 'rule_id':
                        alert['rule_id'] = text
                    elif tag == 'level':
                        try:
                            alert['level'] = int(text)
                        except (ValueError, TypeError):
                            alert['level'] = None
                    elif tag == 'group':
                        alert['group'] = text
                    elif tag == 'event_location':
                        alert['event_location'] = text
                    elif tag == 'format':
                        alert['format'] = text
                    elif tag == 'do_not_delay':
                        alert['do_not_delay'] = True
                    elif tag == 'do_not_group':
                        alert['do_not_group'] = True
                alerts.append(alert)
            except ET.ParseError:
                continue
        return alerts

    def parse_global_email_settings(content):
        """Extract email-related settings from <global> block."""
        result = {
            'email_notification': '',
            'smtp_server': '',
            'email_from': '',
            'email_to': ''
        }
        global_pattern = re.compile(r'<global>(.*?)</global>', re.DOTALL)
        global_match = global_pattern.search(content)
        if global_match:
            global_text = global_match.group(1)
            for key in result:
                tag_pattern = re.compile(rf'<{key}>\s*(.*?)\s*</{key}>')
                tag_match = tag_pattern.search(global_text)
                if tag_match:
                    result[key] = tag_match.group(1).strip()
        return result

    def generate_email_alerts_xml(alerts):
        """Generate formatted XML string from alerts list."""
        lines = []
        for alert in alerts:
            lines.append('  <email_alerts>')
            for email in alert.get('email_to', []):
                lines.append(f'    <email_to>{email}</email_to>')
            if alert.get('rule_id'):
                lines.append(f'    <rule_id>{alert["rule_id"]}</rule_id>')
            if alert.get('level') is not None:
                lines.append(f'    <level>{alert["level"]}</level>')
            if alert.get('group'):
                lines.append(f'    <group>{alert["group"]}</group>')
            if alert.get('event_location'):
                lines.append(f'    <event_location>{alert["event_location"]}</event_location>')
            if alert.get('format'):
                lines.append(f'    <format>{alert["format"]}</format>')
            if alert.get('do_not_delay'):
                lines.append('    <do_not_delay />')
            if alert.get('do_not_group'):
                lines.append('    <do_not_group />')
            lines.append('  </email_alerts>')
        return '\n'.join(lines)

    def replace_email_alerts_in_config(content, new_xml):
        """Replace all <email_alerts> blocks in config with new XML."""
        # Step 1: Remove all existing <email_alerts> blocks
        pattern = re.compile(r'[ \t]*<email_alerts>.*?</email_alerts>[ \t]*\n?', re.DOTALL)
        cleaned = pattern.sub('', content)

        # Step 2: Clean up extra blank lines left by removal (3+ consecutive → 2)
        cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)

        # Step 3: If no new alerts, just return cleaned content
        if not new_xml.strip():
            return cleaned

        # Step 4: Insert new XML before the LAST </ossec_config>
        last_close = cleaned.rfind('</ossec_config>')
        if last_close == -1:
            return cleaned

        # Ensure proper newline before insertion
        insert_pos = last_close
        prefix = cleaned[:insert_pos]
        suffix = cleaned[insert_pos:]

        # Make sure there's a newline before the new XML
        if prefix and not prefix.endswith('\n'):
            prefix += '\n'

        return prefix + new_xml + '\n' + suffix

    def validate_email_alerts_input(alerts):
        """Validate email alerts input data. Returns (valid, error_message)."""
        email_pattern = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
        rule_id_pattern = re.compile(r'^[0-9,\s]+$')

        if not isinstance(alerts, list):
            return False, 'alerts must be a list'

        for i, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                return False, f'Alert #{i+1} must be an object'

            email_to = alert.get('email_to', [])
            if not isinstance(email_to, list) or len(email_to) == 0:
                return False, f'Alert #{i+1}: email_to is required and must be a non-empty list'

            for email in email_to:
                if not email_pattern.match(str(email)):
                    return False, f'Alert #{i+1}: invalid email format: {email}'

            rule_id = alert.get('rule_id', '')
            if rule_id and not rule_id_pattern.match(str(rule_id)):
                return False, f'Alert #{i+1}: rule_id can only contain numbers and commas'

            level = alert.get('level')
            if level is not None:
                try:
                    level_int = int(level)
                    if level_int < 1 or level_int > 16:
                        return False, f'Alert #{i+1}: level must be between 1 and 16'
                except (ValueError, TypeError):
                    return False, f'Alert #{i+1}: level must be a number'

        return True, ''

    def read_node_config_content(name):
        """Read ossec.conf content for a node. Returns (content, error_response) tuple."""
        import subprocess
        import socket

        config_path = '/var/ossec/etc/ossec.conf'
        api = get_api_session()
        nodes = api.get_nodes()

        target_node = None
        for n in nodes:
            if n.get('name') == name:
                target_node = n
                break

        if not target_node:
            return None, (jsonify({'error': f'Node "{name}" not found'}), 404)

        local_hostname = socket.gethostname()
        is_local = (target_node.get('type') == 'master' or
                   name == local_hostname or
                   name.replace('-server', '') == local_hostname or
                   local_hostname.replace('-server', '') == name.replace('-server', ''))

        if is_local:
            if not os.path.exists(config_path):
                return None, (jsonify({'error': f'Config file not found: {config_path}'}), 404)
            with open(config_path, 'r', encoding='utf-8') as f:
                return f.read(), None
        else:
            config = get_config()
            ssh_cfg = config.get_ssh_config_for_node(name)
            if not ssh_cfg:
                return None, (jsonify({'error': f'Worker node "{name}" requires SSH configuration.'}), 400)
            try:
                ssh_cmd = [
                    'ssh',
                    '-i', ssh_cfg['key_file'],
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=10',
                    '-p', str(ssh_cfg['port']),
                    f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                    f"cat {config_path}"
                ]
                result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    return result.stdout, None
                else:
                    return None, (jsonify({'error': f'SSH read failed: {result.stderr.strip()}'}), 400)
            except subprocess.TimeoutExpired:
                return None, (jsonify({'error': 'SSH connection timed out'}), 400)
            except Exception as e:
                return None, (jsonify({'error': f'SSH error: {str(e)}'}), 400)

    def write_node_config_content(name, content):
        """Write ossec.conf content to a node with backup. Returns (success_response, error_response) tuple."""
        import subprocess
        import shutil
        import socket

        config_path = '/var/ossec/etc/ossec.conf'
        backup_dir = '/var/ossec/etc/backup'

        api = get_api_session()
        nodes = api.get_nodes()

        target_node = None
        for n in nodes:
            if n.get('name') == name:
                target_node = n
                break

        if not target_node:
            return None, (jsonify({'error': f'Node "{name}" not found'}), 404)

        local_hostname = socket.gethostname()
        is_local = (target_node.get('type') == 'master' or
                   name == local_hostname or
                   name.replace('-server', '') == local_hostname or
                   local_hostname.replace('-server', '') == name.replace('-server', ''))

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'ossec.conf.{timestamp}.bak'

        if is_local:
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir, mode=0o750)
            backup_path = os.path.join(backup_dir, backup_filename)
            if os.path.exists(config_path):
                shutil.copy2(config_path, backup_path)
                logger.info(f"Email alerts backup: {backup_path}")
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(content)
            logger.info(f"Email alerts config saved: {config_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
            return {'success': True, 'message': 'Email alerts saved', 'backup_path': backup_path}, None
        else:
            config = get_config()
            ssh_cfg = config.get_ssh_config_for_node(name)
            if not ssh_cfg:
                return None, (jsonify({'error': f'SSH not configured for node "{name}"'}), 400)
            try:
                backup_path = f'{backup_dir}/{backup_filename}'
                remote_cmd = f"mkdir -p {backup_dir} && cp {config_path} {backup_path} 2>/dev/null; cat > {config_path}"
                ssh_cmd = [
                    'ssh',
                    '-i', ssh_cfg['key_file'],
                    '-o', 'StrictHostKeyChecking=no',
                    '-o', 'ConnectTimeout=10',
                    '-p', str(ssh_cfg['port']),
                    f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                    remote_cmd
                ]
                result = subprocess.run(ssh_cmd, input=content, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    logger.info(f"Email alerts config saved via SSH: {name} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                    return {'success': True, 'message': f'Email alerts saved to {name}', 'backup_path': backup_path, 'via_ssh': True}, None
                else:
                    return None, (jsonify({'error': f'SSH save failed: {result.stderr.strip()}'}), 400)
            except subprocess.TimeoutExpired:
                return None, (jsonify({'error': 'SSH connection timed out'}), 400)
            except Exception as e:
                return None, (jsonify({'error': f'SSH error: {str(e)}'}), 400)

    # ============ Email Alerts API Endpoints ============

    @app.route('/api/nodes/<name>/email-alerts', methods=['GET'])
    @login_required
    def get_email_alerts(name):
        """Get email alert rules from ossec.conf."""
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            content, err = read_node_config_content(name)
            if err:
                return err

            alerts = parse_email_alerts_from_config(content)
            global_email = parse_global_email_settings(content)
            global_configured = bool(
                global_email.get('email_notification', '').lower() == 'yes' and
                global_email.get('smtp_server') and
                global_email.get('email_from')
            )

            return jsonify({
                'alerts': alerts,
                'global_email': global_email,
                'global_email_configured': global_configured
            })
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"Get email alerts failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/email-alerts', methods=['PUT'])
    @login_required
    def save_email_alerts(name):
        """Save email alert rules to ossec.conf."""
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            data = request.get_json(silent=True) or {}
            alerts = data.get('alerts', [])

            # Validate input format
            valid, error_msg = validate_email_alerts_input(alerts)
            if not valid:
                return jsonify({'error': error_msg}), 400

            # Validate rule IDs, levels, and groups exist
            if alerts:
                warnings = []
                try:
                    rules_dict, group_to_rules, parse_errors = get_all_rules()
                    all_rule_ids = set(rules_dict.keys())
                    all_groups = set(group_to_rules.keys())
                    # Collect all valid levels from existing rules
                    all_levels = set()
                    for r in rules_dict.values():
                        lvl = r.get('level')
                        if lvl is not None:
                            try:
                                all_levels.add(int(lvl))
                            except (ValueError, TypeError):
                                pass

                    for i, alert in enumerate(alerts):
                        prefix = f'Rule #{i+1}'

                        # Check rule_id exists
                        rule_id_str = alert.get('rule_id', '').strip()
                        if rule_id_str:
                            for rid in rule_id_str.split(','):
                                rid = rid.strip()
                                if rid and rid not in all_rule_ids:
                                    warnings.append(f'{prefix}: Rule ID {rid} not found')

                        # Check group exists
                        group_str = alert.get('group', '').strip()
                        if group_str:
                            for g in group_str.split(','):
                                g = g.strip()
                                if g and g not in all_groups:
                                    warnings.append(f'{prefix}: Group "{g}" not found')

                        # Check level - verify at least some rules match
                        level = alert.get('level')
                        if level is not None:
                            level_int = int(level)
                            if level_int not in all_levels and not any(lv >= level_int for lv in all_levels):
                                warnings.append(f'{prefix}: No rules found with level >= {level_int}')

                        # Check at least one filter is specified
                        has_filter = bool(rule_id_str or group_str or alert.get('level') is not None or alert.get('event_location', '').strip())
                        if not has_filter:
                            warnings.append(f'{prefix}: No filter specified (rule_id, level, group, or event_location). This rule will match ALL alerts.')

                except Exception as e:
                    logger.warning(f"Email alerts validation warning: {str(e)}")

                if warnings:
                    return jsonify({'error': 'Validation failed:\n' + '\n'.join(warnings)}), 400

            # Read current config
            content, err = read_node_config_content(name)
            if err:
                return err

            # Generate new XML and replace
            new_xml = generate_email_alerts_xml(alerts)
            new_content = replace_email_alerts_in_config(content, new_xml)

            # Write back with backup
            success, err = write_node_config_content(name, new_content)
            if err:
                return err

            return jsonify(success)
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"Save email alerts failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/logs-info', methods=['GET'])
    @login_required
    def get_node_logs_info(name):
        """Get info about log files (archives and alerts) for a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import socket

            # Define all log files to check
            log_files = {
                'archives_log': '/var/ossec/logs/archives/archives.log',
                'archives_json': '/var/ossec/logs/archives/archives.json',
                'alerts_log': '/var/ossec/logs/alerts/alerts.log',
                'alerts_json': '/var/ossec/logs/alerts/alerts.json'
            }

            api = get_api_session()
            nodes = api.get_nodes()

            # Find the requested node
            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            result = {'node': name, 'files': {}}

            if is_local:
                # Check local files
                for file_type, file_path in log_files.items():
                    if os.path.exists(file_path):
                        try:
                            stat = os.stat(file_path)
                            result['files'][file_type] = {
                                'exists': True,
                                'path': file_path,
                                'size': stat.st_size
                            }
                        except Exception:
                            result['files'][file_type] = {'exists': False}
                    else:
                        result['files'][file_type] = {'exists': False}

                return jsonify(result)
            else:
                # Remote worker node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Use stat command to get file info for all log files
                        file_paths = ' '.join(log_files.values())
                        check_cmd = f"for f in {file_paths}; do if [ -f \"$f\" ]; then stat -c '%s' \"$f\" 2>/dev/null || stat -f '%z' \"$f\" 2>/dev/null; else echo 'NOT_FOUND'; fi; done"
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            check_cmd
                        ]
                        proc_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if proc_result.returncode == 0:
                            lines = proc_result.stdout.strip().split('\n')
                            for i, (file_type, file_path) in enumerate(log_files.items()):
                                if i < len(lines):
                                    if lines[i] == 'NOT_FOUND':
                                        result['files'][file_type] = {'exists': False}
                                    else:
                                        try:
                                            size = int(lines[i])
                                            result['files'][file_type] = {
                                                'exists': True,
                                                'path': file_path,
                                                'size': size
                                            }
                                        except ValueError:
                                            result['files'][file_type] = {'exists': False}
                                else:
                                    result['files'][file_type] = {'exists': False}
                            return jsonify(result)
                        else:
                            return jsonify({'error': f'SSH command failed: {proc_result.stderr}'}), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH connection timed out'}), 400
                    except Exception as e:
                        return jsonify({'error': f'SSH error: {str(e)}'}), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True
                    }), 400
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/logs/<category>/<log_type>', methods=['GET'])
    @login_required
    def get_node_log_content(name, category, log_type):
        """Get log file content (archives or alerts) for a node."""
        # Validate node name, category, and log type
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        if category not in ['archives', 'alerts']:
            return jsonify({'error': 'Invalid category. Must be "archives" or "alerts".'}), 400
        if log_type not in ['log', 'json']:
            return jsonify({'error': 'Invalid log type. Must be "log" or "json".'}), 400

        try:
            import subprocess
            import socket

            # Get line limit from query params (default 100)
            lines_limit = request.args.get('lines', 100, type=int)
            if lines_limit < 1:
                lines_limit = 100
            if lines_limit > 10000:
                lines_limit = 10000

            log_dir = f'/var/ossec/logs/{category}'
            file_name = f'{category}.{log_type}'
            file_path = os.path.join(log_dir, file_name)

            api = get_api_session()
            nodes = api.get_nodes()

            # Find the requested node
            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            if is_local:
                # Read local file
                if not os.path.exists(file_path):
                    return jsonify({'error': f'Archive file not found: {file_path}'}), 404

                # Get file size
                stat = os.stat(file_path)
                file_size = stat.st_size

                # Read last N lines using tail
                try:
                    proc = subprocess.run(
                        ['tail', '-n', str(lines_limit), file_path],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    content = proc.stdout.rstrip('\n')
                except Exception as e:
                    # Fallback: read entire file and get last N lines
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        all_lines = f.readlines()
                        content = ''.join(all_lines[-lines_limit:]).rstrip('\n')

                logger.info(f"Log read: {file_path} (last {lines_limit} lines) by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'content': content,
                    'path': file_path,
                    'node': name,
                    'category': category,
                    'type': log_type,
                    'lines': lines_limit,
                    'size': file_size,
                    'is_local': True
                })
            else:
                # Remote worker node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Get file size and content
                        remote_cmd = f"stat -c '%s' {file_path} 2>/dev/null || stat -f '%z' {file_path} 2>/dev/null; echo '---SEPARATOR---'; tail -n {lines_limit} {file_path}"
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            remote_cmd
                        ]
                        proc_result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=60)

                        if proc_result.returncode == 0:
                            output = proc_result.stdout
                            parts = output.split('---SEPARATOR---\n', 1)
                            file_size = 0
                            content = ''
                            if len(parts) == 2:
                                try:
                                    file_size = int(parts[0].strip())
                                except ValueError:
                                    pass
                                content = parts[1].rstrip('\n')
                            else:
                                content = output.rstrip('\n')

                            logger.info(f"Log read via SSH: {name}:{file_path} (last {lines_limit} lines) by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                            return jsonify({
                                'content': content,
                                'path': file_path,
                                'node': name,
                                'category': category,
                                'type': log_type,
                                'lines': lines_limit,
                                'size': file_size,
                                'is_local': False,
                                'via_ssh': True
                            })
                        else:
                            error_msg = proc_result.stderr.strip() or 'SSH command failed'
                            if 'No such file' in error_msg or 'cannot open' in error_msg.lower():
                                return jsonify({'error': f'Log file not found on {name}'}), 404
                            return jsonify({'error': f'SSH read failed: {error_msg}'}), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH connection timed out'}), 400
                    except Exception as e:
                        return jsonify({'error': f'SSH error: {str(e)}'}), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True
                    }), 400
        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/restart', methods=['POST'])
    @login_required
    def restart_node_services(name):
        """Restart all Wazuh services on a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            import subprocess
            import socket

            logger.info(f"Services restart requested for node '{sanitize_for_log(name)}' by user '{session.get('api_session', {}).get('username', 'unknown')}'")

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            if is_local:
                # Local node - restart directly
                result = None
                error_msg = None

                # Try systemctl first (modern systems)
                try:
                    result = subprocess.run(
                        ['systemctl', 'restart', 'wazuh-manager'],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )
                    if result.returncode == 0:
                        logger.info(f"Services restarted successfully on node '{name}' via systemctl")
                        return jsonify({
                            'success': True,
                            'message': f'Wazuh services restarted on {name}'
                        })
                    else:
                        error_msg = result.stderr or 'Unknown error'
                except FileNotFoundError:
                    pass  # systemctl not available
                except subprocess.TimeoutExpired:
                    error_msg = 'Restart command timed out'

                # Fallback to wazuh-control
                wazuh_control = '/var/ossec/bin/wazuh-control'
                if os.path.exists(wazuh_control):
                    try:
                        result = subprocess.run(
                            [wazuh_control, 'restart'],
                            capture_output=True,
                            text=True,
                            timeout=120
                        )
                        if result.returncode == 0:
                            logger.info(f"Services restarted successfully on node '{name}' via wazuh-control")
                            return jsonify({
                                'success': True,
                                'message': f'Wazuh services restarted on {name}'
                            })
                        else:
                            error_msg = result.stderr or result.stdout or 'Unknown error'
                    except subprocess.TimeoutExpired:
                        error_msg = 'Restart command timed out'

                if error_msg:
                    logger.error(f"Services restart failed on node '{name}': {error_msg}")
                    return jsonify({'error': error_msg}), 500

                return jsonify({'error': 'No restart method available'}), 500
            else:
                # Remote node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Try systemctl first via SSH
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            'systemctl restart wazuh-manager || /var/ossec/bin/wazuh-control restart'
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=120)

                        if result.returncode == 0:
                            logger.info(f"Services restarted successfully on remote node '{name}' via SSH")
                            return jsonify({
                                'success': True,
                                'message': f'Wazuh services restarted on {name} (via SSH)'
                            })
                        else:
                            error_msg = result.stderr.strip() or result.stdout.strip() or 'SSH command failed'
                            logger.error(f"Remote restart failed for {name}: {error_msg}")
                            return jsonify({'error': f'Restart failed: {error_msg}'}), 500
                    except subprocess.TimeoutExpired:
                        return jsonify({'error': 'SSH restart command timed out (120s)'}), 500
                    except Exception as e:
                        logger.error(f"SSH restart error for {name}: {str(e)}")
                        return jsonify({'error': f'SSH error: {str(e)}'}), 500
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"Services restart failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/download/<file_type>', methods=['GET'])
    @login_required
    def download_node_file(name, file_type):
        """Download ossec.conf or cluster.key for a node."""
        # Validate node name and file_type
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        # file_type is validated below against whitelist

        from flask import send_file, Response
        import io
        import socket

        try:
            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            # Define file paths
            file_paths = {
                'config': '/var/ossec/etc/ossec.conf',
                'cluster-key': '/var/ossec/etc/cluster.key'
            }

            if file_type not in file_paths:
                return jsonify({'error': 'Invalid file type'}), 400

            file_path = file_paths[file_type]

            # Generate download filename with node name
            if file_type == 'config':
                download_name = f'{name}_ossec.conf'
            else:
                download_name = f'{name}_cluster.key'

            if is_local:
                # Local node - read file directly
                if not os.path.exists(file_path):
                    if file_type == 'cluster-key':
                        return jsonify({'error': 'cluster.key not found. This file only exists in cluster mode setups.'}), 404
                    return jsonify({'error': f'File not found: {file_path}'}), 404

                # Read file content - try text first, then binary
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    mimetype = 'text/plain'
                except UnicodeDecodeError:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                    mimetype = 'application/octet-stream'

                logger.info(f"File downloaded: {file_path} as {download_name} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
            else:
                # Remote node - try SSH if configured
                import subprocess
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"cat {file_path}"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0:
                            content = result.stdout
                            mimetype = 'text/plain'
                            logger.info(f"File downloaded via SSH: {name}:{file_path} as {download_name} by user '{session.get('api_session', {}).get('username', 'unknown')}'")
                        else:
                            error_msg = result.stderr.strip() or 'SSH command failed'
                            if 'No such file' in error_msg:
                                if file_type == 'cluster-key':
                                    return jsonify({'error': 'cluster.key not found on remote node. This file only exists in cluster mode setups.'}), 404
                                return jsonify({'error': f'File not found on remote node: {file_path}'}), 404
                            return jsonify({
                                'error': f'SSH read failed: {error_msg}',
                                'is_remote': True,
                                'node_ip': target_node.get('ip', '')
                            }), 400
                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH download error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

            # Return as downloadable file
            return Response(
                content,
                mimetype=mimetype,
                headers={
                    'Content-Disposition': f'attachment; filename={download_name}'
                }
            )

        except PermissionError:
            return jsonify({'error': 'Permission denied. Run with sudo or as root.'}), 403
        except Exception as e:
            logger.error(f"File download failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/upgrade-files', methods=['GET'])
    @login_required
    def get_node_upgrade_files(name):
        """Get list of agent upgrade files (WPK packages) on a node."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400

        import subprocess
        import socket
        import re

        try:
            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            upgrade_path = '/var/ossec/var/upgrade'
            files = []

            if is_local:
                # Local node - read directory directly
                if os.path.isdir(upgrade_path):
                    for filename in os.listdir(upgrade_path):
                        filepath = os.path.join(upgrade_path, filename)
                        if os.path.isfile(filepath) and filename.endswith('.wpk'):
                            stat = os.stat(filepath)
                            files.append({
                                'name': filename,
                                'size': stat.st_size,
                                'mtime': stat.st_mtime
                            })
            else:
                # Remote node - try SSH if configured
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Use ls -la to get file details
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"ls -la {upgrade_path}/*.wpk 2>/dev/null || echo ''"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode == 0 and result.stdout.strip():
                            for line in result.stdout.strip().split('\n'):
                                if '.wpk' in line:
                                    # Parse ls -la output: -rw-r--r-- 1 root root 12345678 Jan  1 12:00 filename.wpk
                                    parts = line.split()
                                    if len(parts) >= 9:
                                        filename = parts[-1].split('/')[-1]
                                        try:
                                            size = int(parts[4])
                                        except:
                                            size = 0
                                        files.append({
                                            'name': filename,
                                            'size': size,
                                            'mtime': 0  # Skip mtime parsing for simplicity
                                        })
                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH upgrade files error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    # SSH not configured for this node
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

            # Sort by filename
            files.sort(key=lambda x: x['name'])

            # Get manager version
            manager_version = target_node.get('version', '')

            return jsonify({
                'node': name,
                'path': upgrade_path,
                'files': files,
                'manager_version': manager_version
            })

        except Exception as e:
            logger.error(f"Get upgrade files failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/upgrade-files', methods=['POST'])
    @login_required
    def upload_node_upgrade_file(name):
        """Upload a WPK file to a node's upgrade directory."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400

        import subprocess
        import socket
        import tempfile
        from werkzeug.utils import secure_filename

        try:
            # Check if file was uploaded
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400

            file = request.files['file']
            if file.filename == '':
                return jsonify({'error': 'No file selected'}), 400

            # Sanitize filename
            safe_filename = secure_filename(file.filename)
            if not safe_filename:
                return jsonify({'error': 'Invalid filename'}), 400

            # Validate file extension
            if not safe_filename.endswith('.wpk'):
                return jsonify({'error': 'Only .wpk files are allowed'}), 400

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            upgrade_path = '/var/ossec/var/upgrade'
            dest_path = os.path.join(upgrade_path, safe_filename)

            if is_local:
                # Local node - save file directly
                # Ensure directory exists
                if not os.path.isdir(upgrade_path):
                    os.makedirs(upgrade_path, mode=0o755, exist_ok=True)

                # Save file
                file.save(dest_path)

                # Set proper permissions: root:root 660 (same as Wazuh's own downloads)
                os.chmod(dest_path, 0o660)
                try:
                    import pwd
                    import grp
                    uid = pwd.getpwnam('root').pw_uid
                    gid = grp.getgrnam('root').gr_gid
                    os.chown(dest_path, uid, gid)
                except Exception as e:
                    logger.warning(f"Could not set ownership: {e}")

                logger.info(f"WPK uploaded: {dest_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'success': True,
                    'message': f'File "{safe_filename}" uploaded successfully',
                    'path': dest_path
                })

            else:
                # Remote node - use SCP via SSH
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Save to temp file first
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.wpk') as tmp:
                            file.save(tmp.name)
                            tmp_path = tmp.name

                        try:
                            # SCP file to remote node
                            scp_cmd = [
                                'scp',
                                '-i', ssh_cfg['key_file'],
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'ConnectTimeout=10',
                                '-P', str(ssh_cfg['port']),
                                tmp_path,
                                f"{ssh_cfg['user']}@{ssh_cfg['host']}:{dest_path}"
                            ]
                            result = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=120)

                            if result.returncode != 0:
                                return jsonify({
                                    'error': f'SCP failed: {result.stderr.strip()}',
                                    'is_remote': True,
                                    'node_ip': target_node.get('ip', '')
                                }), 400

                            # Set permissions via SSH: root:root 660 (same as Wazuh's own downloads)
                            ssh_cmd = [
                                'ssh',
                                '-i', ssh_cfg['key_file'],
                                '-o', 'StrictHostKeyChecking=no',
                                '-o', 'ConnectTimeout=10',
                                '-p', str(ssh_cfg['port']),
                                f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                                f"chmod 660 {dest_path} && chown root:root {dest_path}"
                            ]
                            subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                            logger.info(f"WPK uploaded via SSH: {name}:{dest_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                            return jsonify({
                                'success': True,
                                'message': f'File "{safe_filename}" uploaded to {name} successfully',
                                'path': dest_path
                            })

                        finally:
                            # Clean up temp file
                            os.unlink(tmp_path)

                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH/SCP connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH upload error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

        except Exception as e:
            logger.error(f"Upload WPK failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/upgrade-files/<filename>', methods=['DELETE'])
    @login_required
    def delete_node_upgrade_file(name, filename):
        """Delete a WPK file from a node's upgrade directory."""
        # Validate node name
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400

        import subprocess
        import socket
        from werkzeug.utils import secure_filename

        try:
            # Sanitize and validate filename
            safe_filename = secure_filename(filename)
            if not safe_filename or not safe_filename.endswith('.wpk'):
                return jsonify({'error': 'Invalid file type'}), 400

            # Additional path traversal protection
            if '/' in filename or '\\' in filename or '..' in filename:
                return jsonify({'error': 'Invalid filename'}), 400

            # Check if this is a local or remote node
            api = get_api_session()
            nodes = api.get_nodes()

            target_node = None
            for n in nodes:
                if n.get('name') == name:
                    target_node = n
                    break

            if not target_node:
                return jsonify({'error': f'Node "{name}" not found'}), 404

            # Check if this is the local node
            local_hostname = socket.gethostname()
            is_local = (target_node.get('type') == 'master' or
                       name == local_hostname or
                       name.replace('-server', '') == local_hostname or
                       local_hostname.replace('-server', '') == name.replace('-server', ''))

            upgrade_path = '/var/ossec/var/upgrade'
            file_path = os.path.join(upgrade_path, safe_filename)

            if is_local:
                # Local node - delete file directly
                if not os.path.exists(file_path):
                    return jsonify({'error': f'File not found: {safe_filename}'}), 404

                os.remove(file_path)
                logger.info(f"WPK deleted: {file_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                return jsonify({
                    'success': True,
                    'message': f'File "{safe_filename}" deleted successfully'
                })

            else:
                # Remote node - use SSH
                config = get_config()
                ssh_cfg = config.get_ssh_config_for_node(name)

                if ssh_cfg:
                    try:
                        # Use safe_shell_arg for the file path in the remote command
                        ssh_cmd = [
                            'ssh',
                            '-i', ssh_cfg['key_file'],
                            '-o', 'StrictHostKeyChecking=no',
                            '-o', 'ConnectTimeout=10',
                            '-p', str(ssh_cfg['port']),
                            f"{ssh_cfg['user']}@{ssh_cfg['host']}",
                            f"rm -f {safe_shell_arg(file_path)}"
                        ]
                        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)

                        if result.returncode != 0:
                            return jsonify({
                                'error': f'SSH delete failed: {result.stderr.strip()}',
                                'is_remote': True,
                                'node_ip': target_node.get('ip', '')
                            }), 400

                        logger.info(f"WPK deleted via SSH: {name}:{file_path} by user '{session.get('api_session', {}).get('username', 'unknown')}'")

                        return jsonify({
                            'success': True,
                            'message': f'File "{safe_filename}" deleted from {name} successfully'
                        })

                    except subprocess.TimeoutExpired:
                        return jsonify({
                            'error': 'SSH connection timed out',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                    except Exception as e:
                        logger.error(f"SSH delete error for {name}: {str(e)}")
                        return jsonify({
                            'error': f'SSH error: {str(e)}',
                            'is_remote': True,
                            'node_ip': target_node.get('ip', '')
                        }), 400
                else:
                    return jsonify({
                        'error': f'Worker node "{name}" requires SSH configuration.',
                        'is_remote': True,
                        'node_ip': target_node.get('ip', '')
                    }), 400

        except Exception as e:
            logger.error(f"Delete WPK failed: {str(e)}")
            return jsonify({'error': str(e)}), 500

    # ---------- Batch A: config safety, custom WPK upgrade, agent runtime config ----------

    @app.route('/api/nodes/<name>/config/validate', methods=['GET'])
    @login_required
    def validate_node_config(name):
        """Ask Wazuh whether the node's current ossec.conf is valid.

        Editing ossec.conf and restarting blindly can leave a manager down; this
        is the check the CLI performs before a restart.
        """
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            api = get_api_session()
            local = api.request('GET', '/cluster/local/info')
            local_name = (local.get('data', {}).get('affected_items') or [{}])[0].get('node')
            if local_name and name != local_name:
                result = api.request('GET', f'/cluster/{name}/configuration/validation')
            else:
                result = api.request('GET', '/manager/configuration/validation')
            items = result.get('data', {}).get('affected_items') or []
            failed = result.get('data', {}).get('failed_items') or []
            status = (items[0].get('status') if items else None) or ('KO' if failed else 'unknown')
            details = []
            for f in failed:
                err = f.get('error', {})
                details.append(err.get('message') if isinstance(err, dict) else str(err))
            for item in items:
                details.extend(item.get('details') or [])
            logger.info(f"CONFIG VALIDATE: user={get_current_user()} node={sanitize_for_log(name)} status={status}")
            return jsonify({'node': name, 'status': status, 'valid': status == 'OK',
                            'details': details, 'result': result})
        except Exception as e:
            logger.error(f"CONFIG VALIDATE ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/<name>/reload-ruleset', methods=['PUT'])
    @login_required
    def reload_node_ruleset(name):
        """Reload the ruleset in analysisd without restarting the manager."""
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            api = get_api_session()
            local = api.request('GET', '/cluster/local/info')
            local_name = (local.get('data', {}).get('affected_items') or [{}])[0].get('node')
            if local_name and name != local_name:
                result = api.request('PUT', '/cluster/analysisd/reload', params={'nodes_list': name})
            else:
                result = api.request('PUT', '/manager/analysisd/reload')
            failed = result.get('data', {}).get('failed_items') or []
            logger.info(f"RULESET RELOAD: user={get_current_user()} node={sanitize_for_log(name)} failed={len(failed)}")
            if failed:
                err = failed[0].get('error', {})
                msg = err.get('message') if isinstance(err, dict) else str(err)
                return jsonify({'error': msg or 'Reload failed', 'result': result}), 400
            return jsonify({'success': True, 'message': f"Ruleset reloaded on {name}", 'result': result})
        except Exception as e:
            logger.error(f"RULESET RELOAD ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    # ossec.conf is NOT synchronised by the cluster: each node keeps its own copy.
    # A node can therefore silently miss a CDB list declaration or have a module
    # disabled, which quietly kills whole families of rules on that node only.
    # These are the sections where such a drift actually changes detection.
    CONFIG_DIFF_SECTIONS = {
        'ruleset':         ('list', 'rule_dir', 'decoder_dir', 'rule_exclude', 'decoder_exclude'),
        'syscheck':        ('directories', 'ignore', 'nodiff', 'disabled', 'frequency'),
        'rootcheck':       ('disabled',),
        'localfile':       ('location', 'log_format', 'command'),
        'active-response': ('command', 'location', 'disabled'),
        'command':         ('name', 'executable'),
    }

    def _config_fingerprint(raw_xml: str) -> dict:
        """Reduce an ossec.conf to the comparable items of each relevant section."""
        import xml.etree.ElementTree as ET
        result = {name: [] for name in CONFIG_DIFF_SECTIONS}
        result['wodle'] = []
        try:
            root = ET.fromstring('<root>' + raw_xml + '</root>')
        except Exception:
            # ossec.conf may hold several <ossec_config> blocks and comments
            try:
                cleaned = re.sub(r'<!--.*?-->', '', raw_xml, flags=re.S)
                root = ET.fromstring('<root>' + cleaned + '</root>')
            except Exception as e:
                raise ValueError(f'Unable to parse configuration: {e}')

        for section, tags in CONFIG_DIFF_SECTIONS.items():
            for node in root.iter(section):
                for tag in tags:
                    for child in node.findall(tag):
                        value = ' '.join((child.text or '').split())
                        attrs = ' '.join(f'{k}={v}' for k, v in sorted(child.attrib.items()))
                        item = f'{tag}: {value}' + (f'  [{attrs}]' if attrs else '')
                        result[section].append(item)
        for node in root.iter('wodle'):
            name = node.get('name', '?')
            disabled = (node.findtext('disabled') or 'no').strip()
            result['wodle'].append(f'{name}: disabled={disabled}')
        return {k: sorted(set(v)) for k, v in result.items()}

    # ---------- Rule packs (Jason Tools maintained rule series) ----------

    PACKS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'packs')

    def _wazuh_path():
        """Honour wazuh_path from config.yaml instead of assuming /var/ossec."""
        try:
            return get_config().wazuh_path or '/var/ossec'
        except Exception:
            return '/var/ossec'

    def _pack_state_dir():
        return os.path.join(_wazuh_path(), 'etc', 'jt-packs')
    PACK_ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
    PACK_DEST_ROOTS = ('etc/rules/', 'etc/lists/', 'etc/decoders/')

    def _pack_dir(pack_id):
        if not PACK_ID_PATTERN.match(pack_id or ''):
            return None
        path = os.path.join(PACKS_DIR, pack_id)
        # never let an id escape the catalogue directory
        if os.path.realpath(path) != os.path.join(os.path.realpath(PACKS_DIR), pack_id):
            return None
        return path if os.path.isdir(path) else None

    def _read_manifest(pack_id):
        pdir = _pack_dir(pack_id)
        if not pdir:
            return None
        try:
            with open(os.path.join(pdir, 'manifest.json'), encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return None

    def _pack_state_path(pack_id):
        return os.path.join(_pack_state_dir(), pack_id + '.json')

    def _installed_state(pack_id):
        try:
            with open(_pack_state_path(pack_id), encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return None

    def _validate_dest(dest):
        """A manifest may only write into the Wazuh rule/list/decoder directories."""
        if not dest or '..' in dest or dest.startswith('/'):
            return False
        if not any(dest.startswith(root) for root in PACK_DEST_ROOTS):
            return False
        return bool(re.match(r'^[A-Za-z0-9._/-]+$', dest))

    def _ruleset_is_valid():
        """Run the same check the manager does at startup."""
        import subprocess
        try:
            proc = subprocess.run([os.path.join(_wazuh_path(), 'bin', 'wazuh-analysisd'), '-t'],
                                  capture_output=True, text=True, timeout=120)
            output = (proc.stdout or '') + (proc.stderr or '')
            bad = [l for l in output.splitlines()
                   if re.search(r'\b(ERROR|CRITICAL)\b', l)]
            return (not bad), bad[:10]
        except Exception as e:
            return False, [str(e)]

    def _declare_lists(list_paths, remove=False):
        """Add or remove <list> entries in ossec.conf. Returns the previous content."""
        conf_path = os.path.join(_wazuh_path(), 'etc', 'ossec.conf')
        with open(conf_path, encoding='utf-8') as fh:
            original = fh.read()
        content = original
        for rel in list_paths:
            tag = '<list>%s</list>' % rel
            present = tag in content
            if remove and present:
                content = re.sub(r'[ \t]*' + re.escape(tag) + r'\n', '', content)
            elif not remove and not present:
                block = re.search(r'<ruleset>.*?</ruleset>', content, re.S)
                if not block:
                    continue
                last = None
                for m in re.finditer(r'[ \t]*<list>[^<]+</list>\n', block.group(0)):
                    last = m
                if last:
                    indent = re.match(r'[ \t]*', last.group(0)).group(0)
                    pos = block.start() + last.end()
                else:
                    indent = '    '
                    pos = block.start() + block.group(0).rfind('</ruleset>')
                content = content[:pos] + indent + tag + '\n' + content[pos:]
        if content != original:
            with open(conf_path, 'w', encoding='utf-8') as fh:
                fh.write(content)
        return original

    def _installed_rule_ids(skip_files=()):
        """Rule ids already present on the manager, for conflict detection."""
        import xml.etree.ElementTree as ET
        ids = {}
        for path in sorted(glob.glob(os.path.join(_wazuh_path(), 'etc', 'rules', '*.xml'))):
            if os.path.basename(path) in skip_files:
                continue
            try:
                with open(path, encoding='utf-8', errors='ignore') as fh:
                    root = ET.fromstring('<rules>' + fh.read() + '</rules>')
            except Exception:
                continue
            for rule in root.iter('rule'):
                ids[rule.get('id')] = os.path.basename(path)
        return ids

    def _pack_rule_ids(pdir, manifest):
        import xml.etree.ElementTree as ET
        ids = []
        for entry in manifest.get('files', []):
            if entry.get('type') != 'rule':
                continue
            src = os.path.join(pdir, 'rules', entry['name'])
            try:
                with open(src, encoding='utf-8', errors='ignore') as fh:
                    root = ET.fromstring('<rules>' + fh.read() + '</rules>')
            except Exception:
                continue
            ids.extend(r.get('id') for r in root.iter('rule'))
        return ids

    @app.route('/api/packs', methods=['GET'])
    @login_required
    def list_packs():
        """The Jason Tools rule catalogue, with the installed state of each pack."""
        try:
            packs = []
            for entry in sorted(os.listdir(PACKS_DIR)) if os.path.isdir(PACKS_DIR) else []:
                manifest = _read_manifest(entry)
                if not manifest:
                    continue
                state = _installed_state(entry)
                packs.append({
                    'id': manifest.get('id', entry),
                    'name': manifest.get('name', entry),
                    'name_zh': manifest.get('name_zh', ''),
                    'version': manifest.get('version', ''),
                    'summary': manifest.get('summary', ''),
                    'summary_zh': manifest.get('summary_zh', ''),
                    'author': manifest.get('author', ''),
                    'license': manifest.get('license', ''),
                    'rule_id_range': manifest.get('rule_id_range', ''),
                    'file_count': len(manifest.get('files', [])),
                    'installed': bool(state),
                    'installed_version': (state or {}).get('version'),
                    'installed_at': (state or {}).get('installed_at'),
                    'update_available': bool(state) and state.get('version') != manifest.get('version'),
                })
            return jsonify({'packs': packs, 'total': len(packs)})
        except Exception as e:
            logger.error(f"PACK LIST ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/packs/<pack_id>', methods=['GET'])
    @login_required
    def get_pack_detail(pack_id):
        """Manifest, the rules it contains, and any conflict with what is installed."""
        manifest = _read_manifest(pack_id)
        if not manifest:
            return jsonify({'error': 'Unknown pack'}), 404
        try:
            pdir = _pack_dir(pack_id)
            state = _installed_state(pack_id)
            own_files = {f['name'] for f in manifest.get('files', []) if f.get('type') == 'rule'}
            existing = _installed_rule_ids(skip_files=own_files if state else ())
            rule_ids = _pack_rule_ids(pdir, manifest)
            conflicts = [{'rule': rid, 'file': existing[rid]} for rid in rule_ids if rid in existing]

            files = []
            for entry in manifest.get('files', []):
                sub = 'rules' if entry['type'] == 'rule' else ('lists' if entry['type'] == 'list' else 'decoders')
                src = os.path.join(pdir, sub, entry['name'])
                size = os.path.getsize(src) if os.path.isfile(src) else 0
                files.append({**entry, 'size': size})
            return jsonify({
                'manifest': manifest,
                'files': files,
                'rule_ids': rule_ids,
                'rule_count': len(rule_ids),
                'conflicts': conflicts,
                'installed': bool(state),
                'state': state,
            })
        except Exception as e:
            logger.error(f"PACK DETAIL ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/packs/<pack_id>/install', methods=['POST'])
    @login_required
    def install_pack(pack_id):
        """Install a pack, rolling everything back if the ruleset stops validating.

        Nothing is left half-applied: files are backed up before being written and
        restored on any failure, including a failed ruleset check.
        """
        import shutil, time as _time
        manifest = _read_manifest(pack_id)
        if not manifest:
            return jsonify({'error': 'Unknown pack'}), 404
        pdir = _pack_dir(pack_id)
        data = request.get_json(silent=True) or {}
        force = bool(data.get('force'))

        try:
            state = _installed_state(pack_id)
            own = {f['name'] for f in manifest.get('files', []) if f.get('type') == 'rule'}
            existing = _installed_rule_ids(skip_files=own if state else ())
            conflicts = [rid for rid in _pack_rule_ids(pdir, manifest) if rid in existing]
            if conflicts and not force:
                return jsonify({'error': 'Rule ID conflict with rules already installed',
                                'conflicts': conflicts[:20]}), 409

            backup_dir = os.path.join(_pack_state_dir(), 'backup',
                                      f'{pack_id}-{int(_time.time())}')
            os.makedirs(backup_dir, exist_ok=True)
            os.makedirs(_pack_state_dir(), exist_ok=True)

            written, backed_up, list_paths = [], [], []
            conf_before = None
            try:
                for entry in manifest.get('files', []):
                    dest_rel = entry.get('dest', '')
                    if not _validate_dest(dest_rel):
                        raise ValueError(f'Refusing unsafe destination: {dest_rel}')
                    sub = 'rules' if entry['type'] == 'rule' else ('lists' if entry['type'] == 'list' else 'decoders')
                    src = os.path.join(pdir, sub, entry['name'])
                    dest = os.path.join(_wazuh_path(), dest_rel)
                    if os.path.exists(dest):
                        shutil.copy2(dest, os.path.join(backup_dir, os.path.basename(dest)))
                        backed_up.append(dest)
                    shutil.copy2(src, dest)
                    try:
                        shutil.chown(dest, 'wazuh', 'wazuh')
                    except Exception:
                        pass
                    os.chmod(dest, 0o660)
                    written.append(dest)
                    if entry['type'] == 'list' and entry.get('declare'):
                        list_paths.append(dest_rel)

                if list_paths:
                    conf_before = _declare_lists(list_paths, remove=False)

                ok, problems = _ruleset_is_valid()
                if not ok:
                    raise RuntimeError('Ruleset validation failed: ' + '; '.join(problems[:3]))
            except Exception as install_error:
                # roll everything back
                for dest in written:
                    backup = os.path.join(backup_dir, os.path.basename(dest))
                    if os.path.exists(backup):
                        shutil.copy2(backup, dest)
                    elif os.path.exists(dest):
                        os.remove(dest)
                if conf_before is not None:
                    with open(os.path.join(_wazuh_path(), 'etc', 'ossec.conf'), 'w', encoding='utf-8') as fh:
                        fh.write(conf_before)
                logger.error(f"PACK INSTALL ROLLED BACK: user={get_current_user()} "
                             f"pack={sanitize_for_log(pack_id)} error={sanitize_for_log(str(install_error))}")
                return jsonify({'error': str(install_error), 'rolled_back': True}), 400

            state = {
                'id': pack_id,
                'version': manifest.get('version', ''),
                'installed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'installed_by': get_current_user(),
                'files': [{'dest': e['dest'], 'sha256': e.get('sha256', '')} for e in manifest.get('files', [])],
                'declared_lists': list_paths,
                'backup_dir': backup_dir,
                'replaced': backed_up,
            }
            with open(_pack_state_path(pack_id), 'w', encoding='utf-8') as fh:
                json.dump(state, fh, ensure_ascii=False, indent=2)

            logger.info(f"PACK INSTALLED: user={get_current_user()} pack={sanitize_for_log(pack_id)} "
                        f"version={manifest.get('version')} files={len(written)}")
            return jsonify({'success': True, 'pack': pack_id, 'files': len(written),
                            'declared_lists': list_paths, 'replaced': backed_up,
                            'message': f"Installed {pack_id} {manifest.get('version','')}. "
                                       f"Reload the ruleset for it to take effect."})
        except Exception as e:
            logger.error(f"PACK INSTALL ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/packs/<pack_id>', methods=['DELETE'])
    @login_required
    def uninstall_pack(pack_id):
        """Remove a pack, restoring anything it replaced."""
        import shutil
        if not PACK_ID_PATTERN.match(pack_id or ''):
            return jsonify({'error': 'Invalid pack id'}), 400
        state = _installed_state(pack_id)
        if not state:
            return jsonify({'error': 'Pack is not installed'}), 404
        data = request.get_json(silent=True) or {}
        force = bool(data.get('force'))
        try:
            modified = []
            for entry in state.get('files', []):
                dest = os.path.join(_wazuh_path(), entry['dest'])
                if not os.path.exists(dest):
                    continue
                if entry.get('sha256'):
                    import hashlib
                    with open(dest, 'rb') as fh:
                        current = hashlib.sha256(fh.read()).hexdigest()
                    if current != entry['sha256']:
                        modified.append(entry['dest'])
            if modified and not force:
                return jsonify({'error': 'Some files were edited after installation',
                                'modified': modified,
                                'hint': 'Re-send with force=true to remove them anyway'}), 409

            removed = []
            for entry in state.get('files', []):
                dest = os.path.join(_wazuh_path(), entry['dest'])
                backup = os.path.join(state.get('backup_dir', ''), os.path.basename(dest))
                if os.path.isfile(backup):
                    shutil.copy2(backup, dest)      # restore what the pack replaced
                elif os.path.exists(dest):
                    os.remove(dest)
                    removed.append(entry['dest'])

            if state.get('declared_lists'):
                _declare_lists(state['declared_lists'], remove=True)

            ok, problems = _ruleset_is_valid()
            os.remove(_pack_state_path(pack_id))
            logger.info(f"PACK UNINSTALLED: user={get_current_user()} pack={sanitize_for_log(pack_id)} "
                        f"removed={len(removed)} ruleset_ok={ok}")
            return jsonify({'success': True, 'pack': pack_id, 'removed': removed,
                            'ruleset_valid': ok, 'problems': problems,
                            'message': f"Removed {pack_id}. Reload the ruleset for it to take effect."})
        except Exception as e:
            logger.error(f"PACK UNINSTALL ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/nodes/config-diff', methods=['GET'])
    @login_required
    def get_node_config_diff():
        """Compare each node's ossec.conf against the master, section by section.

        The cluster synchronises rules and lists but not ossec.conf, so a worker
        can be missing a <list> declaration and silently ignore every rule that
        uses it. Nothing in Wazuh surfaces that drift.
        """
        try:
            api = get_api_session()
            nodes = api.get_nodes() or []
            if not nodes:
                return jsonify({'error': 'No cluster nodes available'}), 400

            master = next((n for n in nodes if n.get('type') == 'master'), nodes[0])
            reference = master.get('name')

            fingerprints, errors = {}, {}
            for node in nodes:
                name = node.get('name')
                if not name or not validate_node_name(name):
                    continue
                try:
                    ok, raw = api.request_raw('GET', f'/cluster/{name}/configuration',
                                              params={'raw': 'true'})
                    if not ok:
                        errors[name] = str(raw)[:200]
                        continue
                    fingerprints[name] = _config_fingerprint(raw)
                except Exception as e:
                    errors[name] = str(e)[:200]

            if reference not in fingerprints:
                return jsonify({'error': f"Could not read the master node's configuration ({reference})",
                                'errors': errors}), 502

            base = fingerprints[reference]
            differences = []
            for name, fp in fingerprints.items():
                if name == reference:
                    continue
                for section in sorted(set(base) | set(fp)):
                    only_master = [i for i in base.get(section, []) if i not in fp.get(section, [])]
                    only_node = [i for i in fp.get(section, []) if i not in base.get(section, [])]
                    if only_master or only_node:
                        differences.append({
                            'node': name,
                            'section': section,
                            'missing_on_node': only_master,
                            'extra_on_node': only_node,
                        })

            logger.info(
                f"NODE CONFIG DIFF: user={get_current_user()} reference={sanitize_for_log(reference)} "
                f"nodes={len(fingerprints)} differences={len(differences)}"
            )
            return jsonify({
                'reference': reference,
                'nodes': sorted(fingerprints),
                'differences': differences,
                'diff_count': len(differences),
                'errors': errors,
                'sections': sorted(set(CONFIG_DIFF_SECTIONS) | {'wodle'}),
            })
        except Exception as e:
            logger.error(f"NODE CONFIG DIFF ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/cluster/reload-ruleset', methods=['POST'])
    @login_required
    def reload_cluster_ruleset():
        """Reload the ruleset on every node at once.

        Editing rules on the master does not make them active on the workers:
        the cluster syncs the files but each node's analysisd keeps its own
        in-memory copy until it is told to reload. Without this, a rule fix can
        appear to be live while the node that actually processes those agents is
        still running the old ruleset.
        """
        try:
            api = get_api_session()
            status = api.request('GET', '/cluster/status')
            data = status.get('data', {}) or {}
            clustered = str(data.get('enabled', 'no')).lower() in ('yes', 'true') and \
                        str(data.get('running', 'no')).lower() in ('yes', 'true')

            if clustered:
                # no nodes_list -> every node in the cluster
                result = api.request('PUT', '/cluster/analysisd/reload')
                scope = 'cluster'
            else:
                result = api.request('PUT', '/manager/analysisd/reload')
                scope = 'manager'

            payload = result.get('data', {}) or {}
            affected = payload.get('affected_items') or []
            failed = payload.get('failed_items') or []
            nodes, warnings = [], []
            for item in affected:
                if isinstance(item, dict):
                    name = item.get('name') or item.get('node') or 'manager'
                    node_warnings = item.get('warnings') or item.get('msg') or []
                    if isinstance(node_warnings, str):
                        node_warnings = [node_warnings]
                    nodes.append({'node': name, 'ok': True, 'warnings': node_warnings})
                    warnings.extend(node_warnings)
                else:
                    nodes.append({'node': str(item), 'ok': True, 'warnings': []})
            errors = []
            for item in failed:
                err = item.get('error', {})
                msg = err.get('message') if isinstance(err, dict) else str(err)
                for name in (item.get('id') or ['unknown']):
                    nodes.append({'node': str(name), 'ok': False, 'warnings': []})
                    errors.append(f'{name}: {msg}')

            logger.info(
                f"RULESET RELOAD ({scope}): user={get_current_user()} "
                f"ok={len([n for n in nodes if n['ok']])} failed={len(errors)}"
            )
            return jsonify({
                'scope': scope,
                'nodes': nodes,
                'ok_count': len([n for n in nodes if n['ok']]),
                'fail_count': len(errors),
                'errors': errors,
                'warnings': warnings[:20],
                'message': f"Ruleset reloaded on {len([n for n in nodes if n['ok']])} node(s)",
            })
        except Exception as e:
            logger.error(f"CLUSTER RULESET RELOAD ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/upgrade-custom', methods=['POST'])
    @login_required
    def upgrade_agents_custom():
        """Upgrade agents from a WPK file already present on the manager.

        This is the path that works on an air-gapped manager, where the normal
        upgrade cannot reach packages.wazuh.com.
        """
        try:
            data = request.get_json(silent=True) or {}
            agent_ids, err = require_agent_ids(data)
            if err:
                return err
            file_path = (data.get('file_path') or '').strip()
            if not file_path:
                return jsonify({'error': 'A WPK file must be selected'}), 400
            # Accept only a bare WPK name; the path handed to Wazuh is always
            # rebuilt from it, so nothing the caller sends can escape the dir.
            filename = os.path.basename(file_path)
            if not re.match(r'^[A-Za-z0-9._-]+\.wpk$', filename):
                return jsonify({'error': 'Invalid WPK file name'}), 400
            installer = (data.get('installer') or '').strip()
            if installer and not re.match(r'^[A-Za-z0-9._-]+$', installer):
                return jsonify({'error': 'Invalid installer name'}), 400

            params = {'agents_list': ','.join(agent_ids), 'file_path': f'var/upgrade/{filename}'}
            if installer:
                params['installer'] = installer
            api = get_api_session()
            result = api.request('PUT', '/agents/upgrade_custom', params=params)
            failed = result.get('data', {}).get('failed_items') or []
            affected = result.get('data', {}).get('affected_items') or []
            logger.info(
                f"AGENT UPGRADE CUSTOM: user={get_current_user()} agents={agent_ids} "
                f"wpk={sanitize_for_log(filename)} ok={len(affected)} failed={len(failed)}"
            )
            return jsonify({
                'success_count': len(affected),
                'fail_count': len(failed),
                'message': f"Custom upgrade queued for {len(affected)} agent(s)",
                'result': result,
            })
        except Exception as e:
            logger.error(f"AGENT UPGRADE CUSTOM ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/<agent_id>/runtime-config', methods=['GET'])
    @login_required
    def get_agent_runtime_config(agent_id):
        """Read the configuration an agent is actually running.

        Answers 'did my group agent.conf actually reach this agent', which the
        stored group file cannot.
        """
        if not validate_agent_id(agent_id):
            return jsonify({'error': 'Invalid agent ID'}), 400
        component = (request.args.get('component') or 'agent').strip()
        configuration = (request.args.get('configuration') or 'client').strip()
        if not re.match(r'^[a-z-]{1,32}$', component) or not re.match(r'^[a-z_-]{1,32}$', configuration):
            return jsonify({'error': 'Invalid component or configuration'}), 400
        try:
            api = get_api_session()
            result = api.request('GET', f'/agents/{agent_id}/config/{component}/{configuration}')
            if result.get('error'):
                msg = result.get('error')
                if isinstance(msg, dict):
                    msg = msg.get('message', str(msg))
                return jsonify({'error': msg}), 400
            return jsonify({'agent_id': agent_id, 'component': component,
                            'configuration': configuration,
                            'config': result.get('data', {})})
        except Exception as e:
            logger.error(f"AGENT RUNTIME CONFIG ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/<agent_id>/key', methods=['GET'])
    @login_required
    def get_agent_key(agent_id):
        """Fetch an agent's enrollment key (for re-registering a broken agent)."""
        if not validate_agent_id(agent_id):
            return jsonify({'error': 'Invalid agent ID'}), 400
        try:
            api = get_api_session()
            result = api.request('GET', f'/agents/{agent_id}/key')
            items = result.get('data', {}).get('affected_items') or []
            if not items:
                return jsonify({'error': 'Key not available for this agent'}), 404
            logger.info(f"AGENT KEY VIEWED: user={get_current_user()} agent={agent_id}")
            return jsonify({'agent_id': agent_id, 'key': items[0].get('key', '')})
        except Exception as e:
            logger.error(f"AGENT KEY ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    # ---------- Batch B: logtest, decoders, CDB lists ----------

    LOGTEST_FORMATS = {
        'syslog', 'json', 'snort-full', 'squid', 'eventlog', 'eventchannel', 'audit',
        'mysql_log', 'postgresql_log', 'nmapg', 'iis', 'command', 'full_command',
        'djb-multilog', 'multi-line',
    }

    @app.route('/api/logtest', methods=['POST'])
    @login_required
    def run_logtest():
        """Run a log line through the ruleset and report what it matched."""
        try:
            data = request.get_json(silent=True) or {}
            event = data.get('event') or ''
            if not event.strip():
                return jsonify({'error': 'A log line is required'}), 400
            if len(event) > 20000:
                return jsonify({'error': 'Log line is too long'}), 400
            log_format = (data.get('log_format') or 'syslog').strip()
            if log_format not in LOGTEST_FORMATS:
                return jsonify({'error': 'Unsupported log format'}), 400
            location = (data.get('location') or 'stdin').strip()[:256]
            token = (data.get('token') or '').strip()
            if token and not re.match(r'^[A-Za-z0-9]{1,64}$', token):
                return jsonify({'error': 'Invalid session token'}), 400

            payload = {'event': event, 'log_format': log_format, 'location': location}
            if token:
                payload['token'] = token
            api = get_api_session()
            result = api.request('PUT', '/logtest', data=payload)
            if result.get('error') and not result.get('data'):
                msg = result.get('error')
                if isinstance(msg, dict):
                    msg = msg.get('message', str(msg))
                return jsonify({'error': msg}), 400
            payload_data = result.get('data', {})
            logger.info(f"LOGTEST: user={get_current_user()} format={log_format}")
            return jsonify({
                'token': payload_data.get('token', ''),
                'messages': payload_data.get('messages', []),
                'output': payload_data.get('output', {}),
                'alert': bool((payload_data.get('output') or {}).get('rule')),
            })
        except Exception as e:
            logger.error(f"LOGTEST ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logtest/session/<token>', methods=['DELETE'])
    @login_required
    def end_logtest_session(token):
        """Release a logtest session so analysisd frees its resources."""
        if not re.match(r'^[A-Za-z0-9]{1,64}$', token or ''):
            return jsonify({'error': 'Invalid session token'}), 400
        try:
            api = get_api_session()
            result = api.request('DELETE', f'/logtest/sessions/{token}')
            return jsonify({'success': True, 'result': result})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/decoders', methods=['GET'])
    @login_required
    def get_decoders():
        """List decoders, optionally filtered by name / file / free-text search."""
        try:
            params = {'limit': 5000}
            for key, arg in (('search', 'search'), ('filename', 'filename'), ('decoder_name', 'name')):
                value = (request.args.get(arg) or '').strip()
                if value:
                    if len(value) > 128:
                        return jsonify({'error': f'{arg} is too long'}), 400
                    params[key] = value
            api = get_api_session()
            result = api.request('GET', '/decoders', params=params)
            items = result.get('data', {}).get('affected_items') or []
            for item in items:
                # relative_dirname is relative to /var/ossec: built-ins live under
                # ruleset/, anything the operator adds lives under etc/.
                item['is_custom'] = (item.get('relative_dirname') or '').startswith('etc/')
            return jsonify({'decoders': items, 'total': result.get('data', {}).get('total_affected_items', len(items))})
        except Exception as e:
            logger.error(f"DECODERS ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/decoders/file', methods=['GET'])
    @login_required
    def get_decoder_file():
        """Return the XML of one decoder file."""
        filename = (request.args.get('filename') or '').strip()
        if not re.match(r'^[A-Za-z0-9._-]+\.xml$', filename):
            return jsonify({'error': 'Invalid decoder file name'}), 400
        try:
            api = get_api_session()
            ok, content = api.request_raw('GET', f'/decoders/files/{filename}', params={'raw': 'true'})
            if not ok:
                return jsonify({'error': content}), 400
            return jsonify({'filename': filename, 'content': content})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lists', methods=['GET'])
    @login_required
    def get_cdb_lists():
        """List the CDB lists known to the manager."""
        try:
            api = get_api_session()
            result = api.request('GET', '/lists', params={'limit': 1000})
            items = result.get('data', {}).get('affected_items') or []
            for item in items:
                item['is_custom'] = (item.get('relative_dirname') or '').startswith('etc/')
            return jsonify({'lists': items, 'total': len(items)})
        except Exception as e:
            logger.error(f"CDB LISTS ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    def _cdb_filename_ok(name: str) -> bool:
        return bool(name) and len(name) <= 128 and bool(re.match(r'^[A-Za-z0-9._-]+$', name))

    @app.route('/api/lists/file', methods=['GET'])
    @login_required
    def get_cdb_list_file():
        """Read one CDB list as plain text."""
        filename = (request.args.get('filename') or '').strip()
        if not _cdb_filename_ok(filename):
            return jsonify({'error': 'Invalid list name'}), 400
        try:
            api = get_api_session()
            ok, content = api.request_raw('GET', f'/lists/files/{filename}', params={'raw': 'true'})
            if not ok:
                return jsonify({'error': content}), 400
            return jsonify({'filename': filename, 'content': content})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lists/file', methods=['PUT'])
    @login_required
    def save_cdb_list_file():
        """Create or overwrite a CDB list.

        Wazuh needs the ruleset reloaded (or the manager restarted) before a
        changed list takes effect; the UI says so after a successful save.
        """
        data = request.get_json(silent=True) or {}
        filename = (data.get('filename') or '').strip()
        if not _cdb_filename_ok(filename):
            return jsonify({'error': 'Invalid list name'}), 400
        content = data.get('content')
        if content is None:
            return jsonify({'error': 'Content is required'}), 400
        if len(content) > 5 * 1024 * 1024:
            return jsonify({'error': 'List is too large'}), 400
        try:
            api = get_api_session()
            ok, response = api.request_raw('PUT', f'/lists/files/{filename}',
                                           body=content, params={'overwrite': 'true'})
            if not ok:
                logger.warning(f"CDB LIST SAVE FAILED: user={get_current_user()} "
                               f"file={sanitize_for_log(filename)} error={sanitize_for_log(str(response))}")
                return jsonify({'error': response}), 400
            logger.info(f"CDB LIST SAVED: user={get_current_user()} file={sanitize_for_log(filename)} "
                        f"bytes={len(content)}")
            return jsonify({'success': True,
                            'message': f"Saved {filename}. Reload the ruleset for it to take effect."})
        except Exception as e:
            logger.error(f"CDB LIST SAVE ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/lists/file', methods=['DELETE'])
    @login_required
    def delete_cdb_list_file():
        """Delete a CDB list."""
        filename = (request.args.get('filename') or '').strip()
        if not _cdb_filename_ok(filename):
            return jsonify({'error': 'Invalid list name'}), 400
        try:
            api = get_api_session()
            result = api.request('DELETE', f'/lists/files/{filename}')
            failed = result.get('data', {}).get('failed_items') or []
            if failed:
                err = failed[0].get('error', {})
                return jsonify({'error': err.get('message') if isinstance(err, dict) else str(err)}), 400
            logger.info(f"CDB LIST DELETED: user={get_current_user()} file={sanitize_for_log(filename)}")
            return jsonify({'success': True, 'message': f"Deleted {filename}"})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ---------- Batch C: cross-agent inventory search ----------

    # type -> (syscollector path, preferred columns)
    INVENTORY_TYPES = {
        'packages':   ('packages',   ['name', 'version', 'architecture', 'vendor', 'format']),
        'ports':      ('ports',      ['local.port', 'protocol', 'local.ip', 'state', 'process', 'pid']),
        'processes':  ('processes',  ['name', 'pid', 'ppid', 'state', 'cmd']),
        'services':   ('services',   ['name', 'state', 'start_type', 'description']),
        'users':      ('users',      ['user_name', 'user_id', 'user_home', 'user_shell']),
        'hotfixes':   ('hotfixes',   ['hotfix']),
        'netiface':   ('netiface',   ['name', 'mac', 'state', 'mtu', 'type']),
        'os':         ('os',         ['os.name', 'os.version', 'architecture', 'hostname']),
        'browser_extensions': ('browser_extensions', ['name', 'browser_name', 'version', 'enabled']),
    }

    @app.route('/api/inventory/types', methods=['GET'])
    @login_required
    def get_inventory_types():
        """Expose the inventory categories and their preferred columns."""
        return jsonify({'types': {k: {'columns': v[1]} for k, v in INVENTORY_TYPES.items()}})

    @app.route('/api/inventory/search', methods=['GET'])
    @login_required
    def search_inventory():
        """Search one syscollector category across many agents at once.

        The Dashboard shows inventory one agent at a time; the question that
        actually matters during an incident is the reverse -- which agents have
        this package / this port open / this process running.
        """
        try:
            inv_type = (request.args.get('type') or 'packages').strip()
            if inv_type not in INVENTORY_TYPES:
                return jsonify({'error': 'Unknown inventory type'}), 400
            query = (request.args.get('q') or '').strip()
            if len(query) > 128:
                return jsonify({'error': 'Search text is too long'}), 400

            agents_arg = (request.args.get('agents') or 'active').strip()
            per_agent_limit = 500
            MAX_AGENTS = 300
            MAX_ROWS = 5000

            api = get_api_session()

            # Decide which agents to query, and remember their names for display
            if agents_arg in ('active', 'all'):
                status = None if agents_arg == 'all' else 'active'
                agent_items = api.get_agents(status=status, limit=MAX_AGENTS)
            else:
                ids = [a for a in agents_arg.split(',') if a]
                if not all(validate_agent_id(a) for a in ids):
                    return jsonify({'error': 'Invalid agent ID in the list'}), 400
                agent_items = api.get_agents(limit=MAX_AGENTS)
                agent_items = [a for a in agent_items if a.get('id') in ids]

            # get_agents() already flattens os into a display string
            targets = [(a.get('id'), a.get('name', ''), a.get('os', ''))
                       for a in agent_items if a.get('id') and a.get('id') != '000']
            truncated_agents = len(targets) >= MAX_AGENTS
            path, columns = INVENTORY_TYPES[inv_type]

            def fetch(target):
                agent_id, agent_name, agent_os = target
                params = {'limit': per_agent_limit}
                if query:
                    params['search'] = query
                try:
                    res = api.request('GET', f'/syscollector/{agent_id}/{path}', params=params)
                except SessionExpiredException:
                    raise
                except Exception as e:
                    return agent_id, agent_name, agent_os, [], str(e)
                if res.get('error') and not res.get('data'):
                    err = res.get('error')
                    if isinstance(err, dict):
                        err = err.get('message', str(err))
                    return agent_id, agent_name, agent_os, [], str(err)
                return agent_id, agent_name, agent_os, (res.get('data', {}).get('affected_items') or []), None

            rows, errors = [], []
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=8) as pool:
                for agent_id, agent_name, agent_os, items, error in pool.map(fetch, targets):
                    if error:
                        errors.append({'agent_id': agent_id, 'agent_name': agent_name,
                                       'error': sanitize_for_log(error, 120)})
                        continue
                    for item in items:
                        if len(rows) >= MAX_ROWS:
                            break
                        row = {'agent_id': agent_id, 'agent_name': agent_name, 'agent_os': agent_os}
                        row.update(item if isinstance(item, dict) else {'value': item})
                        rows.append(row)

            matched_agents = len({r['agent_id'] for r in rows})
            logger.info(
                f"INVENTORY SEARCH: user={get_current_user()} type={inv_type} "
                f"q={sanitize_for_log(query)} agents={len(targets)} rows={len(rows)}"
            )
            return jsonify({
                'type': inv_type,
                'query': query,
                'columns': columns,
                'rows': rows,
                'total': len(rows),
                'agents_queried': len(targets),
                'agents_matched': matched_agents,
                'agents_failed': errors,
                'truncated': len(rows) >= MAX_ROWS or truncated_agents,
                'max_rows': MAX_ROWS,
            })
        except SessionExpiredException:
            raise
        except Exception as e:
            logger.error(f"INVENTORY SEARCH ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    # ---------- Batch D: daemon health, group files, active response, quick enrol ----------

    WAZUH_DAEMONS = ['wazuh-analysisd', 'wazuh-remoted', 'wazuh-db']

    @app.route('/api/nodes/<name>/daemon-stats', methods=['GET'])
    @login_required
    def get_node_daemon_stats(name):
        """Live analysisd/remoted/wazuh-db counters for one node.

        Queue usage and dropped events are the first thing to look at when a
        manager silently stops keeping up, and they are buried in the Dashboard.
        """
        if not validate_node_name(name):
            return jsonify({'error': 'Invalid node name'}), 400
        try:
            api = get_api_session()
            local = api.request('GET', '/cluster/local/info')
            local_name = (local.get('data', {}).get('affected_items') or [{}])[0].get('node')
            params = {'daemons_list': ','.join(WAZUH_DAEMONS)}
            if local_name and name != local_name:
                result = api.request('GET', f'/cluster/{name}/daemons/stats', params=params)
            else:
                result = api.request('GET', '/manager/daemons/stats', params=params)
            items = result.get('data', {}).get('affected_items') or []
            failed = result.get('data', {}).get('failed_items') or []
            errors = []
            for f in failed:
                err = f.get('error', {})
                errors.append(err.get('message') if isinstance(err, dict) else str(err))
            return jsonify({'node': name, 'daemons': items, 'errors': errors})
        except Exception as e:
            logger.error(f"DAEMON STATS ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/files', methods=['GET'])
    @login_required
    def list_group_files(name):
        """Every file in a group directory, not just agent.conf."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        try:
            api = get_api_session()
            result = api.request('GET', f'/groups/{name}/files', params={'limit': 500})
            items = result.get('data', {}).get('affected_items') or []
            return jsonify({'group': name, 'files': items, 'total': len(items)})
        except Exception as e:
            logger.error(f"GROUP FILES ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/groups/<name>/files/<path:filename>', methods=['GET'])
    @login_required
    def get_group_file(name, filename):
        """Contents of one file inside a group directory."""
        if not validate_group_name(name):
            return jsonify({'error': 'Invalid group name'}), 400
        if not re.match(r'^[A-Za-z0-9._-]+$', filename or ''):
            return jsonify({'error': 'Invalid file name'}), 400
        try:
            api = get_api_session()
            ok, content = api.request_raw('GET', f'/groups/{name}/files/{filename}',
                                          params={'raw': 'true'})
            if not ok:
                return jsonify({'error': content}), 400
            return jsonify({'group': name, 'filename': filename, 'content': content})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # Only commands Wazuh ships as active-response scripts, plus the operator's
    # own (a leading '!' means "a script name, not a binary").
    AR_COMMAND_PATTERN = re.compile(r'^!?[A-Za-z0-9._-]{1,64}$')

    @app.route('/api/active-response', methods=['POST'])
    @login_required
    def run_active_response():
        """Send an active-response command to selected agents."""
        try:
            data = request.get_json(silent=True) or {}
            command = (data.get('command') or '').strip()
            if not AR_COMMAND_PATTERN.match(command):
                return jsonify({'error': 'Invalid active response command'}), 400
            arguments = data.get('arguments') or []
            if not isinstance(arguments, list) or len(arguments) > 16:
                return jsonify({'error': 'Invalid arguments'}), 400
            clean_args = []
            for arg in arguments:
                arg = str(arg)
                if len(arg) > 128 or not re.match(r'^[A-Za-z0-9 ._:/-]*$', arg):
                    return jsonify({'error': f'Invalid argument: {sanitize_for_log(arg, 60)}'}), 400
                if arg:
                    clean_args.append(arg)

            all_agents = bool(data.get('all_agents'))
            if all_agents:
                params = {'agents_list': '*'}
                agent_ids = ['*']
            else:
                agent_ids, err = require_agent_ids(data)
                if err:
                    return err
                params = {'agents_list': ','.join(agent_ids)}

            if data.get('dry_run'):
                logger.info(f"ACTIVE RESPONSE [DRY-RUN]: user={get_current_user()} "
                            f"command={sanitize_for_log(command)} agents={agent_ids}")
                return jsonify({'dry_run': True,
                                'message': f"[DRY-RUN] Would run '{command}' on {len(agent_ids)} agent(s)"})

            body = {'command': command}
            if clean_args:
                body['arguments'] = clean_args
            api = get_api_session()
            result = api.request('PUT', '/active-response', data=body, params=params)
            affected = result.get('data', {}).get('affected_items') or []
            failed = result.get('data', {}).get('failed_items') or []
            logger.info(f"ACTIVE RESPONSE: user={get_current_user()} command={sanitize_for_log(command)} "
                        f"args={clean_args} agents={agent_ids} ok={len(affected)} failed={len(failed)}")
            return jsonify({'success_count': len(affected), 'fail_count': len(failed),
                            'message': f"Command sent to {len(affected)} agent(s)", 'result': result})
        except Exception as e:
            logger.error(f"ACTIVE RESPONSE ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/agents/register', methods=['POST'])
    @login_required
    def register_agents():
        """Pre-register agents by name and hand back their enrollment keys.

        Lets an operator prepare keys before touching the machines, which the
        Dashboard's single deploy command cannot do.
        """
        try:
            data = request.get_json(silent=True) or {}
            names = data.get('names') or []
            if not isinstance(names, list) or not names:
                return jsonify({'error': 'At least one agent name is required'}), 400
            if len(names) > 100:
                return jsonify({'error': 'At most 100 agents can be registered at once'}), 400
            clean = []
            for name in names:
                name = str(name).strip()
                if not name:
                    continue
                if len(name) > 128 or not re.match(r'^[A-Za-z0-9._-]+$', name):
                    return jsonify({'error': f'Invalid agent name: {sanitize_for_log(name, 60)}'}), 400
                clean.append(name)
            if not clean:
                return jsonify({'error': 'At least one agent name is required'}), 400

            api = get_api_session()
            created, failed = [], []
            for name in clean:
                result = api.request('POST', '/agents/insert/quick', params={'agent_name': name})
                items = result.get('data', {}).get('affected_items') or []
                if items:
                    created.append({'name': name, 'id': items[0].get('id', ''),
                                    'key': items[0].get('key', '')})
                    continue
                err = result.get('error')
                detail = result.get('detail') or result.get('message')
                bad = result.get('data', {}).get('failed_items') or []
                if bad:
                    inner = bad[0].get('error', {})
                    detail = inner.get('message') if isinstance(inner, dict) else str(inner)
                failed.append({'name': name, 'error': str(detail or err or 'Registration failed')})
            logger.info(f"AGENT REGISTER: user={get_current_user()} created={[c['name'] for c in created]} "
                        f"failed={len(failed)}")
            return jsonify({'created': created, 'failed': failed,
                            'message': f"Registered {len(created)} of {len(clean)} agent(s)"})
        except Exception as e:
            logger.error(f"AGENT REGISTER ERROR: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/settings', methods=['GET'])
    @login_required
    def get_settings():
        """Get current settings for display in Settings modal."""
        try:
            config = get_config()
            return jsonify({
                'config_file_path': config.config_file_path,
                'api_verify_ssl': config.api_verify_ssl,
                'ssh_enabled': config.ssh_enabled,
                'ssh_key_file': config.ssh_key_file if config.ssh_enabled else None,
                'ssh_nodes': config.ssh_nodes if config.ssh_enabled else {}
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stats/summary', methods=['GET'])
    @login_required
    def get_stats_summary():
        try:
            api = get_api_session()
            summary = api.get_stats_summary()
            return jsonify({'summary': summary})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/stats/report', methods=['GET'])
    @login_required
    def get_stats_report():
        try:
            api = get_api_session()
            agents = api.get_agents()

            # Calculate stats
            from collections import defaultdict

            # Pre-initialize all possible agent statuses (including 0 counts)
            ALL_STATUSES = ['active', 'disconnected', 'pending', 'never_connected']
            status_counts = defaultdict(int, {s: 0 for s in ALL_STATUSES})
            group_counts = defaultdict(int)
            os_counts = defaultdict(int)
            network_counts = defaultdict(int)
            version_counts = defaultdict(int)

            for agent in agents:
                status_counts[agent.get('status', 'Unknown')] += 1
                # Split comma-separated groups and count each separately
                group_str = agent.get('group') or ''
                if group_str:
                    for g in group_str.split(','):
                        group_counts[g.strip()] += 1
                else:
                    group_counts['(no group)'] += 1
                os_name = agent.get('os') or 'Unknown'
                os_counts[os_name] += 1
                # Count agent versions
                version = agent.get('version') or 'Unknown'
                version_counts[version] += 1
                # Calculate network segment (/24)
                ip = agent.get('ip') or ''
                if ip and ip != 'any':
                    parts = ip.split('.')
                    if len(parts) == 4:
                        network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                        network_counts[network] += 1
                    else:
                        network_counts['(invalid IP)'] += 1
                else:
                    network_counts['(no IP)'] += 1

            total = len(agents)

            by_status = [{'status': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                        for k, v in sorted(status_counts.items(), key=lambda x: x[1], reverse=True)]
            by_group = [{'group': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                       for k, v in sorted(group_counts.items(), key=lambda x: x[1], reverse=True)]
            by_os = [{'os': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                    for k, v in sorted(os_counts.items(), key=lambda x: x[0].lower())]
            # Sort networks by IP address for better readability
            def sort_network(item):
                net = item[0]
                if net.startswith('('):
                    return (999, 999, 999, 0)  # Put special entries at end
                parts = net.replace('/24', '').split('.')
                return tuple(int(p) for p in parts)
            by_network = [{'network': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                         for k, v in sorted(network_counts.items(), key=sort_network)]
            # Sort versions in descending order (newest first)
            def parse_version(ver):
                """Parse version string like 'v4.14.0' or 'Wazuh v4.14.0' into tuple."""
                import re
                match = re.search(r'(\d+)\.(\d+)\.(\d+)', ver)
                if match:
                    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                return (0, 0, 0)

            by_version = [{'version': k, 'count': v, 'percentage': round(v/total*100, 1) if total else 0}
                         for k, v in sorted(version_counts.items(), key=lambda x: parse_version(x[0]), reverse=True)]

            return jsonify({
                'by_status': by_status,
                'by_group': by_group,
                'by_os': by_os,
                'by_network': by_network,
                'by_version': by_version
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # User Management API endpoints
    @app.route('/api/users', methods=['GET'])
    @login_required
    def get_users():
        """Get all API users and available roles."""
        try:
            api = get_api_session()

            # Get users
            users = api.get_users()

            # Roles come from the API only. Wazuh ships no `wazuh-user` binary
            # (RBAC users/roles are API-managed), so there is no CLI fallback.
            roles = api.get_roles()
            roles_source = 'api'

            result = {
                'users': users,
                'roles': roles,
                'roles_source': roles_source
            }

            # Note if roles couldn't be fetched
            if not roles:
                result['roles_warning'] = 'Could not fetch roles via API or CLI. Check permissions.'

            return jsonify(result)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users', methods=['POST'])
    @login_required
    def create_user():
        """Create a new API user via API."""
        try:
            data = request.get_json(silent=True) or {}
            username = data.get('username')
            password = data.get('password')
            role_names = data.get('role_names', [])
            operator = get_current_user()

            if not username:
                return jsonify({'error': 'Username is required'}), 400
            if not password:
                return jsonify({'error': 'Password is required'}), 400

            api = get_api_session()

            # Create user via API
            result = api.create_user(username, password)

            if result.get('error'):
                logger.warning(f"USER CREATE FAILED: operator={operator} new_user={username} error={result['error']}")
                return jsonify({'error': result['error']}), 400

            # Assign roles if specified
            if role_names:
                # Get user_id of newly created user
                users = api.get_users()
                new_user = next((u for u in users if u['username'] == username), None)
                if new_user and new_user.get('user_id'):
                    user_id = new_user['user_id']
                    roles = api.get_roles()
                    role_map = {r['name']: r['id'] for r in roles}
                    for role_name in role_names:
                        role_id = role_map.get(role_name)
                        if role_id:
                            api.assign_user_role(user_id, role_id)

            logger.info(f"USER CREATE: operator={operator} new_user={username} roles={role_names}")
            return jsonify({'message': f"User '{username}' created successfully"})
        except Exception as e:
            logger.error(f"USER CREATE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users/<username>', methods=['DELETE'])
    @login_required
    def delete_user(username):
        """Delete an API user via API."""
        if not validate_username(username):
            return jsonify({'error': 'Invalid username'}), 400
        try:
            operator = get_current_user()
            # Prevent deleting system users
            if username in ['wazuh', 'wazuh-wui']:
                logger.warning(f"USER DELETE BLOCKED: operator={operator} attempted to delete system user={username}")
                return jsonify({'error': 'Cannot delete system users'}), 400

            api = get_api_session()
            result = api.delete_user(username)

            if result.get('error'):
                logger.warning(f"USER DELETE FAILED: operator={operator} target={username} error={result['error']}")
                return jsonify({'error': result['error']}), 400

            logger.info(f"USER DELETE: operator={operator} deleted_user={username}")
            return jsonify({
                'message': f"User '{username}' deleted successfully"
            })
        except Exception as e:
            logger.error(f"USER DELETE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/users/<username>/roles', methods=['PUT'])
    @login_required
    def update_user_roles(username):
        """Update roles for a user."""
        if not validate_username(username):
            return jsonify({'error': 'Invalid username'}), 400
        try:
            data = request.get_json(silent=True) or {}
            role_ids = data.get('role_ids', [])
            operator = get_current_user()

            api = get_api_session()

            # First get user_id from username
            users = api.get_users()
            user = next((u for u in users if u['username'] == username), None)
            if not user:
                return jsonify({'error': f"User '{username}' not found"}), 404

            user_id = user.get('user_id')
            if not user_id:
                return jsonify({'error': 'Could not get user ID'}), 400

            old_roles = user.get('role_ids', [])
            # Remove all current roles
            if user.get('role_ids'):
                for role_id in user['role_ids']:
                    api.remove_user_role(user_id, role_id)

            # Then assign new roles
            for role_id in role_ids:
                api.assign_user_role(user_id, role_id)

            logger.info(f"USER ROLES UPDATE: operator={operator} target={username} old_roles={old_roles} new_roles={role_ids}")
            return jsonify({
                'message': f"Roles updated for user '{username}'"
            })
        except Exception as e:
            logger.error(f"USER ROLES UPDATE ERROR: {str(e)}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logs', methods=['GET'])
    @login_required
    def get_logs():
        """Get application logs."""
        try:
            lines = request.args.get('lines', 100, type=int)
            lines = min(max(lines, 10), 5000)  # Limit between 10 and 5000

            log_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_file = os.path.join(log_dir, 'wazuh_agent_mgr.log')

            if not os.path.exists(log_file):
                return jsonify({'content': 'Log file not found', 'path': log_file})

            # Read last N lines efficiently
            with open(log_file, 'r', encoding='utf-8') as f:
                all_lines = f.readlines()
                last_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines

            return jsonify({
                'content': ''.join(last_lines),
                'path': log_file,
                'total_lines': len(all_lines),
                'showing': len(last_lines)
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/logs/download', methods=['GET'])
    @login_required
    def download_logs():
        """Download full log file."""
        from flask import Response

        try:
            log_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_file = os.path.join(log_dir, 'wazuh_agent_mgr.log')

            if not os.path.exists(log_file):
                return jsonify({'error': 'Log file not found'}), 404

            with open(log_file, 'r', encoding='utf-8') as f:
                content = f.read()

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'wazuh_agent_mgr_{timestamp}.log'

            logger.info(f"Log downloaded by user '{session.get('api_session', {}).get('username', 'unknown')}'")

            return Response(
                content,
                mimetype='text/plain',
                headers={
                    'Content-Disposition': f'attachment; filename={filename}'
                }
            )
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # ============ Rules API ============

    def parse_rule_file(file_path: str, is_custom: bool = False) -> tuple:
        """Parse a Wazuh rule XML file and extract rule information.

        Returns:
            Tuple of (rules, error). `error` is None on success, or a short
            message when the file could not be parsed -- Wazuh's own ruleset
            occasionally ships XML that ElementTree rejects, and silently
            dropping those files hides rules from the Rules tab.
        """
        import xml.etree.ElementTree as ET
        rules = []
        try:
            # Read file content and wrap in root element for parsing
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Wrap content if it doesn't have a single root
            if not content.strip().startswith('<?xml'):
                content = '<rules>' + content + '</rules>'
            else:
                # Remove XML declaration and wrap
                lines = content.split('\n')
                if lines[0].startswith('<?xml'):
                    content = '<rules>' + '\n'.join(lines[1:]) + '</rules>'

            root = ET.fromstring(content)

            for group in root.findall('.//group'):
                outer_group_name = group.get('name', '')
                for rule in group.findall('rule'):
                    rule_id = rule.get('id', '')
                    level = rule.get('level', '0')

                    # Get description
                    desc_elem = rule.find('description')
                    description = desc_elem.text if desc_elem is not None else ''

                    # Get inner <group> element (additional groups this rule belongs to)
                    inner_group_elem = rule.find('group')
                    inner_group = inner_group_elem.text.strip() if inner_group_elem is not None and inner_group_elem.text else ''

                    # Combine outer and inner groups
                    all_groups = outer_group_name
                    if inner_group:
                        if all_groups:
                            all_groups = all_groups.rstrip(',') + ',' + inner_group
                        else:
                            all_groups = inner_group

                    # Get parent references
                    if_sid = rule.find('if_sid')
                    if_matched_sid = rule.find('if_matched_sid')
                    if_group_elem = rule.find('if_group')
                    parent_id = None
                    if_group = None
                    if if_sid is not None and if_sid.text:
                        parent_id = if_sid.text.strip()
                    elif if_matched_sid is not None and if_matched_sid.text:
                        parent_id = if_matched_sid.text.strip()
                    elif if_group_elem is not None and if_group_elem.text:
                        if_group = if_group_elem.text.strip()

                    rules.append({
                        'id': rule_id,
                        'level': int(level) if level.isdigit() else 0,
                        'description': description,
                        'parent_id': parent_id,
                        'if_group': if_group,
                        'group': all_groups,
                        'file': os.path.basename(file_path),
                        'is_custom': is_custom
                    })

            # Also check for rules directly under root (not in group)
            for rule in root.findall('rule'):
                rule_id = rule.get('id', '')
                level = rule.get('level', '0')
                desc_elem = rule.find('description')
                description = desc_elem.text if desc_elem is not None else ''

                # Get inner <group> element
                inner_group_elem = rule.find('group')
                inner_group = inner_group_elem.text.strip() if inner_group_elem is not None and inner_group_elem.text else ''

                if_sid = rule.find('if_sid')
                if_matched_sid = rule.find('if_matched_sid')
                if_group_elem = rule.find('if_group')
                parent_id = None
                if_group = None
                if if_sid is not None and if_sid.text:
                    parent_id = if_sid.text.strip()
                elif if_matched_sid is not None and if_matched_sid.text:
                    parent_id = if_matched_sid.text.strip()
                elif if_group_elem is not None and if_group_elem.text:
                    if_group = if_group_elem.text.strip()

                rules.append({
                    'id': rule_id,
                    'level': int(level) if level.isdigit() else 0,
                    'description': description,
                    'parent_id': parent_id,
                    'if_group': if_group,
                    'group': inner_group,
                    'file': os.path.basename(file_path),
                    'is_custom': is_custom
                })
        except Exception as e:
            logger.warning(f"Error parsing rule file {file_path}: {e}")
            return rules, str(e)
        return rules, None

    def get_all_rules() -> tuple:
        """Get all rules from Wazuh ruleset directories.

        Returns:
            Tuple of (rules_dict, group_to_rules mapping, parse_errors), where
            parse_errors lists the rule files that could not be parsed.
        """
        rules_dict = {}
        group_to_rules = {}  # Maps group name to list of rule IDs
        parse_errors = []
        rule_dirs = [
            ('/var/ossec/ruleset/rules/', False),  # Built-in rules
            ('/var/ossec/etc/rules/', True)         # Custom rules
        ]

        for rule_dir, is_custom in rule_dirs:
            if os.path.isdir(rule_dir):
                for filename in os.listdir(rule_dir):
                    if filename.endswith('.xml'):
                        file_path = os.path.join(rule_dir, filename)
                        parsed_rules, parse_error = parse_rule_file(file_path, is_custom)
                        if parse_error:
                            parse_errors.append({'file': filename, 'error': parse_error})
                        for rule in parsed_rules:
                            if rule['id']:
                                rules_dict[rule['id']] = rule
                                # Build group-to-rules mapping
                                group_name = rule.get('group', '')
                                if group_name:
                                    # Group name may contain multiple groups separated by comma
                                    for g in group_name.split(','):
                                        g = g.strip()
                                        if g:
                                            if g not in group_to_rules:
                                                group_to_rules[g] = []
                                            group_to_rules[g].append(rule['id'])

        return rules_dict, group_to_rules, parse_errors

    def get_rule_content(rule_id: str) -> str:
        """Get the XML content of a specific rule."""
        import re
        rule_dirs = [
            '/var/ossec/ruleset/rules/',
            '/var/ossec/etc/rules/'
        ]

        for rule_dir in rule_dirs:
            if os.path.isdir(rule_dir):
                for filename in os.listdir(rule_dir):
                    if filename.endswith('.xml'):
                        file_path = os.path.join(rule_dir, filename)
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()

                            # Find the rule with matching ID, including leading whitespace
                            pattern = rf'^[ \t]*<rule\s+id="{re.escape(rule_id)}"[^>]*>.*?</rule>'
                            match = re.search(pattern, content, re.DOTALL | re.MULTILINE)
                            if match:
                                return match.group(0)
                        except Exception:
                            continue
        return ''

    def build_hierarchy(rules_dict: dict, group_to_rules: dict, target_rule_id: str) -> dict:
        """Build a hierarchy tree for the target rule, showing parents and children."""
        if target_rule_id not in rules_dict:
            return {'error': f'Rule {target_rule_id} not found'}

        target_rule = rules_dict[target_rule_id]
        visited = {target_rule_id}

        # Find all ancestors (parents going up)
        ancestors = []
        current_id = target_rule.get('parent_id')

        while current_id and current_id in rules_dict and current_id not in visited:
            visited.add(current_id)
            ancestors.insert(0, current_id)
            current_id = rules_dict[current_id].get('parent_id')

        # Check if target rule has if_group (group-based parent)
        if_group = target_rule.get('if_group')
        group_parent_rules = []
        if if_group and not ancestors:
            # Find rules that belong to this group
            group_parent_rules = group_to_rules.get(if_group, [])

        # Find all descendants (children going down).
        # `visited` already prevents cycles, but a long if_group chain can still
        # nest deeper than Python's recursion limit, so cap the depth explicitly.
        MAX_TREE_DEPTH = 100

        def find_children(parent_id: str, parent_group: str = None, depth: int = 0) -> list:
            children = []
            if depth >= MAX_TREE_DEPTH:
                logger.warning(
                    f"Rule hierarchy for {target_rule_id} truncated at depth {MAX_TREE_DEPTH}"
                )
                return children
            for rid, rule in rules_dict.items():
                if rid in visited:
                    continue
                # Check if_sid or if_matched_sid
                if rule.get('parent_id') == parent_id:
                    visited.add(rid)
                    children.append({
                        'id': rid,
                        'level': rule.get('level', 0),
                        'description': rule.get('description', ''),
                        'file': rule.get('file', ''),
                        'is_custom': rule.get('is_custom', False),
                        'children': find_children(rid, rule.get('group'), depth + 1)
                    })
                # Check if_group (this rule depends on parent's group)
                elif parent_group and rule.get('if_group'):
                    rule_if_group = rule.get('if_group')
                    # Check if parent's group contains the if_group
                    parent_groups = [g.strip() for g in parent_group.split(',')]
                    if rule_if_group in parent_groups:
                        visited.add(rid)
                        children.append({
                            'id': rid,
                            'level': rule.get('level', 0),
                            'description': rule.get('description', ''),
                            'file': rule.get('file', ''),
                            'is_custom': rule.get('is_custom', False),
                            'if_group': rule_if_group,
                            'children': find_children(rid, rule.get('group'), depth + 1)
                        })
            return children

        # Build the tree starting from the root ancestor
        def build_tree(rule_id: str, remaining_ancestors: list) -> dict:
            rule = rules_dict.get(rule_id, {})
            node = {
                'id': rule_id,
                'level': rule.get('level', 0),
                'description': rule.get('description', ''),
                'file': rule.get('file', ''),
                'is_custom': rule.get('is_custom', False),
                'children': []
            }

            if remaining_ancestors:
                # Continue building the ancestor chain
                next_id = remaining_ancestors[0]
                node['children'] = [build_tree(next_id, remaining_ancestors[1:])]
            elif rule_id == target_rule_id:
                # At target, find children
                node['children'] = find_children(target_rule_id, rule.get('group'))

            return node

        # Build hierarchy
        if ancestors:
            hierarchy = [build_tree(ancestors[0], ancestors[1:] + [target_rule_id])]
        elif if_group and group_parent_rules:
            # Target rule uses if_group - show group as parent
            # Filter out target rule from group members
            member_rules = [rid for rid in group_parent_rules if rid != target_rule_id]
            # Build description with member rule IDs
            if len(member_rules) <= 5:
                members_str = ', '.join(member_rules)
            else:
                members_str = ', '.join(member_rules[:5]) + f' ... (+{len(member_rules) - 5} more)'

            group_node = {
                'id': f'[group: {if_group}]',
                'level': '-',
                'description': f'Members: {members_str}' if members_str else f'Group "{if_group}"',
                'file': '',
                'is_custom': False,
                'is_group': True,
                'group_name': if_group,
                'member_rules': member_rules[:10],  # Limit to 10 for display
                'children': []
            }
            # Target rule is the only child of group node (shows dependency clearly)
            target_node = {
                'id': target_rule_id,
                'level': target_rule.get('level', 0),
                'description': target_rule.get('description', ''),
                'file': target_rule.get('file', ''),
                'is_custom': target_rule.get('is_custom', False),
                'if_group': if_group,
                'children': find_children(target_rule_id, target_rule.get('group'))
            }
            group_node['children'].append(target_node)
            hierarchy = [group_node]
        else:
            # No ancestors, start from target
            hierarchy = [{
                'id': target_rule_id,
                'level': target_rule.get('level', 0),
                'description': target_rule.get('description', ''),
                'file': target_rule.get('file', ''),
                'is_custom': target_rule.get('is_custom', False),
                'children': find_children(target_rule_id, target_rule.get('group'))
            }]

        return {
            'target_rule': target_rule,
            'hierarchy': hierarchy,
            'all_rules': {rid: rules_dict[rid] for rid in visited}
        }

    @app.route('/api/rules', methods=['GET'])
    @login_required
    def get_all_rules_list():
        """Get all rules as a flat list for browsing."""
        try:
            rules_dict, group_to_rules, parse_errors = get_all_rules()
            rules_list = sorted(rules_dict.values(), key=lambda r: int(r['id']) if r['id'].isdigit() else 0)
            return jsonify({
                'rules': rules_list,
                'total': len(rules_list),
                'parse_errors': parse_errors
            })
        except Exception as e:
            logger.error(f"Error getting all rules list: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/rules/search', methods=['GET'])
    @login_required
    def search_rules_content():
        """Keyword search across the raw XML of every rule.

        Unlike the client-side filter in the All Rules table -- which only sees
        id/level/description/file/groups -- this searches the full rule body, so
        terms that appear in <field>, <regex>, <decoded_as>, <options> etc. are
        found too.

        Query params:
            q     : whitespace-separated keywords (max 10)
            match : 'all' (default, every keyword must appear) or 'any'
        """
        try:
            q = (request.args.get('q') or '').strip()
            if not q:
                return jsonify({'error': 'Search keywords are required'}), 400
            if len(q) > 500:
                return jsonify({'error': 'Search query is too long'}), 400
            keywords = [k.lower() for k in q.split()][:10]
            if not keywords:
                return jsonify({'error': 'Search keywords are required'}), 400
            match_any = (request.args.get('match') or 'all').lower() == 'any'

            rule_re = re.compile(r'<rule\s[^>]*?\bid="(\d+)"[^>]*>.*?</rule>', re.S)
            level_re = re.compile(r'\blevel="(\d+)"')
            desc_re = re.compile(r'<description>(.*?)</description>', re.S)
            group_re = re.compile(r'<group>(.*?)</group>', re.S)

            MAX_RESULTS = 1000
            results = []
            read_errors = []
            truncated = False

            for rule_dir, is_custom in (('/var/ossec/ruleset/rules/', False),
                                        ('/var/ossec/etc/rules/', True)):
                if not os.path.isdir(rule_dir):
                    continue
                for filename in sorted(os.listdir(rule_dir)):
                    if not filename.endswith('.xml'):
                        continue
                    try:
                        with open(os.path.join(rule_dir, filename), 'r',
                                  encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                    except Exception as e:
                        read_errors.append({'file': filename, 'error': str(e)})
                        continue

                    for m in rule_re.finditer(content):
                        block = m.group(0)
                        low = block.lower()
                        hits = [k for k in keywords if k in low]
                        if not hits:
                            continue
                        if not match_any and len(hits) < len(keywords):
                            continue
                        if len(results) >= MAX_RESULTS:
                            truncated = True
                            break

                        lvl = level_re.search(block)
                        desc = desc_re.search(block)
                        grp = group_re.search(block)
                        # the first line carrying a hit, so the user sees why it matched
                        snippet = ''
                        for line in block.split('\n'):
                            ll = line.lower()
                            if any(k in ll for k in hits):
                                snippet = line.strip()[:300]
                                break
                        results.append({
                            'id': m.group(1),
                            'level': int(lvl.group(1)) if lvl else 0,
                            'description': ' '.join(desc.group(1).split()) if desc else '',
                            'group': ' '.join(grp.group(1).split()) if grp else '',
                            'file': filename,
                            'is_custom': is_custom,
                            'snippet': snippet,
                            'matched': hits,
                        })
                    if truncated:
                        break
                if truncated:
                    break

            logger.info(
                f"RULE CONTENT SEARCH: user={get_current_user()} "
                f"keywords={sanitize_for_log(' '.join(keywords))} match={'any' if match_any else 'all'} "
                f"hits={len(results)}"
            )
            return jsonify({
                'rules': results,
                'total': len(results),
                'keywords': keywords,
                'match': 'any' if match_any else 'all',
                'truncated': truncated,
                'max_results': MAX_RESULTS,
                'read_errors': read_errors,
            })
        except Exception as e:
            logger.error(f"Error searching rule content: {e}")
            return jsonify({'error': str(e)}), 500

    def build_file_hierarchy(rules_dict, query):
        """Build a tree of the rules held in the rule files matching a name fragment.

        Searching by rule ID answers "what is related to this rule". Searching by
        file answers "what does this file actually contain", which is the question
        being asked when reviewing a pack or a single ruleset file. Roots are the
        rules whose parent lives outside the file; everything else nests beneath
        its parent, so the file's internal structure is visible at a glance.
        """
        MAX_FILES = 20
        q = query.strip().lower()
        if q.endswith('.xml'):
            q = q[:-4]
        if not q:
            return None

        by_file = {}
        for rid, rule in rules_dict.items():
            fname = rule.get('file', '') or ''
            base = fname[:-4] if fname.lower().endswith('.xml') else fname
            if q in base.lower():
                by_file.setdefault(fname, []).append(rid)
        if not by_file:
            return None

        matched = sorted(by_file)
        truncated = len(matched) > MAX_FILES
        matched = matched[:MAX_FILES]

        def node(rid, own_ids, seen):
            rule = rules_dict[rid]
            seen.add(rid)
            kids = []
            for cid in sorted(own_ids, key=lambda x: (len(x), x)):
                if cid in seen:
                    continue
                if rules_dict[cid].get('parent_id') == rid:
                    kids.append(node(cid, own_ids, seen))
            return {
                'id': rid,
                'level': rule.get('level', 0),
                'description': rule.get('description', ''),
                'file': rule.get('file', ''),
                'is_custom': rule.get('is_custom', False),
                'children': kids,
            }

        hierarchy, all_rules = [], {}
        for fname in matched:
            own = set(by_file[fname])
            seen = set()
            roots = [r for r in sorted(own, key=lambda x: (len(x), x))
                     if rules_dict[r].get('parent_id') not in own]
            file_children = [node(r, own, seen) for r in roots if r not in seen]
            # anything left over (a cycle, or a parent that was itself nested) still shows
            file_children += [node(r, own, seen) for r in sorted(own, key=lambda x: (len(x), x))
                              if r not in seen]
            for rid in own:
                all_rules[rid] = rules_dict[rid]
            hierarchy.append({
                'id': fname,
                'is_file': True,
                'level': None,
                'description': '%d rules' % len(own),
                'file': fname,
                'is_custom': rules_dict[by_file[fname][0]].get('is_custom', False),
                'children': file_children,
            })

        return {'mode': 'file', 'matched_files': matched, 'truncated': truncated,
                'hierarchy': hierarchy, 'all_rules': all_rules, 'target_rule': None}

    @app.route('/api/rules/hierarchy', methods=['GET'])
    @login_required
    def get_rules_hierarchy():
        """Rule hierarchy, looked up either by rule ID or by rule file name."""
        try:
            rule_id = request.args.get('rule_id', '').strip()
            if not rule_id:
                return jsonify({'error': 'rule_id parameter is required'}), 400

            rules_dict, group_to_rules, parse_errors = get_all_rules()

            if not rule_id.isdigit():
                # Treat anything non-numeric as a file name fragment. The value is
                # only ever substring-matched against file names already discovered
                # on disk, so it never reaches the filesystem itself.
                if len(rule_id) > 64 or not re.match(r'^[A-Za-z0-9._\- ]+$', rule_id):
                    return jsonify({'error': 'Enter a rule ID or part of a rule file name'}), 400
                result = build_file_hierarchy(rules_dict, rule_id)
                if not result:
                    return jsonify({'error': 'No rule file matches "%s"' % rule_id}), 404
                return jsonify(result)

            result = build_hierarchy(rules_dict, group_to_rules, rule_id)

            if 'error' in result:
                return jsonify(result), 404

            return jsonify(result)
        except Exception as e:
            logger.error(f"Error getting rule hierarchy: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/api/rules/<rule_id>', methods=['GET'])
    @login_required
    def get_rule_detail(rule_id: str):
        """Get detailed content of a specific rule."""
        try:
            # Validate rule_id format
            if not rule_id.isdigit():
                return jsonify({'error': 'Invalid rule ID format'}), 400

            content = get_rule_content(rule_id)
            if not content:
                return jsonify({'error': f'Rule {rule_id} not found'}), 404

            return jsonify({'rule_id': rule_id, 'content': content})
        except Exception as e:
            logger.error(f"Error getting rule detail: {e}")
            return jsonify({'error': str(e)}), 500

    return app


def _check_cert_valid(cert_path: str) -> bool:
    """Check if certificate exists and is not expired."""
    if not os.path.exists(cert_path):
        return False
    try:
        import subprocess
        result = subprocess.run(
            ['openssl', 'x509', '-checkend', '0', '-noout', '-in', cert_path],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def _generate_ssl_cert(cert_path: str, key_path: str, days: int = 365) -> bool:
    """Generate self-signed SSL certificate using openssl."""
    import subprocess
    import socket

    hostname = socket.gethostname()
    print(f"Generating self-signed SSL certificate (valid for {days} days)...")

    try:
        # Generate private key and certificate in one command
        result = subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:4096',
            '-keyout', key_path,
            '-out', cert_path,
            '-days', str(days),
            '-nodes',  # No passphrase
            '-subj', f'/CN={hostname}/O=JT Wazuh Manager/C=TW'
        ], capture_output=True, text=True)

        if result.returncode == 0:
            print(f"  Certificate generated: {cert_path}")
            print(f"  Private key generated: {key_path}")
            return True
        else:
            print(f"  ERROR: Failed to generate certificate: {result.stderr}")
            return False
    except FileNotFoundError:
        print("  ERROR: openssl command not found. Please install OpenSSL.")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def harden_wsgi_server() -> bool:
    """Stop the WSGI server from advertising its own version.

    The `Server:` header is written by werkzeug's request handler, below Flask,
    so an after_request hook cannot replace it -- it has to be set on the
    handler class. Returns True when the override was applied.
    """
    try:
        from werkzeug.serving import WSGIRequestHandler
    except Exception:
        return False
    WSGIRequestHandler.server_version = 'jt-wazuh-mgr'
    WSGIRequestHandler.sys_version = ''
    return True


def run_web_server(host: str = '0.0.0.0', port: int = 5000, debug: bool = False,
                   max_login_attempts: int = 3, lockout_minutes: int = 30,
                   ssl_cert: str = None, ssl_key: str = None, ssl_auto: bool = False):
    """Run the web server.

    Args:
        host: Host to bind to
        port: Port to listen on
        debug: Enable debug mode
        max_login_attempts: Max failed login attempts before IP lockout
        lockout_minutes: IP lockout duration in minutes
        ssl_cert: Path to SSL certificate file (for HTTPS)
        ssl_key: Path to SSL private key file (for HTTPS)
        ssl_auto: Auto-generate self-signed certificate if missing or expired

    Environment variables (override parameters):
        WEB_SSL_CERT: Path to SSL certificate file
        WEB_SSL_KEY: Path to SSL private key file
        WEB_SSL_AUTO: Set to 'true' to enable auto-generation
    """
    harden_wsgi_server()
    app = create_app(max_login_attempts=max_login_attempts, lockout_minutes=lockout_minutes)

    # Check environment variables for SSL (override parameters)
    ssl_cert = os.environ.get('WEB_SSL_CERT', ssl_cert)
    ssl_key = os.environ.get('WEB_SSL_KEY', ssl_key)
    ssl_auto = os.environ.get('WEB_SSL_AUTO', '').lower() in ('true', '1', 'yes') or ssl_auto

    # Default certificate paths for ssl_auto
    script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    default_cert = os.path.join(script_dir, 'ssl_cert.pem')
    default_key = os.path.join(script_dir, 'ssl_key.pem')

    # Handle ssl_auto: auto-generate certificates if needed
    if ssl_auto:
        # Use provided paths or defaults
        ssl_cert = ssl_cert or default_cert
        ssl_key = ssl_key or default_key

        # Check if certificates exist and are valid
        cert_valid = _check_cert_valid(ssl_cert)
        key_exists = os.path.exists(ssl_key)

        if not cert_valid or not key_exists:
            if not cert_valid and os.path.exists(ssl_cert):
                print(f"SSL certificate expired or invalid: {ssl_cert}")
            elif not os.path.exists(ssl_cert):
                print(f"SSL certificate not found: {ssl_cert}")

            # Generate new certificates
            if not _generate_ssl_cert(ssl_cert, ssl_key, days=365):
                print("WARNING: Failed to generate SSL certificate, falling back to HTTP")
                ssl_cert = None
                ssl_key = None

    # Configure SSL context if certificates provided
    ssl_context = None
    protocol = 'http'
    if ssl_cert and ssl_key:
        if os.path.exists(ssl_cert) and os.path.exists(ssl_key):
            ssl_context = (ssl_cert, ssl_key)
            protocol = 'https'
            print(f"SSL enabled: cert={ssl_cert}, key={ssl_key}")
        else:
            print(f"WARNING: SSL cert/key files not found, falling back to HTTP")
            if not os.path.exists(ssl_cert):
                print(f"  - Certificate not found: {ssl_cert}")
            if not os.path.exists(ssl_key):
                print(f"  - Key not found: {ssl_key}")

    logger.info(f"SERVER START: version={VERSION} host={host} port={port} protocol={protocol}")
    print(f"Starting JT Wazuh Manager Web UI v{VERSION} at {protocol}://{host}:{port}")
    print("Login with your Wazuh API credentials to continue.")
    print(f"IP lockout: {max_login_attempts} failed attempts = {lockout_minutes} min lockout")
    print(f"Log file: wazuh_agent_mgr.log")

    # Suppress only the Flask development server warning, keep request logs
    import logging as _logging

    class DevServerWarningFilter(_logging.Filter):
        def filter(self, record):
            # Filter out the development server warning
            return 'This is a development server' not in record.getMessage()

    werkzeug_logger = _logging.getLogger('werkzeug')
    werkzeug_logger.addFilter(DevServerWarningFilter())

    app.run(host=host, port=port, debug=debug, ssl_context=ssl_context)
