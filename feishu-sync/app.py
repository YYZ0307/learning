#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
飞书消息同步服务
思路: 监听"中转群"的消息事件 -> 用 forward 接口把原消息原样转发到 N 个目标群。
- 原样转发(forward)可保真图片/贴纸/@/格式。
- 走"@机器人"路线, 不需要高敏感的"获取群内所有消息"权限。
- 目标群列表放在 targets.json, 加群只需加一行。
- 内置限流队列, 应对 20-50 且不断增长的目标群, 避免触发飞书频控。
"""

import base64
import hashlib
import json
import logging
import os
import queue
import threading
import time

import requests
from Crypto.Cipher import AES
from flask import Flask, request, jsonify

# ---------------- 基础配置 ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_json(name, default):
    path = os.path.join(BASE_DIR, name)
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


CONFIG = _load_json("config.json", {})
APP_ID = os.environ.get("FEISHU_APP_ID") or CONFIG.get("app_id", "")
APP_SECRET = os.environ.get("FEISHU_APP_SECRET") or CONFIG.get("app_secret", "")
VERIFICATION_TOKEN = os.environ.get("FEISHU_VERIFICATION_TOKEN") or CONFIG.get("verification_token", "")
ENCRYPT_KEY = os.environ.get("FEISHU_ENCRYPT_KEY") or CONFIG.get("encrypt_key", "")
# 中转群 chat_id: 只有来自这个群的消息才会被同步
SOURCE_CHAT_ID = CONFIG.get("source_chat_id", "")
# 是否要求消息里@了机器人才转发(推荐 True, 可免高敏感权限)
REQUIRE_AT_BOT = CONFIG.get("require_at_bot", True)
# 每次转发之间的最小间隔(秒), 限流用
FORWARD_INTERVAL = float(CONFIG.get("forward_interval_seconds", 0.5))

LARK_HOST = "https://open.feishu.cn"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("feishu-sync")

app = Flask(__name__)


# ---------------- 事件解密 ----------------
class AESCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(key.encode("utf-8")).digest()

    def decrypt(self, enc_b64):
        raw = base64.b64decode(enc_b64)
        iv, data = raw[:16], raw[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plain = cipher.decrypt(data)
        pad = plain[-1]
        return plain[:-pad].decode("utf-8")


def decrypt_event(body):
    """飞书事件若开启加密, body 形如 {"encrypt": "..."}。未加密则原样返回。"""
    if "encrypt" in body:
        if not ENCRYPT_KEY:
            raise RuntimeError("事件已加密但未配置 ENCRYPT_KEY")
        plain = AESCipher(ENCRYPT_KEY).decrypt(body["encrypt"])
        return json.loads(plain)
    return body


# ---------------- token 管理 ----------------
_token_cache = {"token": "", "expire": 0}
_token_lock = threading.Lock()


def get_tenant_access_token():
    with _token_lock:
        now = time.time()
        if _token_cache["token"] and now < _token_cache["expire"] - 60:
            return _token_cache["token"]
        resp = requests.post(
            f"{LARK_HOST}/open-apis/auth/v3/tenant_access_token/internal",
            json={"app_id": APP_ID, "app_secret": APP_SECRET},
            timeout=10,
        )
        data = resp.json()
        if data.get("code") != 0:
            raise RuntimeError(f"获取 tenant_access_token 失败: {data}")
        _token_cache["token"] = data["tenant_access_token"]
        _token_cache["expire"] = now + data.get("expire", 7200)
        return _token_cache["token"]


# ---------------- 转发 ----------------
def forward_message(message_id, target_chat_id):
    token = get_tenant_access_token()
    resp = requests.post(
        f"{LARK_HOST}/open-apis/im/v1/messages/{message_id}/forward",
        params={"receive_id_type": "chat_id"},
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
        },
        json={"receive_id": target_chat_id},
        timeout=10,
    )
    data = resp.json()
    if data.get("code") != 0:
        log.error("转发到 %s 失败: %s", target_chat_id, data)
        return False
    log.info("已转发到 %s", target_chat_id)
    return True


# ---------------- 限流队列 ----------------
# 事件回调必须快速返回, 真正的转发放到后台队列里按间隔执行, 避免频控。
_task_queue = queue.Queue()


def _worker():
    while True:
        message_id = _task_queue.get()
        try:
            targets = _load_json("targets.json", {"targets": []}).get("targets", [])
            for t in targets:
                chat_id = t.get("chat_id") if isinstance(t, dict) else t
                if not chat_id:
                    continue
                forward_message(message_id, chat_id)
                time.sleep(FORWARD_INTERVAL)
        except Exception as e:
            log.exception("转发任务异常: %s", e)
        finally:
            _task_queue.task_done()


threading.Thread(target=_worker, daemon=True).start()


# ---------------- 事件处理 ----------------
_seen_events = {}
_seen_lock = threading.Lock()


def _is_duplicate(event_id):
    """飞书事件可能重复推送, 用 event_id 去重。"""
    if not event_id:
        return False
    with _seen_lock:
        now = time.time()
        for k in [k for k, v in _seen_events.items() if now - v > 600]:
            _seen_events.pop(k, None)
        if event_id in _seen_events:
            return True
        _seen_events[event_id] = now
        return False


def _message_at_bot(message):
    """判断消息是否@了机器人。"""
    mentions = message.get("mentions") or []
    return len(mentions) > 0


def handle_message_event(event):
    message = event.get("message", {})
    chat_id = message.get("chat_id", "")
    message_id = message.get("message_id", "")

    if SOURCE_CHAT_ID and chat_id != SOURCE_CHAT_ID:
        log.info("消息来自非中转群 %s, 忽略", chat_id)
        return
    if REQUIRE_AT_BOT and not _message_at_bot(message):
        log.info("消息未@机器人, 忽略 (message_id=%s)", message_id)
        return
    if not message_id:
        return

    log.info("收到待同步消息 message_id=%s, 入队转发", message_id)
    _task_queue.put(message_id)


@app.route("/feishu/event", methods=["POST"])
def feishu_event():
    body = request.get_json(force=True, silent=True) or {}
    try:
        body = decrypt_event(body)
    except Exception as e:
        log.error("事件解密失败: %s", e)
        return jsonify({"code": -1}), 400

    # URL 验证(配置回调地址时飞书会发一次 challenge)
    if body.get("type") == "url_verification":
        if VERIFICATION_TOKEN and body.get("token") != VERIFICATION_TOKEN:
            return jsonify({"code": -1}), 403
        return jsonify({"challenge": body.get("challenge", "")})

    # 校验 token(事件回调 v2 在 header.token)
    header = body.get("header", {})
    if VERIFICATION_TOKEN and header.get("token", VERIFICATION_TOKEN) != VERIFICATION_TOKEN:
        return jsonify({"code": -1}), 403

    event_id = header.get("event_id", "")
    if _is_duplicate(event_id):
        return jsonify({"code": 0})

    event_type = header.get("event_type", "")
    if event_type == "im.message.receive_v1":
        try:
            handle_message_event(body.get("event", {}))
        except Exception as e:
            log.exception("处理消息事件异常: %s", e)

    # 必须尽快返回 200, 否则飞书会重试
    return jsonify({"code": 0})


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "queue": _task_queue.qsize()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    log.info("飞书消息同步服务启动, 端口 %s", port)
    app.run(host="0.0.0.0", port=port)
