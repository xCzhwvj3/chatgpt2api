"""手动 OAuth 桥服务

让用户用自己浏览器走一遍 OpenAI 的标准 OAuth + PKCE 授权码流程：
  1. 后端生成 code_verifier / code_challenge / state，构造 authorize URL。
  2. 用户在浏览器登录，浏览器最终被 OpenAI 重定向到 platform.openai.com 的
     callback 地址；用户从地址栏或 devtools 抓出 code，回填到前端。
  3. 后端拿之前存好的 code_verifier + 回填的 code 调用 /api/accounts/oauth/token
     得到 {access_token, refresh_token, id_token}。

同时支持服务端批量导入凭证文件（邮箱----密码----2FA密钥），按标准 OAuth + PKCE
流程逐个执行登录、2FA 校验与换票入库，并通过异步任务提供进度查询。

得到的 refresh_token 跟 account_service 自动刷新机制用的 client_id 是同一个
（app_2SKx67EdpoN0G6j64rFvigXD），所以落盘后能直接进入 keepalive 周期。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

from curl_cffi import requests

from services.account_service import account_service
from services.log_service import LOG_TYPE_ACCOUNT, log_service
from services.openai_oauth import (
    auth_base,
    common_headers,
    platform_auth0_client,
    platform_base,
    platform_oauth_audience,
    platform_oauth_client_id,
    platform_oauth_redirect_uri,
    sec_ch_ua,
    user_agent,
)
from services.proxy_service import proxy_settings


class OAuthLoginError(Exception):
    """OAuth 桥流程中的可预期错误，会被 API 层翻译成 400。"""


@dataclass(frozen=True)
class OAuthCredential:
    """入口校验完成后的单条账号凭证，密码与 2FA 仅在内存中用于本次登录。"""

    email: str
    password: str
    totp_secret: str = ""
    line_no: int = 0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_totp_secret(raw: str) -> str:
    """提取并规整 Base32 形式的 TOTP 密钥，支持 otpauth:// URI 与空格/连字符。"""
    value = raw.strip()
    if not value:
        return ""
    if value.lower().startswith("otpauth://"):
        parsed = parse_qs(urlparse(value).query)
        value = str((parsed.get("secret") or [""])[0]).strip()
    cleaned = re.sub(r"[\s\-]+", "", value).upper().rstrip("=")
    if not cleaned:
        raise OAuthLoginError("2FA 密钥为空")
    padded = cleaned + "=" * ((8 - len(cleaned) % 8) % 8)
    try:
        decoded = base64.b32decode(padded, casefold=True)
    except Exception as exc:
        raise OAuthLoginError("2FA 密钥不是有效的 Base32 编码") from exc
    if not decoded:
        raise OAuthLoginError("2FA 密钥解码后为空")
    return cleaned


def generate_totp(secret_base32: str, *, step: int = 30, digits: int = 6, now: float | None = None) -> str:
    """按 RFC 6238 (SHA-1, 30 秒步长, 6 位) 生成当前窗口的 TOTP 验证码。"""
    padded = secret_base32 + "=" * ((8 - len(secret_base32) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((time.time() if now is None else now) // step)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def parse_credentials_text(raw_text: str) -> tuple[list[OAuthCredential], list[dict[str, Any]]]:
    """在入口统一解析并校验凭证文本（支持 邮箱----密码----2FA密钥 或 邮箱----密码）。"""
    text = str(raw_text or "").lstrip("\ufeff")
    credentials: list[OAuthCredential] = []
    parse_errors: list[dict[str, Any]] = []
    seen_emails: set[str] = set()

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if "----" in line:
            parts = [part.strip() for part in line.split("----")]
        elif "\t" in line:
            parts = [part.strip() for part in line.split("\t")]
        else:
            parse_errors.append({
                "line": line_no,
                "email": "",
                "error": "格式错误，请使用 邮箱----密码----2FA密钥（无 2FA 可用 邮箱----密码）",
            })
            continue

        email = parts[0] if len(parts) >= 1 else ""
        password = parts[1] if len(parts) >= 2 else ""
        raw_totp = parts[2] if len(parts) >= 3 else ""

        if not email or "@" not in email:
            parse_errors.append({"line": line_no, "email": email[:80], "error": "邮箱格式无效"})
            continue
        if not password:
            parse_errors.append({"line": line_no, "email": email, "error": "缺少密码"})
            continue

        email_key = email.lower()
        if email_key in seen_emails:
            parse_errors.append({"line": line_no, "email": email, "error": "重复邮箱，已忽略该行"})
            continue

        try:
            totp_secret = _normalize_totp_secret(raw_totp) if raw_totp else ""
        except OAuthLoginError as exc:
            parse_errors.append({"line": line_no, "email": email, "error": str(exc)})
            continue

        seen_emails.add(email_key)
        credentials.append(
            OAuthCredential(
                email=email,
                password=password,
                totp_secret=totp_secret,
                line_no=line_no,
            )
        )

    return credentials, parse_errors


def _parse_json_safe(response: Any) -> dict[str, Any]:
    text = getattr(response, "text", "") or ""
    if not text:
        return {}
    try:
        data = response.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def _format_upstream_error(step_label: str, response: Any, data: dict[str, Any]) -> str:
    """提取上游错误摘要，HTML 验证页或异常页只返回简短状态说明，不透出整段源码。"""
    status = int(getattr(response, "status_code", 0) or 0)
    error_obj = data.get("error")
    error_code = ""
    error_msg = ""
    if isinstance(error_obj, dict):
        error_code = str(error_obj.get("code") or "").strip()
        error_msg = str(error_obj.get("message") or "").strip()
    elif isinstance(error_obj, str):
        error_code = error_obj.strip()
    if not error_msg:
        error_msg = str(data.get("error_description") or data.get("message") or "").strip()

    if error_code == "account_deactivated":
        return f"{step_label}失败：账号已被禁用 (account_deactivated)"
    if error_code == "unsupported_country_region_territory":
        return f"{step_label}失败：当前出口地区不受支持 ({error_code})"
    if error_code == "invalid_state":
        return f"{step_label}失败：认证会话状态失效 (invalid_state)"
    if "invalid credentials" in error_msg.lower() or "wrong password" in error_msg.lower():
        return f"{step_label}失败：邮箱或密码错误"

    if error_msg or error_code:
        detail = f"{error_code}: {error_msg}" if error_code and error_msg else (error_msg or error_code)
        return f"{step_label}失败 (HTTP {status}): {detail}"

    raw_text = str(getattr(response, "text", "") or "").strip()
    lowered = raw_text[:200].lower()
    if "<html" in lowered or "<!doctype" in lowered:
        return f"{step_label}被拦截或返回验证页 (HTTP {status})"
    snippet = raw_text[:180]
    return f"{step_label}失败 (HTTP {status}){': ' + snippet if snippet else ''}"


def _extract_callback_url(data: dict[str, Any]) -> str:
    continue_url = str(data.get("continue_url") or "").strip()
    if continue_url:
        return continue_url
    page = data.get("page")
    if isinstance(page, dict):
        payload = page.get("payload")
        if isinstance(payload, dict):
            return str(payload.get("url") or "").strip()
    return ""


def _extract_totp_factor_id(data: dict[str, Any], continue_url: str) -> str:
    """从密码校验响应中优先挑选非恢复码的 TOTP factor_id。"""
    candidate_lists: list[Any] = []
    page = data.get("page")
    if isinstance(page, dict) and isinstance(page.get("payload"), dict):
        candidate_lists.append(page["payload"].get("factors"))
    auth_session = data.get("oai-client-auth-session")
    if isinstance(auth_session, dict):
        candidate_lists.append(auth_session.get("mfa_challenge_factors"))
        candidate_lists.append(auth_session.get("mfa_factors"))

    for factors in candidate_lists:
        if not isinstance(factors, list):
            continue
        for factor in factors:
            if (
                isinstance(factor, dict)
                and str(factor.get("factor_type") or "").strip().lower() == "totp"
                and not factor.get("is_recovery")
                and str(factor.get("id") or "").strip()
            ):
                return str(factor["id"]).strip()

    if isinstance(page, dict) and isinstance(page.get("payload"), dict):
        factor_id = str(page["payload"].get("factor_id") or "").strip()
        if factor_id:
            return factor_id

    match = re.search(r"/mfa-challenge/([^/?#]+)", continue_url)
    return match.group(1).strip() if match else ""


class OAuthLoginService:
    """维护 PKCE 临时会话、完成 code → token 兑换，并管理批量 OAuth 登录任务。"""

    _SESSION_TTL_SECONDS = 10 * 60  # 用户点开浏览器 + 拿 code 给的时间上限
    _MAX_SESSIONS = 64               # 防止异常累积；超过容量时清理最老的
    _BATCH_JOB_TTL_SECONDS = 60 * 60
    _MAX_BATCH_JOBS = 32

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: dict[str, dict[str, Any]] = {}
        self._batch_lock = threading.Lock()
        self._batch_jobs: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _generate_pkce() -> tuple[str, str]:
        """生成 PKCE code_verifier 与对应的 code_challenge（S256）。"""
        from utils.pkce import generate_pkce
        return generate_pkce()

    def _purge_expired_locked(self) -> None:
        """清理过期或溢出容量的会话，必须在持锁状态下调用。"""
        now = time.time()
        expired = [sid for sid, item in self._sessions.items() if now - item["created_at"] > self._SESSION_TTL_SECONDS]
        for sid in expired:
            self._sessions.pop(sid, None)
        if len(self._sessions) > self._MAX_SESSIONS:
            ordered = sorted(self._sessions.items(), key=lambda kv: kv[1]["created_at"])
            for sid, _ in ordered[: len(self._sessions) - self._MAX_SESSIONS]:
                self._sessions.pop(sid, None)

    def start(self, email_hint: str = "") -> dict[str, str]:
        """登记一个新的 PKCE 会话，返回 session_id 与可让用户打开的 authorize_url。

        state 形如 "<session_id>.<nonce>"，让 callback URL 自带 session_id，
        finish 时即便前端 React 状态被覆盖也能从 URL 恢复正确的 verifier。
        """
        verifier, challenge = self._generate_pkce()
        nonce = secrets.token_urlsafe(32)
        device_id = str(uuid.uuid4())
        session_id = uuid.uuid4().hex
        state = f"{session_id}.{secrets.token_urlsafe(16)}"

        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": platform_oauth_redirect_uri,
            "device_id": device_id,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "auth0Client": platform_auth0_client,
        }
        email_hint = str(email_hint or "").strip()
        if email_hint:
            params["login_hint"] = email_hint

        authorize_url = f"{auth_base}/api/accounts/authorize?{urlencode(params)}"

        with self._lock:
            self._purge_expired_locked()
            self._sessions[session_id] = {
                "code_verifier": verifier,
                "state": state,
                "created_at": time.time(),
                "redirect_uri": platform_oauth_redirect_uri,
            }

        return {
            "session_id": session_id,
            "authorize_url": authorize_url,
            "expires_in": str(self._SESSION_TTL_SECONDS),
            "redirect_uri_prefix": platform_oauth_redirect_uri,
        }

    @staticmethod
    def _extract_code_from_callback(value: str) -> tuple[str, str]:
        """从 callback URL 或 raw code 中提取 (code, state)。

        既允许用户粘贴整段 platform.openai.com/auth/callback?code=...&state=... 的 URL，
        也允许只粘 code 本身。
        """
        raw = str(value or "").strip()
        if not raw:
            return "", ""
        if raw.startswith("http://") or raw.startswith("https://"):
            try:
                parsed = parse_qs(urlparse(raw).query)
            except Exception as exc:
                raise OAuthLoginError(f"无法解析 callback URL: {exc}") from exc
            code = str((parsed.get("code") or [""])[0]).strip()
            state = str((parsed.get("state") or [""])[0]).strip()
            if not code:
                err = str((parsed.get("error_description") or parsed.get("error") or [""])[0]).strip()
                raise OAuthLoginError(err or "callback URL 中没有 code 参数")
            return code, state
        # 用户可能直接粘了 code 字符串
        return raw, ""

    def finish(self, session_id: str, callback: str) -> dict[str, str]:
        """用 session_id 配对的 code_verifier 把 callback 里的 code 换成 token 三件套。

        - 优先用 callback URL 自带 state 里的 session_id（更可靠），
          找不到才用前端传来的 session_id；
        - 失败时不立刻销毁 session（OAuth code 错配换 token 失败通常不会消耗 code），
          只有成功兑换才 pop，便于用户用同一 verifier 重试。
        """
        body_sid = str(session_id or "").strip()
        code, state = self._extract_code_from_callback(callback)
        if not code:
            raise OAuthLoginError("缺少 code 或 callback URL")

        # state 里嵌的 session_id 优先级最高
        state_sid = state.split(".", 1)[0] if state else ""
        candidate_sids = [sid for sid in (state_sid, body_sid) if sid]
        if not candidate_sids:
            raise OAuthLoginError("既未提供 session_id，callback URL 中也未携带 state")

        with self._lock:
            self._purge_expired_locked()
            session = None
            picked_sid = ""
            for sid in candidate_sids:
                cur = self._sessions.get(sid)
                if cur is not None:
                    session = cur
                    picked_sid = sid
                    break
        if session is None:
            raise OAuthLoginError(
                "OAuth 会话已过期或不存在，请回到导入对话框点\"重新生成\"再走一次"
            )

        if state and session.get("state") and state != session["state"]:
            raise OAuthLoginError(
                "state 不匹配。常见原因：你点过两次\"打开授权页面\"，但浏览器里登录的还是前一次的窗口。请点\"重新生成\"重来。"
            )

        tokens = self._exchange_code(
            code,
            session["code_verifier"],
            session.get("redirect_uri") or platform_oauth_redirect_uri,
        )
        # 仅在成功兑换之后才消耗 session
        with self._lock:
            self._sessions.pop(picked_sid, None)
        return tokens

    @staticmethod
    def _exchange_code(
        code: str,
        code_verifier: str,
        redirect_uri: str,
        *,
        session: requests.Session | None = None,
    ) -> dict[str, str]:
        """调用 /api/accounts/oauth/token 用 code+verifier 换 token 三件套。"""
        owns_session = session is None
        if session is None:
            kwargs = proxy_settings.build_session_kwargs(impersonate="chrome", upstream=True, verify=False)
            session = requests.Session(**kwargs)
        try:
            response = session.post(
                f"{auth_base}/api/accounts/oauth/token",
                headers={
                    **common_headers,
                    "referer": f"{platform_base}/",
                    "origin": platform_base,
                    "auth0-client": platform_auth0_client,
                    "sec-ch-ua": sec_ch_ua,
                    "user-agent": user_agent,
                },
                json={
                    "client_id": platform_oauth_client_id,
                    "code_verifier": code_verifier,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                timeout=60,
            )
        except Exception as exc:
            raise OAuthLoginError(f"换 token 网络异常: {exc}") from exc
        finally:
            if owns_session:
                session.close()

        try:
            data = response.json() if response.text else {}
        except Exception:
            data = {}

        if response.status_code != 200 or not isinstance(data, dict) or not data.get("access_token"):
            detail = ""
            if isinstance(data, dict):
                detail = str(data.get("error_description") or data.get("error") or data.get("message") or "")
            if not detail:
                try:
                    detail = str(response.text or "")[:300]
                except Exception:
                    detail = ""
            # 打到 docker logs 方便排错——OAuth 换 token 的失败原因往往只有这里能看到
            print(
                f"[oauth-login] /api/accounts/oauth/token rejected: "
                f"status={response.status_code} detail={detail!r} "
                f"raw_body={(getattr(response, 'text', '') or '')[:500]!r}",
                flush=True,
            )
            raise OAuthLoginError(
                f"OpenAI 拒绝换 token (HTTP {response.status_code}){': ' + detail if detail else ''}"
            )

        access_token = str(data.get("access_token") or "").strip()
        refresh_token = str(data.get("refresh_token") or "").strip()
        id_token = str(data.get("id_token") or "").strip()

        if not access_token:
            raise OAuthLoginError("OpenAI 返回的 access_token 为空")
        if not refresh_token:
            # scope 含 offline_access 时正常会下发 refresh_token；这里给出明确提示
            raise OAuthLoginError(
                "OpenAI 没有返回 refresh_token（可能 scope 未包含 offline_access 或 code 已使用过）"
            )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
        }

    def login_with_credentials(self, cred: OAuthCredential) -> dict[str, str]:
        """按标准 OAuth + PKCE 流程执行单账号登录（授权 → 密码校验 → 可选 TOTP 2FA → 换票）。"""
        verifier, challenge = self._generate_pkce()
        nonce = secrets.token_urlsafe(32)
        device_id = str(uuid.uuid4())
        state = f"{uuid.uuid4().hex}.{secrets.token_urlsafe(16)}"

        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": platform_oauth_redirect_uri,
            "device_id": device_id,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "login_hint": cred.email,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "auth0Client": platform_auth0_client,
        }
        authorize_url = f"{auth_base}/api/accounts/authorize?{urlencode(params)}"

        kwargs = proxy_settings.build_session_kwargs(impersonate="chrome", upstream=True, verify=False)
        session = requests.Session(**kwargs)
        try:
            session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
            session.cookies.set("oai-did", device_id, domain="auth.openai.com")

            nav_headers = {
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "accept-language": "en-US,en;q=0.9",
                "referer": f"{platform_base}/",
                "sec-ch-ua": sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "document",
                "sec-fetch-mode": "navigate",
                "sec-fetch-site": "cross-site",
                "sec-fetch-user": "?1",
                "upgrade-insecure-requests": "1",
                "user-agent": user_agent,
            }

            # 1. 发起标准 OAuth 授权请求，建立登录会话
            try:
                auth_resp = session.get(authorize_url, headers=nav_headers, allow_redirects=True, timeout=30)
            except Exception as exc:
                raise OAuthLoginError(f"授权请求网络异常: {exc}") from exc

            final_url = str(auth_resp.url or "")
            if auth_resp.status_code not in (200, 302):
                raise OAuthLoginError(_format_upstream_error("发起 OAuth 授权", auth_resp, _parse_json_safe(auth_resp)))

            if "/error" in final_url and "payload=" in final_url:
                parsed_query = parse_qs(urlparse(final_url).query)
                payload_b64 = str((parsed_query.get("payload") or [""])[0]).strip()
                error_code = ""
                if payload_b64:
                    try:
                        padded = payload_b64 + "=" * ((4 - len(payload_b64) % 4) % 4)
                        error_payload = json.loads(base64.b64decode(padded))
                        error_code = str(error_payload.get("errorCode") or "").strip()
                    except Exception:
                        error_code = ""
                raise OAuthLoginError(f"授权页返回错误{': ' + error_code if error_code else ''}")

            callback_url = final_url if final_url.startswith(platform_oauth_redirect_uri) else ""

            api_headers = {
                "accept": "application/json",
                "accept-language": "en-US,en;q=0.9",
                "content-type": "application/json",
                "origin": auth_base,
                "referer": final_url or f"{auth_base}/log-in/password",
                "oai-device-id": device_id,
                "sec-ch-ua": sec_ch_ua,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": user_agent,
            }

            # 2. 提交密码校验
            if not callback_url:
                try:
                    pwd_resp = session.post(
                        f"{auth_base}/api/accounts/password/verify",
                        headers=api_headers,
                        json={"password": cred.password},
                        timeout=30,
                    )
                except Exception as exc:
                    raise OAuthLoginError(f"密码校验网络异常: {exc}") from exc

                pwd_data = _parse_json_safe(pwd_resp)
                if pwd_resp.status_code != 200:
                    raise OAuthLoginError(_format_upstream_error("密码校验", pwd_resp, pwd_data))

                next_url = _extract_callback_url(pwd_data)
                page_info = pwd_data.get("page")
                page_type = str(page_info.get("type") or "").strip() if isinstance(page_info, dict) else ""

                # 3. 命中 MFA 挑战时依次触发 challenge 并提交 TOTP 6 位验证码
                if page_type == "mfa_challenge" or "/mfa-challenge/" in next_url:
                    if not cred.totp_secret:
                        raise OAuthLoginError("账号开启了 2FA，但导入行未提供 2FA 密钥")
                    factor_id = _extract_totp_factor_id(pwd_data, next_url)
                    if not factor_id:
                        raise OAuthLoginError("未能从 MFA 挑战响应中识别 TOTP factor_id")

                    mfa_referer = next_url or f"{auth_base}/mfa-challenge/{factor_id}"
                    mfa_headers = {**api_headers, "referer": mfa_referer}

                    # 浏览器在密码页跳转前触发 issue_challenge，因此沿用密码页 referer
                    try:
                        issue_resp = session.post(
                            f"{auth_base}/api/accounts/mfa/issue_challenge",
                            headers=api_headers,
                            json={"id": factor_id, "type": "totp", "force_fresh_challenge": False},
                            timeout=30,
                        )
                    except Exception as exc:
                        raise OAuthLoginError(f"发起 2FA 挑战网络异常: {exc}") from exc
                    if issue_resp.status_code != 200:
                        raise OAuthLoginError(
                            _format_upstream_error("发起 2FA 挑战", issue_resp, _parse_json_safe(issue_resp))
                        )

                    # 若距当前 30 秒 TOTP 窗口结束不足 3 秒，等待进入下一个窗口再提交，避免边界过期
                    remaining = 30 - (time.time() % 30)
                    if remaining < 3:
                        time.sleep(remaining + 0.5)
                    totp_code = generate_totp(cred.totp_secret)

                    try:
                        mfa_resp = session.post(
                            f"{auth_base}/api/accounts/mfa/verify",
                            headers=mfa_headers,
                            json={"id": factor_id, "type": "totp", "code": totp_code},
                            timeout=30,
                        )
                    except Exception as exc:
                        raise OAuthLoginError(f"提交 2FA 验证码网络异常: {exc}") from exc

                    mfa_data = _parse_json_safe(mfa_resp)
                    if mfa_resp.status_code != 200:
                        raise OAuthLoginError(_format_upstream_error("2FA 校验", mfa_resp, mfa_data))
                    next_url = _extract_callback_url(mfa_data)
                elif page_type == "email_otp_verification":
                    raise OAuthLoginError("账号触发邮箱验证码校验，无法仅凭密码和 2FA 自动完成登录")

                # 4. 若 continue_url 是 auth.openai.com 的中间跳转地址，沿重定向拿到 callback URL
                if next_url and not next_url.startswith(platform_oauth_redirect_uri) and "code=" not in next_url:
                    hop_url = urljoin(f"{auth_base}/", next_url)
                    for _ in range(5):
                        if not hop_url.startswith(auth_base):
                            break
                        try:
                            hop_resp = session.get(
                                hop_url,
                                headers={**nav_headers, "referer": f"{auth_base}/"},
                                allow_redirects=False,
                                timeout=30,
                            )
                        except Exception as exc:
                            raise OAuthLoginError(f"跟随授权跳转网络异常: {exc}") from exc
                        location = str(hop_resp.headers.get("location") or "").strip()
                        if not location:
                            break
                        hop_url = urljoin(hop_url, location)
                        if hop_url.startswith(platform_oauth_redirect_uri) or "code=" in hop_url:
                            next_url = hop_url
                            break

                callback_url = next_url

            if not callback_url:
                raise OAuthLoginError("登录后未返回 OAuth callback 地址")

            code, returned_state = self._extract_code_from_callback(callback_url)
            if not code:
                raise OAuthLoginError("callback 地址中未包含授权码 code")
            if returned_state and returned_state != state:
                raise OAuthLoginError("OAuth 回调 state 不匹配")

            # 5. 使用 PKCE code_verifier 换取 access_token / refresh_token / id_token
            return self._exchange_code(code, verifier, platform_oauth_redirect_uri, session=session)
        finally:
            session.close()

    def _purge_batch_jobs_locked(self) -> None:
        now = time.time()
        expired = [
            job_id
            for job_id, job in self._batch_jobs.items()
            if job.get("done") and now - float(job.get("_updated_ts") or 0) > self._BATCH_JOB_TTL_SECONDS
        ]
        for job_id in expired:
            self._batch_jobs.pop(job_id, None)
        if len(self._batch_jobs) > self._MAX_BATCH_JOBS:
            ordered = sorted(self._batch_jobs.items(), key=lambda kv: float(kv[1].get("_updated_ts") or 0))
            for job_id, job in ordered:
                if len(self._batch_jobs) <= self._MAX_BATCH_JOBS:
                    break
                if job.get("done"):
                    self._batch_jobs.pop(job_id, None)

    @staticmethod
    def _public_batch_job(job: dict[str, Any]) -> dict[str, Any]:
        return {
            "job_id": job["job_id"],
            "status": job["status"],
            "total": job["total"],
            "processed": job["processed"],
            "succeeded": job["succeeded"],
            "added": job["added"],
            "skipped": job["skipped"],
            "refreshed": job["refreshed"],
            "failed": job["failed"],
            "current_email": job["current_email"],
            "parse_errors": list(job["parse_errors"]),
            "results": [dict(item) for item in job["results"]],
            "done": job["done"],
            "error": job["error"],
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
        }

    def start_batch_import(
        self,
        credentials: list[OAuthCredential],
        parse_errors: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """创建并启动异步批量 OAuth 登录任务（后台顺序逐个处理，状态中不留存明文凭证）。"""
        if not credentials:
            raise OAuthLoginError("未解析到可登录的账号凭证")

        job_id = uuid.uuid4().hex
        now_iso = _now_iso()
        job: dict[str, Any] = {
            "job_id": job_id,
            "status": "pending",
            "total": len(credentials),
            "processed": 0,
            "succeeded": 0,
            "added": 0,
            "skipped": 0,
            "refreshed": 0,
            "failed": 0,
            "current_email": "",
            "parse_errors": list(parse_errors or []),
            "results": [],
            "done": False,
            "error": None,
            "created_at": now_iso,
            "updated_at": now_iso,
            "_updated_ts": time.time(),
        }
        with self._batch_lock:
            self._purge_batch_jobs_locked()
            self._batch_jobs[job_id] = job
            snapshot = self._public_batch_job(job)

        worker = threading.Thread(
            target=self._run_batch_import,
            args=(job_id, list(credentials)),
            name=f"oauth-batch-{job_id[:8]}",
            daemon=True,
        )
        worker.start()
        return snapshot

    def get_batch_import_job(self, job_id: str) -> dict[str, Any] | None:
        with self._batch_lock:
            self._purge_batch_jobs_locked()
            job = self._batch_jobs.get(job_id)
            return self._public_batch_job(job) if job is not None else None

    def _update_batch_job(self, job_id: str, **updates: Any) -> None:
        with self._batch_lock:
            job = self._batch_jobs.get(job_id)
            if job is None:
                return
            job.update(updates)
            job["updated_at"] = _now_iso()
            job["_updated_ts"] = time.time()

    def _run_batch_import(self, job_id: str, credentials: list[OAuthCredential]) -> None:
        """后台顺序执行每条账号的 OAuth 登录、入库与刷新，单条失败不影响后续条目。"""
        self._update_batch_job(job_id, status="running")

        succeeded = 0
        added_total = 0
        skipped_total = 0
        refreshed_total = 0
        failed = 0

        for index, cred in enumerate(credentials, start=1):
            self._update_batch_job(job_id, current_email=cred.email)
            item_result: dict[str, Any] = {
                "email": cred.email,
                "ok": False,
                "added": 0,
                "skipped": 0,
                "refreshed": 0,
                "error": "",
            }
            try:
                tokens = self.login_with_credentials(cred)
                payload = {
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens["refresh_token"],
                    "id_token": tokens["id_token"],
                    "email": cred.email,
                    "source_type": "oauth_login",
                }
                add_result = account_service.add_account_items([payload])
                refresh_result = account_service.refresh_accounts([tokens["access_token"]])

                added_cnt = int(add_result.get("added") or 0)
                skipped_cnt = int(add_result.get("skipped") or 0)
                refreshed_cnt = int(refresh_result.get("refreshed") or 0)
                refresh_errors = refresh_result.get("errors") or []
                refresh_err_msg = ""
                if refresh_errors and isinstance(refresh_errors[0], dict):
                    refresh_err_msg = str(refresh_errors[0].get("error") or "").strip()

                succeeded += 1
                added_total += added_cnt
                skipped_total += skipped_cnt
                refreshed_total += refreshed_cnt

                item_result.update({
                    "ok": True,
                    "added": added_cnt,
                    "skipped": skipped_cnt,
                    "refreshed": refreshed_cnt,
                    "error": f"已入库，刷新信息失败: {refresh_err_msg}" if refresh_err_msg else "",
                })
            except Exception as exc:
                failed += 1
                item_result["error"] = str(exc) or "OAuth 登录失败"
                print(f"[oauth-batch] login failed for {cred.email}: {item_result['error']}", flush=True)

            with self._batch_lock:
                job = self._batch_jobs.get(job_id)
                if job is not None:
                    job["results"].append(item_result)
                    job["processed"] = index
                    job["succeeded"] = succeeded
                    job["added"] = added_total
                    job["skipped"] = skipped_total
                    job["refreshed"] = refreshed_total
                    job["failed"] = failed
                    job["updated_at"] = _now_iso()
                    job["_updated_ts"] = time.time()

        final_status = "completed" if succeeded > 0 else "failed"
        self._update_batch_job(
            job_id,
            status=final_status,
            current_email="",
            done=True,
            error=None if succeeded > 0 else "所有账号均登录失败",
        )
        log_service.add(
            LOG_TYPE_ACCOUNT,
            f"批量 OAuth 登录完成：成功 {succeeded}，失败 {failed}，新增 {added_total}",
            {
                "job_id": job_id,
                "total": len(credentials),
                "succeeded": succeeded,
                "added": added_total,
                "skipped": skipped_total,
                "refreshed": refreshed_total,
                "failed": failed,
            },
        )


oauth_login_service = OAuthLoginService()
