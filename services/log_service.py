from __future__ import annotations

import hashlib
import json
import itertools
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from threading import Lock
from typing import Any, Iterator
from uuid import uuid4

from fastapi import HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, StreamingResponse

from services.config import DATA_DIR
from services.protocol.error_response import anthropic_error_response, openai_error_response
from utils.helper import UPLOAD_LIMIT_MESSAGE, anthropic_sse_stream, is_upload_limit_error, sse_json_stream

LOG_TYPE_CALL = "call"
LOG_TYPE_ACCOUNT = "account"
INTERNAL_RESPONSE_KEYS = {"_account_email", "_conversation_id"}
# 日志文件超过 10 MB 时自动截断为最新 5000 条，避免长期运行后无限膨胀拖慢读写
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_KEEP_LINES = 5000
LOG_TRIM_CHECK_INTERVAL = 100
LOG_READ_CHUNK_BYTES = 64 * 1024


class LogService:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        # 启动后首次写入即检查一次体积，便于平滑收缩存量超大日志文件
        self._writes_since_trim_check = LOG_TRIM_CHECK_INTERVAL

    @staticmethod
    def _legacy_id(raw_line: str) -> str:
        payload = raw_line.encode("utf-8", errors="ignore")
        return hashlib.sha1(payload).hexdigest()[:24]

    def _parse_line(self, raw_line: str) -> dict[str, Any] | None:
        try:
            item = json.loads(raw_line)
        except Exception:
            return None
        if not isinstance(item, dict):
            return None
        parsed = dict(item)
        parsed["id"] = str(parsed.get("id") or self._legacy_id(raw_line))
        return parsed

    @staticmethod
    def _serialize_item(item: dict[str, Any]) -> str:
        return json.dumps(item, ensure_ascii=False, separators=(",", ":"))

    def _iter_lines_reverse(self) -> Iterator[str]:
        """从文件末尾按 64 KiB 分块倒序读取日志行，避免全量读入内存。"""
        try:
            file_handle = self.path.open("rb")
        except FileNotFoundError:
            return
        with file_handle as file:
            pos = file.seek(0, os.SEEK_END)
            carry = b""
            while pos > 0:
                read_size = min(LOG_READ_CHUNK_BYTES, pos)
                pos -= read_size
                file.seek(pos)
                chunk = file.read(read_size)
                parts = (chunk + carry).split(b"\n")
                carry = parts[0]
                for raw_bytes in reversed(parts[1:]):
                    if raw_bytes:
                        yield raw_bytes.decode("utf-8", errors="replace")
            if carry:
                yield carry.decode("utf-8", errors="replace")

    def _trim_if_needed_locked(self) -> None:
        """在写锁保护下检查日志体积，超限时原子保留最近 LOG_KEEP_LINES 条记录。"""
        try:
            if not self.path.exists() or self.path.stat().st_size <= LOG_MAX_BYTES:
                return
        except OSError:
            return
        kept_reversed: list[str] = []
        for raw_line in self._iter_lines_reverse():
            kept_reversed.append(raw_line)
            if len(kept_reversed) >= LOG_KEEP_LINES:
                break
        kept_reversed.reverse()
        tmp_path = self.path.with_name(f".{self.path.name}.{os.getpid()}.trim.tmp")
        content = "\n".join(kept_reversed) + ("\n" if kept_reversed else "")
        tmp_path.write_text(content, encoding="utf-8")
        os.replace(tmp_path, self.path)

    @staticmethod
    def _matches_filters(item: dict[str, Any], *, type: str = "", start_date: str = "", end_date: str = "") -> bool:
        t = str(item.get("time") or "")
        day = t[:10]
        if type and item.get("type") != type:
            return False
        if start_date and day < start_date:
            return False
        if end_date and day > end_date:
            return False
        return True

    def add(self, type: str, summary: str = "", detail: dict[str, Any] | None = None, **data: Any) -> None:
        item = {
            "id": uuid4().hex,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": type,
            "summary": summary,
            "detail": detail or data,
        }
        line = self._serialize_item(item) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as file:
                file.write(line)
            self._writes_since_trim_check += 1
            if self._writes_since_trim_check >= LOG_TRIM_CHECK_INTERVAL:
                self._writes_since_trim_check = 0
                self._trim_if_needed_locked()

    def list(self, type: str = "", start_date: str = "", end_date: str = "", limit: int = 200) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        items: list[dict[str, Any]] = []
        for raw_line in self._iter_lines_reverse():
            item = self._parse_line(raw_line)
            if item is None:
                continue
            if not self._matches_filters(item, type=type, start_date=start_date, end_date=end_date):
                continue
            items.append(item)
            if len(items) >= limit:
                break
        return items

    def delete(self, ids: list[str]) -> dict[str, int]:
        target_ids = {str(item or "").strip() for item in ids if str(item or "").strip()}
        if not self.path.exists() or not target_ids:
            return {"removed": 0}
        with self._lock:
            if not self.path.exists():
                return {"removed": 0}
            removed = 0
            tmp_path = self.path.with_name(f".{self.path.name}.{os.getpid()}.delete.tmp")
            with self.path.open("r", encoding="utf-8", errors="replace") as src, tmp_path.open("w", encoding="utf-8") as dst:
                for line in src:
                    raw_line = line.rstrip("\r\n")
                    if not raw_line:
                        continue
                    item = self._parse_line(raw_line)
                    if item is None:
                        dst.write(raw_line + "\n")
                        continue
                    if str(item.get("id") or "") in target_ids:
                        removed += 1
                        continue
                    dst.write(self._serialize_item(item) + "\n")
            os.replace(tmp_path, self.path)
            return {"removed": removed}


log_service = LogService(DATA_DIR / "logs.jsonl")


def _collect_urls(value: object) -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "url" and isinstance(item, str):
                urls.append(item)
            elif key == "urls" and isinstance(item, list):
                urls.extend(str(url) for url in item if isinstance(url, str))
            else:
                urls.extend(_collect_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.extend(_collect_urls(item))
    return urls


def _collect_account_emails(value: object) -> list[str]:
    emails: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {"_account_email", "account_email"} and isinstance(item, str) and item.strip():
                emails.append(item.strip())
            else:
                emails.extend(_collect_account_emails(item))
    elif isinstance(value, list):
        for item in value:
            emails.extend(_collect_account_emails(item))
    return emails


def _collect_conversation_ids(value: object) -> list[str]:
    ids: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "_conversation_id" and isinstance(item, str) and item.strip():
                ids.append(item.strip())
            else:
                ids.extend(_collect_conversation_ids(item))
    elif isinstance(value, list):
        for item in value:
            ids.extend(_collect_conversation_ids(item))
    return ids


def _strip_internal_response_fields(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: _strip_internal_response_fields(item)
            for key, item in value.items()
            if key not in INTERNAL_RESPONSE_KEYS
        }
    if isinstance(value, list):
        return [_strip_internal_response_fields(item) for item in value]
    return value


def _request_excerpt(text: object, limit: int = 1000) -> str:
    value = str(text or "").strip()
    if not value:
        return ""
    normalized = " ".join(value.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: limit - 1].rstrip() + "…"


def _image_error_response(exc: Exception) -> JSONResponse:
    from services.protocol.conversation import public_image_error_message

    if is_upload_limit_error(exc):
        return openai_error_response(
            UPLOAD_LIMIT_MESSAGE,
            429,
            error_type="rate_limit_error",
            code="upload_limit_exceeded",
        )
    message = public_image_error_message(str(exc))
    if "no available image quota" in message.lower():
        return openai_error_response(
            {
                "error": {
                    "message": "no available image quota",
                    "type": "insufficient_quota",
                    "param": None,
                    "code": "insufficient_quota",
                }
            },
            429,
        )
    if hasattr(exc, "to_openai_error") and hasattr(exc, "status_code"):
        return JSONResponse(status_code=int(exc.status_code), content=exc.to_openai_error())
    return openai_error_response(message, 502)


def _protocol_error_response(exc: Exception, status_code: int, sse: str) -> JSONResponse:
    if is_upload_limit_error(exc):
        if sse == "anthropic":
            return anthropic_error_response(UPLOAD_LIMIT_MESSAGE, 429)
        return openai_error_response(
            UPLOAD_LIMIT_MESSAGE,
            429,
            error_type="rate_limit_error",
            code="upload_limit_exceeded",
        )
    message = str(exc)
    if sse == "anthropic":
        return anthropic_error_response(message, status_code)
    return openai_error_response(message, status_code)


def _next_item(items):
    try:
        return True, next(items)
    except StopIteration:
        return False, None


@dataclass
class LoggedCall:
    identity: dict[str, object]
    endpoint: str
    model: str
    summary: str
    started: float = field(default_factory=time.time)
    request_text: str = ""
    request_shape: dict[str, int] | None = None

    async def run(self, handler, *args, sse: str = "openai"):
        from services.protocol.conversation import ImageGenerationError

        try:
            result = await run_in_threadpool(handler, *args)
        except ImageGenerationError as exc:
            await self.alog("调用失败", status="failed", error=str(exc), account_email=getattr(exc, "account_email", ""),
                            conversation_id=getattr(exc, "conversation_id", ""))
            return _image_error_response(exc)
        except HTTPException as exc:
            await self.alog("调用失败", status="failed", error=str(exc.detail))
            raise
        except Exception as exc:
            await self.alog("调用失败", status="failed", error=str(exc), account_email=getattr(exc, "account_email", ""))
            if self.endpoint.startswith("/v1/images"):
                return _image_error_response(exc)
            return _protocol_error_response(exc, 502, sse)

        if isinstance(result, dict):
            await self.alog("调用完成", result)
            response = dict(result)
            response.pop("_account_email", None)
            return response

        sender = anthropic_sse_stream if sse == "anthropic" else sse_json_stream
        try:
            has_first, first = await run_in_threadpool(_next_item, result)
        except ImageGenerationError as exc:
            await self.alog("调用失败", status="failed", error=str(exc), account_email=getattr(exc, "account_email", ""),
                            conversation_id=getattr(exc, "conversation_id", ""))
            return _image_error_response(exc)
        except HTTPException as exc:
            await self.alog("调用失败", status="failed", error=str(exc.detail))
            raise
        except Exception as exc:
            await self.alog("调用失败", status="failed", error=str(exc), account_email=getattr(exc, "account_email", ""))
            if self.endpoint.startswith("/v1/images"):
                return _image_error_response(exc)
            return _protocol_error_response(exc, 502, sse)
        if not has_first:
            await self.alog("流式调用结束")
            return StreamingResponse(sender(()), media_type="text/event-stream")
        return StreamingResponse(sender(self.stream(itertools.chain([first], result))), media_type="text/event-stream")

    def stream(self, items):
        urls: list[str] = []
        account_emails: list[str] = []
        conversation_ids: list[str] = []
        failed = False
        try:
            for item in items:
                urls.extend(_collect_urls(item))
                account_emails.extend(_collect_account_emails(item))
                conversation_ids.extend(_collect_conversation_ids(item))
                yield _strip_internal_response_fields(item)
        except Exception as exc:
            failed = True
            self.log(
                "流式调用失败",
                status="failed",
                error=str(exc),
                urls=urls,
                account_email=(account_emails[0] if account_emails else getattr(exc, "account_email", "")),
                conversation_id=(conversation_ids[0] if conversation_ids else getattr(exc, "conversation_id", "")),
            )
            if self.endpoint.startswith("/v1/images") and not hasattr(exc, "to_openai_error"):
                from services.protocol.conversation import ImageGenerationError, public_image_error_message

                raise ImageGenerationError(public_image_error_message(str(exc))) from exc
            raise
        finally:
            if not failed:
                self.log("流式调用结束", urls=urls, account_email=account_emails[0] if account_emails else "",
                         conversation_id=conversation_ids[0] if conversation_ids else "")

    async def alog(
        self,
        suffix: str,
        result: object = None,
        status: str = "success",
        error: str = "",
        urls: list[str] | None = None,
        account_email: str = "",
        conversation_id: str = "",
    ) -> None:
        """在线程池中异步写入调用日志，避免磁盘 I/O 与文件截断阻塞事件循环。"""
        await run_in_threadpool(
            self.log,
            suffix,
            result,
            status,
            error,
            urls,
            account_email,
            conversation_id,
        )

    def log(self, suffix: str, result: object = None, status: str = "success", error: str = "",
            urls: list[str] | None = None, account_email: str = "", conversation_id: str = "") -> None:
        detail = {
            "key_id": self.identity.get("id"),
            "key_name": self.identity.get("name"),
            "role": self.identity.get("role"),
            "endpoint": self.endpoint,
            "model": self.model,
            "started_at": datetime.fromtimestamp(self.started).strftime("%Y-%m-%d %H:%M:%S"),
            "ended_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "duration_ms": int((time.time() - self.started) * 1000),
            "status": status,
        }
        request_excerpt = _request_excerpt(self.request_text)
        if request_excerpt:
            detail["request_text"] = request_excerpt
        if self.request_shape:
            detail["request_shape"] = self.request_shape
        if error:
            detail["error"] = error
        email = str(account_email or "").strip()
        if not email:
            emails = _collect_account_emails(result)
            email = emails[0] if emails else ""
        if email:
            detail["account_email"] = email
        conv_id = str(conversation_id or "").strip()
        if not conv_id:
            conv_ids = _collect_conversation_ids(result)
            conv_id = conv_ids[0] if conv_ids else ""
        if conv_id:
            detail["conversation_id"] = conv_id
        collected_urls = [*(urls or []), *_collect_urls(result)]
        if collected_urls and not self.endpoint.startswith("/v1/search"):
            detail["urls"] = list(dict.fromkeys(collected_urls))
        log_service.add(LOG_TYPE_CALL, f"{self.summary}{suffix}", detail)
