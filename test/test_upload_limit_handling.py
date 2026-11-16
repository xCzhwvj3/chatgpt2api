from __future__ import annotations

import base64
import unittest
from unittest import mock

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.ai as ai_module
from services.openai_backend_api import OpenAIBackendAPI
from services.protocol.conversation import (
    ConversationRequest,
    ImageGenerationError,
    is_image_concurrency_error,
    stream_image_outputs_with_pool,
    stream_text_deltas,
)
from utils.helper import (
    UPLOAD_LIMIT_MESSAGE,
    UpstreamHTTPError,
    is_upload_limit_error,
)


PNG_BYTES = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
)
UPLOAD_LIMIT_BODY = {
    "detail": {
        "code": "throttled",
        "error_code": "throttled",
        "message": "你已达到文件上传上限。请17小时 内重试。",
        "type": "throttled",
        "reason": "upload_protection_limit_exceeded",
    }
}


def upload_limit_error() -> UpstreamHTTPError:
    return UpstreamHTTPError("/backend-api/files", 429, UPLOAD_LIMIT_BODY)


class UploadLimitClassificationTests(unittest.TestCase):
    def test_upload_limit_is_not_treated_as_concurrency_limit(self) -> None:
        error = upload_limit_error()

        self.assertTrue(is_upload_limit_error(error))
        self.assertFalse(is_image_concurrency_error(error))
        self.assertFalse(OpenAIBackendAPI._is_image_file_concurrency_error(error))

    def test_concurrency_limit_is_not_treated_as_upload_limit(self) -> None:
        error = UpstreamHTTPError(
            "/backend-api/files",
            503,
            {"detail": {"code": "throttled", "source": "concurrency_limit"}},
        )

        self.assertFalse(is_upload_limit_error(error))
        self.assertTrue(is_image_concurrency_error(error))

    def test_file_upload_does_not_retry_upload_limit(self) -> None:
        backend = OpenAIBackendAPI.__new__(OpenAIBackendAPI)
        backend.base_url = "https://chatgpt.test"
        backend.user_agent = "ua"
        backend.session = mock.Mock()
        backend._headers = mock.Mock(return_value={})
        backend._sleep_with_request_deadline = mock.Mock()
        response = mock.Mock(status_code=429, headers={})
        response.json.return_value = UPLOAD_LIMIT_BODY
        backend.session.post.return_value = response

        with self.assertRaises(UpstreamHTTPError) as caught:
            backend._upload_image(f"data:image/png;base64,{base64.b64encode(PNG_BYTES).decode('ascii')}")

        self.assertTrue(is_upload_limit_error(caught.exception))
        self.assertEqual(backend.session.post.call_count, 1)
        backend._sleep_with_request_deadline.assert_not_called()


class UploadLimitRetryTests(unittest.TestCase):
    def test_text_request_switches_to_next_account(self) -> None:
        parent_backend = OpenAIBackendAPI.__new__(OpenAIBackendAPI)
        parent_backend.access_token = "token-1"
        created_backends: list[mock.Mock] = []

        def new_backend(access_token: str = "") -> mock.Mock:
            backend = mock.Mock()
            backend.access_token = access_token
            created_backends.append(backend)
            return backend

        def fake_events(active_backend: mock.Mock, **_kwargs):
            if active_backend.access_token == "token-1":
                raise upload_limit_error()
            yield {"type": "conversation.delta", "delta": "ok"}

        excluded_seen: list[set[str]] = []

        def next_text_token(excluded: set[str]) -> str:
            excluded_seen.append(set(excluded))
            return "token-2"

        with (
            mock.patch("services.protocol.conversation.OpenAIBackendAPI", side_effect=new_backend),
            mock.patch("services.protocol.conversation.conversation_events", side_effect=fake_events),
            mock.patch(
                "services.protocol.conversation.account_service.get_text_access_token",
                side_effect=next_text_token,
            ) as get_token,
            mock.patch("services.protocol.conversation.account_service.mark_text_used"),
        ):
            chunks = list(stream_text_deltas(parent_backend, ConversationRequest(prompt="hello", model="auto")))

        self.assertEqual(chunks, ["ok"])
        self.assertEqual([backend.access_token for backend in created_backends], ["token-1", "token-2"])
        self.assertEqual(excluded_seen, [{"token-1"}])
        get_token.assert_called_once()

    def test_image_request_returns_429_after_upload_limit_retries(self) -> None:
        request = ConversationRequest(prompt="draw", model="gpt-image-2", n=1)

        with (
            mock.patch("services.protocol.conversation.is_supported_image_model", return_value=True),
            mock.patch(
                "services.protocol.conversation.account_service.get_available_access_token",
                return_value="token-1",
            ) as get_account_token,
            mock.patch(
                "services.protocol.conversation.account_service.get_account",
                return_value={"email": "user@example.com"},
            ),
            mock.patch("services.protocol.conversation.account_service.mark_image_result"),
            mock.patch("services.protocol.conversation.OpenAIBackendAPI", return_value=mock.Mock()),
            mock.patch(
                "services.protocol.conversation.stream_image_outputs",
                side_effect=upload_limit_error(),
            ),
        ):
            with self.assertRaises(ImageGenerationError) as caught:
                list(stream_image_outputs_with_pool(request))

        error = caught.exception
        self.assertEqual(error.status_code, 429)
        self.assertEqual(error.error_type, "rate_limit_error")
        self.assertEqual(error.code, "upload_limit_exceeded")
        self.assertEqual(str(error), UPLOAD_LIMIT_MESSAGE)
        self.assertEqual(get_account_token.call_count, 4)


class UploadLimitApiResponseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity_patcher = mock.patch.object(
            ai_module,
            "require_identity",
            return_value={"id": "test", "name": "Test", "role": "admin"},
        )
        self.filter_patcher = mock.patch.object(ai_module, "filter_or_log", mock.AsyncMock())
        self.log_patcher = mock.patch.object(ai_module.LoggedCall, "log")
        self.identity_patcher.start()
        self.filter_patcher.start()
        self.log_patcher.start()
        self.addCleanup(self.identity_patcher.stop)
        self.addCleanup(self.filter_patcher.stop)
        self.addCleanup(self.log_patcher.stop)

        app = FastAPI()
        app.include_router(ai_module.create_router())
        self.client = TestClient(app)

    def test_chat_completions_files_returns_429_for_upload_limit(self) -> None:
        error = upload_limit_error()
        with mock.patch.object(ai_module.openai_v1_chat_complete, "handle", side_effect=error):
            response = self.client.post(
                "/v1/chat/completions/files",
                headers={"Authorization": "Bearer test"},
                data={"prompt": "describe", "model": "auto", "stream": "false"},
                files=[("files", ("image.png", PNG_BYTES, "image/png"))],
            )

        self.assertEqual(response.status_code, 429, response.text)
        payload = response.json()
        self.assertEqual(payload["error"]["type"], "rate_limit_error")
        self.assertEqual(payload["error"]["code"], "upload_limit_exceeded")
        self.assertEqual(payload["error"]["message"], UPLOAD_LIMIT_MESSAGE)
        self.assertNotIn("backend-api/files", response.text)


if __name__ == "__main__":
    unittest.main()
