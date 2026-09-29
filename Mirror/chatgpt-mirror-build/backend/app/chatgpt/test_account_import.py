import json
from unittest.mock import patch

from django.test import TestCase
from rest_framework.exceptions import ValidationError
from rest_framework.test import APIClient

from app.accounts.models import User
from app.chatgpt.models import ChatgptAccount


class ChatgptAccountImportTests(TestCase):
    """管理端「添加上游账号」的消费端契约。

    网关返回的信封由 Rust 侧 `tests/token_import.rs` 锁定；这里锁的是 Django 这一端：
    `ChatgptAccount.save_data` 直接读 `user_info.email`/`user_info.plan_type`/`access_token`，
    少任何一项都会抛 KeyError（2026-09-28 定位到的真实缺陷：网关只回传了 `/backend-api/me` 正文）。
    """

    url = "/0x/chatgpt/"
    session_token = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..fixture-iv.fixture-ct.fixture-tag"

    def setUp(self):
        self.client = APIClient()
        admin = User.objects.create_user(username="import-admin", is_superuser=True, is_staff=True)
        self.client.force_authenticate(admin)

    def envelope(self, **changes):
        data = {
            "user_info": {"email": "fixture@example.invalid", "plan_type": "plus"},
            "access_token": "exchanged-access-token",
            "session_token": self.session_token,
            "access_token_valid": True,
            "session_token_valid": True,
        }
        data.update(changes)
        return data

    @patch("app.chatgpt.views.chatgpt.req_gateway")
    def test_session_token_import_stores_both_credentials(self, req_gateway):
        req_gateway.return_value = self.envelope()
        response = self.client.post(
            self.url, {"chatgpt_token_list": ["pasted-session-token"]}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        account = ChatgptAccount.objects.get(chatgpt_username="fixture@example.invalid")
        self.assertEqual(account.access_token, "exchanged-access-token")
        self.assertEqual(account.session_token, self.session_token)
        self.assertEqual(account.plan_type, "plus")
        self.assertTrue(account.access_token_valid)
        self.assertTrue(account.session_token_valid)
        # 录入的是粘贴原文；凭据分类由网关按 JWT 段数判定，Django 不改写输入。
        # 第一次调用是录入，随后还有一个关闭记忆的调用。
        self.assertEqual(
            req_gateway.call_args_list[0].kwargs["json"], {"chatgpt_token": "pasted-session-token"}
        )

    @patch("app.chatgpt.views.chatgpt.req_gateway")
    def test_access_token_import_clears_stale_session_token(self, req_gateway):
        ChatgptAccount.objects.create(
            chatgpt_username="fixture@example.invalid", session_token=self.session_token,
            created_time=1, updated_time=1,
        )
        req_gateway.return_value = self.envelope(session_token=None, session_token_valid=False)
        response = self.client.post(
            self.url, {"chatgpt_token_list": ["pasted-access-token"]}, format="json"
        )
        self.assertEqual(response.status_code, 200)
        account = ChatgptAccount.objects.get(chatgpt_username="fixture@example.invalid")
        self.assertEqual(account.access_token, "exchanged-access-token")
        self.assertFalse(account.session_token_valid)

    @patch("app.chatgpt.views.chatgpt.req_gateway")
    def test_gateway_message_reaches_the_admin_without_html(self, req_gateway):
        req_gateway.side_effect = ValidationError(
            {"message": "session_token 无法换取 access_token"}
        )
        response = self.client.post(
            self.url, {"chatgpt_token_list": ["pasted-session-token"]}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        body = json.dumps(response.data, ensure_ascii=False)
        self.assertIn("session_token 无法换取 access_token", body)
        self.assertNotIn("<html", body)
        self.assertEqual(ChatgptAccount.objects.count(), 0)

    @patch("app.chatgpt.views.chatgpt.req_gateway")
    def test_comment_lines_are_skipped_and_partial_failures_are_reported(self, req_gateway):
        """粘贴整份 Netscape/草稿文件时：注释行与空行跳过，坏行不拖垮好行。"""

        def call(method, uri, **kwargs):
            if uri == "/api/get-user-info":
                if kwargs["json"]["chatgpt_token"] == "bad-token":
                    raise ValidationError({"message": "session_token 无法换取 access_token"})
                return self.envelope()
            return {"message": "ok"}

        req_gateway.side_effect = call
        response = self.client.post(
            self.url,
            {
                "chatgpt_token_list": [
                    "# Netscape HTTP Cookie File",
                    "   ",
                    "bad-token",
                    "good-token",
                ]
            },
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("部分添加成功", response.data["message"])
        self.assertEqual(len(response.data["errors"]), 1)
        self.assertEqual(ChatgptAccount.objects.count(), 1)
        self.assertNotIn(
            "bad-token",
            json.dumps(response.data, ensure_ascii=False),
            "错误明细不得回显凭据本身",
        )
        imported = [c for c in req_gateway.call_args_list if c.args[1] == "/api/get-user-info"]
        self.assertEqual(
            [c.kwargs["json"]["chatgpt_token"] for c in imported], ["bad-token", "good-token"]
        )

    @patch("app.chatgpt.views.chatgpt.req_gateway")
    def test_only_comment_lines_reports_an_actionable_error(self, req_gateway):
        response = self.client.post(
            self.url, {"chatgpt_token_list": ["# 真实上游探针的 SessionToken 草稿", ""]}, format="json"
        )
        self.assertEqual(response.status_code, 400)
        self.assertIn(
            "没有可录入的 Token", json.dumps(response.data, ensure_ascii=False)
        )
        req_gateway.assert_not_called()
