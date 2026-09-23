from unittest.mock import patch

from django.test import SimpleTestCase

from app.cron import _update_token


class UpdateTokenTests(SimpleTestCase):
    """凭据刷新 cron：Cloudflare 拦截是上游瞬时故障，不能当成 token 失效。"""

    @patch("app.cron.ChatgptAccount")
    @patch("app.cron.requests.post")
    def test_upstream_block_keeps_token_and_returns_transient(self, post, account):
        post.return_value.status_code = 502
        post.return_value.json.return_value = {
            "message": "session_token 校验失败: api/auth/session 返回状态 403; Cloudflare 拦截，已刷新 CF cookies 并重试一次仍被拒绝",
            "code": "upstream_blocked",
        }
        self.assertIsNone(_update_token("upstream@example.com", "synthetic-session-token"))
        account.save_data.assert_not_called()

    @patch("app.cron.ChatgptAccount")
    @patch("app.cron.requests.post")
    def test_real_token_failure_still_returns_false(self, post, account):
        post.return_value.status_code = 400
        post.return_value.json.return_value = {"message": "session_token 失效"}
        self.assertFalse(_update_token("upstream@example.com", "synthetic-session-token"))
        account.save_data.assert_not_called()

    @patch("app.cron.ChatgptAccount")
    @patch("app.cron.requests.post")
    def test_successful_refresh_still_writes_credentials(self, post, account):
        post.return_value.status_code = 200
        post.return_value.json.return_value = {
            "access_token": "synthetic-access-token",
            "user_info": {"email": "upstream@example.com", "plan_type": "plus"},
        }
        self.assertTrue(_update_token("upstream@example.com", "synthetic-session-token"))
        account.save_data.assert_called_once()
