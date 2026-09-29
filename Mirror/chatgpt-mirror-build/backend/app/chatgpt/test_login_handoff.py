from unittest.mock import patch

from django.test import TestCase
from django.test.utils import override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from app.accounts.models import User
from app.chatgpt.models import ChatgptAccount, ChatgptCar
from app.chatgpt.views.chatgpt import ChatGPTLoginView


class LoginHandoffUrlTests(TestCase):
    """管理端登录跳转的地址形态。

    原版网关是单端口同源部署（自托管 /admin、镜像面与 /api/*），网关返回的相对
    `/api/not-login` 天然落在同一来源。候选编排把管理界面拆到 nginx 侧车
    （40003）、镜像面留在网关（40002），同一段相对路径会被浏览器解析到管理端源上，
    nginx 没有该 location → 404（2026-09-29 实测）。
    """

    def setUp(self):
        self.factory = APIRequestFactory()
        self.account = ChatgptAccount.objects.create(
            chatgpt_username="handoff@example.com",
            plan_type="plus",
            access_token="secret-access",
            access_token_valid=True,
            created_time=1,
            updated_time=1,
        )
        car = ChatgptCar.objects.create(
            car_name="handoff-car",
            gpt_account_list=[self.account.id],
            created_time=1,
            updated_time=1,
        )
        self.user = User.objects.create_user(
            username="handoff-user",
            password="Strong-password-123!",
            gptcar_list=[car.id],
        )
        self.login_url = f"/api/not-login?user_gateway_token={'a' * 64}"

    def login(self, gateway_response):
        with patch(
            "app.chatgpt.views.chatgpt.req_gateway", return_value=gateway_response
        ):
            request = self.factory.post(
                "/0x/chatgpt/login",
                {"chatgpt_id": self.account.id, "login_mode": "api"},
                format="json",
                # 登录成功会写访问日志，而 VisitLog.user_agent 非空（浏览器必然携带）。
                HTTP_USER_AGENT="test-browser",
            )
            force_authenticate(request, user=self.user)
            return ChatGPTLoginView.as_view()(request)

    @override_settings(MIRROR_PUBLIC_URL="http://127.0.0.1:40002")
    def test_relative_handoff_is_made_absolute(self):
        response = self.login({"login_url": self.login_url})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["login_url"], "http://127.0.0.1:40002" + self.login_url
        )

    @override_settings(MIRROR_PUBLIC_URL="")
    def test_unset_mirror_url_keeps_the_relative_handoff(self):
        """原版单端口部署（同源）不配置该变量，语义必须保持不变。"""
        response = self.login({"login_url": self.login_url})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["login_url"], self.login_url)

    @override_settings(MIRROR_PUBLIC_URL="https://mirror.example.com")
    def test_absolute_handoff_is_not_rewritten(self):
        absolute = "https://other.example.com/api/not-login?user_gateway_token=b"
        response = self.login({"login_url": absolute})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["login_url"], absolute)
