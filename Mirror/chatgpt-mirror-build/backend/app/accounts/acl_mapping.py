from django.conf import settings
from django.utils.crypto import constant_time_compare
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.views import APIView

from app.accounts.models import User
from app.chatgpt.models import ChatgptAccount


class GatewayAclMappingView(APIView):
    authentication_classes = ()
    permission_classes = ()
    throttle_classes = ()

    def post(self, request):
        secret = settings.GATEWAY_ADMIN_SECRET
        if not secret or not constant_time_compare(
            request.headers.get("Authorization", ""), "Bearer " + secret,
        ):
            raise AuthenticationFailed("无效的网关认证")
        # 只取身份列，避免把密码、令牌等凭据字段带进网关映射表。
        users = User.objects.order_by("pk").values("pk", "username", "is_staff", "is_superuser")
        accounts = ChatgptAccount.objects.order_by("pk").values("pk", "chatgpt_username")
        return Response({
            "users": [
                {
                    "username": item["username"],
                    "user_id": str(item["pk"]),
                    "is_admin": bool(item["is_staff"] or item["is_superuser"]),
                }
                for item in users
            ],
            "accounts": [
                {
                    "chatgpt_username": item["chatgpt_username"],
                    "account_id": str(item["pk"]),
                }
                for item in accounts
            ],
        })
