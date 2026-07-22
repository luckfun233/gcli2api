from typing import List, Optional

import hashlib
import secrets
import time

from config import get_api_password, get_panel_password
from fastapi import Depends, HTTPException, Header, Query, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from log import log
from src.ratelimit import check_token_rate_limit

# HTTP Bearer security scheme
security = HTTPBearer()

# 安全加固：默认弱密码黑名单。当配置密码为此列表中的值时，所有鉴权一律拒绝。
# 与 src/auth.py 保持一致，避免公网部署时使用默认 "pwd" 导致 1 秒被爆破。
_WEAK_DEFAULT_PASSWORDS = {"pwd", "", "password", "admin", "123456", "12345678"}


def _is_weak_password(password: Optional[str]) -> bool:
    """判断密码是否为不安全的弱默认值（必须拒绝）。

    M4 改造：argon2 hash 不算弱密码（即使对应明文是弱的，也在 verify 阶段拦截）。
    """
    if not password:
        return True
    # M4: argon2 hash 形式的密码不算弱密码
    if password.startswith("$argon2"):
        return False
    return password in _WEAK_DEFAULT_PASSWORDS

# ====================== OAuth Configuration ======================

_GEMINICLI_VERSION = "0.35.2"
_GEMINICLI_PLATFORM = "win32"
_GEMINICLI_ARCH = "x64"
_GEMINICLI_SURFACE = "cloud-shell"

def get_geminicli_user_agent(model: str = "") -> str:
    """生成动态 User-Agent: GeminiCLI/{version}/{model} ({platform}; {arch}; {surface})"""
    if model:
        return f"GeminiCLI/{_GEMINICLI_VERSION}/{model} ({_GEMINICLI_PLATFORM}; {_GEMINICLI_ARCH}; {_GEMINICLI_SURFACE})"
    return f"GeminiCLI/{_GEMINICLI_VERSION} ({_GEMINICLI_PLATFORM}; {_GEMINICLI_ARCH}; {_GEMINICLI_SURFACE})"

# 静态常量
GEMINICLI_USER_AGENT = get_geminicli_user_agent()

# Antigravity CLI 客户端仿真常量
ANTIGRAVITY_CLI_VERSION = "1.0.1"
ANTIGRAVITY_CLI_PLATFORM = "windows/amd64"
ANTIGRAVITY_USER_AGENT = f"antigravity/cli/{ANTIGRAVITY_CLI_VERSION} {ANTIGRAVITY_CLI_PLATFORM}"

# OAuth Configuration - 标准模式
CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
CLIENT_SECRET = "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"
SCOPES = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

# Antigravity OAuth Configuration
ANTIGRAVITY_CLIENT_ID = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
ANTIGRAVITY_CLIENT_SECRET = "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"
ANTIGRAVITY_SCOPES = [
    'https://www.googleapis.com/auth/cloud-platform',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/cclog',
    'https://www.googleapis.com/auth/experimentsandconfigs'
]

# 统一的 Token URL（两种模式相同）
TOKEN_URL = "https://oauth2.googleapis.com/token"

# 回调服务器配置
CALLBACK_HOST = "localhost"

# Model name lists for different features
BASE_MODELS = [
    "gemini-2.5-pro",
    "gemini-2.5-flash",
    "gemini-3-flash-preview",
    "gemini-3.1-pro-preview",
    "gemini-3.1-flash-lite",
]


# ====================== Model Helper Functions ======================

def is_fake_streaming_model(model_name: str) -> bool:
    """Check if model name indicates fake streaming should be used."""
    return model_name.startswith("假流式/")


def is_anti_truncation_model(model_name: str) -> bool:
    """Check if model name indicates anti-truncation should be used."""
    return model_name.startswith("流式抗截断/")


def get_base_model_from_feature_model(model_name: str) -> str:
    """Get base model name from feature model name."""
    # Remove feature prefixes
    for prefix in ["假流式/", "流式抗截断/"]:
        if model_name.startswith(prefix):
            return model_name[len(prefix) :]
    return model_name


def get_available_models(router_type: str = "openai") -> List[str]:
    """
    Get available models with feature prefixes.

    Args:
        router_type: "openai" or "gemini"

    Returns:
        List of model names with feature prefixes
    """
    models = []

    for base_model in BASE_MODELS:
        # 基础模型
        models.append(base_model)

        # 假流式模型 (前缀格式)
        models.append(f"假流式/{base_model}")

        # 流式抗截断模型 (仅在流式传输时有效，前缀格式)
        models.append(f"流式抗截断/{base_model}")

        # 定义思考后缀（根据模型系列不同）
        thinking_suffixes = []

        # Gemini 2.5 系列: 使用思考预算后缀
        if "gemini-2.5" in base_model:
            thinking_suffixes = ["-max", "-high", "-medium", "-low", "-minimal"]
        # Gemini 3 系列: 使用思考等级后缀
        elif "gemini-3" in base_model:
            if "flash" in base_model:
                # 3-flash-preview: 支持 high/medium/low/minimal
                thinking_suffixes = ["-high", "-medium", "-low", "-minimal"]
            elif "pro" in base_model:
                # 3-pro-preview: 支持 high/low
                thinking_suffixes = ["-high", "-low"]

        search_suffix = "-search"

        # 1. 单独的 thinking 后缀
        for thinking_suffix in thinking_suffixes:
            models.append(f"{base_model}{thinking_suffix}")
            models.append(f"假流式/{base_model}{thinking_suffix}")
            models.append(f"流式抗截断/{base_model}{thinking_suffix}")

        # 2. 单独的 search 后缀
        models.append(f"{base_model}{search_suffix}")
        models.append(f"假流式/{base_model}{search_suffix}")
        models.append(f"流式抗截断/{base_model}{search_suffix}")

        # 3. thinking + search 组合后缀
        for thinking_suffix in thinking_suffixes:
            combined_suffix = f"{thinking_suffix}{search_suffix}"
            models.append(f"{base_model}{combined_suffix}")
            models.append(f"假流式/{base_model}{combined_suffix}")
            models.append(f"流式抗截断/{base_model}{combined_suffix}")

    return models


# ====================== Authentication Functions ======================

async def authenticate_flexible(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None, alias="x-api-key"),
    access_token: Optional[str] = Header(None, alias="access_token"),
    x_goog_api_key: Optional[str] = Header(None, alias="x-goog-api-key"),
    x_anthropic_auth_token: Optional[str] = Header(None, alias="x-anthropic-auth-token"),
    anthropic_auth_token: Optional[str] = Header(None, alias="anthropic-auth-token"),
    key: Optional[str] = Query(None)
) -> str:
    """
    统一的灵活认证函数，支持多种认证方式

    此函数可以直接用作 FastAPI 的 Depends 依赖

    支持的认证方式:
        - URL 参数: key
        - HTTP 头部: Authorization (Bearer token)
        - HTTP 头部: x-api-key
        - HTTP 头部: access_token
        - HTTP 头部: x-goog-api-key
        - HTTP 头部: x-anthropic-auth-token
        - HTTP 头部: anthropic-auth-token

    Args:
        request: FastAPI Request 对象
        authorization: Authorization 头部值（自动注入）
        x_api_key: x-api-key 头部值（自动注入）
        access_token: access_token 头部值（自动注入）
        x_goog_api_key: x-goog-api-key 头部值（自动注入）
        x_anthropic_auth_token: x-anthropic-auth-token 头部值（自动注入）
        anthropic_auth_token: anthropic-auth-token 头部值（自动注入）
        key: URL 参数 key（自动注入）

    Returns:
        验证通过的token

    Raises:
        HTTPException: 认证失败时抛出异常

    使用示例:
        @router.post("/endpoint")
        async def endpoint(token: str = Depends(authenticate_flexible)):
            # token 已验证通过
            pass
    """
    password = await get_api_password()
    token = None
    auth_method = None

    # 安全加固：拒绝默认弱密码。若服务端密码为默认 "pwd" 等弱值，
    # 一律拒绝所有 API 调用，避免公网部署被秒破。
    # M4: hash 形式的密码不算弱密码（hash 本身是强随机串），弱密码判断在 verify 阶段做。
    if _is_weak_password(password):
        log.error(
            "拒绝 API 鉴权：服务端配置了默认弱密码（pwd/空等）。"
            "请通过环境变量 API_PASSWORD/PASSWORD 配置强密码后重启服务。"
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="服务端未配置访问密码，拒绝访问。请联系管理员设置 API_PASSWORD 环境变量。",
        )

    # 1. 尝试从 URL 参数 key 获取（Google 官方标准方式）
    if key:
        token = key
        auth_method = "URL parameter 'key'"

    # 2. 尝试从 x-goog-api-key 头部获取（Google API 标准方式）
    elif x_goog_api_key:
        token = x_goog_api_key
        auth_method = "x-goog-api-key header"

    # 3. 尝试从 x-anthropic-auth-token 头部获取（Anthropic 标准方式）
    elif x_anthropic_auth_token:
        token = x_anthropic_auth_token
        auth_method = "x-anthropic-auth-token header"

    # 4. 尝试从 anthropic-auth-token 头部获取（Anthropic 替代方式）
    elif anthropic_auth_token:
        token = anthropic_auth_token
        auth_method = "anthropic-auth-token header"

    # 5. 尝试从 x-api-key 头部获取
    elif x_api_key:
        token = x_api_key
        auth_method = "x-api-key header"

    # 6. 尝试从 access_token 头部获取
    elif access_token:
        token = access_token
        auth_method = "access_token header"

    # 7. 尝试从 Authorization 头部获取
    elif authorization:
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication scheme. Use 'Bearer <token>'",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = authorization[7:]  # 移除 "Bearer " 前缀
        auth_method = "Authorization Bearer header"

    # 检查是否提供了任何认证凭据
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication credentials. Use 'key' URL parameter, 'x-goog-api-key', 'x-anthropic-auth-token', 'anthropic-auth-token', 'x-api-key', 'access_token' header, or 'Authorization: Bearer <token>'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # M4: 验证 token —— 调用 verify_password 支持明文 / argon2 hash 两种存储形式
    from src.auth import verify_password as _verify_api_password
    if not await _verify_api_password(token):
        log.debug(f"Authentication failed using {auth_method}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="密码错误"
        )

    # M6: Token 维度限流（认证通过后）。防止凭证被盗后高频刷量。
    check_token_rate_limit(token)

    log.debug(f"Authentication successful using {auth_method}")
    return token


# 为了保持向后兼容，保留旧函数名作为别名
authenticate_bearer = authenticate_flexible
authenticate_gemini_flexible = authenticate_flexible


# ====================== Panel Authentication Functions ======================

# M1: session 滚动续期 TTL（与登录时 7 天保持一致）
_SESSION_TTL_SEC = 7 * 86400


async def verify_panel_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    """
    控制面板鉴权（M1 双轨过渡 + M4 兼容）

    M1 改造：
    1. 优先尝试 session 鉴权（token 即 session_id），命中则滚动续期并返回 session_id。
    2. session 查询失败或未命中时，fallback 到密码直连（调用 verify_password，
       支持 M4 的明文 / argon2 hash 两种存储形式）。
    3. 过渡期 fallback 在 M1 上线 30 天后应移除，强制走 session（见下方 TODO）。

    Args:
        credentials: HTTPAuthorizationCredentials 自动注入

    Returns:
        session_id（session 模式）或明文密码（fallback 模式）。
        调用方无需关心返回的是哪种，只用作"已认证"标记。

    Raises:
        HTTPException: 鉴权失败时抛出 401 / 503
    """
    token = credentials.credentials

    # 1. 优先尝试 session 鉴权（M1）
    try:
        from src.storage_adapter import get_storage_adapter
        adapter = await get_storage_adapter()
        session = await adapter.get_session(token)
        if session:
            now = time.time()
            # 检查是否过期
            if session.get("expires_at", 0) <= now:
                await adapter.delete_session(token)  # 顺手清理
                raise HTTPException(status_code=401, detail="session 已过期，请重新登录")
            # M1 风险点补充：校验 password_hash 是否匹配当前密码
            # （环境变量改密码 / DB 改密码后，旧 session 因 hash 不匹配而失效）
            current_password = await get_panel_password()
            current_password_hash = hashlib.sha256(
                current_password.encode("utf-8")
            ).hexdigest()
            if session.get("password_hash") and session["password_hash"] != current_password_hash:
                await adapter.delete_session(token)
                raise HTTPException(status_code=401, detail="密码已变更，请重新登录")
            # 滚动续期（最多续到 7 天）
            new_expires = min(now + _SESSION_TTL_SEC, session.get("last_active_at", now) + _SESSION_TTL_SEC + 86400)
            await adapter.touch_session(token, now, new_expires)
            return token  # 返回 session_id
    except HTTPException:
        raise
    except Exception as e:
        # session 查询失败要 fallback 到密码，避免 DB 抖动导致全员登出
        log.error(f"session 鉴权查询失败，将尝试密码 fallback: {e}")

    # 2. 过渡期 fallback：直接比对密码（M4: verify_password 内部处理明文/hash）
    # TODO(M1): M1 上线 30 天后移除此 fallback 分支，强制走 session 模式。
    #           移除前应在面板日志里统计 fallback 命中次数，若仍有流量则延长过渡期并告警。
    password = await get_panel_password()

    # 拒绝默认弱密码：未配置强密码时一律拒绝面板访问
    if _is_weak_password(password):
        log.error(
            "拒绝面板访问：检测到默认弱密码（pwd/空等）。"
            "请通过环境变量 PANEL_PASSWORD/PASSWORD 配置强密码后重启服务。"
        )
        raise HTTPException(
            status_code=503,
            detail="服务端未配置面板密码，拒绝访问。请联系管理员设置 PANEL_PASSWORD 环境变量。",
        )

    # M4: 调用 verify_password 支持 argon2 hash
    from src.auth import verify_password as _verify_panel_password
    if await _verify_panel_password(token):
        log.warning("检测到旧客户端密码直连 fallback 命中，请升级到 session 模式")
        return token  # 返回密码（兼容老客户端）

    raise HTTPException(status_code=401, detail="密码错误或 session 无效")
