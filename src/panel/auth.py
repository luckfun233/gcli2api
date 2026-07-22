"""
认证路由模块 - 处理 /auth/* 相关的HTTP请求
"""

import hashlib
import secrets
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from log import log
from src.auth import (
    asyncio_complete_auth_flow,
    complete_auth_flow_from_callback_url,
    create_auth_url,
    get_auth_status,
    verify_password,
)
from src.models import (
    LoginRequest,
    AuthStartRequest,
    AuthCallbackRequest,
    AuthCallbackUrlRequest,
)
from src.storage_adapter import get_storage_adapter
from src.utils import verify_panel_token


# 创建路由器
router = APIRouter(prefix="/auth", tags=["auth"])

# 简易登录暴力破解防护：每 IP 在窗口内最多失败 N 次，超过则冷却
_LOGIN_WINDOW_SEC = 300  # 5 分钟窗口
_LOGIN_MAX_FAILURES = 10  # 窗口内最多失败次数
_LOGIN_COOLDOWN_SEC = 600  # 触发后冷却 10 分钟
_login_failures: dict[str, list[float]] = defaultdict(list)
_login_blocked_until: dict[str, float] = {}


# =============================================================================
# M2: WebSocket 一次性票据（ws-ticket）机制
# =============================================================================
# 背景：原本 WebSocket 通过 URL query ?token=xxx 传递面板密码，会被
#   - 浏览器历史记录、Nginx access log、Referer 头、CDN 日志等记录
#   - 一旦泄露等同于密码泄露
# 方案：客户端先用 Bearer token 调用 /auth/ws-ticket 换取 30s 一次性 ticket，
#   再用 ?ticket=xxx 建立 WebSocket。ticket 单次使用、短 TTL，泄露后无法重放。
# 存储：内存 dict（单 worker 场景足够；多 worker 部署见 M1 session 改造方案）。
_WS_TICKET_TTL_SEC = 30  # 票据有效期 30 秒
_ws_tickets: dict[str, dict] = {}  # ticket -> {"expires_at": float, "used": bool}


def _cleanup_expired_ws_tickets() -> None:
    """惰性清理过期/已使用的 ticket，避免内存无限增长。"""
    now = time.time()
    expired = [
        t for t, info in _ws_tickets.items()
        if info["expires_at"] <= now or info["used"]
    ]
    for t in expired:
        _ws_tickets.pop(t, None)


def consume_ws_ticket(ticket: str) -> bool:
    """校验并一次性消费 ws-ticket。成功返回 True，失败返回 False。"""
    if not ticket:
        return False
    _cleanup_expired_ws_tickets()
    info = _ws_tickets.get(ticket)
    if not info:
        return False
    if info["used"]:
        # 已使用的 ticket 直接清除（防重放）
        _ws_tickets.pop(ticket, None)
        return False
    if info["expires_at"] <= time.time():
        _ws_tickets.pop(ticket, None)
        return False
    # 标记为已使用（一次性消费）
    info["used"] = True
    _ws_tickets.pop(ticket, None)  # 立即移除，杜绝重放
    return True


def _login_check_blocked(client_ip: str) -> bool:
    """检查 IP 是否在冷却期内。返回 True 表示被阻止。"""
    blocked_until = _login_blocked_until.get(client_ip, 0)
    if blocked_until and time.time() < blocked_until:
        return True
    # 冷却期已过，清理
    if blocked_until:
        _login_blocked_until.pop(client_ip, None)
        _login_failures.pop(client_ip, None)
    return False


def _login_record_failure(client_ip: str) -> None:
    """记录一次登录失败，超过阈值则进入冷却。"""
    now = time.time()
    failures = _login_failures[client_ip]
    # 清理过期记录
    _login_failures[client_ip] = [t for t in failures if now - t < _LOGIN_WINDOW_SEC]
    _login_failures[client_ip].append(now)
    if len(_login_failures[client_ip]) >= _LOGIN_MAX_FAILURES:
        _login_blocked_until[client_ip] = now + _LOGIN_COOLDOWN_SEC
        log.warning(f"登录暴力破解防护触发: ip={client_ip} 冷却 {_LOGIN_COOLDOWN_SEC}s")


def _login_clear_failures(client_ip: str) -> None:
    """登录成功后清理失败记录。"""
    _login_failures.pop(client_ip, None)
    _login_blocked_until.pop(client_ip, None)


# M1: Session 配置
_SESSION_TTL_SEC = 7 * 86400  # 7 天绝对过期


def _hash_password(password: str) -> str:
    """计算密码的 SHA-256 hash（用于 session 的 password_hash 字段）。

    注意：这是 session 内部用于"密码改后失效判断"的 hash，与 M4 的 argon2 hash
    不是一回事 —— M1 不依赖 M4，session 创建时密码还在内存中。
    """
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


@router.post("/login")
async def login(request: LoginRequest, http_request: Request):
    """用户登录

    M1 改造：登录成功后返回独立的服务端 session token（而非明文密码），
    原密码不再直接作为 token 使用。

    安全加固：每 IP 5 分钟内最多失败 10 次，超过则冷却 10 分钟。
    """
    try:
        client_ip = http_request.client.host if http_request.client else "unknown"
        if _login_check_blocked(client_ip):
            log.warning(f"登录被限流: ip={client_ip}")
            raise HTTPException(status_code=429, detail="登录尝试过于频繁，请稍后再试")

        if await verify_password(request.password):
            _login_clear_failures(client_ip)
            # M1: 创建 session，token 字段装的是 session_id（兼容前端字段名）
            session_id = secrets.token_urlsafe(32)
            password_hash = _hash_password(request.password)
            now = time.time()
            expires_at = now + _SESSION_TTL_SEC
            try:
                adapter = await get_storage_adapter()
                await adapter.create_session(
                    session_id=session_id,
                    password_hash=password_hash,
                    expires_at=expires_at,
                    client_ip=client_ip,
                    user_agent=http_request.headers.get("user-agent", ""),
                )
            except Exception as e:
                log.error(f"创建 session 失败，回退到密码直连: {e}")
                # DB 不可用时回退到旧逻辑（保证可用性），但记日志告警
                return JSONResponse(
                    content={"token": request.password, "message": "登录成功"}
                )
            return JSONResponse(
                content={
                    "token": session_id,  # 兼容前端字段名
                    "session_id": session_id,
                    "expires_at": expires_at,
                    "message": "登录成功",
                }
            )
        else:
            _login_record_failure(client_ip)
            raise HTTPException(status_code=401, detail="密码错误")
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"登录失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.post("/logout")
async def logout(token: str = Depends(verify_panel_token)):
    """登出当前 session（M1）

    verify_panel_token 返回的 token 可能是 session_id（M1 模式）或明文密码
    （fallback 模式）。仅当为 session 模式时调用 delete_session。
    """
    try:
        adapter = await get_storage_adapter()
        session = await adapter.get_session(token)
        if session:
            await adapter.delete_session(token)
            return JSONResponse(content={"message": "已登出"})
        # fallback 模式（token 是明文密码）：客户端清 localStorage 即可
        return JSONResponse(content={"message": "已登出"})
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"登出失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.get("/sessions")
async def list_sessions(token: str = Depends(verify_panel_token)):
    """列出当前密码下的所有活跃 session（M1，可选 UI 管理用）

    不返回 session_id 本身（避免泄露后可劫持）。
    """
    try:
        adapter = await get_storage_adapter()
        # 通过当前 session 反查 password_hash
        current_session = await adapter.get_session(token)
        if not current_session:
            # fallback 模式（明文密码直连），无 session 列表
            return JSONResponse(content={"sessions": []})
        password_hash = current_session.get("password_hash", "")
        if not password_hash:
            return JSONResponse(content={"sessions": []})
        sessions = await adapter.list_sessions_by_password_hash(password_hash)
        return JSONResponse(content={"sessions": sessions})
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"列出 session 失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.post("/ws-ticket")
async def issue_ws_ticket(token: str = Depends(verify_panel_token)):
    """签发一次性短时 WebSocket 票据（M2）

    客户端用 Bearer token 调用本端点换取 30 秒内有效的 ws-ticket，
    再用 `?ticket=xxx` 建立 WebSocket 连接。ticket 单次使用、不可重放，
    避免将长期凭证（面板密码）放入 URL query 而被日志/历史记录泄露。

    依赖 verify_panel_token 自动校验 Authorization: Bearer <password>。
    """
    try:
        _cleanup_expired_ws_tickets()
        ticket = secrets.token_urlsafe(32)
        _ws_tickets[ticket] = {
            "expires_at": time.time() + _WS_TICKET_TTL_SEC,
            "used": False,
        }
        return JSONResponse(
            content={"ticket": ticket, "expires_in": _WS_TICKET_TTL_SEC}
        )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"签发 ws-ticket 失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.post("/start")
async def start_auth(request: AuthStartRequest, token: str = Depends(verify_panel_token)):
    """开始认证流程，支持自动检测项目ID"""
    try:
        # 如果没有提供项目ID，尝试自动检测
        project_id = request.project_id
        if not project_id:
            log.info("用户未提供项目ID，后续将使用自动检测...")

        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        result = await create_auth_url(
            project_id, user_session, mode=request.mode
        )

        if result["success"]:
            return JSONResponse(
                content={
                    "auth_url": result["auth_url"],
                    "state": result["state"],
                    "auto_project_detection": result.get("auto_project_detection", False),
                    "detected_project_id": result.get("detected_project_id"),
                }
            )
        else:
            raise HTTPException(status_code=500, detail=result["error"])

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"开始认证流程失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.post("/callback")
async def auth_callback(request: AuthCallbackRequest, token: str = Depends(verify_panel_token)):
    """处理认证回调，支持自动检测项目ID"""
    try:
        # 项目ID现在是可选的，在回调处理中进行自动检测
        project_id = request.project_id

        # 使用认证令牌作为用户会话标识
        user_session = token if token else None
        # 异步等待OAuth回调完成
        result = await asyncio_complete_auth_flow(
            project_id, user_session, mode=request.mode
        )

        if result["success"]:
            # 单项目认证成功
            return JSONResponse(
                content={
                    "credentials": result["credentials"],
                    "file_path": result["file_path"],
                    "message": "认证成功，凭证已保存",
                    "auto_detected_project": result.get("auto_detected_project", False),
                }
            )
        else:
            # 如果需要手动项目ID或项目选择，在响应中标明
            if result.get("requires_manual_project_id"):
                # 使用JSON响应
                return JSONResponse(
                    status_code=400,
                    content={"error": result["error"], "requires_manual_project_id": True},
                )
            elif result.get("requires_project_selection"):
                # 返回项目列表供用户选择
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": result["error"],
                        "requires_project_selection": True,
                        "available_projects": result["available_projects"],
                    },
                )
            else:
                raise HTTPException(status_code=400, detail=result["error"])

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"处理认证回调失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.post("/callback-url")
async def auth_callback_url(request: AuthCallbackUrlRequest, token: str = Depends(verify_panel_token)):
    """从回调URL直接完成认证"""
    try:
        # 验证URL格式
        if not request.callback_url or not request.callback_url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="请提供有效的回调URL")

        # 从回调URL完成认证
        result = await complete_auth_flow_from_callback_url(
            request.callback_url, request.project_id, mode=request.mode
        )

        if result["success"]:
            # 单项目认证成功
            return JSONResponse(
                content={
                    "credentials": result["credentials"],
                    "file_path": result["file_path"],
                    "message": "从回调URL认证成功，凭证已保存",
                    "auto_detected_project": result.get("auto_detected_project", False),
                }
            )
        else:
            # 处理各种错误情况
            if result.get("requires_manual_project_id"):
                return JSONResponse(
                    status_code=400,
                    content={"error": result["error"], "requires_manual_project_id": True},
                )
            elif result.get("requires_project_selection"):
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": result["error"],
                        "requires_project_selection": True,
                        "available_projects": result["available_projects"],
                    },
                )
            else:
                raise HTTPException(status_code=400, detail=result["error"])

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"从回调URL处理认证失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.get("/status/{project_id}")
async def check_auth_status(project_id: str, token: str = Depends(verify_panel_token)):
    """检查认证状态"""
    try:
        if not project_id:
            raise HTTPException(status_code=400, detail="Project ID 不能为空")

        status = get_auth_status(project_id)
        return JSONResponse(content=status)

    except Exception as e:
        log.error(f"检查认证状态失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")
