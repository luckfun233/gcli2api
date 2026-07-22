"""
Main Web Integration - Integrates all routers and modules
集合router并开启主服务
"""

import asyncio
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from config import get_server_host, get_server_port
from log import log
from src.ratelimit import check_ip_rate_limit

# Import managers and utilities
from src.credential_manager import credential_manager

# Import all routers
from src.router.antigravity.openai import router as antigravity_openai_router
from src.router.antigravity.gemini import router as antigravity_gemini_router
from src.router.antigravity.anthropic import router as antigravity_anthropic_router
from src.router.antigravity.model_list import router as antigravity_model_list_router
from src.router.geminicli.openai import router as geminicli_openai_router
from src.router.geminicli.gemini import router as geminicli_gemini_router
from src.router.geminicli.anthropic import router as geminicli_anthropic_router
from src.router.geminicli.model_list import router as geminicli_model_list_router
from src.router.vertex.gemini import router as vertex_gemini_router
from src.router.vertex.openai import router as vertex_openai_router
from src.router.vertex.model_list import router as vertex_model_list_router
from src.task_manager import shutdown_all_tasks
from src.panel import router as panel_router
from src.keeplive import keepalive_service

# 全局凭证管理器
global_credential_manager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """应用生命周期管理"""
    global global_credential_manager

    log.info("启动 GCLI2API 主服务")

    # 初始化配置缓存（优先执行）
    try:
        import config
        await config.init_config()
        log.info("配置缓存初始化成功")
    except Exception as e:
        log.error(f"配置缓存初始化失败: {e}")

    # 安全加固：检测弱默认密码，拒绝启动（fail-fast）
    # 弱密码包括：空、pwd、password、admin、123456、12345678
    # 公网部署下这些密码会在 1 秒内被扫描器爆破
    try:
        from src.auth import _is_weak_password
        api_pwd = await config.get_api_password()
        panel_pwd = await config.get_panel_password()
        if _is_weak_password(api_pwd) or _is_weak_password(panel_pwd):
            log.error("=" * 60)
            log.error("启动失败：检测到弱密码或未配置密码")
            log.error("公网部署下弱密码会在 1 秒内被扫描器爆破成功。")
            log.error("请通过环境变量配置强密码后重启：")
            log.error("  export API_PASSWORD=<强随机字符串>")
            log.error("  export PANEL_PASSWORD=<强随机字符串>")
            log.error("  或使用通用密码：export PASSWORD=<强随机字符串>")
            log.error("弱密码黑名单：空、pwd、password、admin、123456、12345678")
            log.error("=" * 60)
            import sys
            sys.exit(1)
        else:
            log.info("密码强度检查通过")
    except SystemExit:
        raise
    except Exception as e:
        log.error(f"密码检测失败: {e}")
        log.error("出于安全考虑，拒绝启动。请确保已正确配置密码环境变量。")
        import sys
        sys.exit(1)

    # 初始化全局凭证管理器（通过单例工厂）
    try:
        # credential_manager 会在第一次调用时自动初始化
        # 这里预先触发初始化以便在启动时检测错误
        await credential_manager._get_or_create()
        log.info("凭证管理器初始化成功")
    except Exception as e:
        log.error(f"凭证管理器初始化失败: {e}")
        global_credential_manager = None

    # OAuth回调服务器将在需要时按需启动

    # 启动保活服务（未配置URL时自动跳过，零开销）
    try:
        await keepalive_service.start()
    except Exception as e:
        log.error(f"保活服务启动失败: {e}")

    yield

    # 清理资源
    log.info("开始关闭 GCLI2API 主服务")

    # 停止保活服务
    try:
        await keepalive_service.stop()
    except Exception as e:
        log.error(f"关闭保活服务时出错: {e}")

    # 首先关闭所有异步任务
    try:
        await shutdown_all_tasks(timeout=10.0)
        log.info("所有异步任务已关闭")
    except Exception as e:
        log.error(f"关闭异步任务时出错: {e}")

    # 然后关闭凭证管理器
    if global_credential_manager:
        try:
            await global_credential_manager.close()
            log.info("凭证管理器已关闭")
        except Exception as e:
            log.error(f"关闭凭证管理器时出错: {e}")

    log.info("GCLI2API 主服务已停止")


# 创建FastAPI应用
# 安全加固：关闭 OpenAPI 文档（/docs /redoc /openapi.json）防止暴露 API 结构
app = FastAPI(
    title="GCLI2API",
    description="Gemini API proxy with OpenAI compatibility",
    version="2.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# CORS中间件
# 安全加固：移除 allow_credentials=True。
# 规范禁止 allow_origins=["*"] 与 allow_credentials=True 同时使用，
# 此处作为 API 代理服务（客户端不固定），保留通配 origin 但不带 credentials，
# 浏览器会拒绝跨域携带 Cookie，避免 CSRF。
# 说明：本服务主要面向 CLI / 服务端调用（curl、SDK），不是浏览器 Web 应用，
# 因此通配源 + 无 credentials 是安全的。面板前端与 API 同源，不受 CORS 限制。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 安全加固：HTTPS 强制跳转（仅 FORCE_HTTPS=true 时启用）
# 适用于裸端口暴露公网的场景。HF Space / 反代终结 TLS 的场景无需开启。
_FORCE_HTTPS = os.getenv("FORCE_HTTPS", "").lower() in ("true", "1", "yes", "on")


@app.middleware("http")
async def ip_rate_limit_middleware(request: Request, call_next):
    """M6: IP 维度全局限流。防止扫描器/暴破针对单 IP 滥用带宽。

    跳过静态资源（/docs /front）和健康检查（/keepalive），
    这些路径无敏感逻辑且访问频率天然较高。
    """
    path = request.url.path
    if (
        path.startswith(("/docs", "/front"))
        or path in ("/keepalive", "/favicon.ico")
    ):
        return await call_next(request)
    try:
        check_ip_rate_limit(request)
    except Exception as e:
        # check_ip_rate_limit 抛 HTTPException；middleware 中需要手动转 JSON
        status_code = getattr(e, "status_code", 429)
        detail = getattr(e, "detail", "请求过于频繁")
        headers = getattr(e, "headers", None) or {}
        return JSONResponse(
            status_code=status_code,
            content={"detail": detail},
            headers=headers,
        )
    return await call_next(request)


@app.middleware("http")
async def force_https_middleware(request: Request, call_next):
    if _FORCE_HTTPS:
        # 优先检查 X-Forwarded-Proto（反代场景），其次检查直接连接的 scheme
        forwarded_proto = request.headers.get("x-forwarded-proto", "")
        if forwarded_proto:
            if forwarded_proto != "https":
                redirect_url = request.url.replace(scheme="https")
                return RedirectResponse(str(redirect_url), status_code=301)
        elif request.url.scheme == "http":
            redirect_url = request.url.replace(scheme="https")
            return RedirectResponse(str(redirect_url), status_code=301)
    return await call_next(request)


# 安全加固：统一注入安全响应头
# - X-Content-Type-Options: nosniff 防 MIME 嗅探
# - X-Frame-Options: DENY 防 clickjacking
# - Referrer-Policy: strict-origin-when-cross-origin 限制 Referer 泄露
# - CSP 仅对 HTML 页面注入，避免影响 API JSON 和静态资源
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "frame-ancestors 'none'"
        )
    return response

# 挂载路由器
# OpenAI兼容路由 - 处理OpenAI格式请求
app.include_router(geminicli_openai_router, prefix="", tags=["Geminicli OpenAI API"])

# Gemini原生路由 - 处理Gemini格式请求
app.include_router(geminicli_gemini_router, prefix="", tags=["Geminicli Gemini API"])

# Geminicli模型列表路由 - 处理Gemini格式的模型列表请求
app.include_router(geminicli_model_list_router, prefix="", tags=["Geminicli Model List"])

# Antigravity路由 - 处理OpenAI格式请求并转换为Antigravity API
app.include_router(antigravity_openai_router, prefix="", tags=["Antigravity OpenAI API"])

# Antigravity路由 - 处理Gemini格式请求并转换为Antigravity API
app.include_router(antigravity_gemini_router, prefix="", tags=["Antigravity Gemini API"])

# Antigravity模型列表路由 - 处理Gemini格式的模型列表请求
app.include_router(antigravity_model_list_router, prefix="", tags=["Antigravity Model List"])

# Antigravity Anthropic Messages 路由 - Anthropic Messages 格式兼容
app.include_router(antigravity_anthropic_router, prefix="", tags=["Antigravity Anthropic Messages"])

# Geminicli Anthropic Messages 路由 - Anthropic Messages 格式兼容 (Geminicli)
app.include_router(geminicli_anthropic_router, prefix="", tags=["Geminicli Anthropic Messages"])

# Panel路由 - 包含认证、凭证管理和控制面板功能
app.include_router(panel_router, prefix="", tags=["Panel Interface"])

# Vertex AI 路由 - Gemini 原生格式
app.include_router(vertex_gemini_router, prefix="", tags=["Vertex Gemini API"])

# Vertex AI 路由 - OpenAI 兼容格式
app.include_router(vertex_openai_router, prefix="", tags=["Vertex OpenAI API"])

# Vertex AI 路由 - 模型列表
app.include_router(vertex_model_list_router, prefix="", tags=["Vertex Model List"])

# 静态文件路由 - 服务docs目录下的文件
app.mount("/docs", StaticFiles(directory="docs"), name="docs")

# 静态文件路由 - 服务front目录下的文件（HTML、JS、CSS等）
app.mount("/front", StaticFiles(directory="front"), name="front")


# 保活接口（仅响应 HEAD）
@app.head("/keepalive")
async def keepalive() -> Response:
    return Response(status_code=200)

def main():
    """主启动函数"""
    from hypercorn.asyncio import serve
    from hypercorn.config import Config
    from hypercorn.run import run

    workers = int(os.environ.get("WORKERS", 1))

    async def _run():
        port = await get_server_port()
        host = await get_server_host()

        log.info("=" * 60)
        log.info("启动 GCLI2API")
        log.info("=" * 60)
        log.info(f"控制面板: http://127.0.0.1:{port}")
        if workers > 1:
            log.info(f"Worker 数量: {workers}")
        if _FORCE_HTTPS:
            log.info("FORCE_HTTPS 已启用，HTTP 请求将 301 跳转到 HTTPS")
        log.info("=" * 60)

        # M8: 裸端口暴露公网且未配置 HTTPS 时告警
        if host == "0.0.0.0" and not _FORCE_HTTPS:
            log.warning("=" * 60)
            log.warning("安全告警：服务监听 0.0.0.0 且未启用 FORCE_HTTPS")
            log.warning("若直接暴露公网，token 将以明文传输。建议：")
            log.warning("  1. 在反向代理（Nginx/Caddy）后部署，由反代终结 TLS")
            log.warning("  2. 或设置 FORCE_HTTPS=true 强制 HTTPS 跳转")
            log.warning("=" * 60)

        config = Config()
        config.bind = [f"{host}:{port}"]
        config.accesslog = "-"
        config.errorlog = "-"
        config.loglevel = "INFO"
        # L2: 请求体大小上限 10MB（可通过 MAX_REQUEST_BODY_SIZE 环境变量调整），防止超大 body OOM
        config.max_request_size = int(os.environ.get("MAX_REQUEST_BODY_SIZE", 10 * 1024 * 1024))

        await serve(app, config)

    if workers == 1:
        asyncio.run(_run())
    else:
        # 多 worker 模式下 hypercorn run 自行管理进程，先同步获取配置
        port = int(os.environ.get("PORT", 7861))
        host = os.environ.get("HOST", "0.0.0.0")

        log.info("=" * 60)
        log.info("启动 GCLI2API")
        log.info("=" * 60)
        log.info(f"控制面板: http://127.0.0.1:{port}")
        log.info(f"Worker 数量: {workers}")
        if _FORCE_HTTPS:
            log.info("FORCE_HTTPS 已启用，HTTP 请求将 301 跳转到 HTTPS")
        log.info("=" * 60)

        # M8: 裸端口暴露公网且未配置 HTTPS 时告警
        if host == "0.0.0.0" and not _FORCE_HTTPS:
            log.warning("=" * 60)
            log.warning("安全告警：服务监听 0.0.0.0 且未启用 FORCE_HTTPS")
            log.warning("若直接暴露公网，token 将以明文传输。建议：")
            log.warning("  1. 在反向代理（Nginx/Caddy）后部署，由反代终结 TLS")
            log.warning("  2. 或设置 FORCE_HTTPS=true 强制 HTTPS 跳转")
            log.warning("=" * 60)

        config = Config()
        config.bind = [f"{host}:{port}"]
        config.accesslog = "-"
        config.errorlog = "-"
        config.loglevel = "INFO"
        # L2: 请求体大小上限 10MB
        config.max_request_size = int(os.environ.get("MAX_REQUEST_BODY_SIZE", 10 * 1024 * 1024))
        config.workers = workers
        config.application_path = "web:app"

        run(config)


if __name__ == "__main__":
    main()
