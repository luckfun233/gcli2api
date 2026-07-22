"""
配置路由模块 - 处理 /config/* 相关的HTTP请求
"""

import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

import config
from log import log
from src.keeplive import keepalive_service
from src.models import ConfigSaveRequest
from src.storage_adapter import get_storage_adapter
from src.utils import verify_panel_token
from .utils import get_env_locked_keys


# 创建路由器
router = APIRouter(prefix="/config", tags=["config"])

# 密码占位符：前端展示用，保存时若值为此占位符或为空则跳过更新
_PASSWORD_PLACEHOLDER = "********"
_DEFAULT_WEAK_PASSWORD = "pwd"

# 安全加固：与 src/auth.py、src/utils.py 保持一致的弱密码黑名单。
# 通过 /config/save 设置这些值时一律拒绝，避免运维误操作把服务变成裸奔状态。
_WEAK_DEFAULT_PASSWORDS = {"pwd", "", "password", "admin", "123456", "12345678"}


def _is_weak_password(password: Optional[str]) -> bool:
    """判断密码是否为不安全的弱默认值（必须拒绝）。"""
    if not password:
        return True
    return password in _WEAK_DEFAULT_PASSWORDS


def _mask_password(value: str) -> str:
    """密码脱敏：未配置（默认 pwd）返回空串，已配置返回固定占位符。"""
    if not value or value == _DEFAULT_WEAK_PASSWORD:
        return ""
    return _PASSWORD_PLACEHOLDER


def _is_placeholder(value: str) -> bool:
    """判断值是否为占位符或空，保存时应跳过。"""
    return (not value) or value == _PASSWORD_PLACEHOLDER


@router.get("/get")
async def get_config(token: str = Depends(verify_panel_token)):
    """获取当前配置"""
    try:


        # 读取当前配置（包括环境变量和TOML文件中的配置）
        current_config = {}

        # 基础配置
        current_config["code_assist_endpoint"] = await config.get_code_assist_endpoint()
        current_config["credentials_dir"] = await config.get_credentials_dir()
        current_config["proxy"] = await config.get_proxy_config() or ""

        # 代理端点配置
        current_config["oauth_proxy_url"] = await config.get_oauth_proxy_url()
        current_config["googleapis_proxy_url"] = await config.get_googleapis_proxy_url()
        current_config["resource_manager_api_url"] = await config.get_resource_manager_api_url()
        current_config["service_usage_api_url"] = await config.get_service_usage_api_url()
        current_config["antigravity_api_url"] = await config.get_antigravity_api_url()

        # 自动封禁配置
        current_config["auto_ban_enabled"] = await config.get_auto_ban_enabled()
        current_config["auto_ban_error_codes"] = await config.get_auto_ban_error_codes()

        # 429重试配置
        current_config["retry_429_max_retries"] = await config.get_retry_429_max_retries()
        current_config["retry_429_enabled"] = await config.get_retry_429_enabled()
        current_config["retry_429_interval"] = await config.get_retry_429_interval()
        # 抗截断配置
        current_config["anti_truncation_max_attempts"] = await config.get_anti_truncation_max_attempts()

        # 兼容性配置
        current_config["compatibility_mode_enabled"] = await config.get_compatibility_mode_enabled()

        # 思维链返回配置
        current_config["return_thoughts_to_frontend"] = await config.get_return_thoughts_to_frontend()

        # Antigravity流式转非流式配置
        current_config["antigravity_stream2nostream"] = await config.get_antigravity_stream2nostream()
        current_config["antigravity_switch_credential_enabled"] = await config.get_antigravity_switch_credential_enabled()

        # 保活配置
        current_config["keepalive_url"] = await config.get_keepalive_url()
        current_config["keepalive_interval"] = await config.get_keepalive_interval()

        # 服务器配置
        # 安全加固：密码字段不返回明文，只返回是否已配置（非默认值），
        # 前端展示占位符。保存时若值为占位符则不更新。
        current_config["host"] = await config.get_server_host()
        current_config["port"] = await config.get_server_port()
        current_config["api_password"] = _mask_password(await config.get_api_password())
        current_config["panel_password"] = _mask_password(await config.get_panel_password())
        current_config["password"] = _mask_password(await config.get_server_password())
        current_config["api_password_configured"] = bool(os.getenv("API_PASSWORD") or os.getenv("PASSWORD"))
        current_config["panel_password_configured"] = bool(os.getenv("PANEL_PASSWORD") or os.getenv("PASSWORD"))

        # 从存储系统读取配置
        storage_adapter = await get_storage_adapter()
        storage_config = await storage_adapter.get_all_config()

        # 获取环境变量锁定的配置键
        env_locked_keys = get_env_locked_keys()

        # 合并存储系统配置（不覆盖环境变量）
        for key, value in storage_config.items():
            if key not in env_locked_keys:
                current_config[key] = value

        return JSONResponse(content={"config": current_config, "env_locked": list(env_locked_keys)})

    except Exception as e:
        log.error(f"获取配置失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")


@router.post("/save")
async def save_config(request: ConfigSaveRequest, token: str = Depends(verify_panel_token)):
    """保存配置"""
    try:

        new_config = request.config

        log.debug(f"收到的配置数据: {list(new_config.keys())}")
        log.debug(f"收到的password值: {new_config.get('password', 'NOT_FOUND')}")

        # 验证配置项
        if "retry_429_max_retries" in new_config:
            if (
                not isinstance(new_config["retry_429_max_retries"], int)
                or new_config["retry_429_max_retries"] < 0
            ):
                raise HTTPException(status_code=400, detail="最大429重试次数必须是大于等于0的整数")

        if "retry_429_enabled" in new_config:
            if not isinstance(new_config["retry_429_enabled"], bool):
                raise HTTPException(status_code=400, detail="429重试开关必须是布尔值")

        # 验证新的配置项
        if "retry_429_interval" in new_config:
            try:
                interval = float(new_config["retry_429_interval"])
                if interval < 0.01 or interval > 10:
                    raise HTTPException(status_code=400, detail="429重试间隔必须在0.01-10秒之间")
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="429重试间隔必须是有效的数字")

        if "anti_truncation_max_attempts" in new_config:
            if (
                not isinstance(new_config["anti_truncation_max_attempts"], int)
                or new_config["anti_truncation_max_attempts"] < 1
                or new_config["anti_truncation_max_attempts"] > 10
            ):
                raise HTTPException(
                    status_code=400, detail="抗截断最大重试次数必须是1-10之间的整数"
                )

        if "compatibility_mode_enabled" in new_config:
            if not isinstance(new_config["compatibility_mode_enabled"], bool):
                raise HTTPException(status_code=400, detail="兼容性模式开关必须是布尔值")

        if "return_thoughts_to_frontend" in new_config:
            if not isinstance(new_config["return_thoughts_to_frontend"], bool):
                raise HTTPException(status_code=400, detail="思维链返回开关必须是布尔值")

        if "antigravity_stream2nostream" in new_config:
            if not isinstance(new_config["antigravity_stream2nostream"], bool):
                raise HTTPException(status_code=400, detail="Antigravity流式转非流式开关必须是布尔值")

        if "antigravity_switch_credential_enabled" in new_config:
            if not isinstance(new_config["antigravity_switch_credential_enabled"], bool):
                raise HTTPException(status_code=400, detail="Antigravity切换凭证开关必须是布尔值")

        # 验证保活配置
        if "keepalive_url" in new_config:
            if not isinstance(new_config["keepalive_url"], str):
                raise HTTPException(status_code=400, detail="保活URL必须是字符串")

        if "keepalive_interval" in new_config:
            try:
                interval = int(new_config["keepalive_interval"])
                if interval < 5 or interval > 86400:
                    raise HTTPException(status_code=400, detail="保活间隔必须在 5-86400 秒之间")
                new_config["keepalive_interval"] = interval
            except (ValueError, TypeError):
                raise HTTPException(status_code=400, detail="保活间隔必须是有效整数")
        # 验证服务器配置
        if "host" in new_config:
            if not isinstance(new_config["host"], str) or not new_config["host"].strip():
                raise HTTPException(status_code=400, detail="服务器主机地址不能为空")

        if "port" in new_config:
            if (
                not isinstance(new_config["port"], int)
                or new_config["port"] < 1
                or new_config["port"] > 65535
            ):
                raise HTTPException(status_code=400, detail="端口号必须是1-65535之间的整数")

        if "api_password" in new_config:
            if not isinstance(new_config["api_password"], str):
                raise HTTPException(status_code=400, detail="API访问密码必须是字符串")
            # 安全加固：拒绝设置弱默认密码，否则公网部署会被秒破
            if not _is_placeholder(new_config["api_password"]) and _is_weak_password(new_config["api_password"]):
                raise HTTPException(
                    status_code=400,
                    detail="API访问密码过于简单（禁止空/pwd/password/admin/123456/12345678），请使用更强的密码"
                )

        if "panel_password" in new_config:
            if not isinstance(new_config["panel_password"], str):
                raise HTTPException(status_code=400, detail="控制面板密码必须是字符串")
            # 安全加固：拒绝设置弱默认密码
            if not _is_placeholder(new_config["panel_password"]) and _is_weak_password(new_config["panel_password"]):
                raise HTTPException(
                    status_code=400,
                    detail="控制面板密码过于简单（禁止空/pwd/password/admin/123456/12345678），请使用更强的密码"
                )

        if "password" in new_config:
            if not isinstance(new_config["password"], str):
                raise HTTPException(status_code=400, detail="访问密码必须是字符串")
            # 安全加固：拒绝设置弱默认密码
            if not _is_placeholder(new_config["password"]) and _is_weak_password(new_config["password"]):
                raise HTTPException(
                    status_code=400,
                    detail="访问密码过于简单（禁止空/pwd/password/admin/123456/12345678），请使用更强的密码"
                )

        # 获取环境变量锁定的配置键
        env_locked_keys = get_env_locked_keys()

        # 直接使用存储适配器保存配置
        # 安全加固：密码字段若是占位符或空则跳过，避免把脱敏值写回存储
        storage_adapter = await get_storage_adapter()
        for key, value in new_config.items():
            if key not in env_locked_keys:
                if key in ("password", "api_password", "panel_password") and _is_placeholder(str(value)):
                    continue
                await storage_adapter.set_config(key, value)
                if key in ("password", "api_password", "panel_password"):
                    log.debug(f"设置{key}字段为: ***")

        # 重新加载配置缓存（关键！）
        await config.reload_config()

        # 如果保活相关配置发生变化，立即重启保活服务
        keepalive_keys = {"keepalive_url", "keepalive_interval"}
        if keepalive_keys & set(new_config.keys()):
            try:
                await keepalive_service.restart()
            except Exception as e:
                log.warning(f"重启保活服务失败: {e}")

        # 验证保存后的结果
        test_api_password = await config.get_api_password()
        test_panel_password = await config.get_panel_password()
        test_password = await config.get_server_password()
        log.debug(f"保存后立即读取的API密码: {_mask_password(test_api_password)}")
        log.debug(f"保存后立即读取的面板密码: {_mask_password(test_panel_password)}")
        log.debug(f"保存后立即读取的通用密码: {_mask_password(test_password)}")

        # 构建响应消息
        response_data = {
            "message": "配置保存成功",
            "saved_config": {k: v for k, v in new_config.items() if k not in env_locked_keys},
        }

        return JSONResponse(content=response_data)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"保存配置失败: {e}")
        raise HTTPException(status_code=500, detail="内部服务器错误，请查看服务端日志")
