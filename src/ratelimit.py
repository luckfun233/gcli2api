"""Token 维度限流（M6 预留 stub）。

当前为 no-op 占位实现，保证 src.utils.check_token_rate_limit 可正常导入。
真正的 token 维度限流逻辑在 M6 阶段实现。
"""


def check_token_rate_limit(token: str) -> None:
    """检查 token 维度限流。当前为 no-op（M6 未实施）。

    Args:
        token: 已通过认证的 token（session_id 或密码）

    Raises:
        目前不抛异常。M6 实施后超限将抛 HTTPException(429)。
    """
    return None
