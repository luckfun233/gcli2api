echo "同步项目代码..."
git fetch --all

# 安全更新：若本地有未提交修改，先 stash 再恢复，避免静默丢失紧急补丁
LOCAL_CHANGES=$(git status --porcelain)
if [ -n "$LOCAL_CHANGES" ]; then
    echo "检测到本地未提交的修改，已暂存（git stash）"
    git stash
fi

git reset --hard origin/$(git rev-parse --abbrev-ref HEAD)

if [ -n "$LOCAL_CHANGES" ]; then
    echo "尝试恢复本地修改..."
    git stash pop || echo "警告：本地修改恢复失败，可通过 git stash list 查看"
fi

uv sync
source .venv/bin/activate
python web.py