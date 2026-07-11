# AuditAgentX 后端镜像（含常用静态扫描工具）
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

# 系统依赖：git（clone 仓库）
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl \
    && rm -rf /var/lib/apt/lists/*

# 静态扫描工具（可按需精简）
RUN pip install --no-cache-dir semgrep bandit

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY rules ./rules

EXPOSE 8000
# 使用同一套 APP_HOST/APP_PORT 配置；此前 Settings 会读取 .env，但容器命令仍写死
# 0.0.0.0:8000，造成“配置看似生效、实际被忽略”。
CMD ["sh", "-c", "exec uvicorn backend.main:app --host \"${APP_HOST:-0.0.0.0}\" --port \"${APP_PORT:-8000}\""]
