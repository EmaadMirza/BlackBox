FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system blackbox && useradd --system --gid blackbox blackbox
COPY pyproject.toml uv.lock ./
COPY libs ./libs
COPY services ./services
COPY tools ./tools
COPY agent ./agent
COPY baseline ./baseline
COPY bench ./bench
RUN pip install --no-cache-dir uv && uv sync --frozen --extra services --no-editable --no-dev
USER blackbox
EXPOSE 8000
CMD ["/app/.venv/bin/uvicorn", "services.approval.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
