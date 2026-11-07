FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

FROM base AS test
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements-test.txt
COPY auth_service ./auth_service
COPY tests ./tests
COPY pytest.ini .
CMD ["python", "-m", "pytest", "-q"]

FROM base AS runtime
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt && useradd --create-home app
COPY auth_service ./auth_service
COPY main.py .
USER app
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--loop", "uvloop", "--lifespan", "on"]
