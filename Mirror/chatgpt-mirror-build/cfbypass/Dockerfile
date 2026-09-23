FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

COPY cfbypass/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY cfbypass/app.py ./

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
