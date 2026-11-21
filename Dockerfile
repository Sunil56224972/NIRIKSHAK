FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt pytesseract

COPY app ./app
COPY tools ./tools
COPY samples ./samples
COPY supabase ./supabase
COPY run.py ./

RUN useradd -r -m nirikshak && mkdir -p /app/data/evidence && chown -R nirikshak:nirikshak /app
USER nirikshak

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4)"

CMD ["python", "run.py", "--host", "0.0.0.0", "--port", "8000"]
