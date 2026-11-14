FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 GAMC_DATA_DIR=/app/data GAMC_HOST=0.0.0.0
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd -u 10001 -m gamc
COPY app.py manage.py ./
COPY templates ./templates
COPY static ./static
RUN mkdir -p /app/data && chown -R gamc:gamc /app
USER gamc
EXPOSE 8000
CMD ["python", "app.py"]
