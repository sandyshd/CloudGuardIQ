FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml ./
RUN pip install --no-cache-dir .

# Copy application code
COPY cloudguardiq/ cloudguardiq/
COPY function_app.py ./

EXPOSE 8000

CMD ["uvicorn", "cloudguardiq.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
