FROM python:3.12-slim

WORKDIR /app

# Copy all source needed for install
COPY pyproject.toml ./
COPY cloudguardiq/ cloudguardiq/
COPY function_app.py ./

# Install the package and its dependencies
RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["uvicorn", "cloudguardiq.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
