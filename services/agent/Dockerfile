FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all Python source including the crypto/ sub-package
COPY . .

CMD ["python", "-u", "main.py"]
