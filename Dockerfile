# syntax=docker/dockerfile:1
FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8000
COPY . .
CMD ["python", "./noip-rfc2136.py"]
