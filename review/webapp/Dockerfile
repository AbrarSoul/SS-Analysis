FROM python:3.12-slim
WORKDIR /app
COPY server.py ./
COPY static ./static
COPY data ./data
ENV PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "server.py"]
