FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080
CMD ["python", "server.py"]
