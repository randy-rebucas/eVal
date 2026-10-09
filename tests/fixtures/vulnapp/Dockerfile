FROM python:latest
ENV DATABASE_PASSWORD=hunter2hunter2
COPY . /app
RUN curl -sSL https://example.com/install.sh | sh
CMD ["python", "/app/app.py"]
