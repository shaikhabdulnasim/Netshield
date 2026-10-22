FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd -r -u 10001 netshield
COPY app ./app
COPY data ./data
RUN chown -R netshield:netshield /app/data
USER netshield
EXPOSE 53/udp 53/tcp 8080/tcp
CMD ["python", "-m", "app.main"]
