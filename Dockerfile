FROM python:3.8.10-slim

COPY . /app

WORKDIR /app

RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir safety pip-audit

EXPOSE 8082

CMD [ "python", "-m" , "flask", "run", "--host=0.0.0.0", "--port=8082"]
