# INTENTIONALLY VULNERABLE (GT-IAC-006): end-of-life base image by mutable tag, remote script piped to a shell,
# remote ADD, and the service runs as root. Built only inside the local benchmark, never deployed.
FROM python:3.9

ADD https://example.com/install-tools.sh /tmp/install-tools.sh
RUN curl -fsSL https://example.com/bootstrap.sh | sh

WORKDIR /app
COPY . /app
RUN pip install -r requirements.txt

EXPOSE 8000
CMD ["python", "-m", "app"]
