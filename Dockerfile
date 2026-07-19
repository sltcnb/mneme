FROM python:3.14-slim

LABEL org.opencontainers.image.title="mneme" \
      org.opencontainers.image.description="Memory forensics toolkit built on Volatility3"

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir ".[vol,web]"

# Non-root for least privilege.
RUN useradd -m ir && mkdir -p /data && chown -R ir /app /data
USER ir

ENV MNEME_DATA=/data
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["mneme"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8080"]
