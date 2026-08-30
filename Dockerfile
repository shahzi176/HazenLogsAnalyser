# ALPR Log Analyzer — container image
FROM python:3.11-slim-bookworm

WORKDIR /app

# The bundled NanoLog `decompressor` binary is a dynamically-linked ELF
# built against libstdc++/libgcc_s/libc/libm. libc/libm always ship with
# the base image; libstdc++6 does not on the slim variant, so install it
# explicitly rather than assume it's there.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY bin/ ./bin/
RUN chmod +x bin/decompressor

# Non-root runtime user; /app/data is where parsed analyses and the
# retained log text live — mount a volume there to persist across restarts
# and image upgrades.
RUN useradd -m -u 1000 alpr \
    && mkdir -p /app/data \
    && chown -R alpr:alpr /app
USER alpr

VOLUME ["/app/data"]
EXPOSE 5001
ENV PORT=5001

CMD ["python3", "app.py"]
