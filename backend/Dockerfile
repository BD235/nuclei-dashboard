FROM python:3.12-slim

WORKDIR /app

# Dependensi sistem untuk Nuclei
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    ca-certificates \
    git \
    && rm -rf /var/lib/apt/lists/*

# Unduh dan pasang Nuclei v3.3.7
RUN curl -sSL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

# Symlink path runner agar kompatibel
RUN mkdir -p /home/bdicky/go/bin && ln -sf /usr/local/bin/nuclei /home/bdicky/go/bin/nuclei

# Unduh template resmi Nuclei
RUN nuclei -update-templates -silent || true

# Pasang pustaka Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Salin kode program backend
COPY . .

EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
