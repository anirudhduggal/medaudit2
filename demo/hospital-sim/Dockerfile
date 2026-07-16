# St. Elsewhere Hospital -- deliberately vulnerable HL7 demo target.
# For authorized security-testing demonstrations only. Synthetic data only.
FROM python:3.12-slim

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# HL7/MLLP feed + clinical web viewer
EXPOSE 2575 8080

ENV HOSPITAL_MLLP_HOST=0.0.0.0 \
    HOSPITAL_MLLP_PORT=2575 \
    HOSPITAL_WEB_HOST=0.0.0.0 \
    HOSPITAL_WEB_PORT=8080 \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "app.main"]
