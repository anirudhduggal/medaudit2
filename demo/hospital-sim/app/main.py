"""
Entrypoint: initialise + seed the DB, start the vulnerable MLLP listener in a
background thread, and serve the clinical viewer.
"""

import logging
import os
import threading

from . import db
from .seed_data import seed_if_empty
from .mllp_server import VulnerableMLLPServer
from .viewer import app as flask_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("hospital")

MLLP_HOST = os.environ.get("HOSPITAL_MLLP_HOST", "0.0.0.0")
MLLP_PORT = int(os.environ.get("HOSPITAL_MLLP_PORT", "2575"))
WEB_HOST = os.environ.get("HOSPITAL_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("HOSPITAL_WEB_PORT", "8080"))


def main() -> None:
    db.init_db()
    seed_if_empty()

    mllp = VulnerableMLLPServer(host=MLLP_HOST, port=MLLP_PORT)
    threading.Thread(target=mllp.start, daemon=True).start()

    banner = (
        "\n" + "=" * 64 + "\n"
        "  St. Elsewhere Hospital -- DEMO HL7 target (INTENTIONALLY VULNERABLE)\n"
        f"  HL7/MLLP feed : {MLLP_HOST}:{MLLP_PORT}  (plaintext, no TLS)\n"
        f"  Clinical view : http://{WEB_HOST}:{WEB_PORT}/\n"
        "  Synthetic data only. Authorized security testing only.\n"
        + "=" * 64 + "\n"
    )
    logger.info(banner)

    # Flask dev server is fine for a local demo target.
    flask_app.run(host=WEB_HOST, port=WEB_PORT, threaded=True)


if __name__ == "__main__":
    main()
