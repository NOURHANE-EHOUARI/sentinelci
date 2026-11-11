"""`python -m app`: serve shop-api on port 8080 (all interfaces of its container; publish it on 127.0.0.1 only)."""

import uvicorn

from app.main import app

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
