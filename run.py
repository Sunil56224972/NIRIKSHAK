"""Start the NIRIKSHAK server.

    python run.py                 # http://127.0.0.1:8000
    python run.py --host 0.0.0.0  # expose on the station LAN (put it behind HTTPS)
"""
import argparse

import uvicorn

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--reload", action="store_true")
    a = p.parse_args()
    uvicorn.run("app.main:app", host=a.host, port=a.port, reload=a.reload, proxy_headers=True)
