"""Start the Explainable Multi-Stage Log-Correlation workbench:  python run.py [--port 5000]"""
import argparse

from xmslc.server import create_app

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    a = ap.parse_args()
    print(f"\n  XMSLC workbench running at http://{a.host}:{a.port}  (offline, synthetic data only)\n")
    create_app().run(host=a.host, port=a.port, debug=False, threaded=True)
