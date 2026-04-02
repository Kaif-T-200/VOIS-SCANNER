import os
import sys
import subprocess
import webbrowser
import threading
import time


def install_deps():
    print("Checking dependencies...")
    try:
        import fastapi
        import uvicorn
        import pydantic
        import aiohttp
    except ImportError:
        print("Installing dependencies...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("Dependencies installed.")


def run_server():
    backend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend")
    sys.path.insert(0, backend_dir)
    os.chdir(backend_dir)
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)


def main():
    install_deps()

    print("\n" + "=" * 50)
    print("  VOIS Port Scanner v2.0 — Ultimate Edition")
    print("=" * 50)
    print("\nStarting server...")

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    time.sleep(2)

    url = "http://localhost:8000"
    print(f"\nServer running at: {url}")
    print("Opening browser...\n")

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
