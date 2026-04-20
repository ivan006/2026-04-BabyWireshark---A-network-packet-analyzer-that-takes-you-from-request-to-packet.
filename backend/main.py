import os, tempfile
os.environ["SSLKEYLOGFILE"] = os.path.join(tempfile.gettempdir(), "babywireshark_keylog.txt")

import json
import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from concurrent.futures import ThreadPoolExecutor
from dns import resolve
from capture import capture_and_request

app = FastAPI(title="BabyWireshark")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

executor = ThreadPoolExecutor(max_workers=4)


@app.websocket("/inspect")
async def inspect(ws: WebSocket):
    await ws.accept()

    try:
        data = await ws.receive_text()
        payload = json.loads(data)
        url = payload.get("url", "").strip()

        if not url:
            await ws.send_json({"type": "error", "message": "No URL provided"})
            await ws.close()
            return

        # Resolve DNS
        try:
            resolved = resolve(url)
        except Exception as e:
            await ws.send_json({"type": "error", "message": f"DNS resolution failed: {e}"})
            await ws.close()
            return

        await ws.send_json({"type": "resolved", "data": resolved})

        loop = asyncio.get_event_loop()
        packet_queue = asyncio.Queue()

        def on_packet(pkt):
            asyncio.run_coroutine_threadsafe(packet_queue.put(pkt), loop)

        def on_done(all_packets):
            asyncio.run_coroutine_threadsafe(packet_queue.put(None), loop)

        # Run capture in thread (needs root)
        executor.submit(capture_and_request, resolved, on_packet, on_done)

        await ws.send_json({"type": "capturing", "message": f"Capturing traffic to {resolved['ip']}:{resolved['port']}"})

        # Stream packets as they arrive
        while True:
            pkt = await packet_queue.get()
            if pkt is None:
                break
            await ws.send_json({"type": "packet", "data": pkt})

        await ws.send_json({"type": "done", "message": "Capture complete"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await ws.send_json({"type": "error", "message": str(e)})
        except Exception:
            pass


@app.get("/")
def root():
    return {"name": "BabyWireshark", "tagline": "A network packet analyser that takes you from request to packet"}