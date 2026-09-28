import asyncio
import json
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

app = FastAPI()

import mimetypes

mimetypes.add_type("application/javascript", ".js")

# Mount the dashboard static files
dashboard_path = Path(__file__).parent.parent / "dashboard"
app.mount("/dashboard", StaticFiles(directory=str(dashboard_path), html=True), name="dashboard")

@app.get("/")
def read_root():
    return {"message": "BlackBox Server Running. Go to /dashboard"}

@app.get("/health")
def health_check():
    return {"status": "ok"}

async def event_generator():
    # Stub for SSE events
    while True:
        # Example dummy event just to keep stream alive
        event = {"type": "ping", "message": "keep-alive"}
        yield f"data: {json.dumps(event)}\n\n"
        await asyncio.sleep(5)

@app.get("/events")
async def sse_events():
    return StreamingResponse(event_generator(), media_type="text/event-stream")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
