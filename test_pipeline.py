import asyncio
import json
import logging

logging.basicConfig(level=logging.INFO)

from services.pure_rag_pipeline import PureRAGPipeline
from models.schema import Event

events = [
    Event(id="1", event_type="phishing_email", timestamp="2024-12-08T23:45:00", user="m.chen", resource="email", severity="medium", metadata={}),
    Event(id="2", event_type="link_clicked", timestamp="2024-12-08T23:46:00", user="m.chen", resource="browser", severity="high", metadata={}),
    Event(id="3", event_type="credential_theft", timestamp="2024-12-08T23:47:00", user="m.chen", resource="browser", severity="critical", metadata={})
]

pipeline = PureRAGPipeline()

async def test():
    print("Running pipeline...")
    result = await pipeline.analyze_incident(events)
    print("PIPELINE RESULT:")
    print(json.dumps(result, indent=2))

asyncio.run(test())
