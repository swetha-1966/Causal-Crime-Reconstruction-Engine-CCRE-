import asyncio
import sys

from routes.process import process_logs
from routes.upload import upload_logs
from fastapi import UploadFile
import io

async def test():
    try:
        # Load sample data
        with open("../data/sample_logs_1.json", "rb") as f:
            content = f.read()
        
        # Mock upload
        file = UploadFile(filename="sample_logs_1.json", file=io.BytesIO(content))
        await upload_logs(file)
        
        # Test process
        print("Running process_logs...")
        res = await process_logs()
        print("Success")
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test())
