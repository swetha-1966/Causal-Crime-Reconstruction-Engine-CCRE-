import asyncio
import sys
sys.path.insert(0, ".")
from services.rag_service import generate_rag_explanation
import logging

logging.basicConfig(level=logging.INFO)

async def test():
    print("Calling generate_rag_explanation...")
    result = await generate_rag_explanation(
        events=[], 
        causal_links=[], 
        matched_patterns=[], 
        critical_path=[], 
        risk_score=50.0, 
        attack_type="Unknown"
    )
    print("\nRESULT:\n", result[:200], "...")

if __name__ == "__main__":
    asyncio.run(test())
