import os
from datetime import datetime
from typing import Any, Dict, List
from motor.motor_asyncio import AsyncIOMotorClient

DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "appdb")

_client = AsyncIOMotorClient(DATABASE_URL)
_db = _client[DATABASE_NAME]

# Export for imports

db = _db

async def create_document(collection_name: str, data: Dict[str, Any]) -> Dict[str, Any]:
    data = data.copy()
    now = datetime.utcnow()
    data.setdefault("created_at", now)
    data["updated_at"] = now
    result = await db[collection_name].insert_one(data)
    data["_id"] = str(result.inserted_id)
    return data

async def get_documents(collection_name: str, filter_dict: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
    cursor = db[collection_name].find(filter_dict).limit(limit)
    out: List[Dict[str, Any]] = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        out.append(doc)
    return out
