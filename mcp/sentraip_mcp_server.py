#!/usr/bin/env python3
"""
SentraIP MCP Adapter
--------------------
A lightweight FastAPI service that exposes SentraIP's Threat Intelligence API
through standardized MCP-style endpoints. Ready for Tyk integration.

Author: Angelo Ovidi
"""

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi  
import requests
import os
import logging

# === Configuration ===
SENTRAIP_BEARER_TOKEN = os.getenv("SENTRAIP_BEARER_TOKEN")
SENTRAIP_API_BASE = "https://api.sentraip.com/ws/v1"

# === App Setup ===
app = FastAPI(
    title="SentraIP MCP Adapter",
    version="1.0.0",
    description=(
        "FastAPI microservice that acts as an MCP adapter for the SentraIP "
        "Threat Intelligence API. Provides /mcp/check_ip, /mcp/asn, and /mcp/stats endpoints."
    ),
    servers=[
                        {"url": "http://10.10.0.3:8081", "description": "Internal MCP server"}
    ]
)


# Custom OpenAPI schema generator to force 3.0.3
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Force OAS version for Tyk compatibility
    openapi_schema["openapi"] = "3.0.3"

    # Inject servers back into schema explicitly
    openapi_schema["servers"] = [
        {
            "url": "http://10.10.0.3:8081",
            "description": "Internal MCP server"
        }
    ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


# === Helper function ===
def sentraip_get(path, params=None):
    headers = {"Authorization": f"Bearer {SENTRAIP_BEARER_TOKEN}"}
    url = f"{SENTRAIP_API_BASE}/{path}"
    logger.info(f"Querying SentraIP API: {url} params={params}")
    r = requests.get(url, headers=headers, params=params or {})
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()

    logger.info(f"Querying SentraIP API: {url} params={params}")

    try:
        r = requests.get(url, headers=headers, params=params or {}, timeout=10)
        if r.status_code == 401:
            raise HTTPException(status_code=401, detail="Unauthorized: invalid or expired token")
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Resource not found on SentraIP")
        if r.status_code >= 500:
            raise HTTPException(status_code=502, detail="Upstream SentraIP service error")
        return r.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"Request to SentraIP failed: {e}")
        raise HTTPException(status_code=503, detail="Connection to SentraIP failed")


# === Routes ===
@app.get("/mcp/check_ip", tags=["SentraIP"])
def check_ip(ip: str = Query(..., description="IPv4 or IPv6 address to check")):
    """
    Check reputation and threat information for an IP address.
    Example: /mcp/check_ip?ip=1.1.1.1
    """
    return sentraip_get("ip-check", params={"ips": ip})

@app.get("/mcp/stats", tags=["SentraIP"])
def get_stats():
    """
    Retrieve general statistics or usage metrics from SentraIP.
    Example: /mcp/stats
    """
    return sentraip_get("stats")


# === Root endpoint ===
@app.get("/", include_in_schema=False)
def root():
    """Simple health check."""
    return JSONResponse({"status": "ok", "service": "SentraIP MCP Adapter"})


# === Main entrypoint ===
if __name__ == "__main__":
    import uvicorn

    logger.info("Starting SentraIP MCP Adapter on port 8081...")
    uvicorn.run("sentraip_mcp_server:app", host="0.0.0.0", port=8081, reload=False)
