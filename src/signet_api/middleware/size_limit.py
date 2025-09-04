from __future__ import annotations
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


def _max_bytes() -> int:
    return int(
        os.getenv("SIGNET_INGRESS_MAX_BODY_BYTES")
        or os.getenv("SIGNET_MAX_REQUEST_BYTES")
        or "262144"
    )


class SizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):  # type: ignore[override]
        max_bytes = _max_bytes()
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > max_bytes:
                    return JSONResponse({"detail": "payload too large"}, status_code=413)
            except ValueError:
                pass
        body = await request.body()
        if len(body) > max_bytes:
            return JSONResponse({"detail": "payload too large"}, status_code=413)
        # cache so downstream provenance verifier / route handler can reuse
        request.scope["_cached_body"] = body
        return await call_next(request)
