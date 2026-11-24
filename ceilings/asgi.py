import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

from .db import database_engine, database_state


SERVICE = os.environ["CEILINGS_SERVICE"]


@asynccontextmanager
async def lifespan(app):
    if SERVICE != "web":
        app.state.database = database_engine(SERVICE)
    yield
    if SERVICE != "web":
        app.state.database.dispose()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/healthz")
def health():
    if SERVICE == "web":
        return {"service": SERVICE}
    try:
        state = database_state(app.state.database)
    except SQLAlchemyError:
        return JSONResponse({"service": SERVICE, "ready": False}, status_code=503)
    return {"service": SERVICE, **state}


@app.exception_handler(RequestValidationError)
async def invalid_request(request, error):
    return JSONResponse({"detail": "invalid_input"}, status_code=422)


if SERVICE == "web":
    from .web import browser_origin, router

    app.middleware("http")(browser_origin)
    app.include_router(router)
elif SERVICE == "auth":
    from .auth import router

    app.include_router(router)
