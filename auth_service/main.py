from fastapi import FastAPI

from .exceptions import register_exception_handlers
from .lifecycle import lifespan
from .routes import router

app = FastAPI(title="Authentication Service", lifespan=lifespan)
register_exception_handlers(app)
app.include_router(router)
