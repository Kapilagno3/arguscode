import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.router import router


def create_app() -> FastAPI:
    """Factory function for FastAPI application instance."""
    app = FastAPI(
        title="Argus Code Backend",
        description="Autonomous Multi-Agent Developer Platform API",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS Configuration - allow all local dev origins and configured origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Register API routes on standard /api/v1, /api, and root
    app.include_router(router, prefix="/api/v1")
    app.include_router(router, prefix="/api")
    app.include_router(router, prefix="")

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=settings.APP_ENV == "development",
    )
