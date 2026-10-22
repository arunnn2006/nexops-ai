from fastapi import APIRouter

from app.api.v1 import auth, incidents, misc, recovery, services

api_router = APIRouter()
api_router.include_router(auth.auth_router)
api_router.include_router(auth.users_router)
api_router.include_router(services.router)
api_router.include_router(incidents.router)
api_router.include_router(recovery.router)
api_router.include_router(misc.router)
