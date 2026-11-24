"""Authenticated, stateless local Java review. Source is not persisted."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..deps import AuthContext, require_auth
from ...crypto_ml.inference import analyze_java

router = APIRouter(prefix="/api/crypto-ml", tags=["experimental-crypto-ml"])


class JavaReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(default="source.java", min_length=1, max_length=255)
    source: str = Field(min_length=1, max_length=100_000)


class JavaReviewResult(BaseModel):
    filename: str
    modelVersion: str
    datasetRevision: str
    status: str
    misuseScore: float | None
    scoreMeaning: str
    limitations: list[str]
    recommendation: str
    findings: list[dict]
    observations: list[dict]
    unresolved: list[dict]
    contextNotes: list[str] = Field(default_factory=list)
    ml: dict


@router.post("/analyze", response_model=JavaReviewResult)
def analyze(payload: JavaReviewRequest, ctx: AuthContext = Depends(require_auth)):
    """Return a binary screening result, not a confirmed vulnerability finding."""
    if ctx.role not in {"user", "lead", "analyst", "admin"}:
        raise HTTPException(status_code=403, detail="Insufficient role")
    try:
        return analyze_java(payload.source, payload.filename)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (FileNotFoundError, KeyError):
        raise HTTPException(status_code=503, detail="Modelo ML no disponible; ejecutar el experimento de entrenamiento")
    except ModuleNotFoundError as exc:
        if exc.name == "javalang":
            raise HTTPException(status_code=503, detail="Instalar las dependencias server o ml para habilitar el parser Java") from exc
        raise
