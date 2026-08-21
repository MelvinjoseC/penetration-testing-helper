import json
from typing import Any, List, Union
from pydantic import AnyHttpUrl, BeforeValidator, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Annotated

def any_http_url_to_str(v: Any) -> str:
    if isinstance(v, list):
        return [str(item) for item in v]
    return str(v)

class Settings(BaseSettings):
    PROJECT_NAME: str = "AI Penetration Testing Orchestration Platform"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "supersecretkeyforlocaldevelopmentonlychangeinprod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    
    # CORS Origins
    BACKEND_CORS_ORIGINS: Annotated[
        Union[List[str], str],
        BeforeValidator(lambda v: json.loads(v) if isinstance(v, str) and v.startswith("[") else v)
    ] = []

    @field_validator("BACKEND_CORS_ORIGINS")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> Union[List[str], str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(v)

    # Database
    DATABASE_URL: str = "postgresql://pentest_user:pentest_password@localhost:5432/pentest_db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Environment
    ENVIRONMENT: str = "development"

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="ignore"
    )

settings = Settings()
