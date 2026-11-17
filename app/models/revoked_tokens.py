import datetime
from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped,mapped_column
from app.core.database import Base
from datetime import datetime,timezone



class Revokedtoken(Base):
    __tablename__ = "revoked_tokens"

    id:Mapped[int] = mapped_column(
        primary_key=True,

    )
    jti:Mapped[str] = mapped_column(
        String(40),
        unique=True,
        index=True,
        nullable=False
    )
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        default=lambda: datetime.now(timezone.utc), 
        nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), 
        nullable=False
    )