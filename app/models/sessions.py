from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class UserSession(Base):
    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("user_auth.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    refresh_token_jti: Mapped[str] = mapped_column(
        String(40),
        unique=True,
        index=True,
        nullable=False
    )
    device_info: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True
    )
    ip_address: Mapped[str | None] = mapped_column(
        String(45),
        nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    last_active_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    is_revoked: Mapped[bool] = mapped_column(
        nullable=False,
        default=False
    )
