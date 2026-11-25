from datetime import datetime
from sqlalchemy import DateTime, String
from sqlalchemy.orm import mapped_column,Mapped
from app.core.database import Base




class UserAuth(Base):
    __tablename__ = "user_auth"

    id:Mapped[int] = mapped_column(
        primary_key=True,
        nullable=False,
        index=True
    )
    email:Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True

    )
    hashed_password:Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    role:Mapped[str] = mapped_column(
        nullable=False,
        default="user"
    )
    is_active:Mapped[bool] = mapped_column(
        nullable=False,
        default=True
    )
    is_verified: Mapped[bool] = mapped_column(
    nullable=False,
    default=False
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        nullable=False,
        default=0
    )
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None
    )