from sqlalchemy import String
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