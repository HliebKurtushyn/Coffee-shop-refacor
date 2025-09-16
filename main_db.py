from sqlalchemy import create_engine, String, Float, Integer, ForeignKey, func
from sqlalchemy import Boolean, Text, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.orm import validates, joinedload, DeclarativeBase
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from flask_login import UserMixin
from dotenv import load_dotenv
import bcrypt 
import os
import logging

from logger_setup import setup_logger


db_logger = setup_logger("main_db", "app_db.log",
                         level_file=logging.WARNING, level_console=logging.WARNING)
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.dialects").setLevel(logging.WARNING)

load_dotenv()


engine = create_engine(os.getenv('DATABASE_URL'))
Session = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    def create_db(self):
        Base.metadata.create_all(engine)

    def drop_db(self):
        Base.metadata.drop_all(engine)


class Users(Base, UserMixin):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(50), unique=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)

    basket = relationship("Basket", back_populates="user")
    coupons = relationship("Coupons", back_populates="user")

    def set_password(self, password: str):
        self.password = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')

    def check_password(self, password: str):
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password.encode('utf-8')
        )


class Menu(Base):
    __tablename__ = "menu"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    weight: Mapped[str] = mapped_column(String)
    ingredients: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(String)
    price: Mapped[int] = mapped_column(Integer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    file_name: Mapped[str] = mapped_column(String)

    special_offers = relationship("SpecialOffer", back_populates="menu")
    basket = relationship("Basket", back_populates="menu")


class Coupons(Base):
    __tablename__ = "coupons"

    id: Mapped[int] = mapped_column(primary_key=True)
    order_items: Mapped[dict] = mapped_column(JSONB)
    order_time: Mapped[datetime] = mapped_column(DateTime)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))
    qr_code_path: Mapped[str] = mapped_column(String, nullable=True)

    user = relationship("Users", back_populates="coupons")


class Basket(Base):
    __tablename__ = "basket"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey('users.id'), nullable=False)
    menu_id: Mapped[int] = mapped_column(ForeignKey('menu.id'), nullable=False)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False)

    menu: Mapped["Menu"] = relationship("Menu")
    user: Mapped["Users"] = relationship("Users", back_populates="basket")


class SpecialOffer(Base):
    __tablename__ = "special_offers"

    id: Mapped[int] = mapped_column(primary_key=True)
    menu_id: Mapped[int] = mapped_column(ForeignKey('menu.id'), nullable=False)
    discount: Mapped[float] = mapped_column(Float, nullable=False)
    expiration_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    menu: Mapped["Menu"] = relationship("Menu")

    @validates('discount')
    def validate_discount(self, key, discount):
        if not 0 <= float(discount) <= 100:
            raise ValueError("Discount must be between 0 and 100 percent")
        return discount

    @validates('expiration_date')
    def validate_expiration_date(self, key, expiration_date):
        if expiration_date <= datetime.now():
            raise ValueError("Offer can not be added as expired")
        return expiration_date

    @classmethod
    def deactivate_expired(cls, db_session):
        expired = db_session.query(cls).filter(
            cls.active == True,
            cls.expiration_date < datetime.now()
        ).all()
        for offer in expired:
            offer.active = False
        db_session.commit()


base = Base()
# base.create_db()
