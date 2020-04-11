from base import Base
from sqlalchemy import Binary, Boolean, Column, DateTime, Integer
import datetime

class Network(Base):
    __tablename__ = 'network'

    id = Column(Integer, primary_key=True)
    last_updated = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    unknown = Column(Boolean, default=False)

    extended_pan_id = Column(Binary)
    nwk_key = Column(Binary)

    pans = relationship("PAN", back_populates="network")
