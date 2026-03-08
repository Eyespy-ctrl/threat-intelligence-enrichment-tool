# database.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Observable(db.Model):
    __tablename__ = "observables"

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)     # ip, domain, url, hash
    value = db.Column(db.String(255), nullable=False)   # the actual observable
    provider = db.Column(db.String(100))                # which provider returned this row
    country = db.Column(db.String(80))
    score = db.Column(db.String(100))                   # textual or numeric score
    details = db.Column(db.Text)                        # JSON/text dump of provider response
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def as_dict(self):
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "provider": self.provider,
            "country": self.country,
            "score": self.score,
            "details": self.details,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Observable {self.type}:{self.value} from {self.provider}>"
