import uuid
from datetime import datetime, timezone
from .. import db


class MemoryDump(db.Model):
    __tablename__ = 'memory_dumps'

    dump_id     = db.Column(db.String(36), primary_key=True,
                            default=lambda: str(uuid.uuid4()))
    user_id     = db.Column(db.String(36),
                            db.ForeignKey('users.id', ondelete='CASCADE'),
                            nullable=False, index=True)
    file_path   = db.Column(db.Text, nullable=False)
    file_name   = db.Column(db.String(255), nullable=False)
    file_size   = db.Column(db.BigInteger, nullable=False)
    upload_date = db.Column(db.DateTime(timezone=True),
                            default=lambda: datetime.now(timezone.utc),
                            nullable=False)
    status      = db.Column(db.String(32), default='pending', nullable=False)
    hash_value  = db.Column(db.String(64), nullable=True)

    features = db.relationship('AnalysisFeatures', backref='dump',
                               uselist=False, passive_deletes=True)
    results  = db.relationship('AnalysisResult',   backref='dump',
                               passive_deletes=True)

    def to_dict(self):
        return {
            'dump_id':     self.dump_id,
            'file_name':   self.file_name,
            'file_size':   self.file_size,
            'upload_date': self.upload_date.isoformat(),
            'status':      self.status,
            'hash_value':  self.hash_value,
        }


class AnalysisFeatures(db.Model):
    __tablename__ = 'features'

    feature_id    = db.Column(db.String(36), primary_key=True,
                              default=lambda: str(uuid.uuid4()))
    dump_id       = db.Column(db.String(36),
                              db.ForeignKey('memory_dumps.dump_id', ondelete='CASCADE'),
                              nullable=False, unique=True)
    process_count = db.Column(db.Integer, nullable=True)
    dll_count     = db.Column(db.Integer, nullable=True)
    feature_data  = db.Column(db.JSON, nullable=True)

    def to_dict(self):
        return {
            'feature_id':    self.feature_id,
            'dump_id':       self.dump_id,
            'process_count': self.process_count,
            'dll_count':     self.dll_count,
            'feature_data':  self.feature_data,
        }


class MlModel(db.Model):
    __tablename__ = 'ml_models'

    model_id      = db.Column(db.String(36), primary_key=True,
                              default=lambda: str(uuid.uuid4()))
    model_name    = db.Column(db.String(255), nullable=False)
    algorithm     = db.Column(db.String(128), nullable=False)
    accuracy      = db.Column(db.Float, nullable=True)
    training_date = db.Column(db.DateTime(timezone=True),
                              default=lambda: datetime.now(timezone.utc),
                              nullable=False)
    model_path    = db.Column(db.Text, nullable=True)

    results = db.relationship('AnalysisResult', backref='ml_model',
                              passive_deletes=True)

    def to_dict(self):
        return {
            'model_id':      self.model_id,
            'model_name':    self.model_name,
            'algorithm':     self.algorithm,
            'accuracy':      self.accuracy,
            'training_date': self.training_date.isoformat(),
        }


class AnalysisResult(db.Model):
    __tablename__ = 'results'

    result_id           = db.Column(db.String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    dump_id             = db.Column(db.String(36),
                                    db.ForeignKey('memory_dumps.dump_id', ondelete='CASCADE'),
                                    nullable=False)
    model_id            = db.Column(db.String(36),
                                    db.ForeignKey('ml_models.model_id', ondelete='RESTRICT'),
                                    nullable=False)
    prediction          = db.Column(db.String(32), nullable=False)
    confidence          = db.Column(db.Float, nullable=False)
    classification_date = db.Column(db.DateTime(timezone=True),
                                    default=lambda: datetime.now(timezone.utc),
                                    nullable=False)

    __table_args__ = (
        db.UniqueConstraint('dump_id', 'model_id', name='uq_result_dump_model'),
    )

    def to_dict(self):
        return {
            'result_id':           self.result_id,
            'dump_id':             self.dump_id,
            'model_id':            self.model_id,
            'prediction':          self.prediction,
            'confidence':          self.confidence,
            'classification_date': self.classification_date.isoformat(),
        }
