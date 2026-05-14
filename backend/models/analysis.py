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

    model_id           = db.Column(db.String(36), primary_key=True,
                                   default=lambda: str(uuid.uuid4()))
    model_name         = db.Column(db.String(255), nullable=False)
    algorithm          = db.Column(db.String(128), nullable=False)
    accuracy           = db.Column(db.Float, nullable=True)
    training_date      = db.Column(db.DateTime(timezone=True),
                                   default=lambda: datetime.now(timezone.utc),
                                   nullable=False)
    activated_at       = db.Column(db.DateTime(timezone=True), nullable=True)
    model_path         = db.Column(db.Text, nullable=True)
    feature_importance = db.Column(db.JSON, nullable=True)

    results = db.relationship('AnalysisResult', backref='ml_model',
                              passive_deletes=True)

    def to_dict(self):
        return {
            'model_id':           self.model_id,
            'model_name':         self.model_name,
            'algorithm':          self.algorithm,
            'accuracy':           self.accuracy,
            'training_date':      self.training_date.isoformat(),
            'activated_at':       self.activated_at.isoformat() if self.activated_at else None,
            'feature_importance': self.feature_importance,
        }


class AnalysisResult(db.Model):
    __tablename__ = 'results'

    result_id            = db.Column(db.String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    dump_id              = db.Column(db.String(36),
                                     db.ForeignKey('memory_dumps.dump_id', ondelete='CASCADE'),
                                     nullable=False)
    model_id             = db.Column(db.String(36),
                                     db.ForeignKey('ml_models.model_id', ondelete='RESTRICT'),
                                     nullable=False)
    prediction           = db.Column(db.String(32), nullable=False)
    confidence           = db.Column(db.Float, nullable=False)
    classification_date  = db.Column(db.DateTime(timezone=True),
                                     default=lambda: datetime.now(timezone.utc),
                                     nullable=False)

    # Stage 2 — populated only when prediction == 'Malware'
    malware_category     = db.Column(db.String(64),  nullable=True)   # Ransomware|Spyware|Trojan
    category_confidence  = db.Column(db.Float,        nullable=True)
    malware_family       = db.Column(db.String(64),  nullable=True)   # Conti, Zeus, Emotet, …
    family_confidence    = db.Column(db.Float,        nullable=True)

    __table_args__ = (
        db.UniqueConstraint('dump_id', 'model_id', name='uq_result_dump_model'),
    )

    def to_dict(self):
        return {
            'result_id':            self.result_id,
            'dump_id':              self.dump_id,
            'model_id':             self.model_id,
            'prediction':           self.prediction,
            'confidence':           self.confidence,
            'classification_date':  self.classification_date.isoformat(),
            'malware_category':     self.malware_category,
            'category_confidence':  self.category_confidence,
            'malware_family':       self.malware_family,
            'family_confidence':    self.family_confidence,
        }


class LabeledSample(db.Model):
    """
    Ground-truth labeled samples used for adaptive retraining.

    Each row holds a 55-element feature vector (same schema as CICMalMem-2022)
    and a confirmed label.  Rows where included_in_model_id IS NULL are
    "new since last training" and will be appended to the base dataset on the
    next retrain run.
    """
    __tablename__ = 'labeled_samples'

    sample_id            = db.Column(db.String(36), primary_key=True,
                                     default=lambda: str(uuid.uuid4()))
    dump_id              = db.Column(db.String(36),
                                     db.ForeignKey('memory_dumps.dump_id', ondelete='SET NULL'),
                                     nullable=True, index=True)
    feature_vector       = db.Column(db.JSON, nullable=False)
    true_label           = db.Column(db.String(32), nullable=False)   # 'Benign' | 'Malware'
    source               = db.Column(db.String(64), nullable=False, default='manual')
    added_by             = db.Column(db.String(36),
                                     db.ForeignKey('users.id', ondelete='SET NULL'),
                                     nullable=True)
    added_at             = db.Column(db.DateTime(timezone=True),
                                     default=lambda: datetime.now(timezone.utc),
                                     nullable=False, index=True)
    included_in_model_id = db.Column(db.String(36),
                                     db.ForeignKey('ml_models.model_id', ondelete='SET NULL'),
                                     nullable=True, index=True)

    def to_dict(self):
        return {
            'sample_id':            self.sample_id,
            'dump_id':              self.dump_id,
            'true_label':           self.true_label,
            'source':               self.source,
            'added_by':             self.added_by,
            'added_at':             self.added_at.isoformat(),
            'included_in_model_id': self.included_in_model_id,
        }


class AuditLog(db.Model):
    __tablename__ = 'audit_logs'

    log_id        = db.Column(db.String(36), primary_key=True,
                              default=lambda: str(uuid.uuid4()))
    user_id       = db.Column(db.String(36),
                              db.ForeignKey('users.id', ondelete='SET NULL'),
                              nullable=True, index=True)
    action        = db.Column(db.String(64), nullable=False)
    resource_type = db.Column(db.String(64), nullable=True)
    resource_id   = db.Column(db.String(36), nullable=True)
    ip_address    = db.Column(db.String(45), nullable=True)
    timestamp     = db.Column(db.DateTime(timezone=True),
                              default=lambda: datetime.now(timezone.utc),
                              nullable=False, index=True)
    details       = db.Column(db.JSON, nullable=True)

    def to_dict(self):
        return {
            'log_id':        self.log_id,
            'user_id':       self.user_id,
            'action':        self.action,
            'resource_type': self.resource_type,
            'resource_id':   self.resource_id,
            'ip_address':    self.ip_address,
            'timestamp':     self.timestamp.isoformat(),
            'details':       self.details,
        }
