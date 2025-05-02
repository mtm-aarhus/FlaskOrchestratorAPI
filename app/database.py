from app import db
from sqlalchemy.ext.automap import automap_base

def initialize_database():
    """Dynamically load database models using automap."""
    with db.engine.connect() as conn:
        Base = automap_base()
        Base.prepare(autoload_with=db.engine)

        global Queues, Triggers
        Queues = Base.classes.get("Queues")
        Triggers = Base.classes.get("Triggers")
