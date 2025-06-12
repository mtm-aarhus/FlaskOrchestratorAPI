from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    # Configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('OpenOrchestratorSQL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['API_KEY'] = os.getenv('PyOrchestratorAPIKey')
    app.config['SQL_USER'] = os.getenv('SQL_USER')
    app.config['SQL_PASSWORD'] = os.getenv('SQL_PASSWORD')
    app.config['SQL_SERVER'] = os.getenv('SQL_SERVER')


    db.init_app(app)

    with app.app_context():
        from app.database import initialize_database
        initialize_database()

    from app.routes import api
    app.register_blueprint(api.bp)

    return app
