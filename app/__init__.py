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
    app.config['DOWNLOAD_PASSWORD'] = os.getenv('DOWNLOAD_PASSWORD')
    app.config['AUTHORIZED_EMAILS'] = os.getenv('AUTHORIZED_EMAILS')

    app.config['COSMOS_URL'] = os.getenv('COSMOS_URL')
    app.config['COSMOS_KEY'] = os.getenv('COSMOS_KEY')
    app.config['COSMOS_DB_NAME'] = os.getenv('COSMOS_DB_NAME')
    app.config['COSMOS_CONTAINER'] = os.getenv('COSMOS_CONTAINER')
    app.config['COSMOS_COMBINED_CONTAINER'] = os.getenv('COSMOS_COMBINED_CONTAINER')
    app.config['COSMOS_VEJMAN_PERMISSIONS_CONTAINER'] = os.getenv('COSMOS_VEJMAN_PERMISSIONS_CONTAINER')
    
    app.config['AZURE_BLOB_CONNECTION'] = os.getenv('AZURE_BLOB_CONNECTION')

    db.init_app(app)

    with app.app_context():
        from app.database import initialize_database
        initialize_database()

    from app.routes import api
    api.init_api(app)  # This handles both setup and blueprint registration

    from app.routes import auth
    app.register_blueprint(auth.auth_bp)

    return app
