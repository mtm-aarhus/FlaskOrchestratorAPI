from app import create_app

application = create_app()

# Local dev support
if __name__ == "__main__":
    application.run(debug=True)
