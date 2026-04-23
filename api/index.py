from app import app, bootstrap

# Ensure schema/state is initialized on cold starts.
bootstrap()
