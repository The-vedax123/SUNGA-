from app import app, bootstrap

# Ensure schema/state is initialized on cold starts.
try:
    bootstrap()
except BaseException as error:
    # Avoid hard crashes that surface as FUNCTION_INVOCATION_FAILED.
    app.logger.exception("Startup bootstrap failed: %s", error)
