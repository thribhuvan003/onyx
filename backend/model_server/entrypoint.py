"""Container entrypoint for the model server.

The image runs on a distroless Docker Hardened Image with no `/bin/sh`, so the
previous shell `command:` wrapper (which short-circuited on DISABLE_MODEL_SERVER
before exec'ing uvicorn) cannot run. This module reproduces that behavior in pure
Python and is the image's default command.
"""

import os
import sys

from onyx.utils.logger import setup_logger

logger = setup_logger()


def main() -> int:
    if os.environ.get("DISABLE_MODEL_SERVER", "").lower() == "true":
        logger.notice("DISABLE_MODEL_SERVER is set; skipping model server startup.")
        return 0

    # Imported lazily so the DISABLE_MODEL_SERVER short-circuit above stays cheap
    # and avoids importing torch/uvicorn when the server is disabled.
    import uvicorn

    from shared_configs.configs import MODEL_SERVER_ALLOWED_HOST
    from shared_configs.configs import MODEL_SERVER_PORT

    uvicorn.run(
        "model_server.main:app",
        host=MODEL_SERVER_ALLOWED_HOST,
        port=MODEL_SERVER_PORT,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
