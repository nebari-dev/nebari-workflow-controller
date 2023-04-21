import logging

import uvicorn

logger = logging.getLogger(__name__)


def main():
    logger.info("Starting nebari_workflow_controller")
    uvicorn.run(
        "nebari_workflow_controller.app:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
    )


if __name__ == "__main__":
    main()
