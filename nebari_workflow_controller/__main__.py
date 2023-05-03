import argparse
import logging

import uvicorn

from nebari_workflow_controller import DEFAULT_LOGGING_CONFIG as LOGGING_CONFIG

logger = logging.getLogger(__name__)


def main():
    args = parse_args()
    logger.info("Starting nebari_workflow_controller")
    uvicorn.run(
        "nebari_workflow_controller.app:app",
        host="0.0.0.0",
        port=8080,
        reload=False,
        log_level=args.log_level.lower(),
    )


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument(
        "-l",
        "--log-level",
        dest="log_level",
        default="INFO",
        help="Set the log level (default: INFO)",
    )
    args = parser.parse_args()

    # Configure logging
    LOGGING_CONFIG["loggers"][""]["level"] = args.log_level
    LOGGING_CONFIG["loggers"]["nebari_workflow_controller"]["level"] = args.log_level
    logging.config.dictConfig(LOGGING_CONFIG)

    return args


if __name__ == "__main__":
    # If you change these lines, then update nwc.py accordingly
    main()
