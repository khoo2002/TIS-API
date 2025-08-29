import logging
import logging.handlers
import os
import uuid
from typing import Optional


class StructuredLogger:
    """Provide a per-run correlation ID and convenience for struct log format.

    configure(level=logging.INFO, log_dir='/var/log/ingest') will attempt to
    create a rotating file handler under the mounted `ingest_logs` volume
    (default `/var/log/ingest`). If the directory isn't writable, the code
    falls back to stdout only.

    Use:
        StructuredLogger.configure()
        run_id = StructuredLogger.start_run()
        log = StructuredLogger.get_logger(__name__)
    """

    _base_logger = None
    _run_id: Optional[str] = None

    @classmethod
    def configure(cls, level=logging.INFO, log_dir: Optional[str] = None):
        # Keep the root logger configured with a console handler plus an
        # optional file handler (timed rotating).
        log_dir = log_dir or os.getenv('INGEST_LOG_DIR', '/var/log/ingest')

        handlers = []
        console_handler = logging.StreamHandler()
        console_fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_fmt)
        handlers.append(console_handler)

        # Try to create log dir and file handler. If creation fails, keep
        # only the console handler so the app still logs to stdout.
        try:
            os.makedirs(log_dir, exist_ok=True)
            file_path = os.path.join(log_dir, 'ingest.log')
            file_handler = logging.handlers.TimedRotatingFileHandler(
                file_path, when='midnight', backupCount=7, encoding='utf-8'
            )
            file_fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_fmt)
            handlers.append(file_handler)
        except Exception:
            # If we can't create the file handler, proceed with console only
            pass

        logging.basicConfig(level=level, handlers=handlers)
        cls._base_logger = logging.getLogger()

    @classmethod
    def start_run(cls) -> str:
        cls._run_id = str(uuid.uuid4())
        cls._base_logger = cls._base_logger or logging.getLogger()
        cls._base_logger.info(f"Run started: {cls._run_id}")
        return cls._run_id

    @classmethod
    def get_logger(cls, name: Optional[str] = None):
        return logging.getLogger(name)
