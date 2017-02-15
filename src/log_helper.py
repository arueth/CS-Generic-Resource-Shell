import threading

from cloudshell.shell.core.session.logging_session import LoggingSessionContext


class LogHelper:
    @staticmethod
    def get_logger(context):
        session_logger = LoggingSessionContext.get_logger_for_context(context)
        logger = session_logger.getChild(threading.currentThread().name)
        logger.level = session_logger.level

        for handler in session_logger.handlers:
            logger.addHandler(handler)

        for log_filter in session_logger.filters:
            logger.addFilter(log_filter)

        return logger
