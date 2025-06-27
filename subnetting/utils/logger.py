# logger.py

# Tracks and scores execution for network automation scripts.

import logging
from datetime import datetime

class AnswerScoreLogger:
    def __init__(self, name: str, level: str = "INFO"):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        handler = logging.FileHandler(f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.correct_answers = 0
        self.total_attempts = 0

    def log_info(self, message: str):
        self.logger.info(message)

    def log_error(self, message: str):
        self.logger.error(message)

    def record_attempt(self, correct: bool):
        self.total_attempts += 1
        if correct:
            self.correct_answers += 1
        self.logger.info(f"Attempt recorded: {'Correct' if correct else 'Incorrect'} | Total: {self.total_attempts} | Correct: {self.correct_answers}")

    def get_score(self) -> float:
        if self.total_attempts == 0:
            return 0.0
        return round((self.correct_answers / self.total_attempts) * 100, 2)

def setup_logger(name: str, level: str = "INFO") -> AnswerScoreLogger:
    return AnswerScoreLogger(name=name, level=level)

