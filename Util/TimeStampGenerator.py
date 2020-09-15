import time

class TimeStampGenerator:

    @staticmethod
    def generate_timestamp():
        return time.strftime("%Y%m%d-%H%M%S")
