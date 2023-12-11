import functools
import threading
import time
import logging


def runner(
    target, name: str, flag=lambda *args: True, *, delay=0, exception_delay=5
):

    self = target.__self__

    @functools.wraps(target)
    def function_(*args, **kwargs):
        while flag(self):
            time.sleep(delay)
            try:
                target(*args, **kwargs)
            except Exception:
                logging.exception(
                    f"Unhandled exception in runner {name}. Continuing in {exception_delay} seconds"
                )
                time.sleep(exception_delay)

    return function_


def create_runner(
    name: str, target: callable, flag: callable, *, start=False, **kwargs
):
    thread = threading.Thread(
        name=name, target=runner(target=target, name=name, flag=flag, **kwargs)
    )
    if start:
        thread.start()
    return thread
