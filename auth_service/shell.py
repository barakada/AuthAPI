import asyncio

import uvloop
from IPython import start_ipython
from traitlets.config import Config

from .db import AuthStore, Settings, database


def main() -> None:
    settings = Settings()
    lifecycle = database(settings)
    with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
        # Traitlets copies config values. A closure retains the same runner.
        def run_cell(coroutine):
            return runner.run(coroutine)

        pool = runner.run(lifecycle.__aenter__())
        try:
            config = Config()
            config.InteractiveShell.autoawait = True
            config.InteractiveShell.loop_runner = run_cell
            start_ipython(
                config=config,
                user_ns={"db": pool, "store": AuthStore(pool), "settings": settings},
            )
        finally:
            runner.run(lifecycle.__aexit__(None, None, None))


if __name__ == "__main__":
    main()
