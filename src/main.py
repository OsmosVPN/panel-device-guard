import asyncio
import logging
import signal

import uvicorn

from .config import load_config
from .guard import DeviceGuard
from .panel_api import PanelClient
from .web import create_app


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


async def main() -> None:
    setup_logging()
    cfg = load_config()
    api = PanelClient(cfg)
    guard = DeviceGuard(cfg, api)
    logger = logging.getLogger("panel_device_guard")

    tasks: list[asyncio.Task] = [asyncio.create_task(guard.run())]
    server: uvicorn.Server | None = None

    if cfg.web_enabled:
        if not cfg.web_password:
            raise RuntimeError("WEB_PASSWORD must be set when WEB_ENABLED=true")
        app = create_app(cfg, guard)
        uvi_cfg = uvicorn.Config(
            app,
            host="0.0.0.0",
            port=cfg.web_port,
            loop="none",
            log_level="warning",
        )
        server = uvicorn.Server(uvi_cfg)
        tasks.append(asyncio.create_task(server.serve()))
        logger.info(
            "web UI listening on http://0.0.0.0:%s", cfg.web_port
        )

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    def _request_shutdown() -> None:
        if not stop_event.is_set():
            logger.info("shutdown signal received, stopping gracefully")
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _request_shutdown)
        except NotImplementedError:
            # Fallback for environments where add_signal_handler is not supported.
            signal.signal(sig, lambda *_: _request_shutdown())

    stop_waiter = asyncio.create_task(stop_event.wait())
    try:
        done, _ = await asyncio.wait([stop_waiter, *tasks], return_when=asyncio.FIRST_COMPLETED)
        if stop_waiter not in done:
            # One of worker tasks exited unexpectedly.
            for completed in done:
                if completed is stop_waiter:
                    continue
                exc = completed.exception()
                if exc:
                    logger.error("worker task exited with error: %s", exc)
                else:
                    logger.warning("worker task exited unexpectedly")
            stop_event.set()
    finally:
        stop_waiter.cancel()
        if server is not None:
            server.should_exit = True

        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)
        api.close()


if __name__ == "__main__":
    asyncio.run(main())
