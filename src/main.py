import asyncio
import logging

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

    tasks: list[asyncio.Task] = [asyncio.create_task(guard.run())]

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
        logging.getLogger("panel_device_guard").info(
            "web UI listening on http://0.0.0.0:%s", cfg.web_port
        )

    await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
