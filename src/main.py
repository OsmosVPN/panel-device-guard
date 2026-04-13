import asyncio
import logging

from .config import load_config
from .guard import DeviceGuard
from .panel_api import PanelClient
from .web import WebUI


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
    web_ui = WebUI(cfg, guard)
    await asyncio.gather(
        guard.run(),
        web_ui.run(),
    )


if __name__ == "__main__":
    asyncio.run(main())
