import argparse
import asyncio
import logging
import signal

from app.edge.runtime import EdgeWorker, EdgeWorkerConfig


async def serve(worker: EdgeWorker) -> None:
    loop = asyncio.get_running_loop()
    for signal_name in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signal_name, worker.stop)
        except NotImplementedError:
            pass
    await worker.run()


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    parser = argparse.ArgumentParser(description="MineGuard resilient edge inference worker")
    parser.add_argument("--config", required=True, help="Path to the edge worker JSON configuration")
    args = parser.parse_args()
    worker = EdgeWorker(EdgeWorkerConfig.load(args.config))
    try:
        asyncio.run(serve(worker))
    except KeyboardInterrupt:
        worker.stop()


if __name__ == "__main__":
    main()
