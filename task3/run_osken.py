#!/usr/bin/env python3

import sys
import logging

from os_ken import cfg
from os_ken.base import app_manager
from os_ken.lib import hub

# Import these modules before cfg.CONF parses options.
# os_ken.topology.switches registers --observe-links here.
import os_ken.controller.ofp_handler
import os_ken.topology.switches


LOG = logging.getLogger("run_osken")


def normalize_app_name(app_name: str) -> str:
    """
    Convert file path to Python module path.

    Example:
        controllers/task3/shortest_forward.py
    becomes:
        controllers.task3.shortest_forward
    """
    app_name = app_name.strip()

    if app_name.endswith(".py"):
        app_name = app_name[:-3]

    app_name = app_name.replace("/", ".")
    app_name = app_name.replace("\\", ".")

    while app_name.startswith("."):
        app_name = app_name[1:]

    return app_name


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s:%(name)s:%(message)s"
    )

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python run_osken.py controllers/task3/shortest_forward.py --observe-links")
        sys.exit(1)

    raw_args = sys.argv[1:]

    app_names = []
    osken_args = []

    for arg in raw_args:
        if arg.endswith(".py") or arg.startswith("controllers."):
            app_names.append(normalize_app_name(arg))
        else:
            osken_args.append(arg)

    if not app_names:
        print("No controller app specified.")
        print("Example:")
        print("  python run_osken.py controllers/task3/shortest_forward.py --observe-links")
        sys.exit(1)

    # Required OS-Ken built-in apps.
    # ofp_handler: OpenFlow connection handling.
    # switches: topology discovery and LLDP link discovery.
    apps = [
        "os_ken.controller.ofp_handler",
        "os_ken.topology.switches",
    ]

    apps.extend(app_names)

    LOG.info("OS-Ken args: %s", osken_args)
    LOG.info("Loading apps: %s", apps)

    cfg.CONF(
        args=osken_args,
        project="os_ken",
        version="custom-runner"
    )

    app_mgr = app_manager.AppManager.get_instance()

    app_mgr.load_apps(apps)
    contexts = app_mgr.create_contexts()
    services = app_mgr.instantiate_apps(**contexts)

    LOG.info("OS-Ken controller is running. Press Ctrl+C to stop.")

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        LOG.info("Interrupted by user.")
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()
