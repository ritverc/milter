"""Entry point for the amavis-milter daemon."""

from amavis_milter.milter import run_milter


def main() -> None:
    """CLI entry point — reads config path from sys.argv."""
    import sys

    if len(sys.argv) < 2:
        print("Usage: amavis-milter <config.toml>", file=sys.stderr)
        sys.exit(1)

    run_milter(sys.argv[1])


if __name__ == "__main__":
    main()
