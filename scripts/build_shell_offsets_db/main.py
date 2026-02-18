import argparse
import logging
import os
import sys

from dash_scraper import DashScraper

ALL_SCRAPERS = [
    DashScraper,
]


def main():
    parser = argparse.ArgumentParser(
        description="Build an offline SQLite DB of function offsets for stripped shell binaries."
    )
    parser.add_argument(
        "--db",
        required=True,
        help="Path to an existing SQLite database file",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Crawl and list packages without downloading or writing to DB",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug-level logging",
    )

    args = parser.parse_args()

    if not os.path.isfile(args.db):
        parser.error(f"Database file does not exist: {args.db}")

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    for scraper_class in ALL_SCRAPERS:
        scraper = scraper_class(db_path=args.db)
        try:
            logging.info("Running %s scraper", scraper.shell_name())
            scraper.run(dry_run=args.dry_run)
        except KeyboardInterrupt:
            logging.info("Interrupted by user")
            sys.exit(1)
        finally:
            scraper.close()


if __name__ == "__main__":
    main()
