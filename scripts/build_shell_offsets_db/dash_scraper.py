from shell_scraper import PoolSource, ShellScraper

ARCHITECTURES = ["amd64", "i386", "arm64", "armhf"]


class DashScraper(ShellScraper):
    """Scraper for dash shell debug packages."""

    def shell_name(self) -> str:
        return "dash"

    def target_functions(self) -> list[str]:
        return ["setprompt", "list"]

    def pool_sources(self) -> list[PoolSource]:
        return [
            PoolSource(
                debug_pool_url="https://deb.debian.org/debian-debug/pool/main/d/dash/",
                package_format="deb",
                filename_pattern="dash-dbgsym_*",
                architectures=ARCHITECTURES,
            ),
            PoolSource(
                debug_pool_url="http://ddebs.ubuntu.com/pool/main/d/dash/",
                package_format="deb",
                filename_pattern="dash-dbgsym_*",
                architectures=ARCHITECTURES,
            ),
        ]
