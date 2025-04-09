"""
Main entry point for the CLI.
"""

import sys
import click

from .multi_recipient_commands import multi_recipient_group
from .cosign_commands import cosign_group
from .timestamp_commands import timestamp_group
from .cert_revocation_commands import cert_revocation_group

@click.group()
def cli():
    """Cryptography System CLI."""
    pass

# Register command groups
cli.add_command(multi_recipient_group)
cli.add_command(cosign_group)
cli.add_command(timestamp_group)
cli.add_command(cert_revocation_group)

if __name__ == "__main__":
    cli()
