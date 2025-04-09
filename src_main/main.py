"""
Main Entry Point

This module provides the main entry point for the cryptography system.
"""

import sys
import argparse
from .ui.cli import CLI

def main():
    """
    Main entry point for the cryptography system.

    Returns:
        Exit code (0 for success, non-zero for error)
    """
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Cryptography System")
    parser.add_argument("--gui", action="store_true", help="Start the graphical user interface")
    args, remaining_args = parser.parse_known_args()

    if args.gui:
        # Start the GUI
        try:
            from .ui.gui.run import main as run_gui
            run_gui()
            return 0
        except ImportError as e:
            print(f"Error: Could not start GUI: {str(e)}")
            print("Make sure PyQt6 is installed: pip install PyQt6")
            return 1
    else:
        # Start the CLI
        cli = CLI()
        return cli.run(remaining_args)

if __name__ == '__main__':
    sys.exit(main())
