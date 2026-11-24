"""Test package configuration for the add-on."""

import sys
from pathlib import Path


APP_PATH = Path(__file__).resolve().parents[1] / "proton_drive_backup" / "rootfs" / "app"
sys.path.insert(0, str(APP_PATH))
