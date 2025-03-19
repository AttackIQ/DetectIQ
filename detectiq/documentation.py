"""Documentation resources for DetectIQ."""

import os
from pathlib import Path

# Get the directory of this file
PACKAGE_DIR = Path(os.path.dirname(os.path.abspath(__file__)))

# Path to the docs directory relative to the package
DOCS_DIR = PACKAGE_DIR.parent / "docs"
IMAGES_DIR = DOCS_DIR / "images"

# Dictionary of available images
IMAGES = {
    "rules_page": str(IMAGES_DIR / "detectiq_rules_page.png"),
    "sigma_rule_creation_1": str(IMAGES_DIR / "detectiq_sigma_rule_creation_1.png"),
    "sigma_rule_creation_2": str(IMAGES_DIR / "detectiq_sigma_rule_creation_2.png"),
    "yara_rule_creation_1": str(IMAGES_DIR / "detectiq_yara_rule_creation_file_1.png"),
    "yara_rule_creation_2": str(IMAGES_DIR / "detectiq_yara_rule_creation_file_2.png"),
    "settings": str(IMAGES_DIR / "detectiq_settings.png"),
    "about": str(IMAGES_DIR / "detectiq_about.png"),
}


def get_image_path(image_name):
    """Get the path to an image by name.

    Args:
        image_name (str): Name of the image

    Returns:
        str: Full path to the image

    Raises:
        ValueError: If image_name is not found
    """
    if image_name not in IMAGES:
        raise ValueError(f"Image '{image_name}' not found. Available images: {list(IMAGES.keys())}")
    return IMAGES[image_name]


def list_images():
    """List all available documentation images.

    Returns:
        dict: Dictionary of image names and paths
    """
    return IMAGES
