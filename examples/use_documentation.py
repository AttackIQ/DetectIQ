#!/usr/bin/env python3
"""
Example showing how to access DetectIQ documentation resources.

This demonstrates how to:
1. Get paths to documentation images
2. Display images using Python's built-in tools
"""
import os
import sys
from pathlib import Path
import shutil

try:
    from detectiq.documentation import list_images, get_image_path
except ImportError:
    print("DetectIQ package not installed. Please install it with:")
    print("pip install detectiq")
    sys.exit(1)

def main():
    """Main function to demonstrate accessing documentation resources."""
    print("DetectIQ Documentation Resources")
    print("-" * 40)
    
    # List all available images
    images = list_images()
    print(f"Available images: {list(images.keys())}")
    print()
    
    # Copy images to a local directory for use
    output_dir = Path("./docs_output")
    output_dir.mkdir(exist_ok=True)
    
    print(f"Copying images to {output_dir}")
    for name, path in images.items():
        if os.path.exists(path):
            dest = output_dir / f"{name}.png"
            print(f"Copying {name} → {dest}")
            shutil.copy(path, dest)
        else:
            print(f"Warning: Image {name} not found at {path}")
    
    print()
    print("You can now use these images in your documentation or GUI applications")
    
    # Optional: Try to display an image
    try:
        import matplotlib.pyplot as plt
        from PIL import Image
        
        # Get the path to the rules page image
        image_path = get_image_path("rules_page")
        
        if os.path.exists(image_path):
            print()
            print("Displaying the rules page image...")
            img = Image.open(image_path)
            plt.imshow(img)
            plt.axis('off')
            plt.show()
        else:
            print(f"Image not found at {image_path}")
    except ImportError:
        print()
        print("Install matplotlib and Pillow to display images:")
        print("pip install matplotlib pillow")
    except Exception as e:
        print(f"Error displaying image: {e}")

if __name__ == "__main__":
    main() 