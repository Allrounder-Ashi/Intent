"""
Extracts text from screenshots and images such as:
- Scam SMS screenshots
- Fake bank/payment screenshots
- Phishing messages
- Other digital-fraud evidence
"""

import os


def extract_text_from_image(image_path, lang="eng"):
    """
    Extract raw text from one image using Tesseract OCR.

    Returns:
        str: Extracted text, or an empty string if processing fails.
    """

    if not image_path:
        print("[ocr_processor] No image path provided.")
        return ""

    if not os.path.isfile(image_path):
        print(f"[ocr_processor] Image not found: {image_path}")
        return ""

    try:
        import pytesseract
        from PIL import Image
    except ImportError as exc:
        raise ImportError(
            "Required packages are missing.\n"
            "Run:\n"
            "pip install pytesseract pillow"
        ) from exc

    try:
        image = Image.open(image_path)

        # Convert to RGB to avoid issues with certain PNG modes.
        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")

        text = pytesseract.image_to_string(
            image,
            lang=lang
        )

        return text.strip()

    except Exception as exc:
        print(f"[ocr_processor] OCR failed: {exc}")
        return ""


def extract_text_from_images(image_paths, lang="eng"):
    """
    Process multiple images.

    Returns:
        dict:
            {
                "image1.png": "extracted text...",
                "image2.png": "extracted text..."
            }
    """

    results = {}

    for image_path in image_paths:
        results[image_path] = extract_text_from_image(
            image_path,
            lang=lang
        )

    return results


if __name__ == "__main__":

    test_path = "sample_screenshot.png"

    result = extract_text_from_image(test_path)

    print("\n========== OCR RESULT ==========\n")

    if result:
        print(result)
    else:
        print("(No text extracted or file missing)")
