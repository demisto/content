import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import cv2
from skimage import metrics


def calculate_mse(image_path1, image_path2):
    # Load the images
    img1 = cv2.imread(image_path1)  # pylint: disable=[E1101]
    img2 = cv2.imread(image_path2)  # pylint: disable=[E1101]

    # Check if the images are loaded successfully
    if img1 is None or img2 is None:
        return None

    # Calculate Mean Squared Error (MSE)
    mse = ((img1 - img2) ** 2).mean()  # type: ignore[operator]
    return mse


def calculate_ssim(image_path1, image_path2):
    # Load the images
    img1 = cv2.imread(image_path1)  # pylint: disable=[E1101]
    img2 = cv2.imread(image_path2)  # pylint: disable=[E1101]

    # Check if the images are loaded successfully
    if img1 is None or img2 is None:
        return None

    # Convert images to grayscale
    img1_gray = cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY)  # pylint: disable=[E1101]
    img2_gray = cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY)  # pylint: disable=[E1101]

    # Calculate Structural Similarity Index (SSIM)
    ssim = metrics.structural_similarity(img1_gray, img2_gray)
    return ssim


def main():
    try:
        # Get the input parameters
        image_path1 = (demisto.getFilePath(demisto.args().get('org_image')))['path']
        image_path2 = (demisto.getFilePath(demisto.args().get('sec_image')))['path']

        # Calculate MSE and SSIM
        mse = calculate_mse(image_path1, image_path2)
        ssim = calculate_ssim(image_path1, image_path2)

        if mse is not None and ssim is not None:
            # Prepare the results
            results = {
                "MSE": mse,
                "SSIM": ssim
            }

            # Create a human-readable output
            human_readable = f"Image Similarity Comparison Results:\nMSE: {mse}\nSSIM: {ssim}"

            # Create a context output
            context = {
                "ImageSimilarity": results
            }

            return_outputs(human_readable, context, results)
        else:
            raise DemistoException("Failed to load images. Please check the provided image paths.")

    except Exception as e:
        return_error(f"An error occurred: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
