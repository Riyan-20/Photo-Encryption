# Photo Encryption App

This Python-based desktop application allows you to encrypt images using the DES algorithm in two modes: ECB (Electronic Codebook) and OFB (Output Feedback). The encrypted images are rendered on the screen and can be saved as new image files.

## Features

- **Image Encryption**: Encrypts images using DES in ECB and OFB modes.
- **Password-Based Key Derivation**: The app uses a password supplied by the user to derive a DES key using the `scrypt` key derivation function.
- **Image Display**: The encrypted images are displayed within the application.
- **Save Encrypted Images**: Users can save the encrypted images in PNG format.

## Prerequisites

- Python 3.x
- The following Python libraries:
  - `tkinter`: For the graphical user interface.
  - `Pillow`: For image processing (`PIL`).
  - `numpy`: For image-to-byte conversion.
  - `pycryptodome`: For DES encryption and key derivation.

## Installation

1. Install Python 3.x if not already installed. You can download it from the official [Python website](https://www.python.org/downloads/).
2. Clone the repository or download the code.
3. Install the required dependencies using pip:

   ```bash
   pip install pillow numpy pycryptodome
