import tkinter as tk
from PIL import Image, ImageTk
def display_image(image_path):
    root = tk.Tk()
    root.title("Image Display")

    # Open the image file
    image = Image.open(image_path)

    # Convert the image for Tkinter
    tk_image = ImageTk.PhotoImage(image)

    # Create a label widget to display the image
    label = tk.Label(root, image=tk_image)
    label.pack()

    # Run the Tkinter event loop
    root.mainloop()