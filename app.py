from pathlib import Path
import uuid

from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory

from crypto import encrypt_message, decrypt_message
from steganography import encode_message, decode_message, capacity_bytes

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"

UPLOAD_DIR.mkdir(exist_ok=True)
OUTPUT_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "bmp"}

app = Flask(__name__)
app.secret_key = "change-this-secret-key-for-production"


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.get("/")
def home():
    return render_template("home.html")


@app.route("/Encryption", methods=["GET", "POST"])
def encryption():
    if request.method == "GET":
        return render_template("encryption.html")

    image = request.files.get("source_image")
    message = request.form.get("message", "").strip()
    password = request.form.get("password", "")
    prime_1 = request.form.get("prime_1", "")
    prime_2 = request.form.get("prime_2", "")
    new_name = request.form.get("new_name", "").strip()

    if not image or not image.filename:
        flash("Please select a cover image.", "danger")
        return redirect(url_for("encryption"))

    if not allowed_file(image.filename):
        flash("Use PNG, JPG, JPEG or BMP images.", "danger")
        return redirect(url_for("encryption"))

    if not message:
        flash("Please enter a secret message.", "danger")
        return redirect(url_for("encryption"))

    if len(password) < 6:
        flash("Password must contain at least 6 characters.", "danger")
        return redirect(url_for("encryption"))

    # Keep the reference project's Prime 1 / Prime 2 fields.
    # They are validated as positive integers and used as extra key material.
    try:
        p = int(prime_1)
        q = int(prime_2)
        if p < 2 or q < 2:
            raise ValueError
    except ValueError:
        flash("Prime 1 and Prime 2 must be positive integers.", "danger")
        return redirect(url_for("encryption"))

    image_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{Path(image.filename).name}"
    image.save(image_path)

    try:
        encrypted = encrypt_message(
            message,
            password=password,
            prime_1=p,
            prime_2=q,
        )
        output_name = new_name or f"encoded_{Path(image.filename).stem}.png"
        if not output_name.lower().endswith(".png"):
            output_name += ".png"

        output_path = OUTPUT_DIR / output_name
        # PNG is used for the encoded image because JPEG recompression can destroy LSB data.
        encode_message(str(image_path), encrypted, str(output_path))

        return render_template(
            "success.html",
            title="Message Hidden Successfully",
            output_name=output_name,
            output_url=url_for("download_file", filename=output_name),
            mode="encode",
        )
    except Exception as exc:
        flash(f"Encoding failed: {exc}", "danger")
        return redirect(url_for("encryption"))


@app.route("/Decryption", methods=["GET", "POST"])
def decryption():
    if request.method == "GET":
        return render_template("decryption.html")

    image = request.files.get("encoded_image")
    password = request.form.get("password", "")
    prime_1 = request.form.get("prime_1", "")
    prime_2 = request.form.get("prime_2", "")
    output_name = request.form.get("new_cover_name", "").strip()

    if not image or not image.filename:
        flash("Please select the encoded image.", "danger")
        return redirect(url_for("decryption"))

    if not allowed_file(image.filename):
        flash("Use PNG, JPG, JPEG or BMP images.", "danger")
        return redirect(url_for("decryption"))

    if len(password) < 6:
        flash("Please enter the password used during encryption.", "danger")
        return redirect(url_for("decryption"))

    try:
        p = int(prime_1)
        q = int(prime_2)
        if p < 2 or q < 2:
            raise ValueError
    except ValueError:
        flash("Prime 1 and Prime 2 must be positive integers.", "danger")
        return redirect(url_for("decryption"))

    image_path = UPLOAD_DIR / f"{uuid.uuid4().hex}_{Path(image.filename).name}"
    image.save(image_path)

    try:
        encrypted = decode_message(str(image_path))
        message = decrypt_message(
            encrypted,
            password=password,
            prime_1=p,
            prime_2=q,
        )
        return render_template(
            "result.html",
            title="Secret Message Recovered",
            message=message,
        )
    except Exception as exc:
        flash(
            "Could not recover the message. Check the image, password, Prime 1 and Prime 2.",
            "danger",
        )
        return redirect(url_for("decryption"))


@app.get("/capacity")
def capacity():
    filename = request.args.get("filename", "")
    if not filename:
        return {"error": "filename is required"}, 400
    path = UPLOAD_DIR / filename
    if not path.exists():
        return {"error": "file not found"}, 404
    try:
        return {"capacity_bytes": capacity_bytes(str(path))}
    except Exception as exc:
        return {"error": str(exc)}, 400


@app.get("/downloads/<path:filename>")
def download_file(filename):
    return send_from_directory(OUTPUT_DIR, filename, as_attachment=True)


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(debug=True)
