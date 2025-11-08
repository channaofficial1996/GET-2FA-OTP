import os
import imaplib, email, re, pyotp, asyncio
from io import BytesIO

from bs4 import BeautifulSoup
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler,
    ContextTypes, filters
)

from PIL import Image
from pyzbar.pyzbar import decode
import pytesseract   # <-- OCR

BOT_TOKEN = "8286165511:AAFEN68nARNQh3bMeNW49jaxj_K0WtpPvBg"

IMAP_SERVERS = {
    "yandex.com": "imap.yandex.com",
    "zoho.com": "imap.zoho.com",
    "zohomail.com": "imap.zoho.com"
}


def is_valid_email(email_str):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email_str)


def alias_in_any_header(msg, alias_email):
    alias_lower = alias_email.lower()
    for header in ["To", "Delivered-To", "X-Original-To", "Envelope-To"]:
        v = msg.get(header, "")
        if v and alias_lower in v.lower():
            return True
    return False


# ---------- extract body + OCR on images ----------
def extract_body(msg):
    body = ""
    html_content = ""
    image_texts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload:
                continue

            if content_type == "text/plain":
                body += payload.decode(errors="ignore") + "\n"

            elif content_type == "text/html":
                html_content += payload.decode(errors="ignore") + "\n"

            elif content_type.startswith("image/"):
                # TikTok OTP is here
                try:
                    img = Image.open(BytesIO(payload))
                    ocr_text = pytesseract.image_to_string(img)
                    if ocr_text.strip():
                        image_texts.append(ocr_text.strip())
                except Exception:
                    pass
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            if msg.get_content_type().startswith("image/"):
                try:
                    img = Image.open(BytesIO(payload))
                    ocr_text = pytesseract.image_to_string(img)
                    if ocr_text.strip():
                        image_texts.append(ocr_text.strip())
                except Exception:
                    pass
            else:
                body = payload.decode(errors="ignore")

    # convert HTML → text
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        html_text = soup.get_text(separator="\n")
        body += "\n" + html_text

    # append OCR texts to body so find_otp() can see it
    if image_texts:
        body += "\n" + "\n".join(image_texts)

    return body


# ---------- find otp ----------
def find_otp(text, from_email=None, subject=None):
    if not text:
        return None

    blacklist = {
        "DOCTYPE", "OFFICE", "DEVICE", "VERIFY", "TOKEN", "ACCESS",
        "SUBJECT", "HEADER", "FOOTER", "CLIENT", "SERVER", "ACCOUNT", "CODE",
        "SIZING", "IMAGE", "BUTTON", "BORDER", "CENTER", "WIDTH", "HEIGHT",
        "STYLE", "TABLE"
    }

    # ex: 123-456 → 123456
    match = re.search(r"\b(\d{3})-(\d{3})\b", text)
    if match:
        return match.group(1) + match.group(2)

    # ----- TikTok special -----
    if from_email and "tiktok.com" in from_email.lower():
        # 1) the exact sentence in screenshot
        m = re.search(
            r"code in TikTok Marketing API:\s*([A-Za-z0-9]{4,8})",
            text,
            re.IGNORECASE
        )
        if m:
            code = m.group(1).strip()
            if code.upper() not in blacklist:
                return code

        # 2) generic "enter this code:"
        m = re.search(
            r"enter this code[: ]+\s*([A-Za-z0-9]{4,8})",
            text,
            re.IGNORECASE
        )
        if m:
            code = m.group(1).strip()
            if code.upper() not in blacklist:
                return code

        # 3) lines from OCR/HTML – ignore css lines
        lines = [ln.strip() for ln in text.splitlines()]
        for ln in lines:
            if ":" in ln or ";" in ln:  # CSS
                continue
            if len(ln) < 4 or len(ln) > 10:
                continue
            if re.fullmatch(r"[A-Za-z0-9]{4,8}", ln):
                if ln.upper() not in blacklist:
                    return ln

        # 4) fallback all tokens
        matches = re.findall(r"\b([A-Za-z0-9]{4,8})\b", text, re.IGNORECASE)
        for code in matches:
            if code.upper() not in blacklist:
                return code

        return None

    # ----- normal emails like FB, Telegram -----
    match = re.search(r"\b\d{6}\b", text)
    if match:
        return match.group(0)

    match = re.search(r"\b\d{4,8}\b", text)
    if match:
        return match.group(0)

    match = re.search(r"(\d\s){3,7}\d", text)
    if match:
        return match.group(0).replace(" ", "")

    matches = re.findall(r"\b([A-Z0-9]{6})\b", text, re.IGNORECASE)
    for code in matches:
        if code.upper() not in blacklist:
            return code

    return None


def fetch_otp_from_email(email_address, password):
    try:
        domain = email_address.split("@")[1]
        if domain not in IMAP_SERVERS:
            return "❌ Bot គាំទ្រតែ Yandex និង Zoho ប៉ុណ្ណោះ។"

        imap_server = IMAP_SERVERS[domain]
        base_email = email_address.split("+")[0] + "@" + domain
        alias_email = email_address

        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(base_email, password)

        folders = [
            "INBOX", "FB-Security", "Spam", "Social networks",
            "Bulk", "Promotions", "[Gmail]/All Mail"
        ]

        seen_otps = set()

        for folder in folders:
            try:
                select_status, _ = mail.select(folder)
                if select_status != "OK":
                    continue

                result, data = mail.search(None, "ALL")
                if result != "OK":
                    continue

                email_ids = data[0].split()[-20:]  # last 20
                for eid in reversed(email_ids):
                    result, data = mail.fetch(eid, "(RFC822)")
                    if result != "OK":
                        continue

                    msg = email.message_from_bytes(data[0][1])
                    subject = msg.get("Subject", "")
                    from_email = msg.get("From", "")
                    folder_name = folder
                    to_field = msg.get("To", "")

                    # yandex alias check
                    if domain.endswith("yandex.com"):
                        if not alias_in_any_header(msg, alias_email):
                            continue

                    body = extract_body(msg)
                    otp = find_otp(body, from_email=from_email, subject=subject)
                    if not otp:
                        otp = find_otp(subject, from_email=from_email, subject=subject)

                    if otp and otp not in seen_otps:
                        seen_otps.add(otp)
                        return (
                            f"✅ ខាងក្រោមនេះជាកូដរបស់អ្នក\n"
                            f"🔑 OTP: `{otp}`\n"
                            f"📩 From: {from_email}\n"
                            f"📝 Subject: {subject}\n"
                            f"📁 Folder: {folder_name}\n"
                            f"📥 To: {to_field}"
                        )
            except Exception:
                continue

        return "❌ OTP មិនមានក្នុងអ៊ីមែល 20 ចុងក្រោយសម្រាប់ alias នេះទេ។"

    except Exception as e:
        return f"❌ បញ្ហា: {e}"


def generate_otp_from_secret(secret):
    try:
        otp = pyotp.TOTP(secret).now()
        return (
            "🔐 ខាងក្រោមនេះគឺជាកូដ 2FA ពី Secret Key:\n"
            f"✅ 2FA OTP: `{otp}`"
        )
    except Exception as e:
        return f"❌ Secret Key មិនត្រឹមត្រូវទេ: {e}"


# ---------- telegram handlers ----------
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [["📷 QR GET KEY", "🔐 2FA OTP", "📩 Mail OTP"]]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    full_name = update.effective_user.full_name
    await update.message.reply_text(
        f"👋 សួស្ដីបង {full_name}!\n📥 សូមចុចប៊ូតុងខាងក្រោមដើម្បីដំណើរការ",
        reply_markup=reply_markup
    )


async def handle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    context.user_data['qr_wait'] = False

    if text == "📷 QR GET KEY":
        context.user_data['qr_wait'] = True
        await update.message.reply_text("📷 សូមផ្ញើរូប QR code (Authenticator QR)")
        return
    elif text == "🔐 2FA OTP":
        await update.message.reply_text("🧩 សូមផ្ញើ Secret Key ឲ្យបានត្រឹមត្រូវ")
        return
    elif text == "📩 Mail OTP":
        await update.message.reply_text("📧 សូមផ្ញើ email | passwordapp ឲ្យបានត្រឹមត្រូវ")
        return

    if context.user_data.get('qr_wait'):
        await update.message.reply_text("⚠️ សូមផ្ញើរូបភាព QR code។")
        return

    if "|" in text and "@" in text:
        try:
            email_input, password_input = text.split("|", 1)
            email_input = email_input.strip()
            password_input = password_input.strip()
            if not is_valid_email(email_input):
                await update.message.reply_text("❌ Email មិនត្រឹមត្រូវទេ។")
                return
            await update.message.reply_text("⏳ កំពុងស្វែងរក OTP សូមរងចាំ...")
            result = await asyncio.to_thread(fetch_otp_from_email, email_input, password_input)
            await update.message.reply_text(result, parse_mode="Markdown")
        except Exception as e:
            await update.message.reply_text(f"❌ បញ្ហា: {e}")
    elif len(text.replace(" ", "").strip()) >= 16 and text.replace(" ", "").strip().isalnum():
        result = generate_otp_from_secret(text.replace(" ", "").strip())
        await update.message.reply_text(result, parse_mode="Markdown")
    else:
        await update.message.reply_text("⚠️ សូមបញ្ចូល `email|password` ឬ Secret Key ត្រឹមត្រូវ")


async def photo_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if context.user_data.get('qr_wait'):
        photo_file = await update.message.photo[-1].get_file()
        file_path = f"/tmp/{update.message.from_user.id}_qr.png"
        await photo_file.download_to_drive(file_path)
        try:
            img = Image.open(file_path)
            qr_result = decode(img)
            if qr_result and qr_result[0].data:
                qr_data = qr_result[0].data.decode("utf-8")
                secret = None
                if qr_data.startswith("otpauth://"):
                    match = re.search(r"secret=([A-Z2-7]+)", qr_data, re.I)
                    if match:
                        secret = match.group(1)
                if secret:
                    await update.message.reply_text(f"✅ Secret Key: `{secret}`", parse_mode="Markdown")
                else:
                    await update.message.reply_text("❌ មិនរកឃើញ Secret Key នៅក្នុង QR នេះទេ។")
            else:
                await update.message.reply_text("❌ មិនអាចស្គែន QR បានទេ។")
        except Exception as e:
            await update.message.reply_text(f"❌ បញ្ហា៖ {e}")
        context.user_data['qr_wait'] = False
    else:
        await update.message.reply_text("⚠️ សូមចុច '📷 QR GET KEY' ជាមុនសិន។")


# ---------- run bot ----------
app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle))
app.add_handler(MessageHandler(filters.PHOTO, photo_handler))

print("✅ Bot is running...")
app.run_polling()
