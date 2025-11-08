import imaplib, email, re, pyotp, asyncio, os
from bs4 import BeautifulSoup
from telegram import Update, ReplyKeyboardMarkup, InputFile
from telegram.ext import (
    ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters
)
from PIL import Image
from pyzbar.pyzbar import decode

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

# ---------- 1) CLEAN HTML + REMOVE "Image" LINES ----------
def extract_body(msg):
    body = ""
    html_text_total = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            text = payload.decode(errors="ignore")

            if ctype == "text/plain":
                body += text + "\n"
            elif ctype == "text/html":
                # parse HTML, remove <img alt="Image">
                soup = BeautifulSoup(text, "html.parser")
                for img in soup.find_all("img"):
                    alt = (img.get("alt") or "").strip().lower()
                    if alt == "image":
                        img.decompose()
                html_text = soup.get_text(separator="\n")
                html_text_total += html_text + "\n"
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")

    if html_text_total:
        body += "\n" + html_text_total

    # remove lines that are only "Image"
    cleaned_lines = []
    for line in body.splitlines():
        if line.strip().lower() == "image":
            continue
        cleaned_lines.append(line)
    return "\n".join(cleaned_lines)

# ---------- 2) SMART OTP FINDER ----------
def find_otp(text, from_email=None, subject=None):
    if not text:
        return None

    blacklist = {
        "DOCTYPE", "OFFICE", "DEVICE", "VERIFY", "TOKEN", "ACCESS",
        "SUBJECT", "HEADER", "FOOTER", "CLIENT", "SERVER", "ACCOUNT", "CODE",
        "SIZING", "IMAGE", "BUTTON", "BORDER", "CENTER", "WIDTH", "HEIGHT",
        "STYLE", "TABLE"
    }

    # ex 123-456
    m = re.search(r"\b(\d{3})-(\d{3})\b", text)
    if m:
        return m.group(1) + m.group(2)

    # ----- SPECIAL FOR TIKTOK -----
    if from_email and "tiktok.com" in from_email.lower():
        # 1) exact phrase from email
        m = re.search(
            r"enter this code in TikTok Marketing API:\s*([A-Za-z0-9]{4,8})",
            text,
            re.IGNORECASE
        )
        if m:
            code = m.group(1).strip()
            if code.upper() not in blacklist:
                return code

        # 2) code that sits BEFORE "This code will expire"
        m = re.search(
            r"\n\s*([A-Za-z0-9]{4,8})\s*\n\s*This code will expire",
            text,
            re.IGNORECASE
        )
        if m:
            code = m.group(1).strip()
            if code.upper() not in blacklist:
                return code

        # 3) scan line-by-line (ignore css lines)
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line or ";" in line:   # css or html attrs
                continue
            if 4 <= len(line) <= 8 and re.fullmatch(r"[A-Za-z0-9]{4,8}", line):
                if line.upper() not in blacklist:
                    return line

        # 4) fallback to all tokens
        matches = re.findall(r"\b([A-Za-z0-9]{4,8})\b", text, re.IGNORECASE)
        for code in matches:
            if code.upper() not in blacklist:
                return code
        return None

    # ----- NORMAL EMAILS -----
    m = re.search(r"\b\d{6}\b", text)
    if m:
        return m.group(0)

    m = re.search(r"\b\d{4,8}\b", text)
    if m:
        return m.group(0)

    m = re.search(r"(\d\s){3,7}\d", text)
    if m:
        return m.group(0).replace(" ", "")

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
        folders = ["INBOX", "FB-Security", "Spam", "Social networks", "Bulk", "Promotions", "[Gmail]/All Mail"]
        seen_otps = set()
        for folder in folders:
            try:
                select_status, _ = mail.select(folder)
                if select_status != "OK":
                    continue
                result, data = mail.search(None, "ALL")
                if result != "OK":
                    continue
                email_ids = data[0].split()[-20:]
                for eid in reversed(email_ids):
                    result, data = mail.fetch(eid, "(RFC822)")
                    if result != "OK":
                        continue
                    msg = email.message_from_bytes(data[0][1])
                    subject = msg.get("Subject", "")
                    from_email = msg.get("From", "")
                    folder_name = folder
                    to_field = msg.get("To", "")
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

app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle))
app.add_handler(MessageHandler(filters.PHOTO, photo_handler))

print("✅ Bot is running...")
app.run_polling()
