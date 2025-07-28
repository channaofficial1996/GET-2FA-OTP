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

def extract_body(msg):
    body = ""
    html_content = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload:
                text = payload.decode(errors="ignore")
                if content_type == "text/plain":
                    body += text + "\n"
                elif content_type == "text/html":
                    html_content += text + "\n"
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")
    if html_content:
        soup = BeautifulSoup(html_content, "html.parser")
        html_text = soup.get_text(separator="\n")
        body += "\n" + html_text
    return body

def find_otp(text, from_email=None, subject=None):
    if not text:
        return None

    blacklist = {
        "DOCTYPE", "OFFICE", "DEVICE", "VERIFY", "TOKEN", "ACCESS",
        "SUBJECT", "HEADER", "FOOTER", "CLIENT", "SERVER", "ACCOUNT", "CODE"
    }

    # WhatsApp: 953-473 → 953473
    match = re.search(r"\b(\d{3})-(\d{3})\b", text)
    if match:
        return match.group(1) + match.group(2)

    # ✅ TikTok-specific: detect both 6 digit & 6 alphanum code (but not blacklist)
    if from_email and "tiktok.com" in from_email.lower():
        # 1. Try 6 digits (only digits)
        match = re.search(r"\b\d{6}\b", text)
        if match:
            return match.group(0)
        # 2. Try 6 chars (letters/numbers), must not be in blacklist
        lines = text.splitlines()
        for line in lines:
            code_candidate = line.strip()
            if re.fullmatch(r"[A-Za-z0-9]{6}", code_candidate):
                if code_candidate.upper() not in blacklist:
                    return code_candidate
        # 3. Fallback: anywhere in text, 6 alphanum not in blacklist
        matches = re.findall(r"\b([A-Z0-9]{6})\b", text, re.IGNORECASE)
        for code in matches:
            if code.upper() not in blacklist:
                return code
        return None

    # Generic fallback
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

# Remaining logic unchanged for bot operation

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
    elif len(text.strip()) >= 16 and text.strip().isalnum():
        result = generate_otp_from_secret(text.strip())
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
