
import imaplib, email, re, pyotp
from bs4 import BeautifulSoup
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

BOT_TOKEN = "7845423216:AAHE0QIJy9nJ4jhz-xcQURUCQEvnIAgjEdE"

IMAP_SERVERS = {
    "yandex.com": "imap.yandex.com",
    "zoho.com": "imap.zoho.com",
    "zohomail.com": "imap.zoho.com"
}

def alias_in_any_header(msg, alias_email):
    alias_lower = alias_email.lower()
    for header, value in msg.items():
        if alias_lower in value.lower():
            return True
    return False

def extract_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
            elif content_type == "text/html" and not body:
                html = part.get_payload(decode=True).decode(errors="ignore")
                soup = BeautifulSoup(html, "html.parser")
                body = soup.get_text(separator=" ")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")
    return body

def find_otp(text):
    match = re.search(r"\b\d{4,8}\b", text)
    return match.group(0) if match else None

def fetch_otp_from_email(email_address, password):
    try:
        domain = email_address.split("@")[1]
        if domain not in IMAP_SERVERS:
            return "❌ This bot only supports Yandex and Zoho domains."

        imap_server = IMAP_SERVERS[domain]
        base_email = email_address.split("+")[0] + "@" + domain
        alias_email = email_address

        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(base_email, password)

        folders = ["INBOX", "Spam", "Social networks", "Bulk", "Promotions", "[Gmail]/All Mail"]
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
                    if not alias_in_any_header(msg, alias_email):
                        continue

                    subject = msg.get("Subject", "")
                    from_email = msg.get("From", "")
                    folder_name = folder
                    to_field = msg.get("To", "")
                    body = extract_body(msg)

                    otp = find_otp(body)
                    if not otp:
                        otp = find_otp(subject)
                    if otp and otp not in seen_otps:
                        seen_otps.add(otp)
                        return (
                            f"✅ ខាងក្រោមនេះជាកូតរបស់អ្នក\n"
                            f"📩 From: {from_email}\n"
                            f"📝 Subject: {subject}\n"
                            f"📁 Folder: {folder_name}\n"
                            f"📥 To: {to_field}"
                        )
            except Exception:
                continue
        return "❌ OTP not found in last 20 emails sent to your alias."
    except Exception as e:
        return f"❌ Error: {e}"

def generate_otp_from_secret(secret):
    try:
        otp = pyotp.TOTP(secret).now()
        return (
            "🔐 ខាងក្រោមនេះគឺជាកូដ 2FA ពី Street Key:\n"
            f"✅ 2FA OTP: `{otp}`"
        )
    except Exception as e:
        return f"❌ Invalid Secret Key: {e}"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [["📩 GET Mail OTP", "🔐 GET 2FA"]]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    full_name = update.effective_user.full_name
    await update.message.reply_text(
        f"👋 សួស្ដី​បង {full_name}!\n📥 សូមចុចប៊ូតុងខាងក្រោមដើម្បីដំណើរការ",
        reply_markup=reply_markup
    )

async def handle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    if text == "📩 GET Mail OTP":
        await update.message.reply_text("📧 សូមផ្ញើ email | passwordapp ឲ្យបានត្រឹមត្រូវ")
        return
    elif text == "🔐 GET 2FA":
        await update.message.reply_text("🧩 សូមផ្ញើ Secret Key ឲ្យបានត្រឹមត្រូវ")
        return

    if "|" in text and "@" in text:
        try:
            email_input, password_input = text.split("|")
            await update.message.reply_text("⏳ កំពុងស្វែងរក OTP សូមរងចាំ១០វិនាទី...")
            result = fetch_otp_from_email(email_input.strip(), password_input.strip())
            await update.message.reply_text(result)
        except Exception as e:
            await update.message.reply_text(f"❌ បញ្ហា: {e}")
    elif len(text.strip()) >= 16 and text.isalnum():
        result = generate_otp_from_secret(text.strip())
        await update.message.reply_text(result, parse_mode="Markdown")
    else:
        await update.message.reply_text("⚠️ សូមបញ្ចូល `email|password` ឬ Secret Key ត្រឹមត្រូវ")

app = ApplicationBuilder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start))
app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle))
print("✅ Bot is running...")
app.run_polling()
