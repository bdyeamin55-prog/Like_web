from app import app
import os

if __name__ == "__main__":
    # Render বা অন্য প্ল্যাটফর্মের জন্য ডাইনামিক পোর্ট সেট করা
    port = int(os.environ.get("PORT", 31208))
    app.run(host='0.0.0.0', port=port)
