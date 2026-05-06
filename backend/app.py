from flask import Flask, request, jsonify, render_template
import joblib
from utils import extract_features

app = Flask(__name__)

model = joblib.load("model/scam_detector_final.pkl")

# -------------------------------
# WEBSITE PREDICTION (ML)
# -------------------------------
def predict_url(url):
    trusted = ['google.com', 'amazon.com', 'facebook.com', 'microsoft.com',
               'apple.com', 'flipkart.com', 'github.com']

    if any(site in url.lower() for site in trusted):
        return "Safe (Trusted Domain)"

    features = extract_features(url)
    prob = model.predict_proba([features])[0][1]

    if prob > 0.7:
        return f"Scam ({prob:.2f})"
    elif prob < 0.3:
        return f"Safe ({1-prob:.2f})"
    else:
        return f"Suspicious ({prob:.2f})"


# -------------------------------
# API: WEBSITE CHECK
# -------------------------------
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")
    result = predict_url(url)
    return jsonify({"result": result})


# -------------------------------
# API: PRODUCT CHECK (FINAL 🔥)
# -------------------------------
@app.route("/product_check", methods=["POST"])
def product_check():
    data = request.get_json()

    name = data.get("name", "").lower()
    url = data.get("url", "").lower()

    try:
        price = float(data.get("price", 0))
    except:
        price = 0

    score = 0
    reasons = []

    trusted_sites = ["amazon", "flipkart", "myntra"]

    # 🔍 1. BASIC URL CHECK
    if "." not in url or len(url) < 6:
        return jsonify({
            "result": "Suspicious ⚠️",
            "reasons": ["Invalid URL format"]
        })

    # 🔍 2. AMAZON FORMAT CHECK
    if "amazon" in url and "/dp/" not in url:
        score += 2
        reasons.append("Invalid Amazon product link ⚠️")

    # 🌐 3. PLATFORM TRUST
    is_trusted = any(site in url for site in trusted_sites)

    if is_trusted:
        reasons.append("Trusted platform ✅")
    else:
        score += 2
        reasons.append("Untrusted website ⚠️")

    # 🔍 4. PRICE ANOMALY (STRONG SIGNAL)
    expected_prices = {
        "iphone": 70000,
        "nike": 3000,
        "adidas": 3000,
        "laptop": 50000,
        "watch": 2000
    }

    for key in expected_prices:
        if key in name:
            if price < expected_prices[key] * 0.5:
                score += 4
                reasons.append("Price unrealistically low 🚨")

    # 🏷 5. BRAND MISMATCH (ONLY FOR UNTRUSTED)
    brands = ["nike", "adidas", "apple", "samsung"]

    for brand in brands:
        if brand in name:
            if brand not in url and not is_trusted:
                score += 2
                reasons.append("Brand mismatch ⚠️")

    # 🔗 6. SUSPICIOUS URL WORDS
    suspicious_words = ["cheap", "free", "offer", "deal", "win", "prize"]

    if any(word in url for word in suspicious_words):
        score += 2
        reasons.append("Suspicious URL 🚨")

    # 🧪 7. ML CHECK (IGNORE FOR TRUSTED)
    try:
        features = extract_features(url)
        prob = model.predict_proba([features])[0][1]

        if prob > 0.7 and not is_trusted:
            score += 2
            reasons.append("Website looks scammy (ML)")
    except:
        pass

    # 🎯 FINAL RESULT
    if score >= 6:
        result = "Fake ❌"
    elif score >= 3:
        result = "Suspicious ⚠️"
    else:
        result = "Genuine ✅"

    return jsonify({
        "result": result,
        "reasons": reasons
    })


# -------------------------------
# ROUTES
# -------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/website")
def website_page():
    return render_template("website.html")

@app.route("/product")
def product_page():
    return render_template("product.html")


# -------------------------------
# RUN
# -------------------------------
if __name__ == "__main__":
    app.run(debug=True)