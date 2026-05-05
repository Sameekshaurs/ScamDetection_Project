from flask import Flask, request, jsonify, render_template
import joblib
from utils import extract_features

app = Flask(__name__)

model = joblib.load("model/scam_detector_final.pkl")

def predict_url(url):
    trusted = ['google.com', 'amazon.com', 'facebook.com', 'microsoft.com', 'apple.com', 'flipkart.com', 'twitter.com', 'linkedin.com', 'github.com', 'netflix.com', 'paypal.com', 'wikipedia.org', 'yahoo.com', 'bing.com', 'instagram.com', 'dropbox.com', 'spotify.com', 'adobe.com', 'salesforce.com', 'airbnb.com', 'uber.com', 'lyft.com', 'zoom.us', 'slack.com', 'twitch.tv', 'discord.com', 'reddit.com', 'quora.com', 'medium.com', 'stackoverflow.com', 'github.io', 'bitbucket.org', 'gitlab.com', 'heroku.com', 'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com', 'digitalocean.com', 'linode.com', 'vultr.com', 'ovh.com', 'hetzner.com', 'namecheap.com', 'godaddy.com', 'bluehost.com', 'hostgator.com', 'siteground.com', 'inmotionhosting.com', 'a2hosting.com', 'dreamhost.com', 'greenhost.net', 'fastcomet.com', 'interserver.net', 'iPage.com', 'justhost.com', 'arvixe.com', 'webhostingpad.com']
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



# 👉 API
@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    url = data.get("url")
    result = predict_url(url)
    return jsonify({"result": result})

# 👉 Product Check API
@app.route("/product_check", methods=["POST"])
def product_check():
    data = request.get_json()

    name = data.get("name", "").lower()
    url = data.get("url", "")

    try:
        price = float(data.get("price", 0))
    except:
        price = 0

    score = 0

    # keywords
    if any(word in name for word in ["replica", "copy", "fake"]):
        score += 3

    # cheap
    if price < 700:
        score += 2

    # 🔥 URL validity check
    if "." not in url or len(url) < 6:
        score += 2

    # 🔥 suspicious domains
    if any(word in url for word in ["xyz", "free", "offer", "deal", "cheap", "discount", "sale", "bargain", "win", "prize", "bonus", "gift", "promo", "coupon", "limited", "exclusive", "best", "top", "hot", "new", "save", "clearance", "flash", "mega", "super", "ultra", "bestdeal", "bestprice", "bestoffer", "bestdiscount", "bestsale", "bestbargain", "bestwin", "bestprize", "bestbonus", "bestgift", "bestpromo", "limitedoffer", "exclusiveoffer", "hotdeal", "newdeal", "savebig", "clearanceoffer", "flashsale", "megasale", "supersale", "ultrasale", "bestdeals", "bestprices", "bestoffers", "bestdiscounts", "bestsales", "bestbargains", "bestwins", "bestprizes", "bestbonuses", "bestgifts", "bestpromos", "limitedoffers", "exclusiveoffers", "hotdeals", "newdeals", "savebigs", "clearanceoffers", "flashsales", "megasales", "supersales", "ultrasales","bestdeals", "bestprices", "bestoffers", "bestdiscounts", "bestsales", "bestbargains", "bestwins", "bestprizes", "bestbonuses", "bestgifts", "bestpromos", "limitedoffers", "exclusiveoffers", "hotdeals", "newdeals", "savebigs", "clearanceoffers", "flashsales", "megasales", "supersales", "ultrasales"]):
        score += 2

    # final
    if score >= 4:
        result = "Fake ❌"
    elif score >= 2:
        result = "Suspicious ⚠️"
    else:
        result = "Genuine ✅"

    return jsonify({"result": result})

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/website")
def website_page():
    return render_template("website.html")

@app.route("/product")
def product_page():
    return render_template("product.html")

if __name__ == "__main__":
    app.run(debug=True)