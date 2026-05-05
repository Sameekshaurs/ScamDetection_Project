import re

def extract_features(url):
    features = []
    
    features.append(len(url))
    features.append(url.count("."))
    features.append(url.count("-"))
    features.append(url.count("@"))
    features.append(sum(c.isdigit() for c in url))
    
    features.append(1 if "https" in url else 0)
    
    features.append(1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0)
    
    suspicious = ['login','secure','account','update','bank','verify','free','offer']
    features.append(sum(word in url.lower() for word in suspicious))
    
    features.append(len(url.split("/")))
    
    domain = url.split("/")[0]
    features.append(len(domain))
    features.append(domain.count("."))
    
    trusted = ['google', 'amazon', 'facebook', 'microsoft', 'apple', 'netflix']
    features.append(1 if any(word in url.lower() for word in trusted) else 0)
    
    return features