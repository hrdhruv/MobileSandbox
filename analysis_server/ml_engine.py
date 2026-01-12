def analyze_permissions(permissions):
    # Weights for risk calculation
    danger_map = {
        "android.permission.READ_SMS": 35,
        "android.permission.READ_CONTACTS": 25,
        "android.permission.RECORD_AUDIO": 30,
        "android.permission.ACCESS_FINE_LOCATION": 20,
        "android.permission.INTERNET": 5
    }
    
    score = 0
    threats = []
    for p in permissions:
        if p in danger_map:
            score += danger_map[p]
            threats.append(p.split('.')[-1])

    level = "SAFE"
    if score > 25: level = "SUSPICIOUS"
    if score > 50: level = "DANGEROUS"
    
    return {"level": level, "score": score, "flags": threats}