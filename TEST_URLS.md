# 🧪 Test URLs for Smart Proxy Dashboard

## 🎯 **How to Test:**

### **Method 1: Web Interface**
1. Go to: http://127.0.0.1:5000
2. Copy and paste URLs from below
3. Click "Scan URL"
4. Watch results appear in Grafana dashboard

### **Method 2: Automated Testing**
```bash
python test_urls.py
```

---

## ✅ **SAFE/LEGITIMATE SITES** (Should Pass)

### **Popular Websites:**
```
https://google.com
https://microsoft.com
https://github.com
https://stackoverflow.com
https://wikipedia.org
https://youtube.com
https://amazon.com
https://facebook.com
https://twitter.com
https://linkedin.com
```

### **Banking/Financial:**
```
https://chase.com
https://bankofamerica.com
https://wellsfargo.com
https://paypal.com
https://visa.com
https://citibank.com
```

### **E-commerce:**
```
https://amazon.com
https://ebay.com
https://walmart.com
https://target.com
https://bestbuy.com
```

---

## ⚠️ **SUSPICIOUS PATTERNS** (May Trigger Detection)

### **Phishing-like Domains:**
```
https://paypal-security.net
https://amazon-verify.org
https://microsoft-update.co
https://google-security.info
https://apple-support.net
https://facebook-security.org
https://secure-paypal.net
https://verify-amazon.com
https://login-google.net
https://confirm-facebook.org
```

### **Banking Impersonation:**
```
https://chase-bank.net
https://wells-fargo.co
https://bank-of-america.org
https://paypal-verify.net
https://secure-chase.com
```

---

## 🚨 **PHISHING TEST SITES** (Safe for Testing)

### **Official Security Training:**
```
https://phishing-quiz.withgoogle.com
https://www.phishtank.com
https://openphish.com
https://phishing.org
https://www.knowbe4.com
```

### **Security Awareness:**
```
https://www.sans.org/security-awareness-training
https://phishingbox.com
https://www.proofpoint.com/us/security-awareness
```

---

## 🔍 **CUSTOM TEST PATTERNS**

### **Suspicious URL Patterns:**
```
https://secure-login-paypal.net
https://verify-account-amazon.org
https://update-security-microsoft.co
https://confirm-identity-google.info
https://apple-id-verification.net
https://facebook-account-security.org
```

### **Typosquatting Examples:**
```
https://gooogle.com
https://microsft.com
https://amazom.com
https://payapl.com
https://facebok.com
```

---

## 🎮 **Quick Test Sequence**

**Copy these URLs one by one into your web interface:**

1. **Safe Test**: `https://google.com`
2. **Suspicious Test**: `https://paypal-security.net`
3. **Safe Test**: `https://microsoft.com`
4. **Suspicious Test**: `https://amazon-verify.org`
5. **Safe Test**: `https://github.com`

---

## 📊 **What to Watch in Dashboard**

### **Expected Results:**
- **Safe URLs**: Should show as ✅ safe with low threat scores
- **Suspicious URLs**: May trigger 🚨 phishing detection
- **Request Counter**: Should increase with each test
- **Event Logs**: Should show detailed scan results

### **Dashboard Panels to Monitor:**
1. **🚨 Phishing Threats (1h)** - Should increment for detected threats
2. **📊 Total Requests (1h)** - Should increment for each scan
3. **🛡️ Security Timeline** - Should show activity spikes
4. **📋 Event Logs** - Should show detailed scan events

---

## 🚀 **Automated Testing Commands**

### **Run Full Test Suite:**
```bash
python test_urls.py
```

### **Quick Test (2 URLs per category):**
```bash
python test_urls.py
# Choose option 2
```

### **Interactive Testing:**
```bash
python test_urls.py
# Choose option 1, then select categories
```

---

## 🎯 **Testing Tips**

### **Best Practices:**
1. **Start with safe URLs** to verify system is working
2. **Test suspicious patterns** to see ML detection in action
3. **Monitor dashboard** in real-time during testing
4. **Wait 5-10 seconds** between tests to see updates
5. **Check event logs** for detailed analysis results

### **What to Look For:**
- **Confidence Scores**: Higher scores for suspicious URLs
- **Detection Methods**: ML vs Pattern-based detection
- **Response Times**: System performance metrics
- **Event Details**: JSON logs with full analysis

---

## 📈 **Expected Dashboard Behavior**

### **During Testing:**
- **Counters increase** with each scan
- **Timeline shows activity** spikes during testing
- **Logs stream** in real-time with scan results
- **Charts update** every 5 seconds

### **After Testing:**
- **Historical data** preserved for analysis
- **Trend analysis** available over time
- **Performance metrics** show system health
- **Security insights** from aggregated data

---

**🎉 Start testing now! Go to http://127.0.0.1:5000 and try these URLs while watching your dashboard at http://localhost:3000**
