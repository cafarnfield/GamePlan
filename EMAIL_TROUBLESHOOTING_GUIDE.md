# Email Troubleshooting Guide

## 🚀 Quick Start

To troubleshoot email issues, run the diagnostic tool:

```bash
# Test with your own email
node test-email-system.js your-email@domain.com

# Or test with the configured email user
node test-email-system.js
```

## 🔍 Common Issues & Solutions

### 1. "Cannot find module 'nodemailer'"

**Problem:** Missing dependency
**Solution:**
```bash
npm install
```

### 2. "Environment variables not properly configured"

**Problem:** Missing or placeholder values in `.env`
**Solution:** Update your `.env` file with real values:

```bash
EMAIL_SERVICE=smtp
EMAIL_HOST=smtp.office365.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your-actual-email@domain.com
EMAIL_PASS=your-actual-password
EMAIL_FROM=GamePlan <your-actual-email@domain.com>
RESET_BASE_URL=https://yourdomain.com
```

### 3. "Connection timeout" / "ECONNREFUSED"

**Problem:** Network/firewall blocking SMTP
**Solutions:**
- Check if port 587 is blocked by firewall
- Try from a different network
- Contact IT department about SMTP access
- Verify EMAIL_HOST is correct (`smtp.office365.com` for Exchange)

### 4. "Invalid login" / "Authentication failed"

**Problem:** Wrong credentials or Exchange security settings
**Solutions:**

#### For Exchange Online:
1. **Check if MFA is enabled:**
   - If yes, create an App Password
   - Use App Password instead of regular password

2. **Enable SMTP AUTH in Exchange:**
   - Go to Exchange Admin Center
   - Recipients → Mailboxes → Select user → Mail flow settings
   - Enable "Authenticated SMTP"

3. **Check credentials:**
   - Verify EMAIL_USER is your full email address
   - Verify EMAIL_PASS is correct
   - Try logging into Outlook web to confirm credentials

### 5. "Mailbox unavailable"

**Problem:** Email address doesn't exist or is disabled
**Solutions:**
- Verify EMAIL_USER email address exists
- Check if mailbox is enabled in Exchange
- Ensure user has permission to send emails

### 6. Emails not received (but no errors)

**Problem:** Emails going to spam or delivery issues
**Solutions:**
- Check spam/junk folders
- Verify EMAIL_FROM address is valid
- Check Exchange message trace logs
- Ensure recipient email is correct

## 🔧 Step-by-Step Troubleshooting

### Step 1: Run Diagnostic Tool
```bash
node test-email-system.js your-email@domain.com
```

### Step 2: Check Each Component

1. **Environment Variables** ✅
   - All required variables set
   - No placeholder values
   - Correct format

2. **Network Connectivity** 🌐
   - Can connect to smtp.office365.com:587
   - No firewall blocking

3. **Email Service Loading** 📧
   - Service loads without errors
   - Configuration validated

4. **SMTP Authentication** 🔐
   - Credentials accepted
   - Connection established

5. **Test Email Sending** 📮
   - Email sent successfully
   - Check inbox/spam folder

### Step 3: Fix Issues Found

Based on diagnostic results, follow the solutions above.

## 📋 Exchange Online Specific Setup

### Required Settings:
```bash
EMAIL_HOST=smtp.office365.com
EMAIL_PORT=587
EMAIL_SECURE=false
```

### Authentication Options:

#### Option 1: Regular Password (if no MFA)
```bash
EMAIL_USER=your-email@domain.com
EMAIL_PASS=your-regular-password
```

#### Option 2: App Password (if MFA enabled)
1. Go to Microsoft 365 Security settings
2. Create App Password for "GamePlan"
3. Use generated password:
```bash
EMAIL_PASS=generated-app-password
```

### Exchange Admin Requirements:
- SMTP AUTH must be enabled for the user
- User must have "Send As" permissions
- Mailbox must be active and not disabled

## 🧪 Manual Testing

### Test SMTP Connection:
```bash
telnet smtp.office365.com 587
```

### Test with Nodemailer directly:
```javascript
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransporter({
  host: 'smtp.office365.com',
  port: 587,
  secure: false,
  auth: {
    user: 'your-email@domain.com',
    pass: 'your-password'
  }
});

transporter.verify()
  .then(() => console.log('✅ SMTP connection successful'))
  .catch(err => console.error('❌ SMTP connection failed:', err.message));
```

## 📞 Getting Help

### Information to Gather:
1. **Error messages** from diagnostic tool
2. **Exchange admin settings** (SMTP AUTH status)
3. **Network environment** (corporate/home)
4. **MFA status** on the email account
5. **Firewall/antivirus** software in use

### Logs to Check:
- Application startup logs
- Email service initialization messages
- SMTP connection attempts
- Send operation results

### Exchange Admin Tasks:
- Enable SMTP AUTH for user
- Check message trace logs
- Verify mailbox permissions
- Review conditional access policies

## 🔒 Security Best Practices

1. **Use App Passwords** when MFA is enabled
2. **Don't use admin accounts** for application emails
3. **Create dedicated service account** for email sending
4. **Regularly rotate passwords**
5. **Monitor email logs** for suspicious activity
6. **Use HTTPS** for reset URLs in production

## 📈 Monitoring

### Health Checks:
- Email service initialization status
- SMTP connection verification
- Send success/failure rates
- Token generation and usage

### Alerts to Set Up:
- Email service initialization failures
- High authentication failure rates
- Unusual sending patterns
- Token expiration cleanup issues

---

*Keep this guide updated as you encounter and solve new email issues.*
