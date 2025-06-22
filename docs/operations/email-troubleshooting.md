# Email Troubleshooting Guide

This guide provides comprehensive troubleshooting steps for email-related issues in GamePlan, particularly focusing on password reset functionality and SMTP configuration.

## Overview

GamePlan uses email for password reset functionality and user notifications. This guide covers common email configuration issues, SMTP troubleshooting, and Exchange Online specific setup requirements.

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
**Root Cause:** Email dependencies not installed

**Solution:**
```bash
npm install
```

### 2. "Environment variables not properly configured"

**Problem:** Missing or placeholder values in `.env`
**Root Cause:** Email configuration not properly set up

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
**Root Cause:** Network connectivity issues or firewall restrictions

**Solutions:**
- Check if port 587 is blocked by firewall
- Try from a different network
- Contact IT department about SMTP access
- Verify EMAIL_HOST is correct (`smtp.office365.com` for Exchange)

### 4. "Invalid login" / "Authentication failed"

**Problem:** Wrong credentials or Exchange security settings
**Root Cause:** Authentication configuration issues

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
**Root Cause:** Mailbox configuration issues

**Solutions:**
- Verify EMAIL_USER email address exists
- Check if mailbox is enabled in Exchange
- Ensure user has permission to send emails

### 6. Emails not received (but no errors)

**Problem:** Emails going to spam or delivery issues
**Root Cause:** Email delivery or filtering issues

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

## Email Service Configuration

### Environment Variables

#### Required Email Variables
```bash
# Email service configuration
EMAIL_SERVICE=smtp
EMAIL_HOST=smtp.office365.com
EMAIL_PORT=587
EMAIL_SECURE=false

# Authentication
EMAIL_USER=your-email@domain.com
EMAIL_PASS=your-password

# From address
EMAIL_FROM=GamePlan <your-email@domain.com>

# Password reset configuration
RESET_BASE_URL=https://yourdomain.com
RESET_TOKEN_EXPIRY=3600000  # 1 hour
EMAIL_RATE_LIMIT=10         # Per hour per IP
```

#### Optional Email Variables
```bash
# Email templates
EMAIL_TEMPLATE_PATH=./templates/email
EMAIL_LOGO_URL=https://yourdomain.com/logo.png

# SMTP debugging
EMAIL_DEBUG=false
EMAIL_LOGGER=false
```

### Email Service Providers

#### Gmail Configuration
```bash
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your-gmail@gmail.com
EMAIL_PASS=your-app-password  # Use App Password, not regular password
```

#### Outlook/Hotmail Configuration
```bash
EMAIL_HOST=smtp-mail.outlook.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your-email@outlook.com
EMAIL_PASS=your-password
```

#### Custom SMTP Configuration
```bash
EMAIL_HOST=mail.yourdomain.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=noreply@yourdomain.com
EMAIL_PASS=your-smtp-password
```

## Password Reset Email Flow

### 1. User Requests Password Reset
- User enters email address
- System validates email exists and user is approved
- Rate limiting prevents abuse

### 2. Token Generation
- Cryptographically secure token generated
- Token stored in database with expiration
- One-time use token prevents reuse

### 3. Email Sending
- HTML and plain text email templates
- Secure reset link with token
- Professional branding and styling

### 4. Token Validation
- User clicks link in email
- Token validated for existence and expiration
- User redirected to password reset form

### 5. Password Reset
- New password validated for strength
- Token marked as used
- User notified of successful reset

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

### Email Security
1. **Use App Passwords** when MFA is enabled
2. **Don't use admin accounts** for application emails
3. **Create dedicated service account** for email sending
4. **Regularly rotate passwords**
5. **Monitor email logs** for suspicious activity
6. **Use HTTPS** for reset URLs in production

### Token Security
1. **Short expiration times** (1 hour default)
2. **One-time use tokens** prevent replay attacks
3. **Secure token generation** using crypto module
4. **Rate limiting** prevents brute force attacks
5. **Email enumeration protection** consistent responses

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

### Metrics to Track:
- Password reset request volume
- Email delivery success rates
- Token usage patterns
- Authentication failure rates

## Debugging Commands

### Check Email Service Status
```bash
# Check if email service is ready
curl http://localhost:3000/api/health

# Test email configuration
node test-email-system.js

# Check email service logs
docker compose logs gameplan-app | grep -i email
```

### Validate Email Configuration
```bash
# Check environment variables
echo $EMAIL_HOST
echo $EMAIL_USER
echo $EMAIL_FROM

# Test SMTP connection
telnet $EMAIL_HOST $EMAIL_PORT
```

### Monitor Email Activity
```bash
# Check password reset logs
grep "password reset" logs/combined.log

# Monitor email sending
grep "email sent" logs/combined.log

# Check for email errors
grep "email error" logs/combined.log
```

## Common Error Patterns

### SMTP Errors
- **Connection refused**: Check host and port
- **Authentication failed**: Verify credentials
- **TLS errors**: Check EMAIL_SECURE setting
- **Timeout errors**: Check network connectivity

### Configuration Errors
- **Missing variables**: Check .env file
- **Invalid format**: Verify email addresses
- **Wrong ports**: Check provider documentation
- **Security settings**: Verify SMTP AUTH enabled

### Application Errors
- **Service not ready**: Check initialization
- **Template errors**: Verify email templates
- **Rate limiting**: Check request frequency
- **Token errors**: Check database connectivity

## Related Documentation

- [Password Reset System](../features/password-reset-system.md) - Password reset implementation
- [Environment Validation](../operations/environment-validation.md) - Configuration validation
- [Troubleshooting](../operations/troubleshooting.md) - General troubleshooting
- [Health Monitoring](../features/health-monitoring.md) - System monitoring

## Support

For email-related issues:

1. Run the email diagnostic tool first
2. Check the troubleshooting steps above
3. Verify SMTP configuration with your email provider
4. Test with a simple email client to isolate issues
5. Check application logs for detailed error messages

*Keep this guide updated as you encounter and solve new email issues.*
