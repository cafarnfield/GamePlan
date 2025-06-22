# Password Reset System

The GamePlan application includes a comprehensive password reset system that allows users to securely reset their passwords via email, following security best practices and providing a user-friendly experience.

## Overview

The password reset system provides a secure, user-friendly way for users to reset their passwords when they forget them. The system includes email integration, secure token management, and comprehensive security features.

## Features

### Core Functionality
- **Secure Token Generation**: Uses cryptographically secure random tokens
- **Email Integration**: Sends professional HTML and plain text reset emails
- **Token Expiration**: Tokens expire after 1 hour for security
- **One-Time Use**: Each token can only be used once
- **Rate Limiting**: Prevents abuse with configurable rate limits
- **Email Enumeration Protection**: Same response regardless of email existence
- **User Status Validation**: Only approved users can reset passwords

### Security Features
- **Secure Token Storage**: Tokens are stored securely in the database
- **Token Validation**: Comprehensive validation before password reset
- **Password Strength Requirements**: Enforces strong password policies
- **Audit Logging**: All password reset activities are logged
- **IP Tracking**: Tracks IP addresses for security monitoring
- **Automatic Cleanup**: Expired tokens are automatically cleaned up

## System Components

### 1. Database Schema Updates

#### User Model (`models/User.js`)
Added new fields to the User schema:
```javascript
// Password reset fields
resetToken: String,
resetTokenExpiry: Date,
resetTokenUsed: { type: Boolean, default: false }
```

#### Database Indexes
- `resetToken`: For efficient token lookups
- `resetTokenExpiry`: For cleanup operations

### 2. Email Service (`services/emailService.js`)

#### Features
- **Nodemailer Integration**: Professional email sending
- **HTML Templates**: Rich, responsive email templates
- **Plain Text Fallback**: Accessibility and compatibility
- **Configuration Validation**: Checks email settings on startup
- **Error Handling**: Comprehensive error logging and handling

#### Email Template Features
- **Responsive Design**: Works on all devices
- **Security Warnings**: Clear security information
- **Branding**: GamePlan branded templates
- **Accessibility**: Screen reader friendly

### 3. Token Management (`utils/tokenUtils.js`)

#### Token Operations
- **Generation**: Cryptographically secure 64-character tokens
- **Validation**: Comprehensive token validation
- **Expiration**: Automatic expiration handling
- **Cleanup**: Batch cleanup of expired tokens
- **Statistics**: Token usage statistics

#### Security Features
- **Secure Random Generation**: Uses Node.js crypto module
- **Database Consistency**: Atomic operations for token management
- **Logging**: Detailed security logging

### 4. Authentication Routes (`routes/auth.js`)

#### New Routes
- `GET /forgot-password`: Display password reset request form
- `POST /forgot-password`: Process password reset request
- `GET /reset-password/:token`: Display password reset form
- `POST /reset-password`: Process password reset

#### Security Features
- **Rate Limiting**: Configurable rate limits per IP
- **Input Validation**: Comprehensive input validation
- **CSRF Protection**: Built-in CSRF protection
- **Error Handling**: Secure error handling

### 5. User Interface

#### Views Created
- `views/forgotPassword.ejs`: Password reset request form
- `views/resetPassword.ejs`: Password reset form with strength indicator
- `views/resetSuccess.ejs`: Success confirmation page
- `views/resetExpired.ejs`: Expired/invalid token page

#### UI Features
- **Responsive Design**: Mobile-friendly interfaces
- **Password Strength Indicator**: Real-time password strength feedback
- **Form Validation**: Client-side and server-side validation
- **Accessibility**: WCAG compliant design
- **Security Notices**: Clear security information

### 6. Validation (`validators/authValidators.js`)

#### Password Reset Validators
- `validatePasswordResetRequest`: Email validation for reset requests
- `validatePasswordReset`: Password and token validation for reset

#### Security Features
- **XSS Protection**: Input sanitization
- **Strong Password Requirements**: Enforced password complexity
- **Token Validation**: Secure token format validation

## Configuration

### Environment Variables

#### Email Configuration
```bash
# Email service provider
EMAIL_SERVICE=smtp

# SMTP server settings
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_SECURE=false

# Email authentication
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# From address for outgoing emails
EMAIL_FROM=GamePlan <noreply@yourdomain.com>

# Password reset configuration
RESET_TOKEN_EXPIRY=3600000  # 1 hour in milliseconds
RESET_BASE_URL=https://yourdomain.com

# Email rate limiting (requests per hour)
EMAIL_RATE_LIMIT=10
```

#### Security Settings
- **Token Expiry**: Default 1 hour (3600000ms)
- **Rate Limiting**: Default 10 requests per hour per IP
- **Password Requirements**: 8+ chars, uppercase, lowercase, number, special char

## Installation and Setup

### 1. Install Dependencies
```bash
npm install nodemailer
```

### 2. Run Database Migration
```bash
node scripts/add-password-reset-fields.js
```

### 3. Configure Email Settings
Copy the email configuration from `.env.example` to your `.env` file and update with your email provider settings.

### 4. Test Email Configuration
Use the email service test function to verify your email setup:
```javascript
const emailService = require('./services/emailService');
await emailService.sendTestEmail('test@example.com');
```

## Usage

### For Users

#### Request Password Reset
1. Go to `/forgot-password`
2. Enter email address
3. Check email for reset link

#### Reset Password
1. Click link in email
2. Enter new password (must meet strength requirements)
3. Confirm new password
4. Submit form

#### Login with New Password
Use new password to log in

### For Administrators

#### Monitor Password Reset Activity
Check logs for password reset events:
```bash
grep "password reset" logs/combined.log
```

#### Token Statistics
Get token usage statistics:
```javascript
const TokenUtils = require('./utils/tokenUtils');
const stats = await TokenUtils.getTokenStatistics();
console.log(stats);
```

#### Cleanup Expired Tokens
Manually cleanup expired tokens:
```javascript
const TokenUtils = require('./utils/tokenUtils');
const cleaned = await TokenUtils.cleanupExpiredTokens();
console.log(`Cleaned up ${cleaned} expired tokens`);
```

## Security Considerations

### Best Practices Implemented
- **Token Expiration**: Short-lived tokens (1 hour)
- **One-Time Use**: Tokens are invalidated after use
- **Rate Limiting**: Prevents brute force attacks
- **Email Enumeration Protection**: Consistent responses
- **Secure Token Generation**: Cryptographically secure
- **Input Validation**: Comprehensive validation
- **Audit Logging**: Complete activity logging

### Additional Security Measures
- **HTTPS Required**: Always use HTTPS in production
- **Email Security**: Use app passwords, not account passwords
- **Database Security**: Secure database connections
- **Regular Cleanup**: Implement automated token cleanup

## API Documentation

### Password Reset Endpoints

#### POST /forgot-password
Request a password reset email.

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
- 200: Success message (always returned for security)
- 400: Validation error
- 429: Rate limit exceeded

#### GET /reset-password/:token
Display password reset form for valid token.

**Parameters:**
- `token`: Password reset token

**Response:**
- 200: Reset form displayed
- 400: Invalid or expired token

#### POST /reset-password
Process password reset with new password.

**Request Body:**
```json
{
  "token": "reset-token",
  "password": "newPassword123!",
  "confirmPassword": "newPassword123!"
}
```

**Response:**
- 200: Password reset successful
- 400: Validation error or invalid token

## Troubleshooting

### Common Issues

#### Email Not Sending
1. Check email configuration in `.env`
2. Verify SMTP credentials
3. Check firewall/network restrictions
4. Review email service logs

#### Token Validation Errors
1. Check token expiration time
2. Verify database connectivity
3. Check for token reuse
4. Review validation logs

#### Rate Limiting Issues
1. Adjust `EMAIL_RATE_LIMIT` setting
2. Check IP detection logic
3. Review rate limit logs
4. Consider IP whitelisting for testing

### Debugging

#### Enable Debug Logging
Set log level to debug in your environment:
```bash
LOG_LEVEL=debug
```

#### Check Email Service Status
```javascript
const emailService = require('./services/emailService');
console.log('Email service ready:', emailService.isReady());
```

#### Validate Token Manually
```javascript
const TokenUtils = require('./utils/tokenUtils');
const user = await TokenUtils.validateResetToken('your-token-here');
console.log('Token valid:', !!user);
```

## Maintenance

### Regular Tasks

#### Token Cleanup
Set up a cron job to clean expired tokens:
```bash
# Run daily at 2 AM
0 2 * * * cd /path/to/gameplan && node -e "require('./utils/tokenUtils').cleanupExpiredTokens()"
```

#### Monitor Email Delivery
Regularly check email delivery rates and bounce rates.

#### Review Security Logs
Regularly review password reset logs for suspicious activity.

### Future Enhancements
- **Two-Factor Authentication**: Add 2FA support
- **Password History**: Prevent password reuse
- **Account Lockout**: Implement account lockout after failed attempts
- **Email Templates**: Add more email template options
- **Analytics**: Add password reset analytics

## Testing

### Manual Testing Checklist
- [ ] Request password reset with valid email
- [ ] Request password reset with invalid email
- [ ] Use valid reset token
- [ ] Use expired reset token
- [ ] Use already used reset token
- [ ] Test rate limiting
- [ ] Test email delivery
- [ ] Test password strength validation
- [ ] Test responsive design
- [ ] Test accessibility features

## Related Documentation

- [User Approval System](../features/user-approval-system.md) - User registration and approval
- [Email Service](../operations/email-service.md) - Email configuration and troubleshooting
- [Security Features](../operations/security.md) - Security implementation details
- [Authentication](../operations/authentication.md) - Authentication system overview

## Support

For issues or questions about the password reset system:

1. Check this documentation
2. Review the troubleshooting section
3. Check application logs
4. Test email configuration
5. Verify database connectivity

## Changelog

### Version 1.0.0 (Initial Implementation)
- Complete password reset system
- Email integration with Nodemailer
- Secure token management
- Comprehensive UI/UX
- Security best practices
- Rate limiting and validation
- Audit logging and monitoring
- Database migration scripts
- Comprehensive documentation

This documentation covers the complete password reset system implementation for GamePlan. The system provides a secure, user-friendly way for users to reset their passwords while maintaining high security standards.
