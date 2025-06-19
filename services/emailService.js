const nodemailer = require('nodemailer');
const { logger } = require('../utils/logger');

/**
 * Email Service for GamePlan
 * Handles all email functionality including password reset emails
 */
class EmailService {
  constructor() {
    this.transporter = null;
    this.isConfigured = false;
    this.initializeTransporter();
  }

  /**
   * Initialize the email transporter based on environment configuration
   */
  initializeTransporter() {
    try {
      const emailConfig = {
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT) || 587,
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      };

      // Validate required configuration
      if (!emailConfig.host || !emailConfig.auth.user || !emailConfig.auth.pass) {
        logger.warn('Email service not configured - missing required environment variables');
        return;
      }

      this.transporter = nodemailer.createTransport(emailConfig);
      this.isConfigured = true;

      // Verify connection configuration
      this.verifyConnection();

      logger.info('Email service initialized successfully', {
        host: emailConfig.host,
        port: emailConfig.port,
        secure: emailConfig.secure,
        user: emailConfig.auth.user
      });

    } catch (error) {
      logger.error('Failed to initialize email service', {
        error: error.message,
        stack: error.stack
      });
    }
  }

  /**
   * Verify email service connection
   */
  async verifyConnection() {
    if (!this.isConfigured) {
      return false;
    }

    try {
      await this.transporter.verify();
      logger.info('Email service connection verified successfully');
      return true;
    } catch (error) {
      logger.error('Email service connection verification failed', {
        error: error.message
      });
      return false;
    }
  }

  /**
   * Send password reset email
   * @param {string} email - Recipient email address
   * @param {string} resetToken - Password reset token
   * @param {string} userName - User's name
   * @returns {Promise<boolean>} - Success status
   */
  async sendPasswordResetEmail(email, resetToken, userName) {
    if (!this.isConfigured) {
      logger.error('Cannot send password reset email - email service not configured');
      return false;
    }

    try {
      const resetUrl = `${process.env.RESET_BASE_URL}/reset-password/${resetToken}`;
      const expiryHours = Math.floor((process.env.RESET_TOKEN_EXPIRY || 3600000) / (1000 * 60 * 60));

      const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'GamePlan - Password Reset Request',
        html: this.getPasswordResetEmailTemplate(userName, resetUrl, expiryHours),
        text: this.getPasswordResetEmailText(userName, resetUrl, expiryHours)
      };

      const result = await this.transporter.sendMail(mailOptions);

      logger.info('Password reset email sent successfully', {
        to: email,
        messageId: result.messageId,
        userName: userName
      });

      return true;

    } catch (error) {
      logger.error('Failed to send password reset email', {
        error: error.message,
        stack: error.stack,
        to: email,
        userName: userName
      });

      return false;
    }
  }

  /**
   * Get HTML template for password reset email
   * @param {string} userName - User's name
   * @param {string} resetUrl - Password reset URL
   * @param {number} expiryHours - Token expiry in hours
   * @returns {string} - HTML email template
   */
  getPasswordResetEmailTemplate(userName, resetUrl, expiryHours) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GamePlan - Password Reset</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #ffffff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #007bff;
        }
        .header h1 {
            color: #007bff;
            margin: 0;
            font-size: 28px;
        }
        .content {
            margin-bottom: 30px;
        }
        .reset-button {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 5px;
            font-weight: bold;
            margin: 20px 0;
        }
        .reset-button:hover {
            background-color: #0056b3;
        }
        .warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 14px;
        }
        .url-fallback {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            word-break: break-all;
            font-family: monospace;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎮 GamePlan</h1>
        </div>
        
        <div class="content">
            <h2>Password Reset Request</h2>
            
            <p>Hello ${userName},</p>
            
            <p>We received a request to reset your password for your GamePlan account. If you made this request, click the button below to reset your password:</p>
            
            <div style="text-align: center;">
                <a href="${resetUrl}" class="reset-button">Reset My Password</a>
            </div>
            
            <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
            <div class="url-fallback">${resetUrl}</div>
            
            <div class="warning">
                <strong>⚠️ Important Security Information:</strong>
                <ul>
                    <li>This link will expire in ${expiryHours} hour${expiryHours !== 1 ? 's' : ''}</li>
                    <li>This link can only be used once</li>
                    <li>If you didn't request this password reset, please ignore this email</li>
                    <li>Never share this link with anyone</li>
                </ul>
            </div>
            
            <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
            
            <p>For security reasons, we recommend:</p>
            <ul>
                <li>Using a strong, unique password</li>
                <li>Not sharing your account credentials</li>
                <li>Logging out of shared computers</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>This is an automated message from GamePlan. Please do not reply to this email.</p>
            <p>If you need help, please contact our support team.</p>
        </div>
    </div>
</body>
</html>
    `;
  }

  /**
   * Get plain text version for password reset email
   * @param {string} userName - User's name
   * @param {string} resetUrl - Password reset URL
   * @param {number} expiryHours - Token expiry in hours
   * @returns {string} - Plain text email content
   */
  getPasswordResetEmailText(userName, resetUrl, expiryHours) {
    return `
GamePlan - Password Reset Request

Hello ${userName},

We received a request to reset your password for your GamePlan account.

To reset your password, please visit the following link:
${resetUrl}

IMPORTANT SECURITY INFORMATION:
- This link will expire in ${expiryHours} hour${expiryHours !== 1 ? 's' : ''}
- This link can only be used once
- If you didn't request this password reset, please ignore this email
- Never share this link with anyone

If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.

For security reasons, we recommend:
- Using a strong, unique password
- Not sharing your account credentials
- Logging out of shared computers

This is an automated message from GamePlan. Please do not reply to this email.
If you need help, please contact our support team.
    `;
  }

  /**
   * Send test email to verify configuration
   * @param {string} testEmail - Email address to send test to
   * @returns {Promise<boolean>} - Success status
   */
  async sendTestEmail(testEmail) {
    if (!this.isConfigured) {
      logger.error('Cannot send test email - email service not configured');
      return false;
    }

    try {
      const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: testEmail,
        subject: 'GamePlan - Email Service Test',
        html: `
          <h2>GamePlan Email Service Test</h2>
          <p>This is a test email to verify that the GamePlan email service is working correctly.</p>
          <p>If you received this email, the email configuration is working properly.</p>
          <p>Timestamp: ${new Date().toISOString()}</p>
        `,
        text: `
GamePlan Email Service Test

This is a test email to verify that the GamePlan email service is working correctly.
If you received this email, the email configuration is working properly.

Timestamp: ${new Date().toISOString()}
        `
      };

      const result = await this.transporter.sendMail(mailOptions);

      logger.info('Test email sent successfully', {
        to: testEmail,
        messageId: result.messageId
      });

      return true;

    } catch (error) {
      logger.error('Failed to send test email', {
        error: error.message,
        stack: error.stack,
        to: testEmail
      });

      return false;
    }
  }

  /**
   * Send password change notification email
   * @param {string} email - Recipient email address
   * @param {string} userName - User's name
   * @param {Object} changeDetails - Details about the password change
   * @returns {Promise<boolean>} - Success status
   */
  async sendPasswordChangeNotification(email, userName, changeDetails) {
    if (!this.isConfigured) {
      logger.error('Cannot send password change notification - email service not configured');
      return false;
    }

    try {
      const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'GamePlan - Password Changed',
        html: this.getPasswordChangeNotificationTemplate(userName, changeDetails),
        text: this.getPasswordChangeNotificationText(userName, changeDetails)
      };

      const result = await this.transporter.sendMail(mailOptions);

      logger.info('Password change notification sent successfully', {
        to: email,
        messageId: result.messageId,
        userName: userName,
        resetBy: changeDetails.resetBy
      });

      return true;

    } catch (error) {
      logger.error('Failed to send password change notification', {
        error: error.message,
        stack: error.stack,
        to: email,
        userName: userName
      });

      return false;
    }
  }

  /**
   * Get HTML template for password change notification
   * @param {string} userName - User's name
   * @param {Object} changeDetails - Details about the password change
   * @returns {string} - HTML email template
   */
  getPasswordChangeNotificationTemplate(userName, changeDetails) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GamePlan - Password Changed</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: #ffffff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 2px solid #007bff;
        }
        .header h1 {
            color: #007bff;
            margin: 0;
            font-size: 28px;
        }
        .content {
            margin-bottom: 30px;
        }
        .alert {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .alert.security {
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        .info-box {
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 14px;
        }
        .details-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .details-table th,
        .details-table td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .details-table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎮 GamePlan</h1>
        </div>
        
        <div class="content">
            <h2>Password Changed</h2>
            
            <p>Hello ${userName},</p>
            
            <div class="alert security">
                <strong>🔒 Security Notice:</strong> Your GamePlan account password has been changed by an administrator.
            </div>
            
            <p>Your password was reset by an administrator for the following reason:</p>
            <div class="info-box">
                <strong>Reason:</strong> ${changeDetails.reason || 'Administrative password reset'}
            </div>
            
            <table class="details-table">
                <tr>
                    <th>Changed By:</th>
                    <td>${changeDetails.resetBy}</td>
                </tr>
                <tr>
                    <th>Date & Time:</th>
                    <td>${changeDetails.resetAt.toLocaleString()}</td>
                </tr>
                <tr>
                    <th>Account:</th>
                    <td>${userName}</td>
                </tr>
                ${changeDetails.forceChange ? `
                <tr>
                    <th>Action Required:</th>
                    <td><strong>You must change your password on next login</strong></td>
                </tr>
                ` : ''}
            </table>
            
            ${changeDetails.forceChange ? `
            <div class="alert">
                <strong>⚠️ Action Required:</strong>
                <p>You will be required to change your password when you next log in to GamePlan. Please choose a strong, unique password that you haven't used before.</p>
            </div>
            ` : ''}
            
            <h3>🔐 Security Recommendations:</h3>
            <ul>
                <li>Use a strong, unique password for your GamePlan account</li>
                <li>Don't share your password with anyone</li>
                <li>Log out of shared or public computers</li>
                <li>Contact support if you didn't expect this change</li>
            </ul>
            
            <div class="alert security">
                <strong>⚠️ If you didn't expect this password change:</strong>
                <p>Please contact our support team immediately. This could indicate unauthorized access to your account.</p>
            </div>
        </div>
        
        <div class="footer">
            <p>This is an automated security notification from GamePlan.</p>
            <p>If you need help, please contact our support team.</p>
        </div>
    </div>
</body>
</html>
    `;
  }

  /**
   * Get plain text version for password change notification
   * @param {string} userName - User's name
   * @param {Object} changeDetails - Details about the password change
   * @returns {string} - Plain text email content
   */
  getPasswordChangeNotificationText(userName, changeDetails) {
    return `
GamePlan - Password Changed

Hello ${userName},

SECURITY NOTICE: Your GamePlan account password has been changed by an administrator.

Details:
- Changed By: ${changeDetails.resetBy}
- Date & Time: ${changeDetails.resetAt.toLocaleString()}
- Reason: ${changeDetails.reason || 'Administrative password reset'}
- Account: ${userName}
${changeDetails.forceChange ? '- Action Required: You must change your password on next login' : ''}

${changeDetails.forceChange ? `
ACTION REQUIRED:
You will be required to change your password when you next log in to GamePlan. 
Please choose a strong, unique password that you haven't used before.
` : ''}

SECURITY RECOMMENDATIONS:
- Use a strong, unique password for your GamePlan account
- Don't share your password with anyone
- Log out of shared or public computers
- Contact support if you didn't expect this change

WARNING: If you didn't expect this password change, please contact our support team immediately. This could indicate unauthorized access to your account.

This is an automated security notification from GamePlan.
If you need help, please contact our support team.
    `;
  }

  /**
   * Check if email service is properly configured
   * @returns {boolean} - Configuration status
   */
  isReady() {
    return this.isConfigured;
  }
}

// Create and export singleton instance
const emailService = new EmailService();

module.exports = emailService;
