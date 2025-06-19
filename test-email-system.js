#!/usr/bin/env node

/**
 * Email System Diagnostic Tool
 * 
 * This script helps troubleshoot email configuration and connectivity issues
 * for the GamePlan password reset system.
 */

const path = require('path');
require('dotenv').config();

// Color codes for console output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logSection(title) {
  console.log('\n' + '='.repeat(60));
  log(title, 'cyan');
  console.log('='.repeat(60));
}

function logStep(step, message) {
  log(`${step}. ${message}`, 'blue');
}

function logSuccess(message) {
  log(`✅ ${message}`, 'green');
}

function logWarning(message) {
  log(`⚠️  ${message}`, 'yellow');
}

function logError(message) {
  log(`❌ ${message}`, 'red');
}

async function checkEnvironmentVariables() {
  logSection('📋 CHECKING ENVIRONMENT VARIABLES');
  
  const requiredVars = [
    'EMAIL_SERVICE',
    'EMAIL_HOST',
    'EMAIL_PORT',
    'EMAIL_USER',
    'EMAIL_PASS',
    'EMAIL_FROM'
  ];
  
  const optionalVars = [
    'EMAIL_SECURE',
    'RESET_TOKEN_EXPIRY',
    'RESET_BASE_URL',
    'EMAIL_RATE_LIMIT'
  ];
  
  let allRequired = true;
  
  logStep(1, 'Checking required email variables');
  requiredVars.forEach(varName => {
    const value = process.env[varName];
    if (!value) {
      logError(`${varName} is not set`);
      allRequired = false;
    } else if (value.includes('your-') || value.includes('yourdomain')) {
      logWarning(`${varName} contains placeholder value: ${value}`);
      allRequired = false;
    } else {
      logSuccess(`${varName} is set`);
    }
  });
  
  logStep(2, 'Checking optional email variables');
  optionalVars.forEach(varName => {
    const value = process.env[varName];
    if (value) {
      logSuccess(`${varName} = ${value}`);
    } else {
      log(`   ${varName} not set (using default)`, 'yellow');
    }
  });
  
  return allRequired;
}

async function testNetworkConnectivity() {
  logSection('🌐 TESTING NETWORK CONNECTIVITY');
  
  const net = require('net');
  const host = process.env.EMAIL_HOST;
  const port = parseInt(process.env.EMAIL_PORT);
  
  logStep(1, `Testing connection to ${host}:${port}`);
  
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timeout = 10000; // 10 seconds
    
    socket.setTimeout(timeout);
    
    socket.on('connect', () => {
      logSuccess(`Successfully connected to ${host}:${port}`);
      socket.destroy();
      resolve(true);
    });
    
    socket.on('timeout', () => {
      logError(`Connection timeout to ${host}:${port} (${timeout}ms)`);
      socket.destroy();
      resolve(false);
    });
    
    socket.on('error', (err) => {
      logError(`Connection failed to ${host}:${port}: ${err.message}`);
      resolve(false);
    });
    
    socket.connect(port, host);
  });
}

async function testEmailService() {
  logSection('📧 TESTING EMAIL SERVICE');
  
  try {
    logStep(1, 'Loading email service');
    const emailService = require('./services/emailService');
    logSuccess('Email service loaded successfully');
    
    logStep(2, 'Checking email service readiness');
    if (emailService.isReady && emailService.isReady()) {
      logSuccess('Email service is ready');
    } else {
      logWarning('Email service readiness check not available or failed');
    }
    
    return emailService;
  } catch (error) {
    logError(`Failed to load email service: ${error.message}`);
    return null;
  }
}

async function testSMTPAuthentication() {
  logSection('🔐 TESTING SMTP AUTHENTICATION');
  
  const nodemailer = require('nodemailer');
  
  const config = {
    service: process.env.EMAIL_SERVICE,
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  };
  
  logStep(1, 'Creating SMTP transporter');
  const transporter = nodemailer.createTransport(config);
  
  logStep(2, 'Verifying SMTP connection and authentication');
  
  try {
    await transporter.verify();
    logSuccess('SMTP authentication successful');
    return true;
  } catch (error) {
    logError(`SMTP authentication failed: ${error.message}`);
    
    // Provide specific guidance based on error type
    if (error.message.includes('Invalid login')) {
      logWarning('This usually means:');
      console.log('   - Wrong username or password');
      console.log('   - MFA is enabled (need app password)');
      console.log('   - SMTP AUTH is disabled in Exchange');
    } else if (error.message.includes('Connection timeout')) {
      logWarning('This usually means:');
      console.log('   - Firewall blocking port 587');
      console.log('   - Network connectivity issues');
      console.log('   - Wrong SMTP server address');
    }
    
    return false;
  }
}

async function sendTestEmail() {
  logSection('📮 SENDING TEST EMAIL');
  
  const testEmail = process.argv[2] || process.env.EMAIL_USER;
  
  if (!testEmail) {
    logError('No test email address provided');
    console.log('Usage: node test-email-system.js test@example.com');
    return false;
  }
  
  logStep(1, `Sending test email to: ${testEmail}`);
  
  try {
    const emailService = require('./services/emailService');
    
    if (emailService.sendTestEmail) {
      await emailService.sendTestEmail(testEmail);
      logSuccess('Test email sent successfully');
      log('Check your inbox (and spam folder) for the test email', 'yellow');
      return true;
    } else {
      // Fallback: send a simple test email
      const nodemailer = require('nodemailer');
      
      const config = {
        service: process.env.EMAIL_SERVICE,
        host: process.env.EMAIL_HOST,
        port: parseInt(process.env.EMAIL_PORT),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
          user: process.env.EMAIL_USER,
          pass: process.env.EMAIL_PASS
        }
      };
      
      const transporter = nodemailer.createTransport(config);
      
      const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: testEmail,
        subject: 'GamePlan Email System Test',
        text: 'This is a test email from the GamePlan password reset system. If you received this, your email configuration is working correctly!',
        html: `
          <h2>🎮 GamePlan Email Test</h2>
          <p>This is a test email from the GamePlan password reset system.</p>
          <p><strong>If you received this, your email configuration is working correctly!</strong></p>
          <hr>
          <p><small>Test sent at: ${new Date().toISOString()}</small></p>
        `
      };
      
      await transporter.sendMail(mailOptions);
      logSuccess('Test email sent successfully');
      log('Check your inbox (and spam folder) for the test email', 'yellow');
      return true;
    }
  } catch (error) {
    logError(`Failed to send test email: ${error.message}`);
    return false;
  }
}

async function runDiagnostics() {
  log('🔍 GamePlan Email System Diagnostic Tool', 'bright');
  log('This tool will help diagnose email configuration issues\n', 'cyan');
  
  const results = {
    envVars: false,
    network: false,
    service: false,
    auth: false,
    testEmail: false
  };
  
  // Step 1: Check environment variables
  results.envVars = await checkEnvironmentVariables();
  
  if (!results.envVars) {
    logError('Environment variables are not properly configured. Please fix these issues first.');
    return;
  }
  
  // Step 2: Test network connectivity
  results.network = await testNetworkConnectivity();
  
  if (!results.network) {
    logError('Network connectivity failed. Check firewall and network settings.');
    return;
  }
  
  // Step 3: Test email service loading
  const emailService = await testEmailService();
  results.service = !!emailService;
  
  // Step 4: Test SMTP authentication
  results.auth = await testSMTPAuthentication();
  
  if (!results.auth) {
    logError('SMTP authentication failed. Check credentials and Exchange settings.');
    return;
  }
  
  // Step 5: Send test email
  results.testEmail = await sendTestEmail();
  
  // Summary
  logSection('📊 DIAGNOSTIC SUMMARY');
  
  Object.entries(results).forEach(([test, passed]) => {
    if (passed) {
      logSuccess(`${test}: PASSED`);
    } else {
      logError(`${test}: FAILED`);
    }
  });
  
  if (Object.values(results).every(r => r)) {
    log('\n🎉 All tests passed! Your email system should be working correctly.', 'green');
  } else {
    log('\n❌ Some tests failed. Please address the issues above.', 'red');
  }
}

// Handle missing nodemailer gracefully
try {
  require('nodemailer');
} catch (error) {
  logError('nodemailer is not installed. Please run: npm install');
  process.exit(1);
}

// Run diagnostics
runDiagnostics().catch(error => {
  logError(`Diagnostic tool crashed: ${error.message}`);
  console.error(error);
  process.exit(1);
});
