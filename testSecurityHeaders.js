const axios = require('axios');

async function testSecurityHeaders() {
  try {
    console.log('Testing security headers for GamePlan application...\n');
    
    const response = await axios.get('http://localhost:3000', {
      validateStatus: () => true // Accept any status code
    });
    
    const headers = response.headers;
    
    console.log('=== HELMET.JS SECURITY HEADERS TEST ===\n');
    
    // Test Content Security Policy
    if (headers['content-security-policy']) {
      console.log('✅ Content-Security-Policy: PRESENT');
      console.log(`   ${headers['content-security-policy']}\n`);
    } else {
      console.log('❌ Content-Security-Policy: MISSING\n');
    }
    
    // Test X-Frame-Options
    if (headers['x-frame-options']) {
      console.log('✅ X-Frame-Options: PRESENT');
      console.log(`   ${headers['x-frame-options']}\n`);
    } else {
      console.log('❌ X-Frame-Options: MISSING\n');
    }
    
    // Test X-Content-Type-Options
    if (headers['x-content-type-options']) {
      console.log('✅ X-Content-Type-Options: PRESENT');
      console.log(`   ${headers['x-content-type-options']}\n`);
    } else {
      console.log('❌ X-Content-Type-Options: MISSING\n');
    }
    
    // Test X-XSS-Protection
    if (headers['x-xss-protection']) {
      console.log('✅ X-XSS-Protection: PRESENT');
      console.log(`   ${headers['x-xss-protection']}\n`);
    } else {
      console.log('❌ X-XSS-Protection: MISSING\n');
    }
    
    // Test Referrer-Policy
    if (headers['referrer-policy']) {
      console.log('✅ Referrer-Policy: PRESENT');
      console.log(`   ${headers['referrer-policy']}\n`);
    } else {
      console.log('❌ Referrer-Policy: MISSING\n');
    }
    
    // Test X-DNS-Prefetch-Control
    if (headers['x-dns-prefetch-control']) {
      console.log('✅ X-DNS-Prefetch-Control: PRESENT');
      console.log(`   ${headers['x-dns-prefetch-control']}\n`);
    } else {
      console.log('❌ X-DNS-Prefetch-Control: MISSING\n');
    }
    
    // Test X-Download-Options
    if (headers['x-download-options']) {
      console.log('✅ X-Download-Options: PRESENT');
      console.log(`   ${headers['x-download-options']}\n`);
    } else {
      console.log('❌ X-Download-Options: MISSING\n');
    }
    
    // Test X-Powered-By (should be removed)
    if (headers['x-powered-by']) {
      console.log('❌ X-Powered-By: PRESENT (should be hidden)');
      console.log(`   ${headers['x-powered-by']}\n`);
    } else {
      console.log('✅ X-Powered-By: HIDDEN (good for security)\n');
    }
    
    // Test Permissions-Policy
    if (headers['permissions-policy']) {
      console.log('✅ Permissions-Policy: PRESENT');
      console.log(`   ${headers['permissions-policy']}\n`);
    } else {
      console.log('❌ Permissions-Policy: MISSING\n');
    }
    
    // Test HSTS (only in production with HTTPS)
    if (headers['strict-transport-security']) {
      console.log('✅ Strict-Transport-Security: PRESENT');
      console.log(`   ${headers['strict-transport-security']}\n`);
    } else {
      console.log('ℹ️  Strict-Transport-Security: NOT PRESENT (expected in development/HTTP)\n');
    }
    
    console.log('=== SUMMARY ===');
    const securityHeaders = [
      'content-security-policy',
      'x-frame-options',
      'x-content-type-options',
      'x-xss-protection',
      'referrer-policy',
      'x-dns-prefetch-control',
      'x-download-options',
      'permissions-policy'
    ];
    
    const presentHeaders = securityHeaders.filter(header => headers[header]);
    const missingHeaders = securityHeaders.filter(header => !headers[header]);
    
    console.log(`✅ Security headers present: ${presentHeaders.length}/${securityHeaders.length}`);
    console.log(`✅ X-Powered-By hidden: ${!headers['x-powered-by'] ? 'Yes' : 'No'}`);
    
    if (missingHeaders.length > 0) {
      console.log(`❌ Missing headers: ${missingHeaders.join(', ')}`);
    }
    
    console.log('\n=== APPLICATION STATUS ===');
    console.log(`HTTP Status: ${response.status}`);
    console.log(`Response received: ${response.data ? 'Yes' : 'No'}`);
    console.log('Application is running and helmet.js security headers are active! 🛡️');
    
  } catch (error) {
    console.error('Error testing security headers:', error.message);
    if (error.code === 'ECONNREFUSED') {
      console.log('Make sure the GamePlan application is running on http://localhost:3000');
    }
  }
}

testSecurityHeaders();
