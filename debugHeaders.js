const axios = require('axios');

async function debugHeaders() {
  try {
    console.log('Debugging all headers sent by GamePlan application...\n');
    
    const response = await axios.get('http://localhost:3000', {
      validateStatus: () => true // Accept any status code
    });
    
    const headers = response.headers;
    
    console.log('=== ALL RESPONSE HEADERS ===');
    Object.keys(headers).forEach(header => {
      console.log(`${header}: ${headers[header]}`);
    });
    
    console.log('\n=== SECURITY-RELATED HEADERS ===');
    const securityHeaders = [
      'content-security-policy',
      'x-frame-options', 
      'x-content-type-options',
      'x-xss-protection',
      'referrer-policy',
      'x-dns-prefetch-control',
      'x-download-options',
      'permissions-policy',
      'feature-policy', // Old name for permissions-policy
      'strict-transport-security',
      'x-powered-by'
    ];
    
    securityHeaders.forEach(header => {
      if (headers[header]) {
        console.log(`✅ ${header}: ${headers[header]}`);
      } else {
        console.log(`❌ ${header}: NOT PRESENT`);
      }
    });
    
  } catch (error) {
    console.error('Error:', error.message);
  }
}

debugHeaders();
