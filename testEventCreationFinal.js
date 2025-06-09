const axios = require('axios');

async function testEventCreation() {
  try {
    console.log('Testing event creation with fixed form validation...');
    
    // Test data for event creation
    const eventData = {
      name: 'Test Event - Final Fix',
      gameId: '68449fe3290b7d75f013790a', // R.E.P.O. game ID
      description: 'Testing the completely fixed event creation functionality',
      playerLimit: 4,
      date: '2025-06-11T20:00',
      steamAppId: '', // Optional field, left empty
      platforms: ['PC'],
      extensions: '[]' // Empty extensions array
    };

    console.log('Sending POST request to create event...');
    console.log('Event data:', eventData);

    const response = await axios.post('http://localhost:3000/event/new', eventData, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      // Convert object to URL-encoded format
      transformRequest: [(data) => {
        return Object.keys(data)
          .map(key => `${encodeURIComponent(key)}=${encodeURIComponent(data[key])}`)
          .join('&');
      }]
    });

    console.log('✅ Event creation successful!');
    console.log('Response status:', response.status);
    console.log('Response headers:', response.headers);
    
    // Check if we got redirected (which would indicate success)
    if (response.status === 200 && response.request.res.responseUrl) {
      console.log('✅ Redirected to:', response.request.res.responseUrl);
    }

  } catch (error) {
    if (error.response) {
      console.log('❌ Event creation failed');
      console.log('Status:', error.response.status);
      console.log('Status text:', error.response.statusText);
      console.log('Response data:', error.response.data);
    } else if (error.request) {
      console.log('❌ No response received');
      console.log('Request error:', error.request);
    } else {
      console.log('❌ Error setting up request');
      console.log('Error:', error.message);
    }
  }
}

// Run the test
testEventCreation();
