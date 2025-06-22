const fetch = require('node-fetch');
const axios = require('axios');

async function testUpdateAlert() {
  try {
    // Create a new event with a Steam App ID
    console.log('Creating a new event with Steam App ID...');
    const eventResponse = await fetch('http://localhost:3000/event/new', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        name: 'Test Event',
        gameId: '68449fe3290b7d75f013790a',
        description: 'Test Event',
        playerLimit: '3',
        date: '2025-06-10T19:00:00',
        steamAppId: '570'
      })
    });

    console.log('Event response status:', eventResponse.status);
    console.log('Event response headers:', eventResponse.headers);

    if (!eventResponse.ok) {
      const errorText = await eventResponse.text();
      throw new Error(`Error creating event: ${eventResponse.statusText}. Response: ${errorText}`);
    }

    const eventData = await eventResponse.json();
    console.log('Event data:', eventData);
    const eventId = eventData._id;

    // Check the event page for the update alert
    console.log('Checking event page for update alert...');
    const eventPageResponse = await fetch(`http://localhost:3000/event/${eventId}`);
    const eventPageText = await eventPageResponse.text();

    console.log('Event page content:', eventPageText);

    // Check for updates using the Steam API
    console.log('Checking for updates using the Steam API...');
    const updateResponse = await axios.get(`http://localhost:3000/check-updates/570`);
    console.log('Update response:', updateResponse.data);
  } catch (error) {
    console.error('Error testing update alert:', error);
  }
}

testUpdateAlert();
