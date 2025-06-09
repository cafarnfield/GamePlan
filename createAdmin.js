const axios = require('axios');
const fs = require('fs');
const FormData = require('form-data');
const tough = require('tough-cookie');
const { CookieJar } = tough;

async function createAdmin() {
  try {
    // Create a cookie jar to store cookies
    const jar = new CookieJar();

    // First, register a new user
    const registerResponse = await axios.post('http://localhost:3000/register', {
      name: 'Admin User',
      email: 'admin@example.com',
      password: 'admin123',
      gameNickname: 'AdminNick'
    }, { withCredentials: true });

    // Save cookies from registration
    jar.setCookie(registerResponse.headers['set-cookie'][0], 'http://localhost:3000');

    console.log('Registration response status:', registerResponse.status);
    console.log('Registration response data:', registerResponse.data);

    // Then, set the user as admin
    const setupAdminResponse = await axios.post('http://localhost:3000/setup-admin', {
      email: 'admin@example.com'
    }, {
      withCredentials: true,
      headers: { Cookie: jar.getCookieString('http://localhost:3000') }
    });

    // Save cookies from setup-admin
    jar.setCookie(setupAdminResponse.headers['set-cookie'][0], 'http://localhost:3000');

    console.log('Setup admin response status:', setupAdminResponse.status);
    console.log('Setup admin response data:', setupAdminResponse.data);

    console.log('Admin user created and set up successfully');

    // Log in as the admin user
    const loginResponse = await axios.post('http://localhost:3000/login', {
      email: 'admin@example.com',
      password: 'admin123'
    }, {
      withCredentials: true,
      headers: { Cookie: jar.getCookieString('http://localhost:3000') }
    });

    // Save cookies from login
    jar.setCookie(loginResponse.headers['set-cookie'][0], 'http://localhost:3000');

    console.log('Login response status:', loginResponse.status);
    console.log('Login response data:', loginResponse.data);

    console.log('Logged in as admin');

    // Set the user as admin again after login
    const setupAdminAfterLoginResponse = await axios.post('http://localhost:3000/setup-admin', {
      email: 'admin@example.com'
    }, {
      withCredentials: true,
      headers: {
        Cookie: jar.getCookieString('http://localhost:3000'),
        'Content-Type': 'application/json'
      }
    });

    console.log('Setup admin after login response status:', setupAdminAfterLoginResponse.status);
    console.log('Setup admin after login response data:', setupAdminAfterLoginResponse.data);

    // Create a new game
    const gameResponse = await axios.post('http://localhost:3000/admin/add-game', {
      name: 'Test Game',
      description: 'Test Game Description'
    }, {
      withCredentials: true,
      headers: {
        Cookie: jar.getCookieString('http://localhost:3000'),
        'Content-Type': 'application/json'
      }
    });

    console.log('Game creation response status:', gameResponse.status);

    // Create a new event using the newly created game
    const eventResponse = await axios.post('http://localhost:3000/event/new', {
      name: 'Test Event',
      gameId: '6844802264a5e0a1e0f1b26e', // Use the hardcoded game ID for now
      description: 'Test Description',
      playerLimit: 10,
      date: '2025-06-07T18:50:06.030Z',
      extensions: '[]',
      platforms: ['PC', 'PlayStation']
    }, {
      withCredentials: true,
      headers: {
        Cookie: jar.getCookieString('http://localhost:3000'),
        'Content-Type': 'application/json'
      }
    });

    console.log('Event response status:', eventResponse.status);
    console.log('Event response data:', eventResponse.data);

    // Redirect after event creation
    if (eventResponse.status === 302) {
      console.log('Event created successfully, redirecting to homepage');
    } else {
      console.log('Event creation failed with status:', eventResponse.status);
    }

  } catch (error) {
    console.error('Error:', error.response ? error.response.data : error.message);
  }
}

createAdmin();
