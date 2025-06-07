const axios = require('axios');

async function createAdmin() {
  try {
    // First, register a new user
    await axios.post('http://localhost:3000/register', {
      name: 'Admin User',
      email: 'admin@example.com',
      password: 'admin123',
      gameNickname: 'AdminNick'
    });

    // Then, set the user as admin
    await axios.post('http://localhost:3000/setup-admin', {
      email: 'admin@example.com'
    });

    console.log('Admin user created and set up successfully');

    // Log in as the admin user
    const response = await axios.post('http://localhost:3000/login', {
      email: 'admin@example.com',
      password: 'admin123'
    }, { withCredentials: true });

    console.log('Logged in as admin');

    // Try to access the admin/users page
    const adminResponse = await axios.get('http://localhost:3000/admin/users', { withCredentials: true });

    console.log('Successfully accessed /admin/users');
    console.log(adminResponse.data);

  } catch (error) {
    console.error('Error:', error.response ? error.response.data : error.message);
  }
}

createAdmin();
