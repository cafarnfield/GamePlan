const mongoose = require('mongoose');
require('dotenv').config();

const Game = require('./models/Game');

async function getGameIds() {
  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('Connected to MongoDB');
    
    const games = await Game.find({});
    console.log('Available games:');
    games.forEach(game => {
      console.log(`ID: ${game._id}, Name: ${game.name}`);
    });
    
    process.exit(0);
  } catch (error) {
    console.error('Error:', error);
    process.exit(1);
  }
}

getGameIds();
