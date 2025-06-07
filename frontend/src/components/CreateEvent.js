import React, { useState } from 'react';
import axios from 'axios';

const CreateEvent = () => {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [playerLimit, setPlayerLimit] = useState('');
  const [dateTime, setDateTime] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post('/api/events', { name, description, playerLimit, dateTime });
      // Redirect to home page or show success message
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Create Event</h2>
      <input
        type="text"
        placeholder="Event/Game Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        required
      />
      <textarea
        placeholder="Description"
        value={description}
        onChange={(e) => setDescription(e.target.value)}
        required
      />
      <input
        type="number"
        placeholder="Player Limit"
        value={playerLimit}
        onChange={(e) => setPlayerLimit(e.target.value)}
        required
      />
      <input
        type="datetime-local"
        value={dateTime}
        onChange={(e) => setDateTime(e.target.value)}
        required
      />
      <button type="submit">Create Event</button>
    </form>
  );
};

export default CreateEvent;
