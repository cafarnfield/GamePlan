import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const EventList = () => {
  const [events, setEvents] = useState([]);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const res = await axios.get('/api/events');
        setEvents(res.data);
      } catch (err) {
        console.error(err);
      }
    };

    fetchEvents();
  }, []);

  return (
    <div>
      <h2>Upcoming Events</h2>
      <ul>
        {events.map(event => (
          <li key={event._id}>
            <Link to={`/event/${event._id}`}>{event.name}</Link>
            <p>{event.description}</p>
            <p>Player Limit: {event.playerLimit}</p>
            <p>Current Players: {event.players.length}</p>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default EventList;
