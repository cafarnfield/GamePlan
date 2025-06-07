import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams } from 'react-router-dom';

const EventDetails = ({ isAuthenticated }) => {
  const { id } = useParams();
  const [event, setEvent] = useState(null);

  useEffect(() => {
    const fetchEvent = async () => {
      try {
        const res = await axios.get(`/api/events/${id}`);
        setEvent(res.data);
      } catch (err) {
        console.error(err);
      }
    };

    fetchEvent();
  }, [id]);

  const handleJoin = async () => {
    try {
      await axios.post(`/api/events/${id}/join`);
      setEvent(prevEvent => ({
        ...prevEvent,
        players: [...prevEvent.players, { _id: 'user-id' }]
      }));
    } catch (err) {
      console.error(err);
    }
  };

  const handleLeave = async () => {
    try {
      await axios.post(`/api/events/${id}/leave`);
      setEvent(prevEvent => ({
        ...prevEvent,
        players: prevEvent.players.filter(player => player._id !== 'user-id')
      }));
    } catch (err) {
      console.error(err);
    }
  };

  if (!event) return <p>Loading...</p>;

  return (
    <div>
      <h2>{event.name}</h2>
      <p>{event.description}</p>
      <p>Player Limit: {event.playerLimit}</p>
      <p>Current Players: {event.players.length}</p>
      <h3>Players</h3>
      <ul>
        {event.players.map(player => (
          <li key={player._id}>{player.name}</li>
        ))}
      </ul>
      {isAuthenticated && (
        <div>
          {event.players.some(player => player._id === 'user-id') ? (
            <button onClick={handleLeave}>Leave Event</button>
          ) : (
            <button onClick={handleJoin}>Join Event</button>
          )}
        </div>
      )}
    </div>
  );
};

export default EventDetails;
