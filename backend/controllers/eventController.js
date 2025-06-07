const Event = require('../models/Event');
const User = require('../models/User');

exports.createEvent = async (req, res) => {
  const { name, description, playerLimit, dateTime } = req.body;

  try {
    const event = await Event.create({
      name,
      description,
      playerLimit,
      dateTime,
      players: []
    });
    res.status(201).json({ success: true, data: event });
  } catch (err) {
    res.status(400).json({ success: false, error: err.message });
  }
};

exports.getEvents = async (req, res) => {
  try {
    const events = await Event.find().populate('players', 'name');
    res.status(200).json({ success: true, data: events });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.getEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id).populate('players', 'name');
    if (!event) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }
    res.status(200).json({ success: true, data: event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.joinEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }

    if (event.players.length >= event.playerLimit) {
      return res.status(400).json({ success: false, error: 'Event is full' });
    }

    event.players.push(req.user.id);
    await event.save();
    res.status(200).json({ success: true, data: event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};

exports.leaveEvent = async (req, res) => {
  try {
    const event = await Event.findById(req.params.id);
    if (!event) {
      return res.status(404).json({ success: false, error: 'Event not found' });
    }

    event.players = event.players.filter(player => player.toString() !== req.user.id);
    await event.save();
    res.status(200).json({ success: true, data: event });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
};
