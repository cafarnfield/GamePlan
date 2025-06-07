const express = require('express');
const { createEvent, getEvents, getEvent, joinEvent, leaveEvent } = require('../controllers/eventController');
const { protect } = require('../middleware/authMiddleware');

const router = express.Router();

router.post('/', protect, createEvent);
router.get('/', getEvents);
router.get('/:id', getEvent);
router.post('/:id/join', protect, joinEvent);
router.post('/:id/leave', protect, leaveEvent);

module.exports = router;
