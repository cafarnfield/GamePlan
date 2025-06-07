const mongoose = require('mongoose');

const extensionSchema = new mongoose.Schema({
  name: String,
  downloadLink: String,
  installationTime: Number // in minutes
});

const Extension = mongoose.model('Extension', extensionSchema);

module.exports = Extension;
