const mongoose = require('mongoose');

const noteSchema = new mongoose.Schema({
  noteUUID: String,
  noteContent: String,
  noteUserUUID: String,
  noteLastModified: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Note', noteSchema);

