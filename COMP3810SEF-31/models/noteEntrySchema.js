const mongoose = require('mongoose');

const noteEntrySchema = new mongoose.Schema({
  noteUUID: { type: String, required: true },
  noteContent: { type: String, required: true },
  noteUserUUID: { type: String, required: true },
  noteLastModified: { type: Date, default: Date.now }
});

module.exports = mongoose.model('NoteEntry', noteEntrySchema);
