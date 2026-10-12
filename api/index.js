// Vercel serverless entry point. Re-exports the Express app from server.js.
// Both `module.exports` and `.default` are set so the @vercel/node runtime
// finds the handler regardless of its export-detection style. Requiring this
// file must NEVER start an HTTP listener (server.js only listens when run
// directly via `node server.js`).
const app = require("../server.js");

module.exports = app;
module.exports.default = app;
