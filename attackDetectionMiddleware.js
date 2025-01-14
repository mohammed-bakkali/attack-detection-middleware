const fs = require("fs");
const path = require("path");

// Define the path for the attack log file
const logFilePath = path.join(__dirname, "attack_log.txt");
const requestCounts = {}; // To track the number of requests per IP
const RATE_LIMIT = 100; // Maximum requests per IP
const TIME_WINDOW = 60 * 1000; // Time window in milliseconds (1 minute)

// Middleware for attack detection and logging IP
function attackDetectionMiddleware(req, res, next) {
  const { url, method, body, query } = req; // Incoming request
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress; // Get the user's IP
  const userAgent = req.headers["user-agent"] || ""; // Get the User-Agent string

  // Extract information about the browser and system (Operating System)
  const browserInfo = userAgent.match(/(Chrome|Firefox|Safari|Opera|Edge|MSIE|Trident|Vivaldi)/i) ? RegExp.$1 : "Unknown Browser";
  const osInfo = userAgent.match(/\((.*?)\)/) ? RegExp.$1 : "Unknown OS";

  // Function to log suspicious activity
  const logAttack = (message) => {
    const timestamp = new Date().toISOString();
    const entry = `[${timestamp}] [IP: ${ip}] [Browser: ${browserInfo}] [OS: ${osInfo}] ${message}\n`;
    fs.appendFileSync(logFilePath, entry); // Write the activity to the log file
    console.error(entry);
  };

  // Check request rate
  if (!requestCounts[ip]) {
    requestCounts[ip] = []; // If the IP does not exist, create a new array
    console.log("test", requestCounts);
  }
  console.log("a", requestCounts[ip]);
  const currentTime = Date.now();
  requestCounts[ip] = requestCounts[ip].filter(
    (timestamp) => currentTime - timestamp < TIME_WINDOW
  );

  if (requestCounts[ip].length >= RATE_LIMIT) {
    logAttack(`Rate limit exceeded - URL: ${url}`);
    return res.status(429).send("Rate limit exceeded.");
  }

  requestCounts[ip].push(currentTime);

  // SQL Injection detection
  const sqlInjectionPatterns = /(select|union|insert|drop|delete|update|;|--)/i;
  for (const key in query) {
    if (sqlInjectionPatterns.test(query[key])) {
      logAttack(`SQL Injection detected: ${key}=${query[key]} - URL: ${url}`);
      return res.status(400).send("Suspicious activity detected.");
    }
  }

  // XSS (Cross-Site Scripting) detection
  const xssPatterns = /(<script|onerror|onload|javascript:)/i;
  for (const key in query) {
    if (xssPatterns.test(query[key])) {
      logAttack(`XSS detected: ${key}=${query[key]} - URL: ${url}`);
      return res.status(400).send("Suspicious activity detected.");
    }
  }

  // Allow safe requests to proceed
  next();
}

module.exports = attackDetectionMiddleware;
