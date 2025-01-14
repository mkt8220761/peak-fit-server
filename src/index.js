import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import { config } from "dotenv";

// Load environment variables from .env file
config();

// Debugging: Log loaded environment variables
console.log("Loaded PORT from .env:", process.env.PORT);

// Exit if environment variables are not loaded
if (!process.env.PORT) {
  console.error(
    "Error: Environment variables not loaded. Check your .env file."
  );
  process.exit(1);
}

// Import route files
import authRoutes from "./routes/authRoutes.js";
import userRoutes from "./routes/userRoutes.js";
import meRoutes from "./routes/meRoutes.js";
// Initialize the Express app
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json()); // Parse JSON bodies

// Health check route
app.get("/", (req, res) => {
  res.send("PEAK FIT Server is running!");
});

// Define routes
app.use("/auth", authRoutes);
app.use("/users", userRoutes);
app.use("/me", meRoutes);
// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`PEAK FIT Server is running on port ${PORT}`);
});
