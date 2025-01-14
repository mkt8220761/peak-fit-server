import express from "express";
import UserRepository from "../repositories/UserRepository.js";

const router = express.Router();

router.get("/", async (req, res) => {
  try {
    // Fetch all users from the repository
    const users = await UserRepository.getAllUsers();

    if (!users) {
      return res.status(404).json({ message: "No users found." });
    }

    res.status(200).json({ message: "Users retrieved successfully.", users });
  } catch (error) {
    console.error("Error fetching users:", error.message);
    res.status(500).json({ error: "Failed to retrieve users." });
  }
});

export default router;
