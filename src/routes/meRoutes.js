import express from "express";
import * as yup from "yup";
import authMiddleware from "../middlewares/authMiddleware.js";
import UserRepository from "../repositories/UserRepository.js";
import uploadPDF from "../middlewares/uploadPDFMiddleware.js";
import uploadPNG from "../middlewares/uploadPNGMiddleware.js";
const profileUpdateSchema = yup.object().shape({
  username: yup.string().required("Username is required."),
  password: yup
  .string()
  .min(8, "Password must be at least 8 characters.")
  .matches(/[A-Z]/, "Password must contain at least one uppercase letter.")
  .matches(/[a-z]/, "Password must contain at least one lowercase letter.")
  .matches(/[0-9]/, "Password must contain at least one digit.")
  .matches(
    /[!@#$%^&*(),.?":{}|<>]/,
    "Password must contain at least one special character."
  )
  .optional(),
});

const router = express.Router();
router.get("/my-account", authMiddleware, async (req, res) => {
  try {
    const { uid } = req.user;

    const user = await UserRepository.getUserById(uid);

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.status(200).json({
      message: "User details retrieved successfully.",
      user,
    });
  } catch (error) {
    console.error("Error retrieving account:", error.message);
    res.status(500).json({ error: "Failed to retrieve account details." });
  }
});
router.put("/update-profile", authMiddleware, async (req, res) => {
  try {
    const { uid } = req.user;
    const { username, password } = req.body;

    await profileUpdateSchema.validate({ username, password });

    const user = await UserRepository.getUserById(uid);
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    const updateData = { username };

    await UserRepository.updateUser(uid, updateData);

    if (password) {
      try {
        await UserRepository.updateUserPassword(uid, password);
      } catch (err) {
        console.error("Error updating password:", err.message);
        return res
          .status(500)
          .json({ error: "Failed to update password. Please try again." });
      }
    }

    const updatedUser = await UserRepository.getUserById(uid);

    res.status(200).json({
      message: "Profile updated successfully.",
      user: updatedUser,
    });
  } catch (error) {
    console.error("Error updating profile:", error.message);
    if (error.name === "ValidationError") {
      return res.status(400).json({ error: error.message });
    }

    console.error("Error updating profile:", error.message);
    res.status(500).json({ error: "Failed to update profile." });
  }
});

router.post(
  "/upload-certifications",
  authMiddleware,
  uploadPDF.array("files"),
  async (req, res) => {
    try {
      const { uid } = req.user;

      if (!req.files || req.files.length === 0) {
        return res.status(400).json({ error: "No files uploaded." });
      }

      const uploadedFiles = [];
      for (const file of req.files) {
        const fileUrl = await UserRepository.uploadBusinessCertification(file);
        uploadedFiles.push(fileUrl);
      }

      const user = await UserRepository.getUserById(uid);
      const existingCertifications = user.businessCertification || [];

      const updatedCertifications = [
        ...existingCertifications,
        ...uploadedFiles,
      ];

      await UserRepository.updateUser(uid, {
        businessCertification: updatedCertifications,
      });

      res.status(200).json({
        message: "Certifications uploaded successfully.",
        certifications: updatedCertifications,
      });
    } catch (error) {
      console.error("Error uploading certifications:", error.message);
      res.status(500).json({ error: "Failed to upload certifications." });
    }
  }
);
router.put("/delete-certification", authMiddleware, async (req, res) => {
  try {
    const { uid } = req.user;
    const { certification } = req.body.data;

    if (!certification) {
      return res.status(400).json({ error: "Certification URL is required." });
    }

    const user = await UserRepository.getUserById(uid);
    const certifications = user.businessCertification || [];
    console.log(certification);
    if (!certifications.includes(certification)) {
      return res.status(404).json({ error: "Certification not found." });
    }

    await UserRepository.deleteBusinessCertification(certification);

    const updatedCertifications = certifications.filter(
      (cert) => cert !== certification
    );
    await UserRepository.updateUser(uid, {
      businessCertification: updatedCertifications,
    });

    res.status(200).json({
      message: "Certification deleted successfully.",
      certifications: updatedCertifications,
    });
  } catch (error) {
    console.error("Error deleting certification:", error.message);
    res.status(500).json({ error: "Failed to delete certification." });
  }
});
router.post(
  "/upload-profile-picture",
  authMiddleware,
  uploadPNG.single("profilePicture"),
  async (req, res) => {
    try {
      const { uid } = req.user;

      if (!req.file) {
        return res.status(400).json({ error: "No file uploaded." });
      }

      const fileUrl = await UserRepository.uploadProfilePicture(req.file, uid);

      await UserRepository.updateUser(uid, {
        profileImage: fileUrl,
      });

      const updatedUser = await UserRepository.getUserById(uid);

      res.status(200).json({
        message: "Profile picture uploaded successfully.",
        user: updatedUser,
      });
    } catch (error) {
      console.error("Error uploading profile picture:", error.message);
      res.status(500).json({ error: "Failed to upload profile picture." });
    }
  }
);

export default router;
