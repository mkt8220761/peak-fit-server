import express from "express";
import * as yup from "yup";
import UserRepository from "../repositories/UserRepository.js";
import jwt from "jsonwebtoken";
import uploadPDF from "../middlewares/uploadPDFMiddleware.js";
import EmailService from "../classes/EmailService.js";

const router = express.Router();

const signupSchema = yup.object().shape({
  email: yup.string().email().required("Valid email is required."),
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
  username: yup.string().required("Username is required."),
});
router.post(
  "/signup",
  uploadPDF.single("businessCertification"),
  async (req, res) => {
    try {
      const { email, password, username } = await signupSchema.validate(
        req.body,
        { abortEarly: false }
      );

      // Check if a user already exists in Firebase Authentication
      const existingUserInAuth = await UserRepository.getAuthUserByEmail(email);
      if (existingUserInAuth) {
        return res
          .status(409)
          .json({ error: "User already exists. Please log in." });
      }

      // Check if a temporary verification exists in Firestore
      const existingVerification = await UserRepository.getVerificationByEmail(
        email
      );
      if (existingVerification) {
        return res.status(409).json({
          error:
            "Verification already in progress. Please check your email for the verification code.",
        });
      }

      // Ensure a business certification file is provided
      if (!req.file) {
        return res
          .status(400)
          .json({ error: "Business certification (PDF) is required." });
      }

      // Upload the business certification file to Firebase Storage
      const fileUrl = await UserRepository.uploadBusinessCertification(
        req.file
      );

      // Generate a verification code
      const verificationCode = await UserRepository.generateVerificationCode(
        email,
        {
          email,
          password,
          username,
          businessCertification: [fileUrl],
        }
      );

      const verificationLink = `http://localhost:3000/verify?email=${email}&code=${verificationCode}`;

      // Send the verification email
      await EmailService.sendEmail(
        email,
        "Verify Your Account",
        `
          <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
            <h2 style="color: #007BFF;">Welcome to [------PEAKFIT------]!</h2>
            <p>Thank you for signing up. To complete your account setup, please verify your email address.</p>
            <p style="font-weight: bold; font-size: 18px; color: #555;">
              Your verification code:
              <span style="color: #007BFF;">${verificationCode}</span>
            </p>
          </div>
        `
      );
      res.status(200).json({
        message: "Verification email sent. Please verify your account.",
      });
    } catch (error) {
      if (error.name === "ValidationError") {
        const errors = error.inner.map((err) => err.message);
        return res.status(400).json({ errors });
      }

      console.error("Signup Error:", error.message);
      res.status(500).json({ error: "Failed to initiate signup." });
    }
  }
);

// Route to handle user verification
router.post("/verify-signup", async (req, res) => {
  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ error: "Email and code are required." });
    }

    // Validate the verification code
    const userData = await UserRepository.validateVerificationCode(email, code);

    // Create a new user in Firebase Authentication
    const userRecord = await UserRepository.createUser(userData);

    // Generate JWT token for the user
    const authToken = jwt.sign(
      { uid: userRecord.uid, email: userData.email },
      process.env.JWT_SECRET || "nothinglastforever",
      { expiresIn: "1h" }
    );

    res.status(200).json({
      message: "Verification successful.",
      authToken,
    });
  } catch (error) {
    console.error("Verification Error:", error.message);
    res.status(400).json({ error: error.message });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: "Token is required." });
    }

    const decodedToken = await UserRepository.verifyIdToken(token);

    const { uid, email } = decodedToken;

    const user = await UserRepository.getUserById(uid);

    if (!user) {
      return res
        .status(404)
        .json({ error: "No account found for this user. Please sign up." });
    }

    const authToken = jwt.sign(
      { uid, email },
      process.env.JWT_SECRET || "nothinglastforever",
      {
        expiresIn: "12h",
      }
    );

    res.status(200).json({ message: "Login successful!", authToken, user });
  } catch (error) {
    console.error("Login Error:", error.message);

    if (error.code === "auth/invalid-token") {
      return res
        .status(401)
        .json({ error: "Invalid token. Please login again." });
    }
    if (error.code === "auth/id-token-expired") {
      return res
        .status(401)
        .json({ error: "Session expired. Please login again." });
    }

    res
      .status(401)
      .json({ error: "Failed to login. Please check your credentials." });
  }
});
router.post("/resend-code", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required." });
    }

    // Check if the user already exists in Firebase Auth
    const existingUserInAuth = await UserRepository.getAuthUserByEmail(email);
    if (existingUserInAuth) {
      return res
        .status(409)
        .json({ error: "User already exists. Please log in." });
    }

    // Check if a previous verification exists
    const existingVerification = await UserRepository.getVerificationByEmail(
      email
    );
    if (existingVerification) {
      await UserRepository.deleteVerificationByEmail(email);
    }

    // Generate a new verification code
    const newCode = await UserRepository.generateVerificationCode(email, {
      email,
    });

    const verificationLink = `http://localhost:3000/verify?email=${email}&code=${newCode}`;

    // Send the new verification code via email
    await EmailService.sendEmail(
      email,
      "Verify Your Account",
      `
        <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
          <h2 style="color: #007BFF;">Welcome to [------PEAKFIT------]!</h2>
          <p>Thank you for signing up. To complete your account setup, please verify your email address.</p>
          <p style="font-weight: bold; font-size: 18px; color: #555;">
            Your verification code:
            <span style="color: #007BFF;">${newCode}</span>
          </p>
        </div>
      `
    );

    res.status(200).json({
      message: "A new verification code has been sent to your email.",
    });
  } catch (error) {
    console.error("Resend Code Error:", error.message);
    res.status(500).json({ error: "Failed to resend verification code." });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email is required." });
    }

    const resetLink = await UserRepository.generatePasswordResetLink(email);

    res.status(200).json({ message: "Password reset link sent!", resetLink });
  } catch (error) {
    console.error("Reset Password Error:", error.message);

    if (error.code === "auth/user-not-found") {
      return res
        .status(404)
        .json({ error: "No account found with this email address." });
    }
    if (error.code === "auth/invalid-email") {
      return res.status(400).json({ error: "Invalid email address format." });
    }

    res.status(500).json({ error: "Failed to send password reset link." });
  }
});

export default router;
