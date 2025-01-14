import jwt from "jsonwebtoken";

const authMiddleware = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized. Token required." });
    }

    const token = authHeader.split(" ")[1];

    const decodedToken = jwt.verify(
      token,
      process.env.JWT_SECRET || "nothinglastforever"
    );

    req.user = decodedToken;

    next();
  } catch (error) {
    console.error("Authentication Error:", error.message);

    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token." });
    }
    if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token has expired." });
    }

    res.status(500).json({ error: "Failed to authenticate." });
  }
};

export default authMiddleware;
