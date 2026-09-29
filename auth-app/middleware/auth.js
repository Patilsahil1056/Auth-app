const jwt = require("jsonwebtoken");

// Allows access only when BOTH a valid JWT cookie and an active session exist.
module.exports = function requireAuth(req, res, next) {
  const denied = (message) => {
    res.clearCookie("token");
    return res.status(401).render("login", {
      error: message,
      success: null,
      email: "",
    });
  };

  const token = req.cookies.token;
  const sessionUserId = req.session && req.session.userId;

  if (!token || !sessionUserId) {
    return denied("Access denied. Please log in first.");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.id !== sessionUserId) {
      return denied("Access denied. Please log in again.");
    }
    req.userId = decoded.id;
    req.tokenExp = decoded.exp;
    next();
  } catch (err) {
    return denied("Your login has expired. Please log in again.");
  }
};
