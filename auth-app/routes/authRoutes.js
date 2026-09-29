const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const requireAuth = require("../middleware/auth");

const router = express.Router();
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.get("/", (req, res) => res.redirect("/login"));

// ---------- Register ----------
router.get("/register", (req, res) => {
  res.render("register", { error: null, form: {} });
});

router.post("/register", async (req, res) => {
  const name = (req.body.name || "").trim();
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  const form = { name, email };
  const fail = (status, error) => res.status(status).render("register", { error, form });

  if (!name || !email || !password) return fail(400, "All fields are required.");
  if (!emailPattern.test(email)) return fail(400, "Enter a valid email address.");
  if (password.length < 6) return fail(400, "Password must be at least 6 characters.");

  try {
    const existing = await User.findOne({ email });
    if (existing) return fail(409, "This email is already registered. Try logging in.");

    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ name, email, password: hashedPassword });

    res.redirect("/login?registered=1");
  } catch (err) {
    console.error(err);
    fail(500, "Something went wrong. Please try again.");
  }
});

// ---------- Login ----------
router.get("/login", (req, res) => {
  let success = null;
  if (req.query.registered) success = "Registration successful. Please log in.";
  if (req.query.loggedout) success = "You have been logged out.";
  res.render("login", { error: null, success, email: "" });
});

router.post("/login", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = req.body.password || "";
  const fail = () =>
    res.status(401).render("login", {
      error: "Invalid email or password.",
      success: null,
      email,
    });

  try {
    const user = await User.findOne({ email });
    if (!user) return fail();

    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) return fail();

    // 1) Generate the JWT
    const token = jwt.sign({ id: user._id.toString() }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    console.log(`JWT generated for ${user.email}:`, token); // visible in the terminal for the demo

    // 2) Create a fresh session and store the user id in it
    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Could not start a session.");
      }
      req.session.userId = user._id.toString();

      // 3) Send the JWT in an httpOnly cookie
      res.cookie("token", token, {
        httpOnly: true,
        sameSite: "lax",
        maxAge: 60 * 60 * 1000,
      });

      req.session.save((saveErr) => {
        if (saveErr) {
          console.error(saveErr);
          return res.status(500).send("Could not save the session.");
        }
        res.redirect("/dashboard");
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Something went wrong. Please try again.");
  }
});

// ---------- Dashboard (protected) ----------
router.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) {
      return req.session.destroy(() => {
        res.clearCookie("token");
        res.clearCookie("connect.sid");
        res.redirect("/login");
      });
    }
    res.render("dashboard", {
      user,
      tokenPreview: req.cookies.token.slice(0, 40) + "...",
      expiresAt: new Date(req.tokenExp * 1000),
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Something went wrong. Please try again.");
  }
});

// ---------- Logout ----------
router.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("token");
    res.clearCookie("connect.sid");
    res.redirect("/login?loggedout=1");
  });
});

module.exports = router;
