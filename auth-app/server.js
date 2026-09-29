require("dotenv").config();
const path = require("path");
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const cookieParser = require("cookie-parser");

const authRoutes = require("./routes/authRoutes");

const { MONGO_URI, JWT_SECRET, SESSION_SECRET } = process.env;
if (!MONGO_URI || !JWT_SECRET || !SESSION_SECRET) {
  console.error("Missing MONGO_URI, JWT_SECRET or SESSION_SECRET in the .env file.");
  process.exit(1);
}

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// Session management: sessions are stored in MongoDB (collection "sessions")
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: MONGO_URI, collectionName: "sessions" }),
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000, // 1 hour
    },
  })
);

app.use("/", authRoutes);

app.use((req, res) => res.status(404).send("Page not found"));

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("MongoDB Atlas connected");
    app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });
