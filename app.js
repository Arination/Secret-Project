//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

// Load environment-specific configurations from .env file
const { SESSION_SECRET, MONGODB_URI, CLIENT_ID, CLIENT_SECRET } = process.env;

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

// Configure session package
app.use(session({
  secret: SESSION_SECRET || "Our little secret.",
  resave: false,
  saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

// Connect to the database
mongoose.connect(MONGODB_URI || "mongodb://127.0.0.1:27017/userDB", { useNewUrlParser: true });

// Define the user schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Create the User model
const User = mongoose.model("User", userSchema);

// Passport configuration
passport.use(User.createStrategy());

passport.serializeUser((user, cb) => {
  process.nextTick(() => {
    cb(null, user.id);
  });
});

passport.deserializeUser((id, cb) => {
  User.findById(id)
    .then(user => {
      if (user) {
        cb(null, user);
      } else {
        cb(new Error('User not found'));
      }
    })
    .catch(cb);
});

passport.use(new GoogleStrategy({
  clientID: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  scope: ["email", "profile"],
},
(accessToken, refreshToken, profile, cb) => {
  User.findOrCreate({ googleId: profile.id, username: profile.emails[0].value }, (err, user) => {
    return cb(err, user);
  });
}
));

// GET REQUESTS
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  res.redirect('/secrets');
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", (req, res, next) => {
  User.find({ secret: { $ne: null } })
    .then(users => {
      if (users) {
        res.render("secrets", { usersSecrets: users });
      } else {
        next(new Error('User not found'));
      }
    })
    .catch(next);
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(err => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// POST REQUESTS
app.post("/register", (req, res) => {
  User.register({ username: req.body.username }, req.body.password, (err, user) => {
    if (err) {
      console.error(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", (req, res) => {
  const user = new User({ username: req.body.username, password: req.body.password });

  req.login(user, err => {
    if (err) {
      console.error(err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", (req, res, next) => {
  const secret = req.body.secret;
  const userSecretId = req.user.id;

  User.findById(userSecretId)
    .then(user => {
      if (user) {
        user.secret = secret;
        user.save()
          .then(() => {
            res.redirect("/secrets");
          })
          .catch(next); // Pass the error to the next middleware
      } else {
        next(new Error('User not found'));
      }
    })
    .catch(next); // Pass any errors to the next middleware
});

// Centralized Error Handling Middleware
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send("Something went wrong!");
});

app.listen(3000, () => {
  console.log("Server started on port 3000");
});
