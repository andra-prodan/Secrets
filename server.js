//jshint esversion:6

require('dotenv').config();
const express = require('express');
const bodyParcer = require('body-parser');
const mongoose = require('mongoose');
const ejs = require('ejs');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
var FacebookStrategy = require('passport-facebook');
const findOrCreate = require('mongoose-findorcreate');
const { profile } = require('console');

const app = express();

app.set('view engine', 'ejs');

app.use(bodyParcer.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', false);

mongoose.connect(process.env.DB, { useNewUrlParser: true });

var Schema = mongoose.Schema;

var userSchema = new Schema({
    username: {
        type: String,
        index: { unique: true }
    },
    password: {
        type: String
    },
    googleId: String,
    facebookId: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const postSchema = {
    post: String,
    userId: String
}

const User = mongoose.model("user", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

const Post = mongoose.model("post", postSchema);

app.get("/", function (req, res) {
    res.render("home");
});

app.route("/auth/google")
    .get(
        passport.authenticate("google", { scope: ["email"] })
    )

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/', failureMessage: true }),
    function (req, res) {
        res.redirect('/secrets');
    });

app.route("/auth/facebook")
    .get(
        passport.authenticate("facebook", { scope: ["email"] })
    )

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/', failureMessage: true }),
    function (req, res) {
        res.redirect('/secrets');
    });

app.route("/login")

    .get(function (req, res) {
        res.render("login");
    })

    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        passport.authenticate("local", { failureRedirect: "/login" })(req, res, function () {
            res.redirect("/secrets");
        })
    });

app.route("/register")

    .get(function (req, res) {
        res.render("register");
    })

    .post(function (req, res) {
        User.register({ username: req.body.username }, req.body.password, function (err, user) {
            if (!err) {
                passport.authenticate("local", { failureRedirect: "/login" })(req, res, function () {
                    res.redirect("/secrets");
                })
            } else {
                console.log(err);
                res.redirect("/register");
            }
        })
    });

app.route("/secrets")

    .get(function (req, res) {
        if (req.isAuthenticated()) {
            Post.find({}, function (err, posts) {
                if (!err) {
                    res.render("secrets", {
                        posts: posts
                    });
                } else {
                    console.log(err);
                }
            });
        } else {
            res.redirect("/login");
        }
    });

app.route("/mysecret")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            Post.find({ userId: req.user.id }, function (err, posts) {
                res.render("mysecret", {
                    posts: posts
                });
            });
        } else {
            res.redirect("/login");
        }
    })

app.route("/submit")

    .get(function (req, res) {
        if (req.isAuthenticated()) {
            res.render("submit")
        } else {
            res.redirect("/login");
        }
    })

    .post(function (req, res) {
        const newPost = new Post({
            post: req.body.secret,
            userId: req.user.id
        });
        newPost.save(function (err) {
            if (!err) {
                res.redirect("secrets");
            } else {
                console.log(err);
            }
        });
    });

app.route("/logout")
    .get(function (req, res) {
        req.session.destroy(function () {
            res.clearCookie('connect.sid');
            res.redirect("/");
        });

    });

app.listen(process.env.PORT || 3000, function () {
    console.log('Server running...');
});