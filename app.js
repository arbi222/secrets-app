//jshint esversion:6

require("dotenv").config(); // needs to be at the top
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

app.use(express.static("public"));
app.set("view engine" , "ejs");
app.use(bodyParser.urlencoded({extended: true}));


app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://admin-arbi111:" + process.env.DATABASEPASS + "@cluster0.imivdjr.mongodb.net/secretDB");


const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose); // to  plugin we need    new mongoose schema
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User" , userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user , done){
  done(null , user.id); // drop username_1 on database
});
passport.deserializeUser(function(id, done){
    User.findById(id , function(err ,user){
        done(err , user);
    });
});

// for google
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    //console.log(profile);
    User.findOrCreate({ googleId: profile.id}, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/" , function(req , res){
  res.render("home");
})


//google
app.get('/auth/google',
      passport.authenticate('google', { scope: ['profile'] })
    );

app.get('/auth/google/secrets',
      passport.authenticate('google', { failureRedirect: '/login' }),
      function(req, res) {
        // Successful authentication
        res.redirect('/secrets');
    });



app.get("/login" , function(req , res){
  res.render("login");
})


app.get("/register" , function(req , res){
  res.render("register");
})

app.get("/secrets", function(req , res){
      User.find({"secret": {$ne: null}}, function(err , foundUsers){
        if (err){
          console.log(err);
        }
        else{
          if(foundUsers){
              res.render("secrets" , {usersWithSecrets: foundUsers});
          }
        }
      }); // not equal $ne
});

app.post("/submit" , function(req, res){
    const submitedSecret = req.body.secret;

    User.findById(req.user.id , function(err , foundUser){
        if (err){
          console.log(err);
        }
        else{
            if(foundUser){
                foundUser.secret = submitedSecret;
                foundUser.save(function(){
                  res.redirect("/secrets");
                });
            }
        }
    });
});

app.get("/submit" , function(req ,res){
  if (req.isAuthenticated()){
      res.render("submit");
  }
  else{
      res.redirect("/login");
  }
});


app.get("/logout" , function(req ,res){
    req.logout();
    res.redirect("/");
});

app.post("/register" , function(req , res){

    User.register({username: req.body.username} , req.body.password , function(err , user){
      if (err){
        console.log(err);
        res.redirect("/register");
      }
      else{
        passport.authenticate("local")(req, res , function(){ // this function looks for username and password fields
            res.redirect("/secrets");
        });
      }
    });

});


app.post("/login" , function(req , res){

    const user = new User ({
       username: req.body.username,
       password: req.body.password
    });
    req.login(user, function(err){
        if (err){
          console.log(err);
        }
        else{
            passport.authenticate("local", {failureRedirect: "/login"})(req, res, function(){
            res.redirect("/secrets");    
          })
        }
    });

});


app.listen(process.env.PORT || 3000 , function(){
  console.log("Server is running successfully !");
})
