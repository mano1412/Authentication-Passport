require('dotenv').config();
const express = require('express');
const app= express();
const bodyParser=require('body-parser');
const ejs=require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy=require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

//session and cookies part
app.use(session({
   secret:process.env.secret,
   resave:false,
   saveUninitialized:false 
}));
//end of seesion and cookies --

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.mongoUrl, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex",true);
let displayName=null;

const authSchema=new mongoose.Schema({
    username:String,
    name:String,
    email:String,
    password:String,
    googleId:String,
    facebookId:String
});

authSchema.plugin(passportLocalMongoose);
authSchema.plugin(findOrCreate);

const userData= new mongoose.model('user',authSchema);

passport.use(userData.createStrategy());

//serialize and deserialize
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    userData.findById(id, function(err, user) {
      done(err, user);
    });
  });


//Google Strategy  
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK,
    userProfileURL: process.env.USER_INFO
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
      console.log(accessToken);
      displayName=profile.displayName;
    userData.findOrCreate({ username: profile.emails[0].value, googleId: profile.id,name:profile.displayName }, function (err, user) {
        return cb(err, user);
    });
  }
));

//end of goggle strategy

//facebook strategy
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: process.env.FACEBOOK_CALLBACK,
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(accessToken);
      console.log(profile);
      displayName=profile.displayName;
    userData.findOrCreate({ facebookId: profile.id,username:profile.displayName }, function (err, user) {
      return cb(err, user);
    });
  }
));
//end of goggle strategy


//routing part---->
app.get("/",function(req,res){
    if(req.isAuthenticated()){
        res.render('welcome',{naming:displayName});
    }
    else{
        res.redirect('/login');
    }
});

app.get("/login",(req,res)=>{
    res.render('login',{c:0});
})

app.post('/login',(req,res)=>{
     console.log("received login payload",req.body);
     userData.findOne({username:req.body.username},(err,data)=>{
        if(err){
            console.log(err); 
            res.redirect('/login');
        }
         if(data){
             console.log(data);
             displayName=data.name;
              const user= new userData({
                username:req.body.username,
                password:req.body.password
              });
              req.login(user,(err)=>{
                  if(err){
                      console.log(err);
                      res.redirect('login');
                  }
                  else(
                      passport.authenticate('local')(req,res,()=>{
                            res.redirect('/');
                      })
                    )
              })
        }
        else{
            res.redirect('/register');
        }
    });
})

app.get('/register',(req,res)=>{
    res.render('register',{k:0});
})

app.post('/register',(req,res)=>{
     console.log("Received Payload",req.body);
     userData.findOne({username:req.body.username},(err,data)=>{
         if(err){
             console.log(err);
             res.redirect('/register');
             return;
            }
         if(data){
            console.log(data);
            res.render('register',{k:1});
         }
         else{
            userData.register({username:req.body.username,name:req.body.name},req.body.password,(err,user)=>{
                if(err){
                    res.redirect('/register');
                }
                else{
                    displayName=req.body.name;
                    passport.authenticate('local')(req,res,()=>{
                        res.redirect('/');
                    })
                }
            })
        }
    })
})
app.get('/auth/google',
   passport.authenticate("google",{scope:["profile","email"]}))

app.get('/auth/google/welcome', 
passport.authenticate('google', { failureRedirect: '/login' }),
function(req, res) {
     res.redirect('/');
}); 

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
passport.authenticate('facebook', { failureRedirect: '/login' }),
function(req, res) {
    res.redirect('/');
  });

app.get('/logout',(req,res)=>{
    req.logout();
    res.redirect('/login');
})

const PORT=process.env.port||3000;
app.listen(PORT,()=>{
    console.log('Server Started at port 3000');
})