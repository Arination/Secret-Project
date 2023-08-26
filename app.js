//jshint esversion:6
const md5 = require('md5');
require('dotenv').config()
// console.log(process.env.SECRET)
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const bcrypt = require('bcrypt');
const saltRounds = 10;
 
const app = express();
 
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended : true
}));
 
mongoose.connect("mongodb://0.0.0.0:27017/userDB");
 
const userSchema = new mongoose.Schema({
    email : String,
    password : String
});


userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});


const User = mongoose.model("User", userSchema);
 
app.get("/", (req,res)=>{
    res.render("home");
});
 
app.route("/login")
.get((req,res)=>{
    res.render("login");
})
.post((req,res)=>{
    const username = req.body.username;
    const password = req.body.password;
 
    User.findOne({email : username })
    .then((foundUser)=> {
            bcrypt.compare(password, foundUser.password).then(function(result) {
                 if(result === true){
                    res.render("secrets");
                 }
            });
    })
    .catch((err)=> console.log(err));
})
 
app.route("/register")
.get((req,res)=>{
    res.render("register");
})
 
.post((req,res)=>{
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email : req.body.username,
            password : hash
        });
        newUser.save()
        .then(()=> res.render("secrets"))
        .catch((err)=> console.log(err))
    });
    
});
 
app.listen(3000, function(req,res){
    console.log("Server Running at Port 3000");
});