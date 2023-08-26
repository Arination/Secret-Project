//jshint esversion:6
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
 
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
 
const secret = "littleSecret.";
userSchema.plugin(encrypt, {secret: secret, encryptedFields: ["password"]});


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
        if(foundUser.password === password){
            res.render("secrets");
        }
    })
    .catch((err)=> console.log(err));
})
 
app.route("/register")
.get((req,res)=>{
    res.render("register");
})
 
.post((req,res)=>{
    const newUser = new User({
        email : req.body.username,
        password : req.body.password
    });
    newUser.save()
    .then(()=> res.render("secrets"))
    .catch((err)=> console.log(err))
});
 
app.listen(3000, function(req,res){
    console.log("Server Running at Port 3000");
});