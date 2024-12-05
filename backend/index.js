const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("./models/User");
const cors = require('cors');
const { default: mongoose } = require("mongoose");
require("dotenv").config();
const app = express();
app.use(cors({origin:"http://localhost:3000"}))
mongoose.connect(process.env.MONGO_URI,{
    useNewUrlParser: true,
    useUnifiedTopology: true
}).catch(err=>{console.log(err)});

app.use(express.json());

app.post("/register",async (req,res)=>{
    try {
        console.log(req);
        
        const email = req.body.email;
        const password = req.body.password;
        const salt = await bcrypt.genSalt(Number(process.env.SALT));
        const hashedPassword = await bcrypt.hash(password,salt);
        
        const newUser = new User({
            email: email,
            password: hashedPassword,
        });

        const user = await newUser.save();
        console.log(user);
        
        res.status(200).json(user._id);
    } catch (error) {       
        res.status(500).json(error);
    }
});

app.post("/login",async (req,res)=>{
    try {
        console.log(req);
        
        const email = req.body.email;
        const password = req.body.password;
        const user = await User.findOne({email:email});
        
        if(!user) return res.status(202).json("Wrong Credentials!");

        const validPassowrd = await bcrypt.compare(password,user.password);

        if(!validPassowrd) return res.status(202).json("Wrong Password!");
        
        const accessToken = jwt.sign(JSON.stringify(user),process.env.TOKEN_SECRET);
        console.log(accessToken);
        
        res.status(200).json({accessToken:accessToken});
    } catch (error) {
        res.status(500).json(error);
    }
});

app.get("/",function(req,res){
    res.json("Hello World");
});
app.listen(process.env.PORT || 1337,function(){
    console.log("Server started on port 1337");
});