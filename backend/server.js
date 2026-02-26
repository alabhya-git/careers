const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

app.get("/", (req,res)=>{
    res.send("Secure Job Portal Backend Running");
});

app.get("/api/test",(req,res)=>{
    res.json({message:"API working"});
});

app.listen(5000, ()=>{
    console.log("Backend running on port 5000");
});
