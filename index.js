const express = require("express");
const cors = require("cors");
require("dotenv").config();
const routes = require("./routes/route");
const createTables = require("./config/tables");
const nodemailer = require("nodemailer");

const secretKey = process.env.SECRET_KEY;


const app = express();
app.use(express.json());
// app.use(cors(
//   // origin: "*",
//   // methods: ["GET", "POST", "PUT", "DELETE"],
//   // credentials: true
// ));

app.use(cors({ origin: "*" }));

const PORT = 5000;

createTables();


// Routes
app.use("/", routes);





app.get("/test", (req, res) => {
    res.send("Welcome User Profile");
});


app.listen(5000, "0.0.0.0", () => {
    console.log("Server running on http://0.0.0.0:5000");
});


