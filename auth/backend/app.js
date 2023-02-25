const express = require("express");
require("dotenv").config();
require("./db");

const cors = require("cors");

const userRouter = require("./routes/user");

const app = express();

const PORT = process.env.PORT || 8000;

app.use(cors());
app.use(express.json());
app.use("/api/user", userRouter);

app.listen(PORT, () => {
  console.log("app is running on port " + PORT);
});
