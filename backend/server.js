import bcrypt from 'bcrypt';
import express from 'express';
import { authorize, generateToken } from "./jwt.js";
import * as database from "./database.js";

const app = express();

app.use(express.json())

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body
  console.log("sign in", req.body)
  if(!email || !password) {
      res.status(400).send({status: "error", message: "missing fields"})
      return;
  }

  const user = await database.getUserWithEmail(email)
  if(!user) {
      res.status(400).send({status: "error", message: "wrong username"})
      return
  }

  const hashedPassword = user[0].password
  console.log("first", user)
  console.log("data", hashedPassword, password)
  console.log(user[0].id)
  const same = await bcrypt.compare(password, hashedPassword)
  if(!same) {
      res.status(400).send({status: "error", message: "wrong password"})
      return;
  };
  const token = generateToken({ 
    sub: user[0].id,
    email: user[0].email,
    displayName: user[0].displayName,
    profileImage: user[0].profileImage,
  });
  res.send({ status: "ok", userId: token })
});

app.post("/api/signup", async(req, res) => {
  const { email, password, displayName } = req.body
  console.log("sign up", req.body)
  if(!email || !password || !displayName ) {
      res.status(400).send({status: "error", message: "missing fields"})
      return;
  }

  const salt = await bcrypt.genSalt(13)
  const hashedPassword = await bcrypt.hash(password, salt)
  console.log("result: ", salt, hashedPassword)

  const results = await database.createUser({ email, password: hashedPassword, displayName })
  res.send({status: "ok"})
})

app.put("/api/users/displayName", authorize, async (req, res) => {
  const userId = req.user.sub;
  const { displayName } = req.body;
  await database.updateUserDisplayName(userId, displayName);
  console.log("update displayName", displayName, userId)
  res.send({status: "ok"})
});

app.put("/api/users/:id/profileImage", (req, res) => {
  console.log("update profile image", req.body)
  res.send({status: "ok"})
});

app.listen(8080, () => console.log("Listening on port 8080"));
