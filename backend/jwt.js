import jwt from "jsonwebtoken";

const secret = "shhhhhh";

export function authorize(req, res, next) {
  const authHeader = req.headers.authorization
  const token = authHeader ? authHeader.split(' ')[1] : null

  if (!token) {
    console.error("no token sent to server")
    res.status(401).send({error: "no token sent to server"})
    return 
  }

  let decoded
  try {
    decoded = jwt.verify(token, secret);
  } catch(error) {
    console.error(error)
    res.status(403).send({error: "Invalid Token"})
    return
  }

  req.user = decoded
  next()
};

export function generateToken(obj) {
  return jwt.sign(obj,
    secret,
    { expiresIn: "1000000000000000000s" }
  );
};