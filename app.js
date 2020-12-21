const mongodb = require("mongodb");
const MongoClient = mongodb.MongoClient;
const http = require("http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const port = 8080;
const url = "mongodb://localhost:27017/users";
require("dotenv").config();

let collectionUser;
MongoClient.connect(
  url,
  {
    useUnifiedTopology: true,
    useNewUrlParser: true,
  },
  function (err, db) {
    if (err) {
      throw err;
    }
    const dbo = db.db("users");
    collectionUser = dbo.collection("User");
  }
);

// ==== GET ROUTES ==== //

// @desc get all users
//@ route /users
async function findAllUsers(res) {
  try {
    const allUsers = await collectionUser
      .find({}, { projection: { id: 1, name: 1 } })
      .toArray();

    endResponseByStatus(res, 200, allUsers);
  } catch (error) {
    res.end(error);
  }
}

// @desc get user by id
//@ route /user/id
async function findUserById(res, id) {
  try {
    const userById = await collectionUser.findOne(
      { id },
      { projection: { name: 1 } }
    );

    endResponseByStatus(res, 200, userById);
  } catch (error) {
    res.end(error);
  }
}
// @desc Filter users by age
//@ route /users/filter/id
async function filterUsersByAge(res, age) {
  try {
    const users = await collectionUser
      .find({}, { projection: { name: 1, DOB: 1 } })
      .toArray();
    const userArr = [];
    users.forEach((user) => {
      const tempAge = Math.floor((new Date() - user.DOB) / 3.15576e10);
      if (tempAge >= age) userArr.push(user.name);
    });
    endResponseByStatus(res, 200, userArr);
  } catch (error) {
    res.end(error);
  }
}
// ==== POST ROUTES ==== //

// @desc Register New User
//@ route /register
async function registerUser(req, res) {
  try {
    let body = "";
    await req
      .on("data", (chunk) => {
        body += chunk.toString();
      })
      .on("end", async () => {
        let { id, name, email, password, dob } = JSON.parse(body);
        password = bcrypt.hashSync(password, 10);
        const DOB = new Date(dob);

        const newlyRegisteredUser = await collectionUser.insertOne({
          id,
          name,
          email,
          password,
          DOB,
        });
        const token = jwt.sign(
          { id: newlyRegisteredUser.id },
          process.env.ACCESS_TOKEN_SECRET
        );
        endResponseByStatus(res, 201, { token: token });
      });
  } catch (error) {
    res.end(error);
  }
}
// @desc Check For User Available
//@ route /login
async function checkForUserLogin(req, res) {
  try {
    let body = "";
    await req
      .on("data", (chunk) => {
        body += chunk.toString();
      })
      .on("end", async () => {
        const { email, password } = JSON.parse(body);

        const loggedInUser = await collectionUser.findOne({ email });

        if (!loggedInUser) {
          endResponseByStatus(res, 404, { error: "User is not Available" });
        } else {
          const isPasswordValid = bcrypt.compareSync(
            password,
            loggedInUser.password
          );
          if (!isPasswordValid) {
            endResponseByStatus(res, 401, { error: "Unauthorised Access!!" });
          } else {
            const token = jwt.sign(
              { id: loggedInUser.id },
              process.env.ACCESS_TOKEN_SECRET
            );
            endResponseByStatus(res, 200, { token: token });
          }
        }
      });
  } catch (error) {
    res.end(error);
  }
}

// ==== PATCH ROUTES ==== //

// @desc update user by id
// @ route PATCH /update/id
async function updateUserById(req, res, id) {
  try {
    let body = "";
    await req
      .on("data", (chunk) => {
        body += chunk.toString();
      })
      .on("end", async () => {
        const { name, email } = JSON.parse(body);

        const updatedUser = await collectionUser.updateOne(
          { id },
          { $set: { name, email } }
        );

        if (updatedUser.result.nModified === 0) {
          endResponseByStatus(res, 400, "User doesn't exists");
        } else {
          endResponseByStatus(res, 200, updatedUser);
        }
      });
  } catch (error) {
    res.end(error);
  }
}

// ====  Http Server With Routes ==== //
const server = http.createServer((req, res) => {
  const reqMethod = req.method;
  const reqUrl = req.url;

  switch (reqMethod) {
    case "GET": {
      if (verifyToken(req, res)) {
        if (reqUrl === "/users") {
          findAllUsers(res);
        } else if (reqUrl.match(/\/users\/([0-9]+)/)) {
          const id = Number(reqUrl.split("/")[2]);
          findUserById(res, id);
        } else if (reqUrl.match(/\/users\/filter\/([0-9]+)/)) {
          const age = Number(reqUrl.split("/")[3]);
          filterUsersByAge(res, age);
        }
      }
      break;
    }
    case "POST": {
      if (reqUrl === "/register") {
        registerUser(req, res);
      } else if (reqUrl === "/login") {
        checkForUserLogin(req, res);
      }
      break;
    }
    case "PATCH": {
      if (verifyToken(req, res)) {
        if (reqUrl.match(/\/update\/([0-9]+)/)) {
          const id = Number(reqUrl.split("/")[2]);
          updateUserById(req, res, id);
        }
      }
    }
    default: {
      if (reqUrl === "/") {
        res.end("Welcome To User App");
      }
    }
  }
});

// @desc function to end response object with specific data
function endResponseByStatus(res, status, msgData) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(msgData));
}

// @desc Fuction to check for verifyToken
function verifyToken(req, res) {
  //Get auth headers

  const bearerHeader = req.headers["authorization"];

  if (typeof bearerHeader !== "undefined") {
    const bearerToken = bearerHeader.split(" ")[1];
    req.token = bearerToken;
    try {
      jwt.verify(req.token, process.env.ACCESS_TOKEN_SECRET);
      return true;
    } catch (error) {
      endResponseByStatus(res, 401, { error: "Unauthorised User!!" });
    }
  } else {
    endResponseByStatus(res, 403, { error: "Token is not available" });
  }
}

server.listen(port, () => {
  console.log(`Server is listening at ${port}`);
});
