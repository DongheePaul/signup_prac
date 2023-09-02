const express = require("express");
const path = require("path");
const fs = require("fs").promises;
const cookieParser = require("cookie-parser");

const app = express();

app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

const USER_COOKIE_KEY = "USER";
const USERS_JSON_FILENAME = "./user.json";

const bcrypt = require("bcrypt");

async function fetchAllUsers() {
  const data = await fs.readFile(USERS_JSON_FILENAME);
  const users = JSON.parse(data.toString());
  return users;
}

async function fetchUser(username) {
  const users = await fetchAllUsers();
  const user = users.find((user) => user.username === username);
  return user;
}

async function createUser(newUser) {
  //두번째 인자는 salt. 값이 클수록 해시 함수를 여러번 돌려 연산 속도가 늦어짐.
  const hashedPassword = await bcrypt.hash(newUser.password, 10);
  const users = await fetchAllUsers();
  users.push({
    ...newUser,
    password: hashedPassword,
  });
  await fs.writeFile(USERS_JSON_FILENAME, JSON.stringify(users));
}

async function removeUser(username, password) {
  const user = await fetchUser(username);
  if (user.password === password) {
    const users = await fetchAllUsers();
    const index = users.findIndex((u) => u.username === username);
    users.splice(index, 1);
    await fs.writeFile(USERS_JSON_FILENAME, JSON.stringify(users));
  }
}

app.get("/", async (req, res) => {
  // 'user'라는 쿠키 데이터를 가져옴
  // 쿠키가 존재하지 않을 경우 로그인이 되지 않았다는 뜻
  const userCookie = req.cookies[USER_COOKIE_KEY];

  if (userCookie) {
    // 쿠키가 존재하는 경우, 쿠키 VALUE를 JS 객체로 변환
    const userData = JSON.parse(userCookie);
    // user 객체에 저장된 username이 db에 존재하는 경우,
    // 유효한 user이며 로그인이 잘 되어 있다는 뜻.
    const user = await fetchUser(userData.username);
    if (user) {
      // JS 객체로 변환된 user 데이터에서 username, name, password를 추출하여 클라이언트에 렌더링
      res.status(200).send(`
                <a href="/logout">Log Out</a>
                <a href="/withdraw">Withdraw</a>
                <h1>id: ${userData.username}, name: ${userData.name}, password: ${userData.password}</h1>
            `);
      return;
    }
  }

  // 쿠키가 존재하지 않는 경우, 로그인 되지 않은 것으로 간주
  res.status(200).send(`
        <a href="/login.html">Log In</a>
        <a href="/signup.html">Sign Up</a>
        <h1>Not Logged In</h1>
    `);
});

app.post("/signup", async (req, res) => {
  const { username, name, password } = req.body;
  const user = await fetchUser(username);

  // 이미 존재하는 username일 경우 회원 가입 실패
  if (user) {
    res.status(400).send(`duplicate username: ${username}`);
    return;
  }

  // 아직 가입되지 않은 username인 경우 db에 저장
  // KEY = username, VALUE = { name, password }
  const newUser = {
    username,
    name,
    password,
  };
  await createUser({
    username,
    name,
    password,
  });

  // db에 저장된 user 객체를 문자열 형태로 변환하여 쿠키에 저장
  res.cookie(USER_COOKIE_KEY, JSON.stringify(newUser));
  // 가입 완료 후, 루트 페이지로 이동
  res.redirect("/");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await fetchUser(username);

  // 가입 안 된 username인 경우
  if (!user) {
    res.status(400).send(`not registered username: ${username}`);
    return;
  }
  // 비밀번호가 틀렸을 경우
  const matchPassword = await bcrypt.compare(password, user.password);
  if (!matchPassword) {
    res.status(400).send("incorrect password");
    return;
  }

  // db에 저장된 user 객체를 문자열 형태로 변환하여 쿠키에 저장
  res.cookie(USER_COOKIE_KEY, JSON.stringify(user));
  // 로그인(쿠키 발급) 후, 루트 페이지로 이동
  res.redirect("/");
});

app.get("/logout", (req, res) => {
  // 쿠키 삭제 후 루트 페이지로 이동
  res.clearCookie(USER_COOKIE_KEY);
  res.redirect("/");
});

app.get("/withdraw", async (req, res) => {
  const userCookie = req.cookies[USER_COOKIE_KEY];
  const user = JSON.parse(userCookie);
  await removeUser(user.username, user.password);
  res.clearCookie(USER_COOKIE_KEY);
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("server is running at 3000");
});
