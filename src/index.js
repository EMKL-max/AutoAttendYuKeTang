const NodeRSA = require("node-rsa");
const path = require("path");
const fs = require("fs");
const got = require("got");
const { CookieJar } = require("tough-cookie");
const sendNotify = require("./sendNotify");
const moment = require("moment");

const resolve = function (...args) {
  return path.resolve(__dirname, ...args);
};

let count = 0;

const cookieJar = new CookieJar();

let startTime = undefined;

const customGot = got.extend({
  cookieJar,
  timeout: 15000,
  responseType: "json",
  headers: {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Referer: "https://changjiang.yuketang.cn/",
  },
  throwHttpErrors: false,
});

// got 11：body 已经是解析后的对象，统一用它，绝不调用 res.json()
const reqJson = async (url, options = {}) => {
  try {
    const res = await customGot(url, options);
    let body = res.body;
    if (typeof body === "string") {
      try {
        body = JSON.parse(body);
      } catch (e) {
        body = { raw: body.slice(0, 200) };
      }
    }
    return { status: res.statusCode, body: body || {} };
  } catch (err) {
    return { status: 0, body: { error: err.message } };
  }
};

const successLessons = new Set();

const publicKey = fs.readFileSync(resolve("public.pem"), "utf8");
const key = new NodeRSA(publicKey, "pkcs8-public", {
  encryptionScheme: "pkcs1",
});

const api = {
  login: "https://changjiang.yuketang.cn/pc/login/verify_pwd_login/",
  userinfo: "https://changjiang.yuketang.cn/v2/api/web/userinfo",
  getOnLessonData:
    "https://changjiang.yuketang.cn/v/course_meta/on_lesson_courses",
  attendLesson: "https://changjiang.yuketang.cn/v/lesson/lesson_info_v2",
  attendLessonV3: "https://changjiang.yuketang.cn/api/v3/lesson/checkin",
  getOnLessonDataV3:
    "https://changjiang.yuketang.cn/api/v3/classroom/on-lesson",
};

// ---------- cookie ----------

const loadCookieFromEnv = async () => {
  const raw = process.env.YUKETANG_COOKIE;
  if (!raw) return false;
  const loaded = [];
  for (const pair of raw.split(";")) {
    const idx = pair.indexOf("=");
    if (idx <= 0) continue;
    const name = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    if (!name) continue;
    await cookieJar.setCookie(
      `${name}=${value}; Domain=changjiang.yuketang.cn; Path=/`,
      "https://changjiang.yuketang.cn/"
    );
    loaded.push(name);
  }
  console.log("Cookie loaded:", loaded.join(", "));
  return loaded.includes("sessionid");
};

const verifySession = async () => {
  const { status, body } = await reqJson(api.userinfo);
  const ok =
    status === 200 &&
    !!body &&
    (body.success === true || body.code === 0 || !!body.data);
  return { ok, status, body };
};

let keepAliveBroken = false;
const keepAlive = async () => {
  const r = await verifySession();
  if (r.ok) {
    if (keepAliveBroken) {
      console.log("Keep-alive recovered");
      keepAliveBroken = false;
    }
  } else {
    console.log(
      "Keep-alive failed:",
      r.status,
      JSON.stringify(r.body).slice(0, 200)
    );
    if (!keepAliveBroken) {
      keepAliveBroken = true;
      sendNotify(
        "YukeTang: Cookie 可能失效",
        `status=${r.status} ${JSON.stringify(r.body).slice(0, 200)}`
      );
    }
  }
  return r.ok;
};

// ---------- 登录 ----------

const passwordLogin = async (username, password) => {
  const { status, body } = await reqJson(api.login, {
    method: "POST",
    json: {
      type: "PP",
      name: username,
      pwd: key.encrypt(password, "base64"),
    },
  });
  console.log(
    "Password login response:",
    status,
    JSON.stringify(body).slice(0, 300)
  );
  return !!(body && body.success === true);
};

const establishSession = async () => {
  const { USER_INFO } = process.env;
  const [USERNAME, PASSWORD] = (USER_INFO || "")
    .split("|")
    .map((s) => (s || "").trim());

  if (USERNAME && PASSWORD && process.env.YUKETANG_COOKIE === undefined) {
    // 没有 cookie 时优先密码登录
  }

  if (USERNAME && PASSWORD) {
    console.log("Trying password login...");
    const ok = await passwordLogin(USERNAME, PASSWORD);
    if (ok) {
      const v = await verifySession();
      if (v.ok) {
        console.log("Password login OK, session verified.");
        return true;
      }
      console.log(
        "Password login said success but session verify failed:",
        JSON.stringify(v.body).slice(0, 200)
      );
    } else {
      console.log("Password login rejected (possibly blocked by captcha).");
    }
  } else {
    console.log("No USER_INFO provided, skip password login.");
  }

  if (await loadCookieFromEnv()) {
    const v = await verifySession();
    if (v.ok) {
      console.log("Using cookie from YUKETANG_COOKIE, session verified.");
      return true;
    }
    console.log(
      "Cookie from YUKETANG_COOKIE is invalid:",
      JSON.stringify(v.body).slice(0, 200)
    );
  } else {
    console.log("No YUKETANG_COOKIE provided.");
  }

  return false;
};

// ---------- 查课 / 签到 ----------

const getOnLessonInfo = async () => {
  const { body } = await reqJson(api.getOnLessonData);
  const { data, success } = body;
  if (!success || !data) return false;
  const on_lessons = data.on_lessons;
  return on_lessons && on_lessons.length > 0 ? on_lessons : false;
};

const getOnLessonInfoV3 = async () => {
  const { body } = await reqJson(api.getOnLessonDataV3);
  const { data, code } = body;
  if ((code !== 0 && code !== undefined) || !data) return false;
  const onLessonClassrooms = data.onLessonClassrooms;
  return onLessonClassrooms && onLessonClassrooms.length > 0
    ? onLessonClassrooms
    : false;
};

const attendLessonV3 = async ({ lessonId, classroomId, courseName }) => {
  const { body: data } = await reqJson(api.attendLessonV3, {
    method: "POST",
    json: {
      source: 1,
      lessonId,
    },
  });
  const { code } = data;
  const success = code === 0;
  if (success) {
    console.log("Success: ", courseName);
    if (!successLessons.has(classroomId)) {
      sendNotify("YuKeTang: success", courseName);
      successLessons.add(classroomId);
    }
  } else {
    console.log("Error: ", data);
    sendNotify("YukeTang: Error", JSON.stringify(data, null, 2));
  }
};

const attendLesson = async ({ lesson_id, classroom }) => {
  const { body: data } = await reqJson(api.attendLesson, {
    searchParams: { lesson_id, source: 1 },
  });
  const name = classroom?.course?.name;
  const { success } = data;
  if (success) {
    console.log("Success: ", name);
    if (!successLessons.has(lesson_id)) {
      sendNotify("YuKeTang: success", name);
      successLessons.add(lesson_id);
    }
  } else {
    console.log("Error: ", data);
    sendNotify("YukeTang: Error", JSON.stringify(data, null, 2));
  }
};

// ---------- 主循环 ----------

const execCheckIn = async () => {
  console.log(`Number of executions: ${++count}`);
  if (count <= 1) {
    startTime = moment();
  } else {
    const nowTime = moment();
    if (nowTime.diff(startTime, "minute") > 320) {
      sendNotify("YukeTang: End", nowTime.format("YYYY-MM-DD HH:mm:ss"));
      return;
    }
  }
  setTimeout(execCheckIn, 1000 * 20);

  if (count % 15 === 1) {
    const ok = await keepAlive();
    if (!ok) {
      console.log("Session invalid, trying to re-establish...");
      const reOk = await establishSession();
      if (!reOk) {
        console.log("Re-establish session failed, skip this round.");
        return;
      }
      console.log("Session re-established.");
    }
  }

  let lessonInfo = undefined;
  let lessonInfoV3 = undefined;
  try {
    lessonInfo = await getOnLessonInfo();
    lessonInfoV3 = await getOnLessonInfoV3();
  } catch (err) {
    console.log("GetOnInfo Failed:", err.message || err);
  }
  if (!lessonInfo && !lessonInfoV3) {
    return;
  }
  try {
    lessonInfo &&
      lessonInfo.forEach((lesson) =>
        attendLesson(lesson).catch((e) =>
          console.log("attendLesson err:", e.message)
        )
      );
    lessonInfoV3 &&
      lessonInfoV3.forEach((lesson) =>
        attendLessonV3(lesson).catch((e) =>
          console.log("attendLessonV3 err:", e.message)
        )
      );
  } catch (err) {
    console.log("Attend Failed:", err.message || err);
  }
};

const startUp = async () => {
  const ok = await establishSession();
  if (!ok) {
    sendNotify("YukeTang: 登录失败", "密码登录和 cookie 都不可用，请检查 Secret");
    console.log("Failed: unable to establish session.");
    process.exit(1);
  }
  sendNotify("YukeTang: Start", new Date().toLocaleString("zh-CN"));
  execCheckIn();
};

startUp();
