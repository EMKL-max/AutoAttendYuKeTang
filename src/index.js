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
  headers: {
    "User-Agent":
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    Referer: "https://changjiang.yuketang.cn/",
  },
  throwHttpErrors: false,
});

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

// ---------- cookie 相关 ----------

// 把 YUKETANG_COOKIE 字符串注入 cookieJar
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

// 检查当前 cookieJar 里是否已有 sessionid
const hasSessionCookie = async () => {
  try {
    const str = await cookieJar.getCookieString("https://changjiang.yuketang.cn/");
    return /(^|;\s*)sessionid=/.test(str);
  } catch (e) {
    return false;
  }
};

// 用 userinfo 接口验证会话是否有效
const verifySession = async () => {
  try {
    const res = await customGot(api.userinfo);
    const body = await res.json().catch(() => ({}));
    return {
      ok: res.statusCode === 200 && body && (body.success === true || body.code === 0),
      status: res.statusCode,
      body,
    };
  } catch (err) {
    return { ok: false, status: 0, body: { error: err.message } };
  }
};

// 保活：请求一次 userinfo，让服务端续期同时检查会话
let lastKeepAliveFailed = false;
const keepAlive = async () => {
  const r = await verifySession();
  if (r.ok) {
    if (lastKeepAliveFailed) {
      console.log("Keep-alive recovered");
      lastKeepAliveFailed = false;
    }
  } else {
    console.log("Keep-alive failed:", r.status, JSON.stringify(r.body).slice(0, 200));
    if (!lastKeepAliveFailed) {
      lastKeepAliveFailed = true;
      sendNotify(
        "YukeTang: Cookie 可能失效",
        `status=${r.status} ${JSON.stringify(r.body).slice(0, 200)}`
      );
    }
  }
  return r.ok;
};

// ---------- 登录 ----------

// 密码登录（可能被腾讯防水墙拦截）
const passwordLogin = async (username, password) => {
  const res = await customGot(api.login, {
    method: "POST",
    json: {
      type: "PP",
      name: username,
      pwd: key.encrypt(password, "base64"),
    },
  });
  const body = await res.json().catch(() => ({}));
  console.log("Password login response:", JSON.stringify(body).slice(0, 300));
  return !!(body && body.success === true);
};

// 建立会话：先试密码登录，失败则用环境变量里的 cookie
const establishSession = async () => {
  const { USER_INFO } = process.env;
  const [USERNAME, PASSWORD] = (USER_INFO || "").split("|").map((s) => (s || "").trim());

  if (USERNAME && PASSWORD) {
    console.log("Trying password login...");
    try {
      const ok = await passwordLogin(USERNAME, PASSWORD);
      if (ok) {
        const v = await verifySession();
        if (v.ok) {
          console.log("Password login OK, session verified.");
          return true;
        }
        console.log("Password login said success but session verify failed:", JSON.stringify(v.body).slice(0, 200));
      } else {
        console.log("Password login rejected (possibly blocked by captcha).");
      }
    } catch (err) {
      console.log("Password login error:", err.message);
    }
  } else {
    console.log("No USER_INFO provided, skip password login.");
  }

  // 回退：使用 YUKETANG_COOKIE
  if (await loadCookieFromEnv()) {
    const v = await verifySession();
    if (v.ok) {
      console.log("Using cookie from YUKETANG_COOKIE, session verified.");
      return true;
    }
    console.log("Cookie from YUKETANG_COOKIE is invalid:", JSON.stringify(v.body).slice(0, 200));
  } else {
    console.log("No YUKETANG_COOKIE provided.");
  }

  return false;
};

// ---------- 查课 / 签到 ----------

const getOnLessonInfo = async () => {
  const res = await customGot(api.getOnLessonData);
  const body = await res.json().catch(() => ({}));
  const { data, success } = body;
  if (!success || !data) return false;
  const on_lessons = data.on_lessons;
  return on_lessons && on_lessons.length > 0 ? on_lessons : false;
};

const getOnLessonInfoV3 = async () => {
  const res = await customGot(api.getOnLessonDataV3);
  const body = await res.json().catch(() => ({}));
  const { data, code } = body;
  if ((code !== 0 && code !== undefined) || !data) return false;
  const onLessonClassrooms = data.onLessonClassrooms;
  return onLessonClassrooms && onLessonClassrooms.length > 0
    ? onLessonClassrooms
    : false;
};

const attendLessonV3Request = (lessonId) =>
  customGot(api.attendLessonV3, {
    method: "POST",
    json: {
      source: 1,
      lessonId,
    },
  });

const attendLessonV3 = async ({ lessonId, classroomId, courseName }) => {
  const res = await attendLessonV3Request(lessonId);
  const data = await res.json().catch(() => ({}));
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
  const res = await customGot(api.attendLesson, {
    searchParams: { lesson_id, source: 1 },
  });
  const data = await res.json().catch(() => ({}));
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

  // 每 15 次轮询（约 5 分钟）做一次保活 + 会话检查
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
        attendLesson(lesson).catch((e) => console.log("attendLesson err:", e.message))
      );
    lessonInfoV3 &&
      lessonInfoV3.forEach((lesson) =>
        attendLessonV3(lesson).catch((e) => console.log("attendLessonV3 err:", e.message))
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
