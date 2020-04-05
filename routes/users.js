var express = require("express");
var router = express.Router();
var db = require("../db.js");
var bcrypt = require("bcrypt");
var { v4 } = require("uuid");
var mysql = require("mysql2");
var admin = require("firebase-admin");
var serviceAccount = require("../fique-em-casa-5b65f-firebase-adminsdk-8jp90-505966d77d.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://fique-em-casa-5b65f.firebaseio.com",
});

const saltRounds = 12;

/* GET users listing. */
router.get("/:userid", async function (req, res, next) {
  try {
    let [
      rows,
      fields,
    ] = await db
      .get()
      .promise()
      .execute("SELECT phone FROM users WHERE uuid = ?", [req.params.userid]);
    if (rows.length > 0) {
      res.status(200).json({ phone: rows[0].phone });
    } else {
      res.status(404).json({});
    }
  } catch (e) {
    res.status(404).json({});
  }
});

router.post("/register", async function (req, res, next) {
  let { phone, password } = req.body;
  let passwordHash = bcrypt.hashSync(password, saltRounds);
  let user = {
    phone: phone,
    password: passwordHash,
    uuid: v4(),
  };
  try {
    let query = `INSERT INTO users(phone, password, uuid) VALUES(${mysql.escape(
      user.phone
    )}, ${mysql.escape(user.password)}, ${mysql.escape(user.uuid)});`;
    await db.get().promise().execute(query);
    admin
      .auth()
      .createCustomToken(user.uuid, { phoneNumber: user.phone })
      .then(function (customToken) {
        res.status(200).json({ token: customToken });
      })
      .catch(function (error) {
        res.status(500).json({
          code: "create-token-fault",
          message: "Erro na criação do token no servidor",
        });
      });
  } catch (e) {
    if (e.errno == 1062) {
      res.status(401).json({
        code: "phone-duplicate",
        message: "Telefone já cadastrado em nosso sistema",
      });
    } else {
      res
        .status(500)
        .json({ code: "server-fault", message: "Erro no servidor" });
    }
  }
});

router.post("/login", async function (req, res, next) {
  let { phone, password } = req.body;
  try {
    let [
      rows,
      fields,
    ] = await db
      .get()
      .promise()
      .execute("SELECT * FROM users WHERE phone = ?", [phone]);
    if (rows.length > 0) {
      let user = rows[0];
      bcrypt.compare(password, user.password, function (err, result) {
        if (result) {
          admin
            .auth()
            .createCustomToken(user.uuid, { phoneNumber: user.phone })
            .then(function (customToken) {
              res.status(200).json({ token: customToken });
            })
            .catch(function (error) {
              res.status(500).json({
                code: "create-token-fault",
                message: "Erro na criação do token no servidor",
              });
            });
        } else {
          res
            .status(401)
            .json({ code: "password-mismatch", message: "Password incorreto" });
        }
      });
    } else {
      res
        .status(401)
        .send({ code: "phone-mismatch", message: "Telefone incorreto" });
    }
  } catch (e) {
    res.status(500).json({ code: "server-fault", message: "Erro no servidor" });
  }
});

module.exports = router;
