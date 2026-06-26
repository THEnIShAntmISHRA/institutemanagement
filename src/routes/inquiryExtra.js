const express = require("express");
const router = express.Router();
const auth = require("../middleware/auth");
const c = require("../controllers/inquiryExtraController");

router.get("/", auth, c.getAll);
router.delete("/:id", auth, c.remove);

module.exports = router;
