const router = require("express").Router();

const userController = require("../controllers/userController");
const authController = require("../controllers/auth");


//  Using middleware protect to have a successfull login Data
router.patch("/update-me", authController.protect, userController.updateMe);


module.exports = router;