const express = require("express");
const router = express.Router();
const Login = require('../contollers/Login');
const Register = require('../contollers/Register')
const ActiveStatus = require('../contollers/ActiveStatus')
const Count = require('../contollers/ActiveStatus');
const Edit = require('../contollers/update');
const Products = require('../contollers/products');



router.post("/register", Register.register);


router.post("/login", Login.Login);


router.post("/logout", Login.Logout);


router.post("/getDetails", Register.getDetails)


router.post("/activeStatus", ActiveStatus.activeStatus);


router.post("/count", Count.updateCount);


router.put("/edit", Edit.edit);


router.put("/edituser", Edit.editUser);


router.post("/addproducts", Products.addProducts);


router.post("/getproducts", Products.getProducts);


router.post('/renew', Edit.renewProduct);




module.exports = router;
