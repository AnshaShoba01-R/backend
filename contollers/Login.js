const moment = require("moment");
const db = require("../config/db");
const { v4: uuidv4 } = require('uuid');
const CryptoJS = require('crypto-js');
const os = require("os");
const jwt = require("jsonwebtoken");


const secretKey = process.env.SECRET_KEY;

const secretJWT = process.env.JWT;


const activeSessions = {};



exports.Login = (req, res) => {

    const { email, password, product_id, device_id } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            status: "error",
            title: "Missing Credentials",
            message: "Email and password are required.",
        });
    }

    const roles = [
        { table: "super_admin", role: "super_admin", idKey: "unique_id" },
        { table: "admin_product", role: "admin", idKey: "unique_id" },
        { table: "users", role: "user", idKey: "unique_id" },
    ];

    const tryLogin = (index = 0) => {
        if (index >= roles.length) {
            return res.status(404).json({
                status: "error",
                message: "No user found with this email.",
            });
        }

        const { table, role, idKey } = roles[index];
        const query = `SELECT * FROM ${table} WHERE email = ?`;

        db.query(query, [email], (err, results) => {
            if (err) {
                console.error("DB error:", err);
                return res.status(500).json({
                    status: "error",
                    message: "Database access error.",
                });
            }

            if (results.length === 0) {
                return tryLogin(index + 1);
            }

            let user = results[0];

            if ((role === "user")) {
                const providedProductId = req.body.product_id;

                if (!providedProductId) {
                    return res.status(400).json({
                        status: "error",
                        title: "Missing Product ID",
                        message: "Product ID is required",
                    });
                }

                let productMatch = false;

                if (user.product_id === providedProductId) {
                    productMatch = true;
                }

                if (!productMatch && user.products) {
                    try {
                        const productList = typeof user.products === "string"
                            ? JSON.parse(user.products)
                            : user.products;

                        productMatch = productList.some(p => p.product_id === providedProductId);
                    } catch (err) {
                        console.error("Invalid JSON in products field:", user.products);
                        return res.status(500).json({
                            status: "error",
                            message: "Invalid product data."
                        });
                    }
                }

                if (!productMatch) {
                    return res.status(403).json({
                        status: "error",
                        title: "Invalid Product",
                        message: "Product ID does not match the records.",
                    });
                }
            }

            try {
                const bytes = CryptoJS.AES.decrypt(user.password, secretKey);
                const decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);

                if (decryptedPassword !== password) {
                    return res.status(401).json({
                        status: "error",
                        message: "Incorrect password.",
                    });
                }

                // USER

                if (role === "user") {

                    if (user.active === 0) {
                        return res.status(403).json({
                            status: "error",
                            message: "Your product is deactivated. Please contact admin."
                        });
                    }

                    if (user.expiryDate) {
                        const expiryMoment = moment(user.expiryDate, "DD-MM-YYYY").endOf('day');
                        if (moment().isAfter(expiryMoment)) {
                            return res.status(401).json({
                                status: "error",
                                message: "Your License has expired. Please renew to log in."
                            });
                        } else {
                            console.log("Result: Subscription ACTIVE");
                        }
                    }

                    const checkQuery = `SELECT device_id FROM users WHERE email = ? AND unique_id = ?`;
                    db.query(checkQuery, [user.email, user.unique_id], (err, checkResult) => {
                        if (err) {
                            console.error("Check device_id error:", err);
                            return res.status(500).json({
                                status: "error",
                                message: "Machine check failed.",
                            });
                        }

                        const storedDeviceId = checkResult[0]?.device_id;
                        const isFirstLogin = !storedDeviceId;
                        let device_id;

                        if (isFirstLogin) {

                            if (!req.body.device_id) {
                                return res.status(400).json({
                                    status: "error",
                                    message: "Device ID is required"
                                });
                            }

                            device_id = req.body.device_id;

                            const deviceCheckQuery = `SELECT email FROM users WHERE device_id = ?`;
                            db.query(deviceCheckQuery, [device_id], (err, deviceResult) => {
                                if (err) {
                                    console.error("Device check error:", err);
                                    return res.status(500).json({
                                        status: "error",
                                        message: "Device check failed.",
                                    });
                                }

                                if (deviceResult.length > 0) {
                                    return res.status(403).json({
                                        status: "error",
                                        message: "Login denied. This device is already registered with another account.",
                                    });
                                }

                                const now = moment().format("DD-MM-YYYY");

                                const updateQuery = `UPDATE users SET device_id = ?, first_login_at = ? WHERE email = ? AND unique_id = ? AND (first_login_at IS NULL OR first_login_at = '')`;
                                db.query(updateQuery, [device_id, now, user.email, user.unique_id], (err) => {
                                    if (err) {
                                        console.error("Machine ID insert failed:", err);
                                        return res.status(500).json({
                                            status: "error",
                                            message: "Machine ID store failed.",
                                        });
                                    }
                                    return completeLogin(device_id);
                                });

                            });
                        }
                        else {

                            if (!req.body.device_id) {
                                return res.status(400).json({
                                    status: "error",
                                    message: "Device ID is required"
                                });
                            }

                            device_id = req.body.device_id;

                            if (storedDeviceId !== device_id) {
                                return res.status(403).json({
                                    status: "error",
                                    message: "Login denied. Device_Id Not match",
                                });
                            }

                            const deviceCheckQuery = `SELECT email FROM users WHERE device_id = ? AND email != ?`;
                            db.query(deviceCheckQuery, [device_id, user.email], (err, deviceResult) => {
                                if (err) {
                                    console.error("Device check error:", err);
                                    return res.status(500).json({
                                        status: "error",
                                        message: "Device check failed.",
                                    });
                                }

                                if (deviceResult.length > 0) {
                                    return res.status(403).json({
                                        status: "error",
                                        message: "Login denied. This device is already registered with another account.",
                                    });
                                }

                                return completeLogin(device_id);
                            });
                        }

                        function completeLogin(device_id) {
                            const productQuery = `SELECT products FROM admin_product WHERE unique_id = ?`;
                            db.query(productQuery, [user.admin], (err, productResult) => {
                                if (err) {
                                    console.error("Fetch product error:", err);
                                }

                                let remainingDays = 0;
                                let assigned_at = null;

                                if (productResult && productResult.length > 0) {
                                    let products = productResult[0].products;
                                    if (typeof products === "string") {
                                        try {
                                            products = JSON.parse(products);
                                        } catch (e) {
                                            console.error("Invalid products JSON string", e);
                                            products = [];
                                        }
                                    }

                                    const matchingProduct = products.find(
                                        p => String(p.product_id) === String(user.product_id)
                                    );

                                    if (matchingProduct) {
                                        if (matchingProduct.assigned_at) {
                                            assigned_at = matchingProduct.assigned_at;
                                        }

                                        if (matchingProduct.expiryDate) {
                                            const expiry = moment(matchingProduct.expiryDate, "DD-MM-YYYY").endOf('day');
                                            const today = moment().startOf('day');
                                            remainingDays = Math.max(expiry.diff(today, "days"), 0);
                                        }
                                    }
                                }

                                const bytes = CryptoJS.AES.decrypt(user.password, secretKey);
                                const decryptedPassword = bytes.toString(CryptoJS.enc.Utf8);

                                if (decryptedPassword !== password) {
                                    return res.status(401).json({
                                        status: "error",
                                        message: "Incorrect password.",
                                    });
                                }
                                const tokenPayload = {
                                    name: user.name,
                                    email: user.email,
                                    password: decryptedPassword,
                                    product_id: user.product_id,
                                    startDate: assigned_at,
                                    expiryDate: user.expiryDate,
                                    app_start_date: user.first_login_at,
                                    remainingDays
                                };

                                const token = jwt.sign(tokenPayload, secretJWT, { expiresIn: "1h" });

                                return res.status(200).json({
                                    status: "success",
                                    message: "Login Successful",
                                    token,
                                    data: {
                                        role,
                                        name: user.name,
                                    },
                                });
                            });
                        }

                    });
                }

                else {
                    const tokenPayload = {
                        name: user.name,
                        email: user.email
                    };

                    const token = jwt.sign(tokenPayload, secretJWT, { expiresIn: "2m" });

                    return res.status(200).json({
                        status: "success",
                        message: "Login Successful",
                        token,
                        data: {
                            role,
                            id: user[idKey],
                            name: user.name,
                            email: user.email,
                        },
                    });
                }

            } catch (error) {
                console.error("Decryption error:", error);
                return res.status(500).json({
                    status: "error",
                    message: "Password decryption failed.",
                });
            }
        });
    };

    tryLogin();
};



exports.Logout = (req, res) => {

    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(400).json({ message: "Token missing or invalid format" });
    }

    const token = authHeader.split(" ")[1];

    jwt.verify(token, secretJWT, (err, decoded) => {
        if (err) {

            if (err.name === "TokenExpiredError") {

                for (const key in activeSessions) {
                    if (activeSessions[key].token === token) {
                        delete activeSessions[key];
                        break;
                    }
                }
                return res.status(200).json({ message: "Token expired and session removed" });
            }

            return res.status(401).json({ message: "Invalid token" });
        }

        for (const key in activeSessions) {
            if (activeSessions[key].token === token) {
                delete activeSessions[key];
                return res.status(200).json({ message: "Logged out successfully" });
            }
        }

        return res.status(404).json({ message: "Session not found" });
    });
}
