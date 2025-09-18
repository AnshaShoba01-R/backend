const db = require("../config/db");
const CryptoJS = require('crypto-js');
const moment = require("moment");

const secretKey = process.env.SECRET_KEY;


// Edit Admin 


exports.edit = async (req, res) => {
    const { unique_id, product_id, name, email, password, product_name, assigned_at, machines, subscription } = req.body;

    if (!unique_id || !product_id) {
        return res.status(400).json({ error: "unique_id and product_id required" });
    }

    const checkSql = `SELECT * FROM admin_product WHERE unique_id = ?`;

    db.query(checkSql, [unique_id], async (err, rows) => {
        if (err) {
            console.error("Error fetching admin_product:", err);
            return res.status(500).json({ message: "Database error" });
        }

        if (rows.length === 0) {
            return res.status(404).json({ message: "Record not found" });
        }

        const row = rows[0];
        let products;

        try {
            products = typeof row.products === "string" ? JSON.parse(row.products) : row.products;
        } catch (err) {
            console.error("Invalid JSON in products column:", err);
            return res.status(500).json({ message: "Invalid product data format" });
        }

        const index = products.findIndex(p => p.product_id === product_id);
        if (index === -1) {
            return res.status(404).json({ message: "Product not found in admin" });
        }

        const oldData = { ...products[index] };
        delete oldData.history;

        if (!products[index].history) {
            products[index].history = [];
        }
        products[index].history.push({
            ...oldData,
            updated_at: require("moment")().format("DD-MM-YYYY")
        });

        if (name) row.name = name;
        if (email) row.email = email;
        if (password) {
            const CryptoJS = require("crypto-js");
            const secretKey = process.env.SECRET_KEY || "your_default_secret";
            row.password = CryptoJS.AES.encrypt(password, secretKey).toString();
        }

        if (name) products[index].admin_name = name;
        if (email) products[index].email = email;
        if (product_name) products[index].product_name = product_name;
        if (machines) products[index].machines = machines;
        if (subscription) products[index].subscription = subscription;

        const moment = require("moment");
        products[index].assigned_at = assigned_at
            ? moment(assigned_at, "DD-MM-YYYY").format("DD-MM-YYYY")
            : moment().format("DD-MM-YYYY");

        if (subscription) {
            try {
                const updatedProduct = addExpiryInfo([products[index]])[0];
                updatedProduct.assigned_at = products[index].assigned_at;

                updatedProduct.history = products[index].history || [];

                products[index] = updatedProduct;

                await db.promise().query(
                    "UPDATE users SET expiryDate = ? WHERE admin = ? AND product_id = ?",
                    [updatedProduct.expiryDate, unique_id, product_id]
                );
            } catch (err) {
                console.error("Invalid subscription format:", err.message);
                return res.status(400).json({ message: "Invalid subscription format" });
            }

        }

        if (subscription) {
            await db.promise().query(
                "UPDATE users SET expiryDate = ? WHERE admin = ? AND product_id = ?",
                [products[index].expiryDate, unique_id, product_id]
            );
        }

        const updateSql = `UPDATE admin_product SET name = ?, email = ?, password = ?, products = ? WHERE unique_id = ?`;
        db.query(updateSql, [
            row.name,
            row.email,
            row.password,
            JSON.stringify(products),
            unique_id
        ], (err) => {
            if (err) {
                console.error("Error updating record:", err);
                return res.status(500).json({ message: "Update failed" });
            }
            return res.json({ message: "Updated successfully" });
        });
    });
};


// Edit User 


exports.editUser = async (req, res) => {
    const { unique_id, name, email, password } = req.body;

    if (!unique_id) {
        return res.status(400).json({ error: "unique_id required" });
    }

    if (!name && !email && !password) {
        return res.status(400).send({ message: "No fields provided to update" });
    }

    const tables = ["super_admin", "admin_product", "users"];

    const updateTable = (index) => {
        if (index >= tables.length) {
            return res.status(404).send({ message: "Record not found" });
        }

        const table = tables[index];
        const checkSql = `SELECT * FROM ${table} WHERE unique_id = ?`;

        db.query(checkSql, [unique_id], (err, rows) => {
            if (err) {
                console.error(`Error checking ${table}:`, err);
                return res.status(500).send({ message: "Database error" });
            }

            if (rows.length > 0) {
                let user = rows[0];

                const moment = require("moment");
                const newVersion = {
                    name: name || user.name,
                    email: email || user.email,
                    password: password ? CryptoJS.AES.encrypt(password, secretKey).toString() : user.password,
                    updated_at: moment().format("DD-MM-YYYY"),
                };

                if (table === "users") {
                    let history = [];
                    try {
                        history = user.history ? JSON.parse(user.history) : [];
                    } catch (err) {
                        history = [];
                    }

                    const snapshot = { ...user };
                    delete snapshot.history;
                    snapshot.updated_at = moment().format("DD-MM-YYYY");
                    history.push(snapshot);

                    // let incomingDevice = req.body.device_id;

                    // if (user.device_id && incomingDevice && incomingDevice.toString().trim().toLowerCase() === "null") {
                    //     newDeviceId = null;
                    // }

                    let incomingDevice = req.body.device_id;
                    let newDeviceId = user.device_id;

                    if (incomingDevice !== undefined) {
                        const deviceStr = incomingDevice.toString().trim().toLowerCase();
                        if (deviceStr === "null") {
                            newDeviceId = null;
                        } else {
                            return res.status(400).send({
                                message: "device_id can only be changed to null."
                            });
                        }
                    }

                    newVersion.device_id = newDeviceId;

                    const updateSql = `UPDATE users SET name = ?, email = ?, password = ?, device_id = ?, history = ? WHERE unique_id = ?`;
                    db.query(updateSql, [
                        newVersion.name,
                        newVersion.email,
                        newVersion.password,
                        newDeviceId,
                        JSON.stringify(history),
                        unique_id
                    ], (err) => {
                        if (err) {
                            console.error("Error updating user JSON history:", err);
                            return res.status(500).send({ message: "Database error" });
                        }
                        const decryptedPassword = CryptoJS.AES.decrypt(user.password, secretKey).toString(CryptoJS.enc.Utf8);
                        res.send({ message: "User updated successfully", updatedUser: { ...newVersion, password: decryptedPassword } });

                    });
                }

                else {
                    const fields = [];
                    const values = [];

                    if (name) {
                        fields.push("name = ?");
                        values.push(name);
                    }
                    if (email) {
                        fields.push("email = ?");
                        values.push(email);
                    }
                    if (password) {
                        fields.push("password = ?");
                        values.push(newVersion.password);
                    }

                    const updateSql = `UPDATE ${table} SET ${fields.join(", ")} WHERE unique_id = ?`;

                    db.query(updateSql, [...values, unique_id], (err) => {
                        if (err) {
                            console.error(`Error updating ${table}:`, err);
                            return res.status(500).send({ message: "Database error" });
                        }
                        res.send({ message: `Updated Successfully` });
                    });
                }
            } else {
                updateTable(index + 1);
            }
        });
    };

    updateTable(0);
};


function addExpiryInfo(products) {
    const productList = Array.isArray(products) ? products : [];

    return productList.map(p => {
        const subscriptionDays = Number(p.subscription);
        const createdDate = p.assigned_at
            ? moment(p.assigned_at, "DD-MM-YYYY")
            : moment();

        if (isNaN(subscriptionDays) || subscriptionDays < 0) {
            throw new Error("Invalid subscription value. Must be a non-negative number.");
        }

        const expiryDate = createdDate.clone().add(subscriptionDays - 1, 'days').endOf('day');

        const isExpired = moment().isAfter(expiryDate);

        return {
            ...p,
            expired: isExpired ? 0 : 1,
            expiryDate: expiryDate.format("DD-MM-YYYY")
        };
    });
}




exports.renewProduct = async (req, res) => {
    const { admin_id, product_id, subscription } = req.body;

    if (!admin_id || !product_id || !subscription) {
        return res.status(400).json({ message: "admin_id, product_id and subscription are required" });
    }

    try {
        const [rows] = await db.promise().query("SELECT * FROM admin_product WHERE unique_id = ?", [admin_id]);

        if (!rows.length) return res.status(404).json({ message: "Admin not found" });

        let products = rows[0].products;
        products = typeof products === "string" ? JSON.parse(products) : products;

        const index = products.findIndex(p => p.product_id === product_id);
        if (index === -1) return res.status(404).json({ message: "Product not found" });

        const oldData = { ...products[index] };
        delete oldData.history;

        if (!products[index].history) {
            products[index].history = [];
        }
        products[index].history.push({
            ...oldData,
            updated_at: require("moment")().format("DD-MM-YYYY")
        });

        const match = [``, subscription, 'days'];

        if (!match) {
            return res.status(400).json({ message: "Invalid subscription format" });
        }

        const [_, num, rawUnit] = match;
        const unit = rawUnit.toLowerCase();
        const assigned_at = moment().format("DD-MM-YYYY");
        const expiryDate = moment().add(parseInt(num) - 1, unit).format("DD-MM-YYYY");


        const newProduct = {
            ...products[index],
            assigned_at,
            subscription,
            expiryDate,
            history: products[index].history
        };

        products[index] = newProduct;

        await db.promise().query(
            "UPDATE admin_product SET products = ? WHERE unique_id = ?",
            [JSON.stringify(products), admin_id]
        );

        await db.promise().query(
            "UPDATE users SET expiryDate = ? WHERE admin = ? AND product_id = ?",
            [expiryDate, admin_id, product_id]
        );

        return res.json({ message: "Product renewed successfully", newProduct });
    } catch (err) {
        console.error("Renew error:", err);
        return res.status(500).json({ message: "Server error occurred while renewing product" });
    }
};
