const moment = require("moment");
const db = require("../config/db");
const { v4: uuidv4 } = require('uuid');
const CryptoJS = require('crypto-js');


const secretKey = process.env.SECRET_KEY;



exports.register = async (req, res) => {

    const { name, email, password, super_admin, admin, role, product_id, product_name, device_id, active, expiry } = req.body;

    try {

        if (!name || !email || !password) {
            return res.status(400).json({ error: "Name, email, and password are required" });
        }

        db.query(
            `SELECT 'exists' AS result FROM super_admin WHERE email = ? UNION SELECT 'exists' FROM admin_product WHERE email = ? UNION SELECT 'exists' FROM users WHERE email = ?`,
            [email, email, email],
            async (err, results) => {
                if (err) {
                    console.error("Database Error:", err);
                    return res.status(500).json({ error: "Database error" });
                }

                const encryptedPassword = CryptoJS.AES.encrypt(password, secretKey).toString();
                const uniqueId = uuidv4();
                const formattedDate = moment().format("DD-MM-YYYY");;

                // SUPER ADMIN

                if (role === "super_admin") {
                    const insertQuery = `
                        INSERT INTO super_admin (unique_id, name, email, password, created_at)
                        VALUES (?, ?, ?, ?, ?)`;
                    const values = [uniqueId, name, email, encryptedPassword, formattedDate];

                    db.query(insertQuery, values, (err) => {
                        if (err) {
                            console.error("Insert Error (super_admin):", err.message);
                            return res.status(500).json({ error: "Insert error", details: err.message });
                        }
                        return res.status(200).json({ message: "super_admin registered", role, uniqueId });
                    });
                }

                // ADMIN

                else if (role === "admin") {
                    const { name, email, password, super_admin, products } = req.body;

                    if (!super_admin) {
                        return res.status(400).json({ error: "Super Admin ID is required" });
                    }

                    if (!products || !Array.isArray(products) || products.length === 0) {
                        return res.status(400).json({ error: "Products array is required and cannot be empty" });
                    }

                    db.query("SELECT unique_id FROM super_admin WHERE unique_id = ?", [super_admin], (err, results) => {
                        if (err) {
                            console.error("DB error while fetching super admin:", err);
                            return res.status(500).json({ error: "Database error", details: err });
                        }
                        if (results.length === 0) {
                            return res.status(400).json({ error: "Super Admin not found" });
                        }

                        const superAdminId = results[0].unique_id;

                        db.query("SELECT * FROM admin_product WHERE email = ?", [email], async (err, adminResults) => {
                            if (err) {
                                console.error("DB error while fetching admin:", err);
                                return res.status(500).json({ error: "Database error", details: err });
                            }

                            const seen = new Set();
                            const cleanedProducts = [];
                            const duplicateInRequest = [];

                            for (const p of products) {
                                const pname = p.product_name?.trim();
                                if (!pname) continue;

                                if (seen.has(pname.toLowerCase())) {
                                    duplicateInRequest.push(pname);
                                } else {
                                    seen.add(pname.toLowerCase());
                                    cleanedProducts.push({ ...p, product_name: pname });
                                }
                            }

                            if (duplicateInRequest.length > 0) {
                                return res.status(400).json({
                                    error: `Duplicate product(s) in request: ${duplicateInRequest.join(", ")}`
                                });
                            }


                            const getGlobalProductIds = () => {
                                return new Promise((resolve, reject) => {
                                    db.query("SELECT products FROM admin_product", [], (err, rows) => {
                                        if (err) return reject(err);
                                        const map = new Map();

                                        for (const row of rows) {
                                            try {
                                                const parsed = Array.isArray(row.products)
                                                    ? row.products
                                                    : JSON.parse(row.products);

                                                parsed.forEach(prod => {
                                                    const name = prod.product_name?.toLowerCase();
                                                    if (name && !map.has(name)) {
                                                        map.set(name, prod.product_id);
                                                    }
                                                });
                                            } catch (e) {
                                                console.warn("Could not parse products for a row:", e);
                                            }
                                        }
                                        resolve(map);
                                    });
                                });
                            };

                            let globalProductMap = new Map();
                            try {
                                globalProductMap = await getGlobalProductIds();
                            } catch (e) {
                                console.error("Failed to fetch global products:", e);
                                return res.status(500).json({ error: "Internal error fetching product catalog" });
                            }

                            const assignProductIds = async (productList) => {
                                return Promise.all(productList.map(async (p) => {
                                    const [rows] = await db.promise().query(
                                        "SELECT product_id FROM products WHERE LOWER(product_name) = ?",
                                        [p.product_name.toLowerCase()]
                                    );

                                    if (!rows.length) {
                                        throw new Error(`Product "${p.product_name}" not found in products table`);
                                    }
                                    const now = moment().format("DD-MM-YYYY");;
                                    return {
                                        ...p,
                                        product_id: rows[0].product_id,
                                        active: 1,
                                        assigned_at: now
                                    };
                                }));
                            };

                            if (adminResults.length > 0) {
                                const existingAdmin = adminResults[0];

                                let existingProducts = [];

                                try {
                                    const raw = existingAdmin.products;

                                    if (Array.isArray(raw)) {
                                        existingProducts = raw;
                                    } else if (typeof raw === "string") {
                                        existingProducts = JSON.parse(raw);
                                    } else {
                                        console.warn("Products data format not recognized, defaulting to empty array");
                                    }
                                } catch (e) {
                                    return res.status(500).json({ error: "Failed to parse existing products" });
                                }

                                const existingNames = new Set(existingProducts.map(p => p.product_name.toLowerCase()));
                                const newCleanProducts = [];
                                const duplicates = [];

                                for (const p of cleanedProducts) {
                                    if (existingNames.has(p.product_name.toLowerCase())) {
                                        duplicates.push(p.product_name);
                                    } else {
                                        newCleanProducts.push(p);
                                    }
                                }

                                if (newCleanProducts.length === 0) {
                                    return res.status(400).json({
                                        error: `Product already exist for admin: ${duplicates.join(", ")}`
                                    });
                                }

                                const newProducts = await assignProductIds(newCleanProducts);

                                const updatedProducts = addExpiryInfo([...existingProducts, ...newProducts], existingAdmin.created_at);

                                const updatedProductsJson = JSON.stringify(updatedProducts);

                                db.query(
                                    "UPDATE admin_product SET products = ? WHERE email = ?",
                                    [updatedProductsJson, email],
                                    (err) => {
                                        if (err) {
                                            console.error("Update error:", err.message);
                                            return res.status(500).json({ error: "Failed to update admin's products" });
                                        }

                                        return res.status(200).json({
                                            message: "New products added to existing admin",
                                            uniqueId: existingAdmin.unique_id,
                                            added: newProducts.map(p => p.product_name),
                                            total: updatedProducts.map(p => p.product_name)
                                        });
                                    }
                                );
                            } else {
                                const adminUniqueId = uuidv4();
                                const encryptedPassword = CryptoJS.AES.encrypt(password, secretKey).toString();

                                const assignedProducts = await assignProductIds(cleanedProducts);

                                let enrichedProducts;
                                try {
                                    enrichedProducts = addExpiryInfo(assignedProducts);
                                } catch (err) {
                                    return res.status(500).json({ error: "Invalid subscription format" });
                                }

                                const productsJson = JSON.stringify(enrichedProducts);

                                const insertQuery = `INSERT INTO admin_product (unique_id, name, email, password, super_admin, products) VALUES (?, ?, ?, ?, ?, ?)`;
                                const values = [adminUniqueId, name, email, encryptedPassword, superAdminId, productsJson];

                                db.query(insertQuery, values, (err) => {
                                    if (err) {
                                        console.error("Insert error:", err.message);
                                        return res.status(500).json({ error: "Failed to register new admin" });
                                    }

                                    return res.status(200).json({
                                        message: "New admin registered with products",
                                        uniqueId: adminUniqueId,
                                        products: enrichedProducts.map(p => p.product_name)
                                    });
                                });
                            }
                        });
                    });
                }

                // USER

                else if (role === "user") {
                    if (!admin || !product_name) {
                        return res.status(400).json("Admin ID and product name are required");
                    }

                    const adminProductQuery = `SELECT products, super_admin FROM admin_product WHERE unique_id = ?`;

                    db.query(adminProductQuery, [admin], (err, results) => {
                        if (err) {
                            console.error("DB error:", err);
                            return res.status(500).json("Database error");
                        }

                        if (results.length === 0) {
                            return res.status(404).json("Admin not found");
                        }

                        const { products, super_admin: superAdminId } = results[0];

                        let matchedProduct;
                        try {
                            const productList = typeof products === 'string' ? JSON.parse(products) : products;
                            matchedProduct = productList.find(p => p.product_name === product_name);

                            if (!matchedProduct) {
                                return res.status(404).json({ title: "Error", message: "Product not found" });
                            }
                        } catch (e) {
                            console.error("JSON parse error:", e);
                            return res.status(500).json("Product data error");
                        }

                        const productId = matchedProduct.product_id;
                        const productActive = matchedProduct.active;
                        const totalMachines = parseInt(matchedProduct.machines || 0);
                        const productExpired = matchedProduct.expiryDate;

                        if (productActive === 0) {
                            return res.status(403).json({
                                title: "Error",
                                message: `The product "${matchedProduct.product_name}" is deactivated. Please contact admin.`
                            });
                        }

                        const countQuery = `SELECT COUNT(*) AS total FROM users WHERE admin = ? AND product_id = ?`;
                        db.query(countQuery, [admin, productId], (err, results) => {
                            if (err) {
                                return res.status(500).json("Error counting users");
                            }

                            const registeredCount = results[0].total;

                            if (registeredCount >= totalMachines) {
                                return res.status(403).json({
                                    title: "Error",
                                    message: "License limit exceeded.Cannot register"
                                });

                            }

                            const checkDuplicateUserQuery = `SELECT * FROM users WHERE admin = ? AND product_name = ? AND email = ?`;

                            db.query(checkDuplicateUserQuery, [admin, product_name, email], (err, userResults) => {
                                if (err) {
                                    console.error("DB error (duplicate check):", err);
                                    return res.status(500).json("Database error");
                                }

                                if (userResults.length > 0) {
                                    return res.status(409).json({ title: "Error", message: "User already exists" });
                                }


                                const uniqueId = uuidv4();
                                const encryptedPassword = CryptoJS.AES.encrypt(password, secretKey).toString();
                                const formattedDate = moment().format("DD-MM-YYYY");;

                                const insertQuery = `
                                        INSERT INTO users (unique_id, name, email, password, admin, super_admin, created_at, device_id, product_id, product_name, active, expiryDate)
                                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)`;

                                const values = [
                                    uniqueId, name, email, encryptedPassword,
                                    admin, superAdminId, formattedDate,
                                    device_id, productId, product_name, productActive, productExpired
                                ];

                                db.query(insertQuery, values, (err) => {
                                    if (err) {
                                        console.error("Insert Error (users):", err.message);
                                        return res.status(500).json("Insert error");
                                    }
                                    return res.status(200).json({
                                        title: "Success",
                                        message: "User registered successfully"
                                    });
                                });
                            });

                        });
                    });
                }

                else {
                    return res.status(400).json({
                        error: "Invalid role. Only super_admin, admin, and user roles are allowed.",
                    });
                }
            }
        );
    }
    catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: "Server error" });
    }
};



function decryptPassword(encryptedPassword) {
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedPassword, secretKey);
        const decrypted = bytes.toString(CryptoJS.enc.Utf8);
        return decrypted || '[decryption failed]';
    } catch (e) {
        return '[error decrypting]';
    }
}



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



const dbQuery = (query, params = []) =>
    new Promise((resolve, reject) => {
        db.query(query, params, (err, result) => {
            if (err) reject(err);
            else resolve(result);
        });
    });



exports.getDetails = async (req, res) => {
    const { name, email, unique_id, product_name, product_id, page = 1, limit = 10 } = req.body;
    const offset = (page - 1) * limit;

    if (!name && !email && !unique_id && !product_name && !product_id) {
        return res.status(400).json({ error: "At least one filter is required" });
    }

    const buildWhereClause = (fields) => {
        const conditions = [];
        const values = [];
        if (fields.includes("name") && name) { conditions.push("name = ?"); values.push(name); }
        if (fields.includes("email") && email) { conditions.push("email = ?"); values.push(email); }
        if (fields.includes("unique_id") && unique_id) { conditions.push("unique_id = ?"); values.push(unique_id); }
        return { clause: conditions.length ? `WHERE ${conditions.join(" AND ")}` : "", values };
    };

    const decryptAndFilterProducts = (admin) => ({ ...admin, password: decryptPassword(admin.password) });
    const filteredResults = {};

    try {
        if (unique_id) {

            const saRes = await dbQuery("SELECT * FROM super_admin WHERE unique_id = ?", [unique_id]);
            if (saRes.length > 0) {
                filteredResults.super_admin = saRes.map(sa => ({ ...sa, password: decryptPassword(sa.password) }));

                const countAdminsRes = await dbQuery("SELECT COUNT(*) AS total FROM admin_product WHERE super_admin = ?", [unique_id]);
                const totalAdminCount = countAdminsRes[0]?.total || 0;

                const adminRes = await dbQuery(
                    `SELECT * FROM admin_product 
                      WHERE super_admin = ? 
                      ORDER BY CAST(JSON_UNQUOTE(JSON_EXTRACT(products, '$.assigned_at')) AS DATETIME) ASC`,
                    [unique_id]
                );

                const admins = adminRes.map(decryptAndFilterProducts);
                if (admins.length) {
                    filteredResults.admin_product = admins;
                    filteredResults.admin_pagination = { page, limit, totalCount: totalAdminCount };
                }

                const adminIds = adminRes.map(a => a.unique_id);
                if (adminIds.length) {
                    const placeholders = adminIds.map(() => "?").join(",");

                    const countQuery = `
                    SELECT COUNT(*) AS total
                    FROM users
                    WHERE admin IN (${placeholders})
                    ${product_name ? "AND product_name = ?" : ""}
                    ${product_id ? "AND product_id = ?" : ""}`;

                    const countParams = [...adminIds];
                    if (product_name) countParams.push(product_name);
                    if (product_id) countParams.push(product_id);
                    const countRes = await dbQuery(countQuery, countParams);
                    const totalCount = countRes[0]?.total || 0;

                    const userQuery = `
                        SELECT users.*, admin_product.name AS admin_name
                        FROM users
                        LEFT JOIN admin_product ON users.admin = admin_product.unique_id
                        WHERE users.admin IN (${placeholders})
                        ${product_name ? "AND users.product_name = ?" : ""}
                        ${product_id ? "AND users.product_id = ?" : ""}
                    ORDER BY users.created_at ASC
                        LIMIT ? OFFSET ?`;
                    const userParams = [...adminIds];
                    if (product_name) userParams.push(product_name);
                    if (product_id) userParams.push(product_id);
                    userParams.push(limit, offset);

                    const users = await dbQuery(userQuery, userParams);

                    filteredResults.users = users.map(u => ({ ...u, password: decryptPassword(u.password) }));
                    filteredResults.pagination = { page, limit, totalCount };
                }

                return res.json({ message: "Filtered results", results: filteredResults });
            }

            const adminRes = await dbQuery("SELECT * FROM admin_product WHERE unique_id = ?", [unique_id]);

            if (adminRes.length > 0) {
                const admins = adminRes.map(decryptAndFilterProducts);
                filteredResults.admin_product = admins;

                const countQuery = `
                    SELECT COUNT(*) AS total
                    FROM users
                    WHERE admin = ?
                    ${product_name ? "AND product_name = ?" : ""}
                    ${product_id ? "AND product_id = ?" : ""}
                    `;

                const countParams = [unique_id];
                if (product_name) countParams.push(product_name);
                if (product_id) countParams.push(product_id);
                const countRes = await dbQuery(countQuery, countParams);
                const totalCount = countRes[0]?.total || 0;

                const userConditions = ["users.admin = ?"];
                const userParams = [unique_id];

                if (product_name) {
                    userConditions.push("users.product_name = ?");
                    userParams.push(product_name);
                }
                if (product_id) {
                    userConditions.push("users.product_id = ?");
                    userParams.push(product_id);
                }
                const userQuery = `
                    SELECT users.*, admin_product.name AS admin_name
                    FROM users
                    LEFT JOIN admin_product ON users.admin = admin_product.unique_id
                    WHERE users.admin = ?
                    ${product_name ? "AND users.product_name = ?" : ""}
                    ${product_id ? "AND users.product_id = ?" : ""}
                    ORDER BY users.created_at ASC
                    LIMIT ? OFFSET ?;
                `;


                if (product_name) userParams.push(product_name);
                if (product_id) userParams.push(product_id);

                userParams.push(limit, offset);

                if (product_name) userParams.push(product_name);
                if (product_id) userParams.push(product_id);

                const users = await dbQuery(userQuery, userParams);

                filteredResults.users = users.map(u => ({ ...u, password: decryptPassword(u.password) }));
                filteredResults.pagination = { page, limit, totalCount };

                return res.json({ message: "Filtered results", results: filteredResults });
            }
        }

        const saFilter = buildWhereClause(["name", "email", "unique_id"]);
        const saData = await dbQuery(`SELECT * FROM super_admin ${saFilter.clause}`, saFilter.values);
        if (saData.length) filteredResults.super_admin = saData.map(sa => ({ ...sa, password: decryptPassword(sa.password) }));

        const adminFilter = buildWhereClause(["name", "email", "unique_id"]);
        const apData = await dbQuery(`SELECT * FROM admin_product ${adminFilter.clause}`, adminFilter.values);
        if (apData.length) filteredResults.admin_product = apData.map(decryptAndFilterProducts);

        const userConditions = [];
        const userValues = [];
        if (name) { userConditions.push("users.name = ?"); userValues.push(name); }
        if (email) { userConditions.push("users.email = ?"); userValues.push(email); }
        if (unique_id) { userConditions.push("users.unique_id = ?"); userValues.push(unique_id); }
        if (product_name) { userConditions.push("users.product_name = ?"); userValues.push(product_name); }
        if (product_id) { userConditions.push("users.product_id = ?"); userValues.push(product_id); }

        const userWhere = userConditions.length ? `WHERE ${userConditions.join(" AND ")}` : "";

        const countRes = await dbQuery(
            `SELECT COUNT(*) AS total
       FROM users
       LEFT JOIN admin_product ON users.admin = admin_product.unique_id
       ${userWhere}`,
            userValues
        );
        const totalCount = countRes[0]?.total || 0;

        const users = await dbQuery(
            `SELECT users.*, admin_product.name AS admin_name FROM users 
    LEFT JOIN admin_product ON users.admin = admin_product.unique_id 
    ${userWhere} ORDER BY users.unique_id ASC 
    LIMIT ? OFFSET ?, [...userValues, limit, offset] `);

        filteredResults.users = users.map(u => ({ ...u, password: decryptPassword(u.password) }));
        filteredResults.pagination = { page, limit, totalCount };

        if (!Object.keys(filteredResults).length) {
            return res.status(404).json({ message: "No matching records found." });
        }

        return res.json({ message: "Filtered results", results: filteredResults });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error", details: err.message });
    }
};







