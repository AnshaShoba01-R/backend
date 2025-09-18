const moment = require("moment");
const db = require("../config/db");




exports.addProducts = async (req, res) => {
    const { product_id, product_name, super_admin } = req.body;

    if (!product_id || !product_name || !super_admin) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const formattedDate = moment().format("DD-MM-YYYY");

    const query = `
    INSERT INTO products (product_id, product_name, super_admin, created_at)
    VALUES (?, ?, ?, ?)
  `;

    try {
        const [result] = await db.promise().query(query, [
            product_id,
            product_name,
            super_admin,
            formattedDate,
        ]);

        res.status(201).json({
            message: "Product created successfully",
            productId: result.insertId,
        });
    }
    catch (err) {
        if (err.code === "ER_DUP_ENTRY") {
            const duplicateField = err.message.includes("product_id")
                ? "Product ID"
                : err.message.includes("product_name")
                    ? "Product Name"
                    : "Product";

            console.warn(`Duplicate entry prevented: ${duplicateField}`);
            return res.status(409).json({
                error: `${duplicateField} already exists`,
            });
        }
        console.error("Insert error:", err);
        res.status(500).json({
            error: "Database error",
            details: err.message,
        });
    }

};




exports.getProducts = async (req, res) => {

    try {
        const { unique_id, role } = req.body;

        if (!unique_id || !role) {
            return res.status(400).json({ error: "Missing unique_id or role" });
        }

        if (role === "super_admin") {
            const [rows] = await db.promise().query(
                "SELECT * FROM products WHERE super_admin = ?",
                [unique_id]
            );
            return res.json(rows);
        }

        if (role === "admin") {
            const [adminRows] = await db.promise().query(
                "SELECT products FROM admin_product WHERE unique_id = ?",
                [unique_id]
            );

            if (!adminRows.length) {
                return res.json([]);
            }

            let adminProducts;
            let rawProducts = adminRows[0].products;

            try {
                if (typeof rawProducts === "string") {
                    rawProducts = rawProducts.trim();
                    adminProducts = JSON.parse(rawProducts);
                } else if (Array.isArray(rawProducts)) {
                    adminProducts = rawProducts;
                } else {
                    adminProducts = [];
                }
            } catch (e) {
                console.error("Failed to parse products JSON:", rawProducts);
                return res.status(500).json({ error: "Invalid products JSON" });
            }

            if (!Array.isArray(adminProducts) || adminProducts.length === 0) {
                return res.json([]);
            }

            const productFlags = {};
            adminProducts.forEach(p => {
                if (p.product_id) {
                    productFlags[p.product_id] = {
                        active: p.active ?? 1,
                        expired: p.expired ?? 1,
                        expiryDate: p.expiryDate ?? null
                    };
                }
            });

            const productIds = adminProducts.map(p => p.product_id).filter(Boolean);
            if (productIds.length === 0) {
                return res.json([]);
            }

            const [rows] = await db.promise().query(
                `SELECT * FROM products WHERE product_id IN (${productIds.map(() => "?").join(",")})`,
                productIds
            );

            const enrichedProducts = rows.map(p => ({
                ...p,
                active: productFlags[p.product_id]?.active ?? 1,
                expired: productFlags[p.product_id]?.expired ?? 1,
                expiryDate: productFlags[p.product_id]?.expiryDate ?? null
            }));

            return res.json(enrichedProducts);
        }


        res.status(400).json({ error: "Invalid role" });
    } catch (err) {
        console.error("Fetch products error:", err);
        res.status(500).json({ error: "Database error", details: err.message });
    }
};




