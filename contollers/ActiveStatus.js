const moment = require("moment");
const db = require("../config/db");
const { v4: uuidv4 } = require('uuid');
const CryptoJS = require('crypto-js');


const secretKey = process.env.SECRET_KEY;

const express = require('express');
const app = express();

app.use(express.json());




exports.activeStatus = async (req, res) => {
    try {
        const { product_id, active, admin_id } = req.body;

        if (!product_id || typeof active === 'undefined' || !admin_id) {
            return res.status(400).send({ error: 'product_id, active, and admin_id are required' });
        }

        const selectSql = 'SELECT products, id FROM admin_product WHERE unique_id = ?';

        db.query(selectSql, [admin_id], (err, results) => {
            if (err) {
                console.error('Select failed:', err);
                return res.status(500).send({ error: 'Database select failed', details: err.message });
            }

            if (results.length === 0) {
                return res.status(404).send({ error: 'Admin not found' });
            }

            let products;
            try {
                products = typeof results[0].products === 'string'
                    ? JSON.parse(results[0].products)
                    : results[0].products;
            } catch (e) {
                console.error('JSON parse error:', e);
                return res.status(500).send({ error: 'Failed to parse products JSON', details: e.message });
            }

            let found = false;
            products = products.map(product => {
                if (product.product_id === product_id) {
                    product.active = active;
                    found = true;
                }
                return product;
            });

            if (!found) {
                return res.status(404).send({ error: 'Product not found' });
            }

            const updateProductsSql = 'UPDATE admin_product SET products = ? WHERE id = ?';
            db.query(updateProductsSql, [JSON.stringify(products), results[0].id], (err2) => {
                if (err2) {
                    console.error('Update failed:', err2);
                    return res.status(500).send({ error: 'Database update failed', details: err2.message });
                }

                const updateUsersSql = 'UPDATE users SET active = ? WHERE admin = ? AND product_id = ?';
                db.query(updateUsersSql, [active, admin_id, product_id], (err3, userUpdateResult) => {
                    if (err3) {
                        console.error('User table update failed:', err3);
                        return res.status(500).send({ error: 'Failed to update users', details: err3.message });
                    }

                    res.status(200).send({
                        success: true,
                        message: 'Product status updated for admin and users',
                        affected_users: userUpdateResult.affectedRows
                    });
                });
            });
        });
    } catch (err) {
        console.error('Unexpected error:', err);
        res.status(500).send({ error: 'Internal server error', details: err.message });
    }
};






exports.updateCount = async (req, res) => {
    const { admin_id, super_admin } = req.body;

    if (!admin_id && !super_admin) {
        return res.status(400).json({ error: "Provide either admin_id or super_admin" });
    }

    try {
        let query = "";
        let params = [];

        if (admin_id) {
            query = `SELECT unique_id, name, email, products FROM admin_product WHERE unique_id = ?`;
            params = [admin_id];
        } else {
            query = `SELECT unique_id, name, email, products FROM admin_product WHERE super_admin = ?`;
            params = [super_admin];
        }

        const [adminRows] = await db.promise().query(query, params);

        if (adminRows.length === 0) {
            return res.status(404).json({ error: "No admins found" });
        }

        const results = [];

        for (const admin of adminRows) {
            let products;
            try {
                products = typeof admin.products === 'string' ? JSON.parse(admin.products) : admin.products;
                if (!Array.isArray(products)) throw new Error();
            } catch (err) {
                console.warn(`Invalid products JSON for admin ${admin.unique_id}`);
                continue;
            }

            const updatedProducts = [];

            for (const product of products) {
                const { product_id, machines = 0 } = product;

                let remainingDays = null;

                if (product.expiryDate) {
                    const expiry = moment(product.expiryDate, "DD-MM-YYYY").endOf('day');
                    const today = moment().startOf('day');
                    remainingDays = Math.max(expiry.diff(today, "days"), 0);
                }
                const [usedResult] = await db.promise().query(
                    `SELECT COUNT(*) AS used FROM users 
           WHERE admin = ? AND product_id = ? 
           AND device_id IS NOT NULL AND device_id != ''`,
                    [admin.unique_id, product_id]
                );

                const used = usedResult[0].used || 0;
                const un_used = Math.max(machines - used, 0);

                updatedProducts.push({
                    ...product,
                    used,
                    un_used,
                    remainingDays
                });
            }

            await db.promise().query(
                `UPDATE admin_product SET products = ? WHERE unique_id = ?`,
                [JSON.stringify(updatedProducts), admin.unique_id]
            );

            results.push({
                admin_id: admin.unique_id,
                admin_name: admin.name,
                admin_email: admin.email,
                products: updatedProducts
            });
        }

        return res.status(200).json({
            message: "Used/Unused counts updated successfully",
            results
        });

    } catch (err) {
        console.error("Error updating count:", err);
        return res.status(500).json({ error: "Internal server error" });
    }
};


