const db = require("../config/db");


const createTables = () => {

  const createSuperAdminTable = `
    CREATE TABLE IF NOT EXISTS super_admin (
      id INT AUTO_INCREMENT PRIMARY KEY,
      unique_id VARCHAR(255) NOT NULL UNIQUE,
      name VARCHAR(255) NOT NULL,
      email VARCHAR(255) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      created_at VARCHAR(25) NOT NULL
    );`;


  const createAdmin_ProductTable = `
    CREATE TABLE IF NOT EXISTS admin_product (
  id INT AUTO_INCREMENT PRIMARY KEY,
  unique_id VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  super_admin VARCHAR(255) NOT NULL,
  products JSON NOT NULL,
  FOREIGN KEY (super_admin) REFERENCES super_admin(unique_id),
  UNIQUE KEY unique_admin_product (email)
    );`;

  const createUsersTable = `     
    CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  unique_id VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL,
  super_admin VARCHAR(255) NOT NULL,
  admin VARCHAR(255) NOT NULL,
  created_at VARCHAR(250) NOT NULL,
  first_login_at VARCHAR(250),
  product_id VARCHAR(250),
  product_name VARCHAR(250),
  active TINYINT,
  expiryDate VARCHAR(250) NOT NULL,
  device_id VARCHAR(255) UNIQUE,
  history JSON, 
  FOREIGN KEY (super_admin) REFERENCES super_admin(unique_id),
  FOREIGN KEY (admin) REFERENCES admin_product(unique_id)
    );`;

  const createProductsTable = `     
    CREATE TABLE IF NOT EXISTS products (
  id INT AUTO_INCREMENT PRIMARY KEY,
  product_id VARCHAR(255) NOT NULL UNIQUE,
  product_name VARCHAR(250) NOT NULL UNIQUE,
  super_admin VARCHAR(255) NOT NULL,
  created_at VARCHAR(25) NOT NULL,
  FOREIGN KEY (super_admin) REFERENCES super_admin(unique_id)
    );`;


  db.query(createSuperAdminTable, (err) => {
    if (err) return console.error("Error creating super_admin table:", err);
    console.log("super_admin table created");

    db.query(createAdmin_ProductTable, (err) => {
      if (err) return console.error("Error creating admin_product table:", err);
      console.log("admin_product table created");

      db.query(createUsersTable, (err) => {
        if (err) return console.error("Error creating users table:", err);
        console.log("users table created");
      });
      db.query(createProductsTable, (err) => {
        if (err) return console.error("Error creating Products table:", err);
        console.log("Products table created");
      });
     
    });
  });
};





module.exports = createTables;
