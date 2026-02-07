db = db.getSiblingDB("receeptDB");

db.createCollection("Client");
db.createCollection("ProductService");
// db.createCollection("Task");
// db.createCollection("InvoiceLine");
db.createCollection("Invoice");
db.createCollection("Payment");
db.createCollection("Alert");