from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"app": "app2", "message": "Welcome to Sample App 2"})

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"app": "app2", "query": q, "results": [f"Match {i}" for i in range(1, 6)]})

@app.route("/products", methods=["GET"])
def list_products():
    category = request.args.get("category", "all")
    return jsonify({"app": "app2", "category": category, "products": [
        {"id": 10, "name": "Gadget X", "price": 199.99, "category": "electronics"},
        {"id": 11, "name": "Gadget Y", "price": 299.99, "category": "electronics"},
        {"id": 12, "name": "Book Z", "price": 14.99, "category": "books"},
    ]})

@app.route("/products/<int:product_id>")
def get_product(product_id):
    return jsonify({"app": "app2", "product": {"id": product_id, "name": f"Item {product_id}", "stock": 42}})

@app.route("/users/<int:user_id>/orders")
def user_orders(user_id):
    return jsonify({"app": "app2", "user_id": user_id, "orders": [
        {"order_id": 1001, "total": 59.99, "status": "shipped"},
        {"order_id": 1002, "total": 129.99, "status": "pending"},
    ]})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
