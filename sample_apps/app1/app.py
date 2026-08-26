from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"app": "app1", "message": "Welcome to Sample App 1"})

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return jsonify({"app": "app1", "query": q, "results": [f"Result {i} for '{q}'" for i in range(1, 4)]})

@app.route("/products", methods=["GET"])
def list_products():
    return jsonify({"app": "app1", "products": [
        {"id": 1, "name": "Widget A", "price": 29.99},
        {"id": 2, "name": "Widget B", "price": 49.99},
        {"id": 3, "name": "Widget C", "price": 19.99},
    ]})

@app.route("/products/<int:product_id>")
def get_product(product_id):
    return jsonify({"app": "app1", "product": {"id": product_id, "name": f"Product {product_id}", "price": 99.99}})

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    return jsonify({"app": "app1", "status": "ok", "token": "sample-jwt-token-abc123"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
