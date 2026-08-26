from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/")
def index():
    return jsonify({"app": "app3", "message": "Welcome to Sample App 3"})

@app.route("/search")
def search():
    q = request.args.get("q", "")
    page = request.args.get("page", 1, type=int)
    return jsonify({"app": "app3", "query": q, "page": page, "total": 42})

@app.route("/products", methods=["GET"])
def list_products():
    return jsonify({"app": "app3", "products": [
        {"id": 100, "name": "Thing 1", "price": 9.99},
        {"id": 101, "name": "Thing 2", "price": 19.99},
        {"id": 102, "name": "Thing 3", "price": 29.99},
    ]})

@app.route("/products/<int:product_id>")
def get_product(product_id):
    return jsonify({"app": "app3", "product": {"id": product_id, "name": f"Thing {product_id}"}})

@app.route("/api/upload", methods=["POST"])
def upload():
    return jsonify({"app": "app3", "status": "uploaded", "filename": "file.txt"})

@app.route("/health")
def health():
    return jsonify({"app": "app3", "status": "healthy"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=True)
