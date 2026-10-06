from flask import Flask, request, jsonify
from database import db
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
from models.user import User
import bcrypt

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root@localhost:3306/flask-crud"

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/user", methods=["POST"])
def create_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    hash_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user:
            return jsonify({"message": "Username indisponivel"})
        
        user = User(username=username, password=hash_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuario cadastrado com sucesso"})

    return jsonify({"message": "Dados invalidos"}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode(), user.password.encode()):
            login_user(user)
            return jsonify({"message": "Login efetuado com sucesso"})

    return jsonify({"message": "Credenciais invalidas"}), 400

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route("/user/<int:user_id>", methods=['GET'])
@login_required
def read_user(user_id):
    user = User.query.get(user_id)

    if user:
        return jsonify({"username": user.username})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:user_id>", methods=['PUT'])
@login_required
def edit_user(user_id):
    data = request.get_json()
    user = User.query.get(user_id)

    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()

        return jsonify({"message": f"Usuário {user_id} atualizado com sucesso"})

    return jsonify({"message": "Usuário não encontrado"}), 404

@app.route("/user/<int:user_id>", methods=['DELETE'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)

    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403

    if user_id == current_user.id:
        return jsonify({"message": "Deleção não permitida"}), 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuário {user_id} deletado com sucesso"})

    return jsonify({"message": "Usuário não encontrado"}), 404

if __name__ == "__main__":
    app.run(debug=True)