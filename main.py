import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from supabase import create_client, Client
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY", "secret")

supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)

# ==========================
# Middleware JWT
# ==========================
def verify_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"message": "Token no proporcionado"}), 401
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"message": "Formato de token inválido"}), 401
        token = parts[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = payload.get("user_id")
            request.rol = payload.get("rol")
            request.correo = payload.get("correo")
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expirado"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token inválido"}), 403
        return func(*args, **kwargs)
    return wrapper

# ==========================
# Usuarios
# ==========================
@app.route("/usuarios", methods=["GET"])
@verify_token
def listar_usuarios():
    try:
        response = supabase.table("usuarios").select("id,nombre,apellido,correo,telefono,edad,rol").execute()
        return jsonify(response.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/usuarios", methods=["POST"])
@verify_token
def crear_usuario():
    try:
        datos = request.get_json()
        password_hash = generate_password_hash(datos["clave"])
        response = supabase.table("usuarios").insert({
            "nombre": datos["nombre"],
            "apellido": datos["apellido"],
            "correo": datos["correo"],
            "clave": password_hash,
            "telefono": datos.get("telefono"),
            "edad": datos.get("edad"),
            "rol": datos.get("rol", "cliente")
        }).execute()
        return jsonify(response.data), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/usuarios/<int:usuario_id>", methods=["DELETE"])
@verify_token
def eliminar_usuario(usuario_id):
    if request.rol != "admin":
        return jsonify({"message": "Solo administradores pueden eliminar usuarios"}), 403
    try:
        supabase.table("usuarios").delete().eq("id", usuario_id).execute()
        return jsonify({"message": "Usuario eliminado"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================
# Login
# ==========================
@app.route("/login", methods=["POST"])
def login():
    try:
        datos = request.get_json()
        correo = datos.get("correo")
        password = datos.get("password")
        if not correo or not password:
            return jsonify({"message": "Correo y contraseña requeridos"}), 400

        response = supabase.table("usuarios").select("*").eq("correo", correo).limit(1).execute()
        if len(response.data) == 0:
            return jsonify({"message": "Autenticación fallida"}), 401
        usuario = response.data[0]
        if not check_password_hash(usuario["clave"], password):
            return jsonify({"message": "Autenticación fallida"}), 401

        token = jwt.encode(
            {
                "user_id": usuario["id"],
                "correo": usuario["correo"],
                "rol": usuario["rol"],
                "exp": datetime.utcnow() + timedelta(hours=2)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({
            "token": token,
            "usuario": {
                "id": usuario["id"],
                "nombre": usuario["nombre"],
                "apellido": usuario["apellido"],
                "correo": usuario["correo"],
                "rol": usuario["rol"]
            }
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================
# Tickets
# ==========================
@app.route("/tickets", methods=["GET"])
@verify_token
def listar_tickets():
    try:
        rol = request.rol
        user_id = request.user_id
        query = supabase.table("tickets").select("*, creado_por(*), asignado_a(*)")
        if rol == "cliente":
            query = query.eq("creado_por", user_id)
        elif rol == "tecnico":
            query = query.eq("asignado_a", user_id)
        response = query.order("created_at", desc=True).execute()
        return jsonify(response.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/tickets", methods=["POST"])
@verify_token
def crear_ticket():
    try:
        datos = request.get_json()
        nuevo = {
            "titulo": datos["titulo"],
            "descripcion": datos.get("descripcion", ""),
            "prioridad": datos.get("prioridad", "media"),
            "creado_por": request.user_id,
            "asignado_a": datos.get("asignado_a")
        }
        response = supabase.table("tickets").insert(nuevo).execute()
        return jsonify(response.data), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/tickets/<int:ticket_id>", methods=["PUT"])
@verify_token
def actualizar_ticket(ticket_id):
    try:
        datos = request.get_json()
        rol = request.rol
        user_id = request.user_id

        ticket_resp = supabase.table("tickets").select("*").eq("id", ticket_id).execute()
        if not ticket_resp.data:
            return jsonify({"message": "Ticket no encontrado"}), 404
        ticket = ticket_resp.data[0]

        if rol == "admin":
            pass
        elif rol == "tecnico" and ticket["asignado_a"] == user_id:
            pass
        elif rol == "cliente" and ticket["creado_por"] == user_id and ticket["estado"] == "abierto":
            pass
        else:
            return jsonify({"message": "No tienes permiso para actualizar este ticket"}), 403

        campos_permitidos = ["titulo", "descripcion", "estado", "prioridad", "asignado_a"]
        update_data = {k: v for k, v in datos.items() if k in campos_permitidos}
        update_data["updated_at"] = datetime.utcnow().isoformat()
        response = supabase.table("tickets").update(update_data).eq("id", ticket_id).execute()
        return jsonify(response.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/tickets/<int:ticket_id>", methods=["DELETE"])
@verify_token
def eliminar_ticket(ticket_id):
    if request.rol != "admin":
        return jsonify({"message": "Solo administradores pueden eliminar tickets"}), 403
    try:
        supabase.table("tickets").delete().eq("id", ticket_id).execute()
        return jsonify({"message": "Ticket eliminado"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================
# Comentarios
# ==========================
@app.route("/tickets/<int:ticket_id>/comentarios", methods=["GET"])
@verify_token
def listar_comentarios(ticket_id):
    try:
        response = supabase.table("comentarios").select("*, usuario_id(*)").eq("ticket_id", ticket_id).order("created_at", desc=False).execute()
        return jsonify(response.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/tickets/<int:ticket_id>/comentarios", methods=["POST"])
@verify_token
def agregar_comentario(ticket_id):
    try:
        datos = request.get_json()
        contenido = datos.get("contenido")
        if not contenido:
            return jsonify({"message": "El comentario no puede estar vacío"}), 400

        # Verificar que el ticket existe y que el usuario tiene acceso
        ticket_resp = supabase.table("tickets").select("*").eq("id", ticket_id).execute()
        if not ticket_resp.data:
            return jsonify({"message": "Ticket no encontrado"}), 404
        ticket = ticket_resp.data[0]
        rol = request.rol
        user_id = request.user_id
        if rol == "cliente" and ticket["creado_por"] != user_id:
            return jsonify({"message": "No tienes permiso para comentar en este ticket"}), 403
        # Técnico solo puede comentar si está asignado
        if rol == "tecnico" and ticket["asignado_a"] != user_id:
            return jsonify({"message": "No tienes permiso para comentar en este ticket"}), 403
        # Admin puede comentar en todos

        nuevo = {
            "ticket_id": ticket_id,
            "usuario_id": user_id,
            "contenido": contenido
        }
        response = supabase.table("comentarios").insert(nuevo).execute()
        return jsonify(response.data), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/comentarios/<int:comentario_id>", methods=["DELETE"])
@verify_token
def eliminar_comentario(comentario_id):
    try:
        # Solo el autor o admin pueden eliminar
        comentario_resp = supabase.table("comentarios").select("usuario_id").eq("id", comentario_id).execute()
        if not comentario_resp.data:
            return jsonify({"message": "Comentario no encontrado"}), 404
        autor_id = comentario_resp.data[0]["usuario_id"]
        if request.rol != "admin" and request.user_id != autor_id:
            return jsonify({"message": "No tienes permiso para eliminar este comentario"}), 403

        supabase.table("comentarios").delete().eq("id", comentario_id).execute()
        return jsonify({"message": "Comentario eliminado"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ==========================
# Iniciar servidor
# ==========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
