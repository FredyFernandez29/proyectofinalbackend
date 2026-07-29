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
            return jsonify({"message": "Token not provided"}), 401
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"message": "Invalid token format"}), 401
        token = parts[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = payload.get("user_id")
            request.rol = payload.get("rol")
            request.correo = payload.get("correo")
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 403
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
        response = query.execute()
        return jsonify(response.data), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/tickets/<int:ticket_id>", methods=["GET"])
@verify_token
def obtener_ticket(ticket_id):
    try:
        response = supabase.table("tickets").select("*, creado_por(*), asignado_a(*)").eq("id", ticket_id).execute()
        if not response.data:
            return jsonify({"message": "Ticket no encontrado"}), 404
        ticket = response.data[0]

        # --- Manejo de nulos en relaciones ---
        creador = ticket.get("creado_por")
        if not creador:
            # Si por alguna razón no tiene creador, denegar acceso
            return jsonify({"message": "Ticket sin creador"}), 400
        # Si creador es un dict, obtener su id; si es un número, usarlo directamente
        creador_id = creador.get("id") if isinstance(creador, dict) else creador

        asignado = ticket.get("asignado_a")
        asignado_id = None
        if asignado:
            asignado_id = asignado.get("id") if isinstance(asignado, dict) else asignado

        rol = request.rol
        user_id = request.user_id

        # Permisos
        if rol == "cliente" and creador_id != user_id:
            return jsonify({"message": "No tienes permiso para ver este ticket"}), 403
        if rol == "tecnico" and asignado_id and asignado_id != user_id:
            return jsonify({"message": "No tienes permiso para ver este ticket"}), 403

        # Obtener comentarios
        comentarios_resp = supabase.table("comentarios").select("*, usuario(*)").eq("ticket_id", ticket_id).order("created_at", desc=False).execute()
        ticket["comentarios"] = comentarios_resp.data if comentarios_resp.data else []

        return jsonify(ticket), 200
    except Exception as e:
        print("Error en obtener_ticket:", e)
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
@app.route("/tickets/<int:ticket_id>/comentarios", methods=["POST"])
@verify_token
def agregar_comentario(ticket_id):
    try:
        datos = request.get_json()
        contenido = datos.get("contenido")
        if not contenido:
            return jsonify({"message": "El comentario no puede estar vacío"}), 400
        nuevo = {
            "ticket_id": ticket_id,
            "usuario_id": request.user_id,
            "contenido": contenido
        }
        response = supabase.table("comentarios").insert(nuevo).execute()
        return jsonify(response.data), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
