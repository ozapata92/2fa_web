from flask import Flask, request, jsonify
from flask_cors import CORS
import pyotp
import qrcode
from PIL import Image
import base64
from io import BytesIO

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["*"]}})


# Almacenamiento temporal de usuarios y claves secretas (deberías utilizar una base de datos)
usuarios = {}


def generar_clave_secreta():
    return pyotp.random_base32()


def generar_url_otpauth(usuario, clave_secreta, nombre_app="TuNombreDeAplicación"):
    return pyotp.totp.TOTP(clave_secreta).provisioning_uri(usuario, issuer_name=nombre_app)


def generar_codigo_totp(clave_secreta):
    totp = pyotp.TOTP(clave_secreta)
    return totp.now()


def generar_imagen_qr(otpauth_url):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otpauth_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    return img


def validar_codigo_2fa(clave_secreta, codigo_ingresado):
    totp = pyotp.TOTP(clave_secreta)
    return totp.verify(codigo_ingresado)


@app.route('/crear_usuario', methods=['POST'])
def crear_usuario():
    usuario = request.form.get('usuario')

    if usuario:
        if usuario not in usuarios:
            clave_secreta = generar_clave_secreta()
            usuarios[usuario] = {'clave_secreta': clave_secreta}
            otpauth_url = generar_url_otpauth(usuario, clave_secreta)

            # Generar la imagen del código QR
            imagen_qr = generar_imagen_qr(otpauth_url)

            # Convertir la imagen del código QR en base64
            buffer = BytesIO()
            imagen_qr.save(buffer, format="PNG")
            imagen_qr_base64 = base64.b64encode(
                buffer.getvalue()).decode('utf-8')
            buffer.close()

            # Guardar la clave secreta en la base de datos (o en un almacenamiento persistente)
            # usuarios[usuario] = {'clave_secreta': clave_secreta}

            # Crear una respuesta JSON que incluye la URL OTPAuth y la imagen del código QR en base64
            respuesta = {
                'mensaje': 'Usuario creado exitosamente',
                'otpauth_url': otpauth_url,
                'imagen_qr_base64': imagen_qr_base64
            }

            return jsonify(respuesta)
        else:
            return jsonify({'mensaje': 'El usuario ya existe'}), 500
    else:
        return jsonify({'mensaje': 'Datos incompletos'})


@app.route('/validar_codigo_2fa', methods=['POST'])
def validar_codigo():
    usuario = request.form.get('usuario')
    codigo_ingresado = request.form.get('codigo_2fa')

    if usuario and codigo_ingresado:
        if usuario in usuarios:
            clave_secreta = usuarios[usuario]['clave_secreta']
            es_valido = validar_codigo_2fa(clave_secreta, codigo_ingresado)

            if es_valido:
                return jsonify({'mensaje': 'Código 2FA válido. Acceso concedido.'})
            else:
                return jsonify({'mensaje': 'Código 2FA no válido. Acceso denegado.'})
        else:
            return jsonify({'mensaje': 'Usuario no encontrado'})
    else:
        return jsonify({'mensaje': 'Datos incompletos'})


if __name__ == '__main__':
    app.run(debug=True)
