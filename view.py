from flask import Flask, jsonify, request, send_file, flash, render_template
from main import app, con
from flask_bcrypt import Bcrypt, check_password_hash, generate_password_hash
from fpdf import FPDF
import jwt
import smtplib
import re
from email.mime.text import MIMEText
import os
import bcrypt
from datetime import datetime, timedelta
from io import BytesIO
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


#INÍCIO DO PIX
import qrcode
from qrcode.constants import ERROR_CORRECT_H
import crcmod


def calcula_crc16(payload):
    crc16 = crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False)
    crc = crc16(payload.encode('utf-8'))
    return f"{crc:04X}"


def format_tlv(id, value):
    return f"{id}{len(value):02d}{value}"


@app.route('/gerar_pix', methods=['POST'])
def gerar_pix():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        jwt.decode(token, senha_secreta, algorithms=['HS256'])  # apenas valida o token
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    try:
        dados = request.get_json()
        id_multa = dados.get('id_multa')

        if not id_multa:
            return jsonify({"erro": "ID da multa é obrigatório."}), 400

        cursor = con.cursor()
        cursor.execute("SELECT valor FROM multas WHERE id_multa = ?", (id_multa,))
        resultado = cursor.fetchone()
        cursor.close()

        if not resultado:
            return jsonify({"erro": "Multa não encontrada."}), 404

        valor_multa = f"{resultado[0]:.2f}"

        cursor = con.cursor()
        cursor.execute("SELECT cg.NOME, cg.CHAVE_PIX, cg.CIDADE FROM PIX cg")
        resultado = cursor.fetchone()
        cursor.close()

        if not resultado:
            return jsonify({"erro": "Chave PIX não encontrada"}), 404

        nome, chave_pix, cidade = resultado
        nome = nome[:25] if nome else "Recebedor PIX"
        cidade = cidade[:15] if cidade else "Cidade"

        merchant_account_info = (
            format_tlv("00", "br.gov.bcb.pix") +
            format_tlv("01", chave_pix)
        )
        campo_26 = format_tlv("26", merchant_account_info)

        payload_sem_crc = (
            "000201" +
            "010212" +
            campo_26 +
            "52040000" +
            "5303986" +
            format_tlv("54", valor_multa) +
            "5802BR" +
            format_tlv("59", nome) +
            format_tlv("60", cidade) +
            format_tlv("62", format_tlv("05", "***")) +
            "6304"
        )

        crc = calcula_crc16(payload_sem_crc)
        payload_completo = payload_sem_crc + crc

        qr_obj = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_H,
            box_size=10,
            border=4
        )
        qr_obj.add_data(payload_completo)
        qr_obj.make(fit=True)
        qr = qr_obj.make_image(fill_color="black", back_color="white")

        pasta_qrcodes = os.path.join(os.getcwd(), "static", "upload", "qrcodes")
        os.makedirs(pasta_qrcodes, exist_ok=True)

        arquivos_existentes = [f for f in os.listdir(pasta_qrcodes) if f.startswith("pix_") and f.endswith(".png")]
        numeros_usados = []
        for nome_arq in arquivos_existentes:
            try:
                num = int(nome_arq.replace("pix_", "").replace(".png", ""))
                numeros_usados.append(num)
            except ValueError:
                continue
        proximo_numero = max(numeros_usados, default=0) + 1
        nome_arquivo = f"pix_{proximo_numero}.png"
        caminho_arquivo = os.path.join(pasta_qrcodes, nome_arquivo)

        qr.save(caminho_arquivo)

        print(payload_completo)

        return send_file(caminho_arquivo, mimetype='image/png', as_attachment=True, download_name=nome_arquivo)

    except Exception as e:
        return jsonify({"erro": f"Ocorreu um erro interno: {str(e)}"}), 500

@app.route('/parametrizar_pix', methods=['GET'])
def get_pix():
    cur = con.cursor()
    cur.execute('SELECT id_pix, nome, chave_pix, cidade, razao, cnpj FROM pix')  # Inclua razao e cnpj
    row = cur.fetchone()

    if not row:
        return jsonify(mensagem='Nenhum Pix configurado.'), 404

    return jsonify({
        'id_pix': row[0],
        'nome': row[1],
        'chave_pix': row[2],
        'cidade': row[3],
        'razao': row[4],
        'cnpj': row[5]
    })


# Define o caminho da pasta onde as logos serão salvas
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static", "uploads", "logo")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER  # <- Adiciona isso para garantir que seja usado corretamente

# Define o caminho da pasta onde as logos serão salvas
UPLOAD_FOLDER = os.path.join(os.getcwd(), "static", "uploads", "logo")

# Informa ao Flask o caminho correto
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Cria a pasta se não existir
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


import os
from werkzeug.utils import secure_filename

@app.route('/parametrizar_pix', methods=['POST'])
def parametrizar_pix():
    # Verifica se a logo foi enviada
    if 'logo' not in request.files:
        return jsonify({'mensagem': 'Logo não enviada.'}), 400

    logo = request.files['logo']

    if logo.filename == '':
        return jsonify({'mensagem': 'Nenhum arquivo selecionado.'}), 400

    # Captura os dados do formulário com segurança
    dados = request.form
    nome = dados.get('nome')
    chave_pix = dados.get('chave_pix')
    cidade = dados.get('cidade')
    razao = dados.get('razao')
    cnpj = dados.get('cnpj')

    # Verifica se todos os campos obrigatórios foram enviados
    if not all([nome, chave_pix, cidade, razao, cnpj]):
        return jsonify({'mensagem': 'Campos obrigatórios ausentes.'}), 400

    # Garante que a subpasta 'logo' exista
    logo_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'logo')
    os.makedirs(logo_dir, exist_ok=True)

    # Sempre salva como 'logo' + extensão original
    ext = os.path.splitext(secure_filename(logo.filename))[1]  # Ex: '.png', '.jpg'
    logo_filename = f'logo{ext}'
    logo_path = os.path.join(logo_dir, logo_filename)
    logo.save(logo_path)

    # Remove outras logos antigas (de extensões diferentes)
    for arquivo in os.listdir(logo_dir):
        if arquivo.startswith('logo') and arquivo != logo_filename:
            os.remove(os.path.join(logo_dir, arquivo))

    # Atualiza banco de dados
    cur = con.cursor()
    cur.execute('DELETE FROM pix')  # Remove configurações antigas

    cur.execute('''
        INSERT INTO pix (nome, chave_pix, cidade, razao, cnpj)
        VALUES (?, ?, ?, ?, ?)
    ''', (nome, chave_pix, cidade, razao, cnpj))

    con.commit()

    return jsonify({
        'mensagem': 'Parâmetros de Pix atualizados com sucesso.'
    })

@app.route('/pix', methods=['GET'])
def pix_parametrizacao():
    cur = con.cursor()
    cur.execute('SELECT id_pix, nome, razao, chave_pix, cidade, cnpj FROM pix')
    row = cur.fetchone()

    if not row:
        return jsonify(mensagem='Nenhum Pix configurado.'), 404

    return jsonify({
        'id_pix':    row[0],
        'nome':      row[1],
        'razao':     row[2],
        'chave_pix': row[3],
        'cidade':    row[4],
        'cnpj':      row[5]
        # NÃO retornamos aqui a logo — ela virá do localStorage
    })

# FIM DO PIX


bcrypt = Bcrypt(app)  # Inicializa o bcrypt para criptografia segura
app.config.from_pyfile('config.py')
senha_secreta = app.config['SECRET_KEY']


# Função para gerar token JWT
def generate_token(user_id, email):
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        # Onde os arquivos serão salvos, caso ele não exista será criado.
        os.makedirs(app.config['UPLOAD_FOLDER'])
    payload = {'id_usuario': user_id, 'email': email}
    # Define o payload onde vai definir as informações que serão passadas para o token.
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    # Faz com que o token seja gerado com as informações do payload e uma senha secreta.
    return token


def remover_bearer(token):
    # Verifica se o token começa com 'Bearer '
    if token.startswith('Bearer '):
        # Se o token começar com 'Bearer ', remove o prefixo 'Bearer ' do token
        return token[len('Bearer '):]
    else:
        # Se o token não começar com 'Bearer ', retorna o token original sem alterações
        return token


def validar_senha(senha):
    padrao = r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'
    return bool(re.fullmatch(padrao, senha))


#EMAIL DO EMPRESTIMO
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage

def email_emprestimo(email, texto, subject, anexo=None, html=False):
    """
    Envia um e-mail para o destinatário especificado, com texto (plain ou HTML), assunto e opcionalmente um anexo de imagem.
    """
    if not email:
        raise ValueError("O campo 'email' é obrigatório.")

    sender = "equipe.asa.literaria@gmail.com"
    password = "yjfy kwcr nazh sirp"  # Substitua pela sua senha de aplicativo

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = email

    # Escolhe o tipo de corpo do e-mail
    if html:
        msg.attach(MIMEText(texto, 'html'))
    else:
        msg.attach(MIMEText(texto, 'plain'))

    # Anexa imagem, se fornecida
    if anexo:
        try:
            with open(anexo, 'rb') as attachment:
                img = MIMEImage(attachment.read())
                img.add_header('Content-Disposition', 'attachment', filename=os.path.basename(anexo))
                msg.attach(img)
        except Exception as e:
            raise RuntimeError(f"Erro ao anexar o arquivo: {e}")

    # Envia o e-mail
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, [email], msg.as_string())
            print(f"E-mail enviado com sucesso para {email}!")
    except Exception as e:
        raise RuntimeError(f"Erro ao enviar o e-mail: {e}")


def atualizar_codigo_envio_email(email, codigo, conexao_db):
    """
    Atualiza o campo CODIGO do usuário no banco de dados e envia um e-mail HTML estilizado com o novo código.
    """
    cursor = conexao_db.cursor()
    try:
        # Atualiza o código do usuário
        cursor.execute(
            'UPDATE USUARIOS SET CODIGO = ? WHERE EMAIL = ?',
            (codigo, email)
        )
        conexao_db.commit()

        # Corpo do e-mail HTML estilizado
        html_email = f"""
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f9f9f9;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    background-color: #fff;
                    max-width: 500px;
                    margin: 40px auto;
                    padding: 30px 40px;
                    border-radius: 12px;
                    box-shadow: 0 2px 8px rgba(0,0,0,0.06);
                    text-align: center;
                }}
                .codigo {{
                    display: inline-block;
                    background: #e3f2fd;
                    color: #1565c0;
                    font-size: 2.2em;
                    font-weight: bold;
                    letter-spacing: 4px;
                    padding: 12px 28px;
                    border-radius: 8px;
                    margin: 24px 0 18px 0;
                    box-shadow: 0 1px 4px rgba(21,101,192,0.08);
                }}
                .footer {{
                    margin-top: 30px;
                    font-size: 0.95em;
                    color: #888;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Olá, tudo bem?</h2>
                <p>
                    Recebemos uma solicitação para verificação de e-mail.<br>
                    Seu código de verificação é:
                </p>
                <div class="codigo">{codigo}</div>
                <p>
                    Digite este código no site para continuar.<br>
                    Se você não solicitou este código, ignore este e-mail.
                </p>
                <div class="footer">
                    Equipe Asa Literária<br>
                    <small>Este é um e-mail automático, por favor não responda.</small>
                </div>
            </div>
        </body>
        </html>
        """

        # Envia o e-mail com HTML
        email_emprestimo(
            email=email,
            texto=html_email,
            subject='Seu Código de Verificação Asa Literária',
            anexo=None,
            html=True  # Adicione essa flag na função email_emprestimo para diferenciar HTML de texto puro
        )

        print(f"Código atualizado e e-mail enviado para {email}.")
        return True

    except Exception as e:
        conexao_db.rollback()
        print(f"Erro ao atualizar o código e enviar e-mail: {e}")
        raise RuntimeError(f"Falha na atualização do código: {e}")

    finally:
        cursor.close()


@app.route('/usuario', methods=['GET'])
def usuario():
    pagina = int(request.args.get('pagina', 1))
    quantidade_por_pagina = 10

    primeiro_usuario = (pagina * quantidade_por_pagina) - quantidade_por_pagina + 1
    ultimo_usuario = pagina * quantidade_por_pagina

    cur = con.cursor()
    cur.execute(f'''
        SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, status
        FROM usuarios
        ROWS {primeiro_usuario} TO {ultimo_usuario}
    ''')
    usuarios = cur.fetchall()

    cur.execute('SELECT COUNT(*) FROM usuarios')
    total_usuarios = cur.fetchone()[0]
    total_paginas = (total_usuarios + quantidade_por_pagina - 1) // quantidade_por_pagina

    usuarios_dic = []
    for u in usuarios:
        usuarios_dic.append({
            'id_usuario': u[0],
            'nome': u[1],
            'email': u[2],
            'telefone': u[3],
            'data_nascimento': u[4],
            'cargo': u[5],
            'status': u[6]
        })

    return jsonify(
        mensagem='Lista de Usuarios',
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_usuarios=total_usuarios,
        usuarios=usuarios_dic
    )


@app.route('/usuarios', methods=['POST'])
def usuario_post():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    telefone = data.get('telefone')
    data_nascimento = data.get('data_nascimento')  # formato dd-mm-aaaa
    data_nascimento = datetime.strptime(data_nascimento, '%d-%m-%Y').date()

    if not validar_senha(senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 404

    cursor = con.cursor()
    cursor.execute('SELECT 1 FROM USUARIOS WHERE email = ?', (email,))

    if cursor.fetchone():
        return jsonify({"error": 'Email do usuário já cadastrado'}), 400

    senha = bcrypt.generate_password_hash(senha).decode('utf-8')

    cursor.execute('INSERT INTO USUARIOS(NOME, EMAIL, SENHA, TELEFONE, DATA_NASCIMENTO) VALUES (?,?,?,?,?) returning id_usuario',
                   (nome, email, senha, telefone, data_nascimento))

    id_usuario = cursor.fetchone()[0]
    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Usuario cadastrado com sucesso!',
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha,
            'telefone': telefone,
            "data_nascimento": data_nascimento.strftime('%d-%m-%Y') if data_nascimento else None
        }
    })


@app.route('/usuariosadm', methods=['POST'])
def usuarioadm_post():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    telefone = data.get('telefone')
    data_nascimento = data.get('data_nascimento')
    cargo = data.get('cargo')

    if not validar_senha(senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 404

    cursor = con.cursor()
    cursor.execute('SELECT 1 FROM USUARIOS WHERE email = ?', (email,))

    if cursor.fetchone():
        return jsonify({"error": 'Email do usuário já cadastrado'}), 400

    senha = bcrypt.generate_password_hash(senha).decode('utf-8')

    cursor.execute('INSERT INTO USUARIOS(NOME, EMAIL, SENHA, TELEFONE, DATA_NASCIMENTO, CARGO) VALUES (?,?,?,?,?,?) returning id_usuario',
                   (nome, email, senha, telefone, data_nascimento, cargo))

    id_usuario = cursor.fetchone()[0]
    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Usuario cadastrado com sucesso!',
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
        }
    })


# ROTA PARA EDITAR PERFIL USANDO CARGO DE USUÁRIO NORMAL, BIBLIOTECÁRIO E ADMIN
@app.route('/usuariosadm/<int:id>', methods=['PUT'])
def usuarioadm_put(id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()
    cursor.execute('SELECT ID_USUARIO, NOME, EMAIL FROM USUARIOS WHERE ID_USUARIO = ?', (id,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({'error': 'Usuário não foi encontrado'}), 404

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    telefone = data.get('telefone')
    data_nascimento = data.get('data_nascimento')
    cargo = data.get('cargo')
    status = data.get('status')

    # Verifica se o novo e-mail já existe no banco e pertence a outro usuário
    cursor.execute('SELECT ID_USUARIO FROM USUARIOS WHERE EMAIL = ? AND ID_USUARIO <> ?', (email, id))
    email_existente = cursor.fetchone()

    if email_existente:
        cursor.close()
        return jsonify({'error': 'O email já está em uso por outro usuário'}), 400

    # Atualiza apenas os campos que podem ser editados
    cursor.execute('UPDATE USUARIOS SET NOME = ?, EMAIL = ?, TELEFONE = ?, DATA_NASCIMENTO = ?, CARGO = ?, STATUS = ? WHERE ID_USUARIO = ?',
                   (nome, email, telefone, data_nascimento, cargo, status, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Usuário editado com sucesso!',
        'usuario': {
            'id_usuario': id,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo,
            'status': status,
        }
    })


@app.route('/usuarios/<int:id>', methods=['PUT'])
def usuario_put(id):
    cursor = con.cursor()
    cursor.execute('SELECT ID_USUARIO, NOME, EMAIL FROM USUARIOS WHERE ID_USUARIO = ?', (id,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({'error': 'Usuário não foi encontrado'}), 404

    nome = request.form.get('nome')
    email = request.form.get('email')
    telefone = request.form.get('telefone')
    data_nascimento = request.form.get('data_nascimento')
    imagem = request.files.get('imagem')  # Recebe a imagem

    # Verifica se o novo e-mail já existe no banco e pertence a outro usuário
    cursor.execute('SELECT ID_USUARIO FROM USUARIOS WHERE EMAIL = ? AND ID_USUARIO <> ?', (email, id))
    email_existente = cursor.fetchone()

    if email_existente:
        cursor.close()
        return jsonify({'error': 'O e-mail já está em uso por outro usuário'}), 400

    # Atualiza apenas os campos que podem ser editados
    cursor.execute('UPDATE USUARIOS SET NOME = ?, EMAIL = ?, TELEFONE = ?, DATA_NASCIMENTO = ? WHERE ID_USUARIO = ?',
                   (nome, email, telefone, data_nascimento, id))

    con.commit()
    cursor.close()

    if imagem:
        nome_imagem = f"{usuario_data[0]}.jpeg"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Usuarios")
        os.makedirs(pasta_destino, exist_ok=True)
        imagem_path = os.path.join(pasta_destino, nome_imagem)
        imagem.save(imagem_path)

    return jsonify({
        'message': 'Usuário editado com sucesso!',
        'usuario': {
            'id_usuario': id,
            'nome': nome,
            'email': email,
            'telefone': telefone,
            'data_nascimento': data_nascimento
        }
    })


@app.route('/usuariosadm/<int:id_usuario>', methods=['DELETE'])
def excluir_usuario(id_usuario):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token de autenticação não fornecido."}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expirado."}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido."}), 401

    cursor = con.cursor()
    cursor.execute('SELECT * FROM usuarios WHERE id_usuario = ?', (id_usuario,))
    usuario = cursor.fetchone()
    if not usuario:
        return jsonify({"error": "Usuário não encontrado."}), 404

    cursor.execute('DELETE FROM usuarios WHERE id_usuario = ?', (id_usuario,))
    con.commit()
    return jsonify({"message": "Usuário excluído com sucesso."}), 200


# ROTA PARA EDITAR PERFIL USANDO CARGO DE USUÁRIO NORMAL, BIBLIOTECÁRIO E ADMIN
@app.route('/editar_senha/<int:id>', methods=['PUT'])
def editar_senha(id):
    cursor = con.cursor()
    cursor.execute('SELECT SENHA FROM USUARIOS WHERE ID_USUARIO = ?', (id,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({'error': 'Usuário não foi encontrado'}), 404

    data = request.get_json()
    senha_atual = data.get('senha_atual')
    nova_senha = data.get('nova_senha')
    confirmar_senha = data.get('confirmar_senha')

    # Hash da senha armazenada no banco
    senha_banco = usuario_data[0]  # Não é necessário fazer encode, o banco já tem o hash.

    # Verifica se a senha atual está correta
    if not bcrypt.check_password_hash(senha_banco, senha_atual):
        cursor.close()
        return jsonify({'error': 'Senha atual incorreta'}), 401

    if not validar_senha(confirmar_senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 404

    # Verifica se a nova senha e a confirmação são iguais
    if nova_senha != confirmar_senha:
        cursor.close()
        return jsonify({'error': 'Nova senha e confirmação não coincidem'}), 400

    # Verifica se a nova senha é diferente da antiga
    if nova_senha == senha_atual:
        cursor.close()
        return jsonify({'error': 'A nova senha deve ser diferente da senha atual'}), 400

    # Criptografa a nova senha
    nova_senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

    # Atualiza a senha no banco de dados
    cursor.execute('UPDATE USUARIOS SET SENHA = ? WHERE ID_USUARIO = ?',
                   (nova_senha_hash, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Senha alterada com sucesso!',
        'usuario': {
            'id_usuario': id
        }
    })


from datetime import datetime, timedelta

def cancelar_reservas_expiradas(conexao_db):
    """
    Cancela automaticamente todas as reservas (status=1) feitas há 2 dias ou mais.
    """
    cursor = conexao_db.cursor()
    # Calcula a data limite (2 dias atrás)
    data_limite = (datetime.now() - timedelta(days=3)).date()
    # Busca reservas feitas até a data limite
    cursor.execute("""
        SELECT id_emprestimo 
        FROM emprestimos 
        WHERE status = 1 AND data_reserva <= ?
    """, (data_limite,))
    reservas_expiradas = cursor.fetchall()

    if reservas_expiradas:
        ids_para_cancelar = [str(r[0]) for r in reservas_expiradas]
        # Atualiza o status dessas reservas para 4 (Cancelado)
        cursor.execute(f"""
            UPDATE emprestimos 
            SET status = 4 
            WHERE id_emprestimo IN ({','.join(['?']*len(ids_para_cancelar))})
        """, ids_para_cancelar)
        conexao_db.commit()
    cursor.close()


@app.route('/login', methods=['POST'])
def login():
    cancelar_reservas_expiradas(con)  # Chama a função automática ao iniciar o login

    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    cursor = con.cursor()
    cursor.execute("SELECT SENHA, ID_USUARIO, NOME, CARGO, EMAIL, DATA_NASCIMENTO, TELEFONE, STATUS, TENTATIVAS_ERRO FROM usuarios WHERE EMAIL = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        return jsonify({"error": "Usuário não encontrado"}), 404

    senha_hash = usuario[0]
    id_usuario = usuario[1]
    nome = usuario[2]
    cargo = usuario[3]
    email = usuario[4]
    data_nascimento = usuario[5]
    telefone = usuario[6]
    status = usuario[7]
    tentativas_erro = usuario[8]

    if status == 'Inativo':
        return jsonify({"error": "Você errou seu email ou sua senha 3 vezes, o usuário foi inativado."}), 403

    if bcrypt.check_password_hash(senha_hash, senha):
        # Resetar tentativas de erro no login bem-sucedido
        cursor.execute("UPDATE USUARIOS SET TENTATIVAS_ERRO = 0 WHERE ID_USUARIO = ?", (id_usuario,))
        # Limpar o código de verificação após login bem-sucedido
        cursor.execute("UPDATE USUARIOS SET CODIGO = NULL WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()
        cursor.close()

        token = generate_token(id_usuario, email)
        return jsonify({
            "message": "Login realizado com sucesso",
            "token": token,
            "usuario": {
                "id_usuario": id_usuario,
                "nome": nome,
                "cargo": cargo,
                "email": email,
                "data_nascimento": data_nascimento.strftime('%d-%m-%Y') if data_nascimento else None,
                "telefone": telefone
            }
        }), 200

    tentativas_erro += 1
    cursor.execute("UPDATE USUARIOS SET TENTATIVAS_ERRO = ? WHERE ID_USUARIO = ?", (tentativas_erro, id_usuario))
    con.commit()

    if tentativas_erro >= 3:
        cursor.execute("UPDATE USUARIOS SET STATUS = 'Inativo' WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

    cursor.close()
    return jsonify({"error": "Email ou senha inválidos"}), 401


# ROTAS DOS LIVROS
@app.route('/livro/<int:id>', methods=['GET'])
def livro_buscar(id):
    cur = con.cursor()
    # Busca os dados do livro
    cur.execute('SELECT id_livro, titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria, nota, paginas, idioma, status FROM livros WHERE id_livro = ?', (id,))
    livro = cur.fetchone()

    if not livro:
        cur.close()
        return jsonify({"error": "Nenhum livro encontrado."}), 404

    livro_dic = {
        'id_livro': livro[0],
        'titulo': livro[1],
        'autor': livro[2],
        'data_publicacao': livro[3],
        'ISBN': livro[4],
        'descricao': livro[5],
        'quantidade': livro[6],
        'categoria': livro[7],
        'nota': livro[8],
        'paginas': livro[9],
        'idioma': livro[10],
        'status': livro[11]
    }

    # Busca todos os usuários que já emprestaram esse livro
    status_map = {
        1: "Reservado",
        2: "Emprestado",
        3: "Devolvido",
        4: "Cancelado"
    }

    cur.execute("""
        SELECT 
            e.id_emprestimo,
            e.id_usuario,
            u.nome,
            u.email,
            e.status,
            e.data_reserva,
            e.data_emprestimo,
            e.data_devolucao,
            e.data_devolvida
        FROM emprestimos e
        JOIN usuarios u ON e.id_usuario = u.id_usuario
        WHERE e.id_livro = ?
        ORDER BY e.data_reserva DESC
    """, (id,))
    registros = cur.fetchall()
    cur.close()

    usuarios_emprestimos = []
    for r in registros:
        usuarios_emprestimos.append({
            'id_emprestimo': r[0],
            'id_usuario': r[1],
            'nome_usuario': r[2],
            'email_usuario': r[3],
            'status': status_map.get(r[4], 'Desconhecido'),
            'data_reserva': r[5].strftime('%d-%m-%Y') if r[5] else None,
            'data_emprestimo': r[6].strftime('%d-%m-%Y') if r[6] else None,
            'data_devolucao': r[7].strftime('%d-%m-%Y') if r[7] else None,
            'data_devolvida': r[8].strftime('%d-%m-%Y') if r[8] else None
        })

    return jsonify(
        livro=livro_dic,
        usuarios_emprestimos=usuarios_emprestimos
    ), 200


# Rota para criar um novo livro
@app.route('/livros', methods=['POST'])
def livro_imagem():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # Recebendo os dados do formulário (não JSON)
    titulo = request.form.get('titulo')
    autor = request.form.get('autor')
    data_publicacao = request.form.get('data_publicacao')
    ISBN = request.form.get('ISBN')
    descricao = request.form.get('descricao')
    quantidade = request.form.get('quantidade')
    categoria = request.form.get('categoria')
    paginas = request.form.get('paginas')
    idioma = request.form.get('idioma')
    imagem = request.files.get('imagem')  # Arquivo enviado

    cursor = con.cursor()

    # Verifica se o livro já existe
    cursor.execute("SELECT 1 FROM livros WHERE TITULO = ?", (titulo,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro já cadastrado"}), 400

    # Define status como 1 (disponível) por padrão
    status = 1

    # Insere o novo livro e retorna o ID gerado
    cursor.execute(
        "INSERT INTO livros (TITULO, AUTOR, DATA_PUBLICACAO, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA, PAGINAS, IDIOMA, STATUS) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ID_livro",
        (titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria, paginas, idioma, status)
    )
    livro_id = cursor.fetchone()[0]
    con.commit()

    # Salvar a imagem se for enviada
    imagem_path = None
    if imagem:
        nome_imagem = f"{livro_id}.jpeg"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Livros")
        os.makedirs(pasta_destino, exist_ok=True)
        imagem_path = os.path.join(pasta_destino, nome_imagem)
        imagem.save(imagem_path)

    cursor.close()

    return jsonify({
        'message': "Livro cadastrado com sucesso!",
        'livro': {
            'id': livro_id,
            'titulo': titulo,
            'autor': autor,
            'data_publicacao': data_publicacao,
            'ISBN': ISBN,
            'descricao': descricao,
            'quantidade': quantidade,
            'categoria': categoria,
            'paginas': paginas,
            'idioma': idioma,
            'status': status,
            'imagem_path': f"/static/uploads/Livros/{livro_id}.jpeg"
        }
    }), 201


@app.route('/livros/<int:id>', methods=['PUT'])
def livro_put(id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()
    cursor.execute('SELECT ID_LIVRO, TITULO, AUTOR, DATA_PUBLICACAO, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA, PAGINAS, IDIOMA, STATUS FROM LIVROS WHERE ID_LIVRO = ?', (id,))
    livro_data = cursor.fetchone()

    if not livro_data:
        cursor.close()
        return jsonify({'error': 'O livro informado não existe'}), 404

    titulo = request.form.get('titulo')
    autor = request.form.get('autor')
    data_publicacao = request.form.get('data_publicacao')
    ISBN = request.form.get('ISBN')
    descricao = request.form.get('descricao')
    quantidade = request.form.get('quantidade')
    categoria = request.form.get('categoria')
    paginas = request.form.get('paginas')
    idioma = request.form.get('idioma')
    status = request.form.get('status')
    imagem = request.files.get('imagem')

    cursor.execute('UPDATE LIVROS SET TITULO = ?, AUTOR = ?, DATA_PUBLICACAO = ?, ISBN = ?, DESCRICAO = ?, QUANTIDADE = ?, CATEGORIA = ?, PAGINAS = ?, IDIOMA = ?, STATUS = ? WHERE ID_LIVRO = ?',
                   (titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria, paginas, idioma, status, id))

    con.commit()
    cursor.close()

    if imagem:
        nome_imagem = f"{livro_data[0]}.jpeg"
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Livros")  # Atualizado para refletir a nova estrutura
        os.makedirs(pasta_destino, exist_ok=True)
        imagem_path = os.path.join(pasta_destino, nome_imagem)
        imagem.save(imagem_path)

    return jsonify({
        'message': 'Livro editado com sucesso!',
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'data_publicacao': data_publicacao,
            'ISBN': ISBN,
            'descricao': descricao,
            'quantidade': quantidade,
            'categoria': categoria,
            'paginas': paginas,
            'idioma': idioma,
            'status': status
        }
    })


@app.route('/livro_indisp/<int:id>', methods=['PUT'])
def tornar_livro_indisponivel(id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Verificar se o livro existe
    cursor.execute("SELECT 1 FROM livros WHERE ID_LIVRO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    # Verificar se há empréstimos em andamento com esse livro
    cursor.execute("SELECT 1 FROM emprestimos WHERE id_livro = ? AND status = 2", (id,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Não é possível tornar o livro indisponível com empréstimos em andamento'}), 400

    # Verificar se há reservas ativas (por exemplo, status = 1) com esse livro
    cursor.execute("SELECT 1 FROM emprestimos WHERE id_livro = ? AND status = 1", (id,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Não é possível tornar o livro indisponível com reservas ativas'}), 400

    # Atualizar o status do livro para 2 (indisponível)
    cursor.execute("UPDATE livros SET status = 2 WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro marcado como indisponível com sucesso!",
        'id_livro': id,
        'novo_status': 2
    })


@app.route('/livro_disp/<int:id>', methods=['PUT'])
def tornar_livro_disponivel(id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Verificar se o livro existe
    cursor.execute("SELECT 1 FROM livros WHERE ID_LIVRO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    # Atualizar o status do livro para 1 (disponível)
    cursor.execute("UPDATE livros SET status = 1 WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro marcado como disponível com sucesso!",
        'id_livro': id,
        'novo_status': 1
    })


# ROTAS DE ADM
PDF_PATH = "relatorio_livros.pdf"

from flask import send_file
from datetime import datetime
from fpdf import FPDF
import os

class PDFRelatorio(FPDF):
    def header(self):
        self.set_font("Helvetica", 'B', 18)
        self.set_text_color(34, 49, 63)
        self.cell(0, 14, getattr(self, 'titulo', 'Relatório'), ln=True, align='C')
        self.set_line_width(0.8)
        self.set_draw_color(52, 152, 219)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(8)


    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f'Gerado em {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 0, 'C')

def safe_str(texto):
    return str(texto).encode('latin-1', 'replace').decode('latin-1')

@app.route('/livros_relatorio', methods=['GET'])
def relatorio():
    pdf_path = "relatorio_livros.pdf"
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    cursor = con.cursor()
    cursor.execute("SELECT id_livro, titulo, autor, data_publicacao, isbn, descricao, quantidade, categoria FROM livros")
    livros = cursor.fetchall()
    cursor.close()

    pdf = PDFRelatorio()
    pdf.titulo = "Relatório de Livros"
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    for livro in livros:
        id_livro, titulo, autor, data_publicacao, isbn, descricao, quantidade, categoria = livro[:8]
        campos = [
            ("Título", titulo),
            ("Autor", autor),
            ("Publicação", data_publicacao),
            ("ISBN", isbn),
            ("Descrição", descricao),
            ("Quantidade", quantidade),
            ("Categoria", categoria)
        ]

        x = 18
        y = pdf.get_y()
        w = 174
        label_w = 38
        value_w = w - 55
        altura_total = 0

        pdf.set_font("Helvetica", 'B', 11)
        altura_total += 7

        pdf.set_font("Helvetica", '', 10)
        for label, valor in campos:
            valor_h = pdf.multi_cell(value_w, 6, safe_str(str(valor)), split_only=True)
            altura_total += max(6, len(valor_h) * 6)

        altura_total += 4

        if pdf.get_y() + altura_total > pdf.page_break_trigger:
            pdf.add_page()
            y = pdf.get_y()

        pdf.set_fill_color(245, 248, 252)
        pdf.set_draw_color(160, 180, 210)
        pdf.rect(x, y, w, altura_total, 'DF')

        pdf.set_xy(x + 6, y + 4)
        pdf.set_font("Helvetica", 'B', 11)
        pdf.set_text_color(52, 73, 94)
        pdf.cell(0, 7, f"Livro Nº {id_livro}", ln=True)

        for label, valor in campos:
            pdf.set_x(x + 12)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.set_text_color(52, 152, 219)
            pdf.cell(label_w, 6, f"{label}:", ln=0)
            pdf.set_font("Helvetica", '', 10)
            pdf.set_text_color(52, 73, 94)
            pdf.multi_cell(value_w, 6, safe_str(str(valor)))
        pdf.ln(4)

    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(40, 60, 120)
    pdf.cell(0, 10, safe_str(f"Total de livros cadastrados: {len(livros)}"), ln=True, align='C')

    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

from flask import send_file
from datetime import datetime
from fpdf import FPDF
import os

class PDFRelatorio(FPDF):
    def header(self):
        self.set_font("Helvetica", 'B', 18)
        self.set_text_color(34, 49, 63)
        self.cell(0, 14, getattr(self, 'titulo', 'Relatório'), ln=True, align='C')
        self.set_line_width(0.8)
        self.set_draw_color(52, 152, 219)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(8)


    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f'Gerado em {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 0, 'C')

def safe_str(texto):
    return str(texto).encode('latin-1', 'replace').decode('latin-1')

def format_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d").strftime("%d/%m/%Y")
    except Exception:
        return date_str

@app.route('/usuarios_relatorio', methods=['GET'])
def relatorio_usuarios():
    pdf_path = "relatorio_usuarios.pdf"
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    cursor = con.cursor()
    cursor.execute("SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, status FROM usuarios")
    usuarios = cursor.fetchall()
    cursor.close()

    ativos = [u for u in usuarios if str(u[6]).lower() == 'ativo']
    inativos = [u for u in usuarios if str(u[6]).lower() != 'ativo']

    pdf = PDFRelatorio()
    pdf.titulo = "Relatório de Usuários"
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    def add_usuario_blocos(titulo, lista_usuarios):
        pdf.set_font("Helvetica", 'B', 13)
        pdf.set_fill_color(220, 232, 246)
        pdf.set_text_color(52, 73, 94)
        pdf.cell(0, 10, safe_str(titulo), ln=True, align='L', fill=True)
        pdf.ln(3)

        for usuario in lista_usuarios:
            id_usuario, nome, email, telefone, data_nascimento, cargo, status = usuario
            campos = [
                ("Nome", nome),
                ("Email", email),
                ("Telefone", telefone),
                ("Nascimento", format_date(data_nascimento)),
                ("Cargo", cargo),
                ("Status", status)
            ]

            x = 18
            y = pdf.get_y()
            w = 174
            label_w = 38
            value_w = w - 55
            altura_total = 0

            pdf.set_font("Helvetica", 'B', 11)
            altura_total += 7

            pdf.set_font("Helvetica", '', 10)
            for label, valor in campos:
                valor_h = pdf.multi_cell(value_w, 6, safe_str(str(valor)), split_only=True)
                altura_total += max(6, len(valor_h) * 6)

            altura_total += 4

            if pdf.get_y() + altura_total > pdf.page_break_trigger:
                pdf.add_page()
                y = pdf.get_y()

            pdf.set_fill_color(245, 248, 252)
            pdf.set_draw_color(160, 180, 210)
            pdf.rect(x, y, w, altura_total, 'DF')

            pdf.set_xy(x + 6, y + 4)
            pdf.set_font("Helvetica", 'B', 11)
            pdf.set_text_color(52, 73, 94)
            pdf.cell(0, 7, f"Usuário Nº {id_usuario}", ln=True)

            for label, valor in campos:
                pdf.set_x(x + 12)
                pdf.set_font("Helvetica", 'B', 10)
                pdf.set_text_color(52, 152, 219)
                pdf.cell(label_w, 6, f"{label}:", ln=0)
                pdf.set_font("Helvetica", '', 10)
                pdf.set_text_color(52, 73, 94)
                pdf.multi_cell(value_w, 6, safe_str(str(valor)))
            pdf.ln(4)

    add_usuario_blocos("Usuários Ativos", ativos)
    add_usuario_blocos("Usuários Inativos", inativos)

    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(40, 60, 120)
    pdf.cell(0, 10, safe_str(f"Total de usuários ativos: {len(ativos)}"), ln=True, align='L')
    pdf.cell(0, 10, safe_str(f"Total de usuários inativos: {len(inativos)}"), ln=True, align='L')
    pdf.cell(0, 10, safe_str(f"Total geral de usuários: {len(usuarios)}"), ln=True, align='L')

    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


from flask import send_file, jsonify
from datetime import datetime
from fpdf import FPDF
import os

class PDFRelatorio(FPDF):
    def header(self):
        self.set_font("Helvetica", 'B', 18)
        self.set_text_color(34, 49, 63)
        self.cell(0, 14, getattr(self, 'titulo', 'Relatório'), ln=True, align='C')
        self.set_line_width(0.8)
        self.set_draw_color(52, 152, 219)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f'Gerado em {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 0, 'C')

def formatar_data(data):
    if isinstance(data, datetime):
        return data.strftime('%d/%m/%Y')
    try:
        return datetime.strptime(str(data), '%Y-%m-%d').strftime('%d/%m/%Y')
    except:
        return str(data) if data else "-"

def calcular_dias(data_inicio, data_fim):
    try:
        if not data_inicio or not data_fim:
            return "-"
        if isinstance(data_inicio, str):
            data_inicio = datetime.strptime(data_inicio, "%Y-%m-%d")
        if isinstance(data_fim, str):
            data_fim = datetime.strptime(data_fim, "%Y-%m-%d")
        return (data_fim - data_inicio).days
    except Exception:
        return "-"

@app.route('/multas_relatorio', methods=['GET'])
def relatorio_multas():
    pdf_path = "relatorio_multas.pdf"
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    try:
        cursor = con.cursor()
        cursor.execute("""
            SELECT m.valor, u.nome, m.data_lancamento, l.titulo, e.data_emprestimo, e.data_devolvida
            FROM multas m
            JOIN usuarios u ON m.id_usuario = u.id_usuario
            JOIN emprestimos e ON m.id_emprestimo = e.id_emprestimo
            JOIN livros l ON e.id_livro = l.id_livro
        """)
        multas = cursor.fetchall()
        cursor.close()
    except Exception as e:
        return jsonify({"erro": f"Erro ao buscar dados do banco: {str(e)}"}), 500

    pdf = PDFRelatorio()
    pdf.titulo = "Relatório de Multas"
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    pdf.set_font("Helvetica", 'B', 13)
    pdf.set_fill_color(220, 232, 246)
    pdf.set_text_color(52, 73, 94)
    pdf.cell(0, 10, "Multas Registradas", ln=True, align='C', fill=True)
    pdf.ln(5)

    total_multas = len(multas)

    for multa in multas:
        valor, nome_usuario, data_lancamento, titulo_livro, data_emprestimo, data_devolvida = multa
        dias_com_livro = calcular_dias(data_emprestimo, data_devolvida)

        campos = [
            ("Usuário", nome_usuario),
            ("Livro", titulo_livro),
            ("Valor", f"R$ {valor:.2f}"),
            ("Data Lançamento", formatar_data(data_lancamento)),
            ("Data Empréstimo", formatar_data(data_emprestimo)),
            ("Data Devolvida", formatar_data(data_devolvida)),
            ("Dias com o livro", dias_com_livro)
        ]

        x = 18
        y = pdf.get_y()
        w = 174
        label_w = 50
        value_w = w - label_w - 10
        altura_total = 0

        pdf.set_font("Helvetica", 'B', 11)
        altura_total += 7

        pdf.set_font("Helvetica", '', 10)
        for label, valor_campo in campos:
            valor_h = pdf.multi_cell(value_w, 6, str(valor_campo), split_only=True)
            altura_total += max(6, len(valor_h) * 6)

        altura_total += 8

        if pdf.get_y() + altura_total > pdf.page_break_trigger:
            pdf.add_page()
            y = pdf.get_y()

        pdf.set_fill_color(245, 248, 252)
        pdf.set_draw_color(160, 180, 210)
        pdf.rect(x, y, w, altura_total, 'DF')

        pdf.set_xy(x + 6, y + 4)
        pdf.set_font("Helvetica", 'B', 11)
        pdf.set_text_color(52, 73, 94)
        pdf.cell(0, 7, "Registro de Multa", ln=True)

        for label, valor_campo in campos:
            pdf.set_x(x + 12)
            pdf.set_font("Helvetica", 'B', 10)
            pdf.set_text_color(52, 152, 219)
            pdf.cell(label_w, 6, f"{label}:", ln=0)
            pdf.set_font("Helvetica", '', 10)
            pdf.set_text_color(52, 73, 94)
            pdf.multi_cell(value_w, 6, str(valor_campo))

        pdf.ln(4)

    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(52, 73, 94)
    pdf.ln(2)
    pdf.cell(0, 10, f"Total de multas: {total_multas}", ln=True, align='C')

    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


from flask import send_file, jsonify
from datetime import datetime
from fpdf import FPDF
import os

class PDFRelatorio(FPDF):
    def header(self):
        self.set_font("Helvetica", 'B', 18)
        self.set_text_color(34, 49, 63)
        self.cell(0, 14, getattr(self, 'titulo', 'Relatório'), ln=True, align='C')
        self.set_line_width(0.8)
        self.set_draw_color(52, 152, 219)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(8)


    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 9)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f'Gerado em {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 0, 'C')

def formatar_data(data):
    if isinstance(data, datetime):
        return data.strftime('%d/%m/%Y')
    try:
        return datetime.strptime(str(data), '%Y-%m-%d').strftime('%d/%m/%Y')
    except:
        return str(data) if data else ""

def traduzir_status(status):
    return {
        1: "Reservado",
        2: "Emprestado",
        3: "Devolvido"
    }.get(status, f"Desconhecido ({status})")

@app.route('/emprestimos_relatorio', methods=['GET'])
def relatorio_emprestimos():
    pdf_path = "relatorio_emprestimos.pdf"
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')

    try:
        cursor = con.cursor()
        cursor.execute("""
            SELECT 
                e.id_emprestimo, 
                l.titulo, 
                u.nome, 
                u.email, 
                e.status, 
                e.data_emprestimo, 
                e.data_devolucao,
                e.data_devolvida,
                e.data_reserva
            FROM emprestimos e
            JOIN livros l ON e.id_livro = l.id_livro
            JOIN usuarios u ON e.id_usuario = u.id_usuario
            WHERE e.status IN (1, 2, 3)
            ORDER BY e.status, e.data_emprestimo
        """)
        emprestimos = cursor.fetchall()
        cursor.close()
    except Exception as e:
        return jsonify({"erro": f"Erro ao buscar dados do banco: {str(e)}"}), 500
#DEVIL MAY CRY
    pdf = PDFRelatorio()
    pdf.titulo = "Relatório de Empréstimos"
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=18)

    grupos = {
        1: "Livros Reservados",
        2: "Livros Emprestados",
        3: "Livros Devolvidos"
    }

    total_por_grupo = {}

    for status_grupo in [1, 2, 3]:
        emprestimos_filtrados = [e for e in emprestimos if e[4] == status_grupo]
        total_por_grupo[status_grupo] = len(emprestimos_filtrados)
        if not emprestimos_filtrados:
            continue

        pdf.set_font("Helvetica", 'B', 13)
        pdf.set_fill_color(220, 232, 246)
        pdf.set_text_color(52, 73, 94)
        pdf.cell(0, 10, grupos[status_grupo], ln=True, align='L', fill=True)
        pdf.ln(3)

        for e in emprestimos_filtrados:
            id_emp, titulo, nome, email, status, data_emp, data_dev, data_devolvida, data_reserva = e

            campos = [
                ("Livro", titulo),
                ("Usuário", nome),
                ("Email", email),
                ("Status", traduzir_status(status)),
                ("Data Reserva", formatar_data(data_reserva) if data_reserva else "-"),
                ("Data Empréstimo", formatar_data(data_emp)),
                ("Prev. Devolução", formatar_data(data_dev)),
                ("Data Devolvida", formatar_data(data_devolvida) if data_devolvida else "-")
            ]

            x = 18
            y = pdf.get_y()
            w = 174
            label_w = 38
            value_w = w - 55
            altura_total = 0

            pdf.set_font("Helvetica", 'B', 11)
            altura_total += 7

            pdf.set_font("Helvetica", '', 10)
            for label, valor in campos:
                valor_h = pdf.multi_cell(value_w, 6, str(valor), split_only=True)
                altura_total += max(6, len(valor_h) * 6)

            altura_total += 4

            if pdf.get_y() + altura_total > pdf.page_break_trigger:
                pdf.add_page()
                y = pdf.get_y()

            pdf.set_fill_color(245, 248, 252)
            pdf.set_draw_color(160, 180, 210)
            pdf.rect(x, y, w, altura_total, 'DF')

            pdf.set_xy(x + 6, y + 4)
            pdf.set_font("Helvetica", 'B', 11)
            pdf.set_text_color(52, 73, 94)
            pdf.cell(0, 7, f"Empréstimo Nº {id_emp}", ln=True)

            for label, valor in campos:
                pdf.set_x(x + 12)
                pdf.set_font("Helvetica", 'B', 10)
                pdf.set_text_color(52, 152, 219)
                pdf.cell(label_w, 6, f"{label}:", ln=0)
                pdf.set_font("Helvetica", '', 10)
                pdf.set_text_color(52, 73, 94)
                pdf.multi_cell(value_w, 6, str(valor))
            pdf.ln(4)

    pdf.set_font("Helvetica", 'B', 12)
    pdf.set_text_color(52, 73, 94)
    pdf.ln(2)
    pdf.cell(0, 10, f"Total Reservados: {total_por_grupo.get(1,0)}", ln=True, align='L')
    pdf.cell(0, 10, f"Total Emprestados: {total_por_grupo.get(2,0)}", ln=True, align='L')
    pdf.cell(0, 10, f"Total Devolvidos: {total_por_grupo.get(3,0)}", ln=True, align='L')
    pdf.cell(0, 10, f"Total Geral: {len(emprestimos)}", ln=True, align='L')

    pdf.output(pdf_path)
    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


@app.route('/bibliotecario', methods=['POST'])
def bibliotecario_post():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')
    telefone = data.get('telefone')
    data_nascimento = data.get('data_nascimento')
    cargo = data.get('cargo')

    if not validar_senha(senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 404

    cursor = con.cursor()
    cursor.execute('SELECT 1 FROM USUARIOS WHERE NOME = ?', (nome,))

    if cursor.fetchone():
        return jsonify('Usuario já cadastrado')

    senha = bcrypt.generate_password_hash(senha).decode('utf-8')

    cursor.execute('INSERT INTO USUARIOS(NOME, EMAIL, SENHA, TELEFONE, DATA_NASCIMENTO, CARGO) VALUES (?,?,?,?,?,?)',
                   (nome, email, senha, telefone, data_nascimento, "Bibliotecario"))

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Bibliotecario cadastrado com sucesso!',
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha,
            'telefone': telefone,
            'data_nascimento': data_nascimento,
            'cargo': cargo
        }
    })


@app.route('/reservas/<int:id_livro>', methods=['POST'])
def reservas(id_livro):
    from datetime import datetime, timedelta

    data_reserva = datetime.now().strftime('%Y-%m-%d')
    status = 1

    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
        email = payload['email']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Verificar se o usuário já possui uma reserva ou empréstimo pendente
    cursor.execute("""
        SELECT COUNT(*) FROM emprestimos 
        WHERE id_usuario = ? AND status IN (1, 2)
    """, (id_usuario,))
    ja_reservado = cursor.fetchone()[0]

    if ja_reservado > 0:
        cursor.close()
        return jsonify({"mensagem": "Você já possui uma reserva ou empréstimo ativo."}), 400

    # Verificar se o usuário possui uma multa pendente
    cursor.execute("""
        SELECT COUNT(*) FROM multas 
        WHERE id_usuario = ? AND status IN (1)
    """, (id_usuario,))
    multa_pendente = cursor.fetchone()[0]

    if multa_pendente > 0:
        cursor.close()
        return jsonify({"mensagem": "Você tem uma multa pendente."}), 400

    # Buscar informações do livro
    cursor.execute("SELECT titulo, autor, quantidade FROM livros WHERE id_livro = ?", (id_livro,))
    livro_data = cursor.fetchone()

    if not livro_data:
        cursor.close()
        return jsonify({"mensagem": "Livro não encontrado"}), 404

    titulo, autor, quantidade_disponivel = livro_data

    if quantidade_disponivel <= 0:
        cursor.close()
        return jsonify({"mensagem": "Livro não disponível para reserva"}), 400

    # Buscar o nome do usuário
    cursor.execute("SELECT nome FROM usuarios WHERE id_usuario = ?", (id_usuario,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({"mensagem": "Usuário não encontrado"}), 404

    nome = usuario_data[0]

    try:
        # Inserir o empréstimo
        cursor.execute(
            'INSERT INTO emprestimos(data_reserva, status, id_livro, id_usuario) VALUES (?, ?, ?, ?)',
            (data_reserva, status, id_livro, id_usuario)
        )
        cursor.execute("UPDATE livros SET quantidade = quantidade - 1 WHERE id_livro = ?", (id_livro,))
        con.commit()
        data_reserva = (datetime.now() + timedelta(days=1)).strftime('%d/%m/%Y')

        # Mensagem de e-mail personalizada
        assunto = "Reserva realizada com sucesso"
        texto = f"""
        Olá, {nome}! 👋

        Sua reserva foi registrada com sucesso! 📚✨

        📝 **Informações da Reserva:**
        • 📖 *Livro:* {titulo}
        • ✍️ *Autor:* {autor}
        • 📆 *Você tem até:* {data_reserva} para buscar seu livro

        Lembre-se de buscar o livro até a data informada, caso contrário sua reserva será cancelada! 😉

        Atenciosamente,  
        Equipe Asa Literária 🏛️
        """

        try:
            print(f"Enviando e-mail para: {email}")
            email_emprestimo(email, texto, assunto)
            print("E-mail enviado com sucesso!")
        except Exception as email_error:
            print(f"Erro ao enviar e-mail: {email_error}")
            flash(f"Erro ao enviar o e-mail: {str(email_error)}", "error")

    except Exception as e:
        return jsonify({"mensagem": f"Erro ao registrar reserva: {str(e)}"}), 500
    finally:
        cursor.close()

    return jsonify({
        'message': 'Reserva realizada com sucesso!',
        'reserva': {
            'id_livro': id_livro,
            'titulo': titulo,
            'autor': autor,
            'id_usuario': id_usuario,
            'nome': nome,
            'data_reserva': data_reserva
        }
    })


@app.route('/emprestimos/<int:id_emprestimo>', methods=['PUT'])
def emprestimos(id_emprestimo):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        jwt.decode(token, senha_secreta, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Buscar id_livro e id_usuario da tabela de empréstimos
    cursor.execute("SELECT id_livro, id_usuario FROM emprestimos WHERE id_emprestimo = ?", (id_emprestimo,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        return jsonify({'mensagem': 'Empréstimo não encontrado'}), 404

    id_livro, id_usuario = row  # <-- Aqui pegamos o id_usuario do empréstimo

    # Buscar informações do livro
    cursor.execute("SELECT titulo, autor FROM livros WHERE id_livro = ?", (id_livro,))
    livro_data = cursor.fetchone()
    if not livro_data:
        cursor.close()
        return jsonify({"mensagem": "Livro não encontrado"}), 404

    titulo, autor = livro_data

    # Buscar nome e email do usuário a partir do id_usuario da tabela empréstimos
    cursor.execute("SELECT nome, email FROM usuarios WHERE id_usuario = ?", (id_usuario,))
    usuario_data = cursor.fetchone()
    if not usuario_data:
        cursor.close()
        return jsonify({"mensagem": "Usuário não encontrado"}), 404

    nome, email = usuario_data  # <-- Agora temos o nome e email corretos

    # Verificar o status atual do empréstimo
    cursor.execute('SELECT status FROM EMPRESTIMOS WHERE ID_EMPRESTIMO = ?', (id_emprestimo,))
    emprestimo_data = cursor.fetchone()
    if not emprestimo_data:
        cursor.close()
        return jsonify({'error': 'O empréstimo informado não existe'}), 404

    status_atual = emprestimo_data[0]

    if status_atual == 2:
        cursor.close()
        return jsonify({'mensagem': 'Esse empréstimo já foi realizado'}), 400

    # Atualizar o empréstimo
    data_emprestimo = datetime.now().date()
    data_devolucao = (datetime.now() + timedelta(days=7)).date()
    status = 2  # Em andamento

    cursor.execute(
        'UPDATE EMPRESTIMOS SET data_emprestimo = ?, data_devolucao = ?, status = ? WHERE ID_EMPRESTIMO = ?',
        (data_emprestimo, data_devolucao, status, id_emprestimo)
    )

    data_emprestimo_str = data_emprestimo.strftime('%d/%m/%Y')
    data_devolucao_str = data_devolucao.strftime('%d/%m/%Y')

    assunto = "Empréstimo realizado com sucesso"
    texto = f"""
    Olá, {nome}! 👋

    Seu empréstimo foi registrado com sucesso! 📚✨

    📝 **Informações do Empréstimo:**
    • 📖 *Livro:* {titulo}
    • ✍️ *Autor:* {autor}
    • 📆 *Data do empréstimo:* {data_emprestimo_str}
    • 📆 *Data da devolução:* {data_devolucao_str}

    Lembre-se de devolver o livro até a data informada, caso contrário você deverá pagar uma multa! 😉

    Atenciosamente,  
    Equipe Asa Literária 🏛️
    """

    try:
        print(f"Enviando e-mail para: {email}")
        email_emprestimo(email, texto, assunto)
        print("E-mail enviado com sucesso!")
    except Exception as email_error:
        print(f"Erro ao enviar e-mail: {email_error}")
        flash(f"Erro ao enviar o e-mail: {str(email_error)}", "error")

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Empréstimo atualizado com sucesso!',
        'livro': {
            'data_emprestimo': data_emprestimo_str,
            'data_devolucao': data_devolucao_str,
            'status': status
        }
    })


@app.route('/reservas', methods=['GET'])
def listar_reservas():
    try:
        termo = request.args.get('q')
        pagina = int(request.args.get('pagina', 1))
        quantidade_por_pagina = 10

        cur = con.cursor()

        # Query base
        sql = """
            SELECT 
                e.id_emprestimo, 
                e.data_reserva,
                e.status,
                e.id_usuario, 
                e.id_livro,
                u.nome AS nome_usuario,
                l.titulo AS titulo_livro,
                l.autor AS autor_livro
            FROM emprestimos e
            JOIN usuarios u ON e.id_usuario = u.id_usuario
            JOIN livros l ON e.id_livro = l.id_livro
            WHERE e.status = 1
        """
        params = []

        # Filtro de busca
        if termo:
            sql += " AND (LOWER(u.nome) LIKE ? OR LOWER(l.titulo) LIKE ?)"
            termo_lower = f"%{termo.lower()}%"
            params.extend([termo_lower, termo_lower])

        sql += " ORDER BY e.data_reserva DESC"

        cur.execute(sql, params)
        reservas = cur.fetchall()

        # Paginação em memória
        total_reservas = len(reservas)
        total_paginas = (total_reservas + quantidade_por_pagina - 1) // quantidade_por_pagina

        inicio = (pagina - 1) * quantidade_por_pagina
        fim = inicio + quantidade_por_pagina
        reservas_pagina = reservas[inicio:fim]

        if not reservas_pagina:
            return jsonify({'mensagem': 'Nenhuma reserva encontrada'}), 404

        # Formatação de datas
        def formatar_data_br(data):
            if data is None:
                return ""
            if isinstance(data, (datetime, date)):
                return data.strftime("%d/%m/%Y")
            if isinstance(data, str):
                try:
                    data_obj = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                    return data_obj.strftime("%d/%m/%Y")
                except ValueError:
                    try:
                        data_obj = datetime.strptime(data, "%Y-%m-%d")
                        return data_obj.strftime("%d/%m/%Y")
                    except Exception:
                        return data
            return str(data)

        reservas_formatadas = [{
            'id_emprestimo': r[0],
            'data_reserva': formatar_data_br(r[1]),
            'status': r[2],
            'id_usuario': r[3],
            'id_livro': r[4],
            'nome_usuario': r[5],
            'titulo_livro': r[6],
            'autor_livro': r[7]
        } for r in reservas_pagina]

        return jsonify({
            'mensagem': 'Lista de Reservas',
            'pagina_atual': pagina,
            'total_paginas': total_paginas,
            'total_reservas': total_reservas,
            'reservas': reservas_formatadas
        })

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@app.route('/emprestimos', methods=['GET'])
def listar_emprestimos():
    try:
        termo = request.args.get('q')
        pagina = int(request.args.get('pagina', 1))
        quantidade_por_pagina = 10

        cur = con.cursor()

        sql = """
            SELECT 
                e.id_emprestimo, 
                e.data_reserva,
                e.data_emprestimo, 
                e.data_devolucao, 
                e.status,
                e.id_usuario, 
                e.id_livro,
                u.nome AS nome_usuario,
                l.titulo AS titulo_livro,
                l.autor AS autor_livro
            FROM emprestimos e
            JOIN usuarios u ON e.id_usuario = u.id_usuario
            JOIN livros l ON e.id_livro = l.id_livro
            WHERE e.status = 2
        """
        params = []

        if termo:
            sql += " AND (LOWER(u.nome) LIKE ? OR LOWER(l.titulo) LIKE ?)"
            termo_lower = f"%{termo.lower()}%"
            params.extend([termo_lower, termo_lower])

        sql += " ORDER BY e.data_emprestimo DESC"

        cur.execute(sql, params)
        emprestimos = cur.fetchall()

        total_emprestimos = len(emprestimos)
        total_paginas = (total_emprestimos + quantidade_por_pagina - 1) // quantidade_por_pagina

        inicio = (pagina - 1) * quantidade_por_pagina
        fim = inicio + quantidade_por_pagina
        emprestimos_pagina = emprestimos[inicio:fim]

        if not emprestimos_pagina:
            return jsonify({'mensagem': 'Nenhum empréstimo encontrado'}), 404

        def formatar_data_br(data):
            if data is None:
                return ""
            if isinstance(data, (datetime, date)):
                return data.strftime("%d/%m/%Y")
            if isinstance(data, str):
                try:
                    data_obj = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                    return data_obj.strftime("%d/%m/%Y")
                except ValueError:
                    try:
                        data_obj = datetime.strptime(data, "%Y-%m-%d")
                        return data_obj.strftime("%d/%m/%Y")
                    except Exception:
                        return data
            return str(data)

        # Dentro da rota /emprestimos:
        emprestimos_formatados = [{
            'id_emprestimo': e[0],
            'data_reserva': formatar_data_br(e[1]),
            'data_emprestimo': formatar_data_br(e[2]),
            'data_devolucao': formatar_data_br(e[3]),
            'status': e[4],
            'id_usuario': e[5],
            'id_livro': e[6],
            'nome_usuario': e[7],
            'titulo_livro': e[8],
            'autor_livro': e[9]
        } for e in emprestimos_pagina]

        return jsonify({
            'mensagem': 'Lista de Empréstimos',
            'pagina_atual': pagina,
            'total_paginas': total_paginas,
            'total_emprestimos': total_emprestimos,
            'emprestimos': emprestimos_formatados
        })

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@app.route('/devolvidos', methods=['GET'])
def listar_devolvidos():
    pagina = int(request.args.get('pagina', 1))
    quantidade_por_pagina = 10

    primeiro_item = (pagina * quantidade_por_pagina) - quantidade_por_pagina + 1
    ultimo_item = pagina * quantidade_por_pagina

    cur = con.cursor()
    cur.execute(f'''
        SELECT 
            e.id_emprestimo, 
            e.data_reserva,
            e.data_emprestimo, 
            e.data_devolucao, 
            e.data_devolvida, 
            e.status,
            e.id_usuario, 
            e.id_livro,
            u.nome AS nome_usuario,
            l.titulo AS titulo_livro,
            l.autor AS autor_livro
        FROM emprestimos e
        JOIN usuarios u ON e.id_usuario = u.id_usuario
        JOIN livros l ON e.id_livro = l.id_livro
        WHERE e.status = 3
        ROWS {primeiro_item} TO {ultimo_item}
    ''')
    devolvidos = cur.fetchall()

    # Conta o total de devolvidos com status = 3
    cur.execute('SELECT COUNT(*) FROM emprestimos WHERE status = 3')
    total_devolvidos = cur.fetchone()[0]
    total_paginas = (total_devolvidos + quantidade_por_pagina - 1) // quantidade_por_pagina

    devolvidos_dic = [{
        'id_emprestimo': d[0],
        'data_reserva': d[1].strftime('%d-%m-%Y') if d[1] else None,
        'data_emprestimo': d[2].strftime('%d-%m-%Y') if d[2] else None,
        'data_devolucao': d[3].strftime('%d-%m-%Y') if d[3] else None,
        'data_devolvida': d[4].strftime('%d-%m-%Y') if d[4] else None,
        'status': d[5],
        'id_usuario': d[6],
        'id_livro': d[7],
        'nome_usuario': d[8],
        'titulo_livro': d[9],
        'autor_livro': d[10]
    } for d in devolvidos]

    return jsonify(
        mensagem='Lista de Devolvidos',
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_devolvidos=total_devolvidos,
        devolvidos=devolvidos_dic
    )


@app.route('/reservasusuario/<int:id_usuario>', methods=['GET'])
def reservas_get_usuario(id_usuario):
    # Parâmetros de paginação
    pagina = int(request.args.get('pagina', 1))
    quantidade_por_pagina = 10
    offset = (pagina - 1) * quantidade_por_pagina

    cur = con.cursor()

    # Query principal com paginação (usando OFFSET/FETCH para Firebird 3+ ou LIMIT/OFFSET para outros bancos)
    base_sql = '''
        SELECT 
            e.id_emprestimo, 
            e.data_reserva,
            e.data_emprestimo, 
            e.data_devolucao, 
            e.data_devolvida, 
            e.status,
            e.id_usuario, 
            e.id_livro,
            u.nome AS nome_usuario,
            l.titulo AS titulo_livro,
            l.autor AS autor_livro
        FROM emprestimos e
        JOIN usuarios u ON e.id_usuario = u.id_usuario
        JOIN livros l ON e.id_livro = l.id_livro
        WHERE e.id_usuario = ?
        ORDER BY e.id_emprestimo DESC
        ROWS ? TO ?
    '''

    # Calculando os parâmetros ROWS X TO Y (Firebird)
    primeiro_item = offset + 1
    ultimo_item = offset + quantidade_por_pagina

    cur.execute(base_sql, (id_usuario, primeiro_item, ultimo_item))
    emprestimos = cur.fetchall()

    # Query para contar total de registros desse usuário
    sql_count = "SELECT COUNT(*) FROM emprestimos WHERE id_usuario = ?"
    cur.execute(sql_count, (id_usuario,))
    total_reservas = cur.fetchone()[0]
    total_paginas = (total_reservas + quantidade_por_pagina - 1) // quantidade_por_pagina

    # Formatação dos resultados
    emprestimos_dic = [{
        'id_emprestimo': e[0],
        'data_reserva': e[1].strftime('%d-%m-%Y') if e[1] else None,
        'data_emprestimo': e[2].strftime('%d-%m-%Y') if e[2] else None,
        'data_devolucao': e[3].strftime('%d-%m-%Y') if e[3] else None,
        'data_devolvida': e[4].strftime('%d-%m-%Y') if e[4] else None,
        'status': e[5],
        'id_usuario': e[6],
        'id_livro': e[7],
        'nome_usuario': e[8],
        'titulo_livro': e[9],
        'autor_livro': e[10]
    } for e in emprestimos]

    return jsonify(
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_reservas=total_reservas,
        reservas=emprestimos_dic
    )



@app.route('/devolucao/<int:id_emprestimo>', methods=['PUT'])
def devolucao(id_emprestimo):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        jwt.decode(token, senha_secreta, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Busca informações do empréstimo
    cursor.execute('SELECT data_emprestimo, data_devolucao, id_livro, id_usuario FROM emprestimos WHERE id_emprestimo = ?', (id_emprestimo,))
    emprestimo_data = cursor.fetchone()

    if not emprestimo_data:
        cursor.close()
        return jsonify({'mensagem': 'Empréstimo não encontrado'}), 404

    data_emprestimo, data_devolucao, id_livro, id_usuario = emprestimo_data

    if not data_emprestimo:
        cursor.close()
        return jsonify({'mensagem': 'Empréstimo ainda não foi realizado. Não é possível fazer a devolução.'}), 400

    data_devolvida = datetime.now().date()
    status = 3  # Devolvido

    # Atualiza o empréstimo
    cursor.execute(
        'UPDATE emprestimos SET data_devolvida = ?, status = ? WHERE id_emprestimo = ?',
        (data_devolvida, status, id_emprestimo)
    )

    # Atualiza a quantidade do livro
    cursor.execute("UPDATE livros SET quantidade = quantidade + 1 WHERE id_livro = ?", (id_livro,))

    # Busca título e autor
    cursor.execute("SELECT titulo, autor FROM livros WHERE id_livro = ?", (id_livro,))
    livro_info = cursor.fetchone()
    titulo, autor = livro_info if livro_info else ("Desconhecido", "Desconhecido")

    # Busca nome e e-mail do usuário
    cursor.execute("SELECT nome, email FROM usuarios WHERE id_usuario = ?", (id_usuario,))
    usuario_info = cursor.fetchone()
    nome, email = usuario_info if usuario_info else ("Usuário", "sem-email@dominio.com")

    con.commit()
    cursor.close()

    data_devolvida_str = data_devolvida.strftime('%d/%m/%Y')

    # Converte data_devolucao se necessário
    data_devolucao_date = data_devolucao.date() if isinstance(data_devolucao, datetime) else data_devolucao
    houve_atraso = data_devolvida > data_devolucao_date

    if houve_atraso:
        # Busca valor da multa no banco
        cursor = con.cursor()
        cursor.execute('SELECT valor FROM multas WHERE id_usuario = ?', (id_usuario,))
        multa_data = cursor.fetchone()
        cursor.close()

        if multa_data and multa_data[0] is not None:
            valor_multa = multa_data[0]
        else:
            valor_multa = 0.00  # Caso não encontre a multa, valor 0

        # Gerar QR Code PIX da multa
        cursor = con.cursor()
        cursor.execute("SELECT NOME, CHAVE_PIX, CIDADE FROM PIX")
        resultado = cursor.fetchone()
        cursor.close()

        if resultado:
            nome_pix, chave_pix, cidade = resultado
            nome_pix = nome_pix[:25] if nome_pix else "Recebedor PIX"
            cidade = cidade[:15] if cidade else "Cidade"

            merchant_account_info = (
                format_tlv("00", "br.gov.bcb.pix") +
                format_tlv("01", chave_pix)
            )
            campo_26 = format_tlv("26", merchant_account_info)

            payload_sem_crc = (
                "000201" +
                "010212" +
                campo_26 +
                "52040000" +
                "5303986" +
                format_tlv("54", f"{valor_multa:.2f}") +
                "5802BR" +
                format_tlv("59", nome_pix) +
                format_tlv("60", cidade) +
                format_tlv("62", format_tlv("05", "***")) +
                "6304"
            )

            crc = calcula_crc16(payload_sem_crc)
            payload_completo = payload_sem_crc + crc

            # Gerar o QR Code
            qr_obj = qrcode.QRCode(
                version=None,
                error_correction=ERROR_CORRECT_H,
                box_size=10,
                border=4
            )
            qr_obj.add_data(payload_completo)
            qr_obj.make(fit=True)
            qr = qr_obj.make_image(fill_color="black", back_color="white")

            # Salvar o QR Code
            pasta_qrcodes = os.path.join(os.getcwd(), "static", "upload", "qrcodes")
            os.makedirs(pasta_qrcodes, exist_ok=True)

            nome_arquivo = f"pix_multa_{id_emprestimo}.png"
            caminho_arquivo = os.path.join(pasta_qrcodes, nome_arquivo)
            qr.save(caminho_arquivo)
        else:
            caminho_arquivo = None

        # Enviar e-mail de atraso com QR code
        assunto = "Devolução realizada com atraso"
        texto = f"""
        Olá, {nome}! 👋

        Seu livro foi devolvido, mas identificamos um atraso. 😟

        📝 **Informações da Devolução:**
        • 📖 *Livro:* {titulo}
        • ✍️ *Autor:* {autor}
        • 📆 *Data da devolução:* {data_devolvida_str}
        • 💰 *Multa a ser paga:* R$ {valor_multa:.2f}

        Para regularizar, pague a multa usando o QR Code em anexo ou entre em contato conosco!

        Atenciosamente,  
        Equipe Asa Literária 🏛️
        """

        try:
            print(f"Enviando e-mail de multa para: {email}")
            email_emprestimo(email, texto, assunto, anexo=caminho_arquivo)  # Envia o QR Code em anexo
            print("E-mail de multa enviado com sucesso!")
        except Exception as email_error:
            print(f"Erro ao enviar e-mail de multa: {email_error}")

    else:
        # Enviar e-mail de devolução sem atraso
        assunto = "Devolução realizada com sucesso"
        texto = f"""
        Olá, {nome}! 👋

        Seu livro foi devolvido com sucesso! 📚✨

        📝 **Informações da Devolução:**
        • 📖 *Livro:* {titulo}
        • ✍️ *Autor:* {autor}
        • 📆 *Data da devolução:* {data_devolvida_str}

        Obrigado por utilizar nossa biblioteca! 😊

        Atenciosamente,  
        Equipe Asa Literária 🏛️
        """

        try:
            print(f"Enviando e-mail de devolução normal para: {email}")
            email_emprestimo(email, texto, assunto)
            print("E-mail de devolução enviado com sucesso!")
        except Exception as email_error:
            print(f"Erro ao enviar e-mail: {email_error}")

    return jsonify({
        'mensagem': 'Devolução registrada com sucesso!',
        'devolucao': {
            'id_emprestimo': id_emprestimo,
            'titulo': titulo,
            'autor': autor,
            'data_devolvida': data_devolvida_str,
            'houve_atraso': houve_atraso,
            'dias_atraso': (data_devolvida - data_devolucao_date).days if houve_atraso else 0
        }
    })


#ROTA DE MULTAS
@app.route('/configmulta', methods=['POST'])
def configmulta():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # Recebendo os dados do formulário
    data = request.get_json()
    valorfixo = data.get('valorfixo')
    acrescimo = data.get('acrescimo')
    ano = data.get('ano')

    cursor = con.cursor()

    # Verifica se o ano já tem multa cadastrada
    cursor.execute("SELECT 1 FROM configmulta WHERE ano = ?", (ano,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Esse ano já tem um valor fixo"}), 400

    # Insere a configuração da multa e retorna o ID gerado
    cursor.execute(
        "INSERT INTO configmulta (valorfixo, acrescimo, ano) VALUES (?, ?, ?) RETURNING ID_Config",
        (valorfixo, acrescimo, ano)
    )
    config_id = cursor.fetchone()[0]
    con.commit()

    return jsonify({
        'message': "Configuração de multa cadastrado com sucesso!",
        'configuração': {
            'id': config_id,
            'valorfixo': valorfixo,
            'acrescimo': acrescimo,
            'ano': ano
        }
    }), 201


@app.route('/configmulta/<int:id>', methods=['PUT'])
def configmulta_put(id):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        jwt.decode(token, senha_secreta, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    cursor = con.cursor()

    # Busca a configuração atual e seu ano
    cursor.execute('SELECT ano FROM CONFIGMULTA WHERE ID_Config = ?', (id,))
    config_data = cursor.fetchone()
    if not config_data:
        cursor.close()
        return jsonify({'error': 'Configuração de multa não encontrada'}), 404

    ano_atual = config_data[0]

    data = request.get_json()
    valorfixo = data.get('valorfixo')
    acrescimo = data.get('acrescimo')
    ano_novo = data.get('ano')

    if ano_novo is None:
        cursor.close()
        return jsonify({'error': 'Ano é obrigatório'}), 400

    # Não permite se já existe outra configuração para o novo ano (exceto a atual)
    cursor.execute('SELECT ID_Config FROM CONFIGMULTA WHERE ano = ? AND ID_Config <> ?', (ano_novo, id))
    ano_existente = cursor.fetchone()
    if ano_existente:
        cursor.close()
        return jsonify({'error': f'O ano {ano_novo} já está em uso em outra configuração'}), 400

    # Não permite se já existe multa registrada para o ano atual da configuração
    cursor.execute('SELECT FIRST 1 1 FROM MULTAS WHERE EXTRACT(YEAR FROM DATA_LANCAMENTO) = ?', (int(ano_atual),))
    multa_ano_atual = cursor.fetchone()
    if multa_ano_atual:
        cursor.close()
        return jsonify({'error': f'Não é possível editar. Já existe multa registrada para o ano atual da configuração ({ano_atual}).'}), 400

    # Não permite se já existe multa registrada para o novo ano informado
    cursor.execute('SELECT FIRST 1 1 FROM MULTAS WHERE EXTRACT(YEAR FROM DATA_LANCAMENTO) = ?', (int(ano_novo),))
    multa_ano_novo = cursor.fetchone()
    if multa_ano_novo:
        cursor.close()
        return jsonify({'error': f'Não é possível editar. Já existe multa registrada para o novo ano informado ({ano_novo}).'}), 400

    # Atualiza a configuração
    cursor.execute('UPDATE CONFIGMULTA SET valorfixo = ?, acrescimo = ?, ano = ? WHERE ID_Config = ?',
                   (valorfixo, acrescimo, ano_novo, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Configuração de multa editada com sucesso!',
        'configuracao_multa': {
            'id_config': id,
            'valorfixo': valorfixo,
            'acrescimo': acrescimo,
            'ano': ano_novo
        }
    })


@app.route('/configmulta', methods=['GET'])
def configmulta_get():
    cur = con.cursor()
    cur.execute('SELECT id_config, valorfixo, acrescimo, ano FROM configmulta')
    configmulta = cur.fetchall()
    configmulta_dic = []
    for configmulta in configmulta:
        configmulta_dic.append({
            'id_config': configmulta[0],
            'valorfixo': configmulta[1],
            'acrescimo': configmulta[2],
            'ano': configmulta[3]
        })
    return jsonify(mensagem='Lista de Configurações', configuracoes=configmulta_dic)


@app.route('/multas', methods=['GET'])
def listar_multas():
    cursor = con.cursor()

    query = """
        SELECT 
            m.id_multa,
            m.valor,
            m.data_lancamento,
            u.nome,
            u.email,
            c.valorfixo,
            c.acrescimo,
            c.ano
        FROM multas m
        JOIN usuarios u ON m.id_usuario = u.id_usuario
        JOIN configmulta c ON m.id_config = c.id_config
    """

    cursor.execute(query)
    resultados = cursor.fetchall()
    cursor.close()

    if not resultados:
        return jsonify({'mensagem': 'Nenhuma multa registrada.'}), 404

    multas_formatadas = []
    for row in resultados:
        id_multa, valor, data_lancamento, nome, email, valorfixo, acrescimo, ano = row
        multas_formatadas.append({
            'id_multa': id_multa,
            'valor': float(valor),
            'data_lancamento': data_lancamento.strftime('%d/%m/%Y'),
            'usuario': {
                'nome': nome,
                'email': email
            },
            'configuracao': {
                'valorfixo': float(valorfixo),
                'acrescimo': float(acrescimo),
                'ano': ano
            }
        })

    return jsonify({'multas': multas_formatadas})


@app.route('/multasusuario/<int:id_usuario>', methods=['GET'])
def listar_multas_por_usuario(id_usuario):
    cursor = con.cursor()

    query = """
        SELECT 
            m.id_multa,
            m.valor,
            m.data_lancamento,
            u.nome,
            u.email,
            c.valorfixo,
            c.acrescimo,
            c.ano
        FROM multas m
        JOIN usuarios u ON m.id_usuario = u.id_usuario
        JOIN configmulta c ON m.id_config = c.id_config
        WHERE m.id_usuario = ?
    """

    cursor.execute(query, (id_usuario,))
    resultados = cursor.fetchall()
    cursor.close()

    if not resultados:
        return jsonify({'mensagem': 'Nenhuma multa encontrada para este usuário.'}), 404

    multas_formatadas = []
    for row in resultados:
        id_multa, valor, data_lancamento, nome, email, valorfixo, acrescimo, ano = row
        multas_formatadas.append({
            'id_multa': id_multa,
            'valor': float(valor),
            'data_lancamento': data_lancamento.strftime('%d/%m/%Y'),
            'usuario': {
                'nome': nome,
                'email': email
            },
            'configuracao': {
                'valorfixo': float(valorfixo),
                'acrescimo': float(acrescimo),
                'ano': ano
            }
        })

    return jsonify({'multas': multas_formatadas})


#Barra de pesquisa
@app.route('/pesquisar_livro', methods=['GET'])
def pesquisar_livros():
    try:
        termo = request.args.get('q', '').strip()
        pagina = int(request.args.get('pagina', 1))
        quantidade_por_pagina = 10

        primeiro_livro = (pagina - 1) * quantidade_por_pagina + 1
        ultimo_livro = pagina * quantidade_por_pagina

        cursor = con.cursor()

        # Monta a query base
        base_query = '''
            SELECT id_livro, titulo, autor, data_publicacao, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA, NOTA, PAGINAS, IDIOMA, STATUS
            FROM livros
            WHERE status = 1
        '''
        count_query = 'SELECT COUNT(*) FROM livros WHERE status = 1'
        parametros = []

        # Adiciona filtro de busca se houver termo
        if termo:
            base_query += " AND (LOWER(titulo) LIKE ? OR LOWER(autor) LIKE ?)"
            count_query += " AND (LOWER(titulo) LIKE ? OR LOWER(autor) LIKE ?)"
            termo_lower = f"%{termo.lower()}%"
            parametros.extend([termo_lower, termo_lower])

        # Adiciona paginação
        base_query += f" ROWS {primeiro_livro} TO {ultimo_livro}"

        # Busca os livros paginados
        cursor.execute(base_query, parametros)
        livros = cursor.fetchall()

        # Conta o total de livros (com ou sem filtro)
        cursor.execute(count_query, parametros)
        total_livros = cursor.fetchone()[0]
        total_paginas = (total_livros + quantidade_por_pagina - 1) // quantidade_por_pagina

        cursor.close()

        if not livros:
            return jsonify({'mensagem': 'Nenhum livro encontrado com os filtros fornecidos.'}), 404

        # Monta o dicionário dos livros
        livros_dic = []
        for l in livros:
            livros_dic.append({
                'id_livro': l[0],
                'titulo': l[1],
                'autor': l[2],
                'data_publicacao': l[3],
                'ISBN': l[4],
                'descricao': l[5],
                'quantidade': l[6],
                'categoria': l[7],
                'nota': l[8],
                'paginas': l[9],
                'idioma': l[10],
                'status': l[11]
            })

        return jsonify(
            mensagem='Resultado da pesquisa',
            pagina_atual=pagina,
            total_paginas=total_paginas,
            total_livros=total_livros,
            livros=livros_dic
        )

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


#AVALIAÇÃO DE LIVROS
from flask import request, jsonify
from datetime import datetime
import jwt

@app.route('/avaliacao', methods=['POST'])
def adicionar_avaliacao():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload.get('id_usuario')
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    dados = request.get_json()
    id_livro = dados.get('id_livro')
    nota = dados.get('nota')
    comentario = dados.get('comentario', '')

    if not id_livro or nota is None:
        return jsonify({'mensagem': 'Campos id_livro e nota são obrigatórios'}), 400
    if not (0 <= nota <= 5):
        return jsonify({'mensagem': 'A nota deve estar entre 0 e 5'}), 400

    cursor = con.cursor()

    # Verifica se o livro existe
    cursor.execute("SELECT 1 FROM livros WHERE id_livro = ?", (id_livro,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({'mensagem': 'Livro não encontrado'}), 404

    # Verifica se o usuário já pegou esse livro emprestado (status 2 ou 3)
    cursor.execute("""
        SELECT 1 FROM emprestimos
        WHERE id_usuario = ? AND id_livro = ? AND status IN (2, 3)
    """, (id_usuario, id_livro))
    emprestimo_valido = cursor.fetchone()

    if not emprestimo_valido:
        cursor.close()
        return jsonify({'mensagem': 'Você só pode avaliar livros que já foram emprestados por você.'}), 403

    # Verifica se o usuário já avaliou esse livro
    cursor.execute("""
        SELECT id_avaliacao FROM avaliacao WHERE id_usuario = ? AND id_livro = ?
    """, (id_usuario, id_livro))
    avaliacao_existente = cursor.fetchone()

    data_avaliacao = datetime.now().date()

    if avaliacao_existente:
        # Atualiza a avaliação existente
        cursor.execute("""
            UPDATE avaliacao
            SET nota = ?, comentario = ?, data_avaliacao = ?
            WHERE id_usuario = ? AND id_livro = ?
        """, (nota, comentario, data_avaliacao, id_usuario, id_livro))
    else:
        # Insere nova avaliação
        cursor.execute("""
            INSERT INTO avaliacao (nota, data_avaliacao, comentario, id_usuario, id_livro)
            VALUES (?, ?, ?, ?, ?)
        """, (nota, data_avaliacao, comentario, id_usuario, id_livro))

    con.commit()
    cursor.close()

    return jsonify({
        'mensagem': 'Avaliação registrada com sucesso!',
        'avaliacao': {
            'id_usuario': id_usuario,
            'id_livro': id_livro,
            'nota': nota,
            'comentario': comentario,
            'data_avaliacao': data_avaliacao.strftime('%d/%m/%Y')
        }
    }), 201


@app.route('/avaliacoes', methods=['GET'])
def lista_avaliacoes():
    id_livro = request.args.get('id_livro')

    cur = con.cursor()
    if id_livro:
        cur.execute('''
            SELECT a.id_avaliacao, a.nota, a.data_avaliacao, a.comentario,
                   a.id_usuario, a.id_livro, u.nome
            FROM avaliacao a
            JOIN usuarios u ON a.id_usuario = u.id_usuario
            WHERE a.id_livro = ?
        ''', (id_livro,))
    else:
        cur.execute('''
            SELECT a.id_avaliacao, a.nota, a.data_avaliacao, a.comentario,
                   a.id_usuario, a.id_livro, u.nome
            FROM avaliacao a
            JOIN usuarios u ON a.id_usuario = u.id_usuario
        ''')

    resultados = cur.fetchall()
    avaliacao_dic = []
    for a in resultados:
        avaliacao_dic.append({
            'id_avaliacao': a[0],
            'nota': a[1],
            'data_avaliacao': a[2],
            'comentario': a[3],
            'id_usuario': a[4],
            'id_livro': a[5],
            'nome_usuario': a[6]
        })

    return jsonify(mensagem='Lista de Avaliações', configuracoes=avaliacao_dic)

@app.route('/avaliacao/<int:id_avaliacao>', methods=['DELETE'])
def deletar_avaliacao(id_avaliacao):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        print(">> PAYLOAD RECEBIDO:", payload)  # <<< Adicione este print
        cargo = payload.get('cargo')
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # ... resto do código ai vc completa ai ...
    cursor = con.cursor()

    # Verifica se a avaliação existe
    cursor.execute("SELECT 1 FROM avaliacao WHERE id_avaliacao = ?", (id_avaliacao,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({'mensagem': 'Avaliação não encontrada'}), 404

    # Deleta a avaliação
    cursor.execute("DELETE FROM avaliacao WHERE id_avaliacao = ?", (id_avaliacao,))
    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Avaliação deletada com sucesso!'}), 200


#ESQUECI MINHA SENHA
import random

# Modificação da rota /validar_email para usar a nova função
@app.route('/validar_email', methods=['POST'])
def validar_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'O campo de e-mail é obrigatório.'}), 400

    cursor = con.cursor()
    cursor.execute('SELECT ID_USUARIO FROM USUARIOS WHERE EMAIL = ?', (email,))
    usuario = cursor.fetchone()
    cursor.close()

    if not usuario:
        return jsonify({'error': 'E-mail não encontrado.'}), 404

    codigo_verificacao = str(random.randint(100000, 999999))

    try:
        # Usa a função auxiliar para atualização e envio
        atualizar_codigo_envio_email(email, codigo_verificacao, con)
        return jsonify({'message': 'Código atualizado e e-mail enviado com sucesso!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/verificar_codigo', methods=['POST'])
def verificar_codigo():
    data = request.get_json()
    codigo_digitado = data.get('codigo')

    if not codigo_digitado:
        return jsonify({'error': 'O código é obrigatório.'}), 400

    cursor = con.cursor()
    cursor.execute('SELECT ID_USUARIO FROM USUARIOS WHERE CODIGO = ?', (codigo_digitado,))
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        return jsonify({'error': 'Código incorreto.'}), 401

    id_usuario = usuario[0]

    # Corrigido: 'CERTO' entre aspas simples
    cursor.execute('UPDATE USUARIOS SET CODIGO = ? WHERE ID_USUARIO = ?', ('CERTO', id_usuario))
    con.commit()
    cursor.close()

    return jsonify({'message': 'Código verificado com sucesso!'}), 200


@app.route('/redefinir_senha/<int:id_usuario>', methods=['PUT'])
def redefinir_senha(id_usuario):
    data = request.get_json()
    nova_senha = data.get('nova_senha')
    confirmar_senha = data.get('confirmar_senha')

    if not nova_senha or not confirmar_senha:
        return jsonify({"error": "Preencha todos os campos."}), 400

    if nova_senha != confirmar_senha:
        return jsonify({"error": "A nova senha e a confirmação não coincidem."}), 400

    if not validar_senha(nova_senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 400

    cursor = con.cursor()
    cursor.execute("SELECT SENHA, CODIGO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
    usuario = cursor.fetchone()

    if not usuario:
        cursor.close()
        return jsonify({"error": "Usuário não encontrado."}), 404

    senha_atual_hash, codigo = usuario

    if codigo != "CERTO":
        cursor.close()
        return jsonify({"error": "Código de verificação inválido ou expirado."}), 403

    if bcrypt.check_password_hash(senha_atual_hash, nova_senha):
        cursor.close()
        return jsonify({"error": "A nova senha não pode ser igual à senha atual."}), 400

    nova_senha_hash = bcrypt.generate_password_hash(nova_senha).decode('utf-8')

    cursor.execute("UPDATE USUARIOS SET SENHA = ?, CODIGO = NULL WHERE ID_USUARIO = ?", (nova_senha_hash, id_usuario))
    con.commit()
    cursor.close()

    return jsonify({"message": "Senha redefinida com sucesso."}), 200

@app.route('/buscar_id_por_email')
def buscar_id_por_email():
    email = request.args.get('email')
    cursor = con.cursor()
    cursor.execute("SELECT ID_USUARIO FROM USUARIOS WHERE EMAIL = ?", (email,))
    usuario = cursor.fetchone()
    cursor.close()
    if not usuario:
        return jsonify({'error': 'Usuário não encontrado.'}), 404
    return jsonify({'id_usuario': usuario[0]})

@app.route('/avaliacao/<int:id_avaliacao>', methods=['DELETE'])
def excluir_avaliacao(id_avaliacao):
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensagem': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        cargo_usuario = payload.get('cargo')  # Supondo que o cargo do usuário esteja no payload
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # Verifica se o usuário é um administrador
    if cargo_usuario != 'ADM':
        return jsonify({'mensagem': 'Você não tem permissão para excluir avaliações.'}), 403

    cursor = con.cursor()

    # Verifica se a avaliação existe
    cursor.execute("SELECT id_avaliacao FROM avaliacao WHERE id_avaliacao = ?", (id_avaliacao,))
    avaliacao = cursor.fetchone()

    if not avaliacao:
        return jsonify({'mensagem': 'Avaliação não encontrada'}), 404

    cursor.execute("DELETE FROM avaliacao WHERE id_avaliacao = ?", (id_avaliacao,))
    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Avaliação excluída com sucesso!'}), 200


from datetime import datetime, date

def format_date(date_value):
    if not date_value:
        return None
    if isinstance(date_value, (datetime, date)):
        return date_value.strftime('%d/%m/%Y')
    # Tenta formatos comuns de string
    for fmt in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%d/%m/%Y', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(date_value, fmt).strftime('%d/%m/%Y')
        except Exception:
            continue
    # Se não conseguir converter, retorna como está
    return str(date_value)



@app.route('/livro_detalhes/<int:id>', methods=['GET'])
def livro_buscar_detalhes(id):
    pagina = int(request.args.get('pagina', 1))
    quantidade_por_pagina = 10

    primeiro_registro = (pagina * quantidade_por_pagina) - quantidade_por_pagina + 1
    ultimo_registro = pagina * quantidade_por_pagina

    cur = con.cursor()
    # Busca o livro
    cur.execute('''
        SELECT id_livro, titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria, nota, paginas, idioma, status
        FROM livros
        WHERE id_livro = ?
    ''', (id,))
    livro = cur.fetchone()

    if not livro:
        return jsonify({"error": "Nenhum livro encontrado."}), 404

    livro_dic = {
        'id_livro': livro[0],
        'titulo': livro[1],
        'autor': livro[2],
        'data_publicacao': format_date(livro[3]),
        'ISBN': livro[4],
        'descricao': livro[5],
        'quantidade': livro[6],
        'categoria': livro[7],
        'nota': livro[8],
        'paginas': livro[9],
        'idioma': livro[10],
        'status': livro[11]
    }

    # Conta total de empréstimos desse livro
    cur.execute('SELECT COUNT(*) FROM emprestimos WHERE id_livro = ?', (id,))
    total_emprestimos = cur.fetchone()[0]
    total_paginas = (total_emprestimos + quantidade_por_pagina - 1) // quantidade_por_pagina

    # Busca os empréstimos paginados
    cur.execute(f'''
        SELECT e.id_emprestimo, e.data_emprestimo, e.data_devolucao, u.id_usuario, u.nome, u.email
        FROM emprestimos e
        JOIN usuarios u ON e.id_usuario = u.id_usuario
        WHERE e.id_livro = ?
        ORDER BY e.data_emprestimo DESC
        ROWS {primeiro_registro} TO {ultimo_registro}
    ''', (id,))
    emprestimos = cur.fetchall()

    historico = []
    for emp in emprestimos:
        historico.append({
            'id_emprestimo': emp[0],
            'data_emprestimo': format_date(emp[1]),
            'data_devolucao': format_date(emp[2]),
            'id_usuario': emp[3],
            'nome_usuario': emp[4],
            'email_usuario': emp[5]
        })

    return jsonify(
        livro=livro_dic,
        pagina_atual=pagina,
        total_paginas=total_paginas,
        total_emprestimos=total_emprestimos,
        historico=historico
    ), 200


@app.route('/historico_emprestimos/<int:id_usuario>', methods=['GET'])
def historico_emprestimos(id_usuario):
    """
    Retorna todos os livros já emprestados por um usuário, com status textual e título do livro.
    """
    # Dicionário para mapear status numérico para texto
    status_map = {
        1: "Reservado",
        2: "Emprestado",
        3: "Devolvido",
        4: "Cancelado"
    }

    cursor = con.cursor()
    # Busca todos os empréstimos do usuário, juntando com o título do livro
    cursor.execute("""
        SELECT 
            e.id_emprestimo,
            e.id_livro,
            l.titulo,
            e.status,
            e.data_reserva,
            e.data_emprestimo,
            e.data_devolucao,
            e.data_devolvida
        FROM emprestimos e
        JOIN livros l ON e.id_livro = l.id_livro
        WHERE e.id_usuario = ?
        ORDER BY e.data_reserva DESC
    """, (id_usuario,))
    emprestimos = cursor.fetchall()
    cursor.close()

    if not emprestimos:
        return jsonify({'mensagem': 'Nenhum empréstimo encontrado para este usuário.'}), 404

    resultado = []
    for e in emprestimos:
        resultado.append({
            'id_emprestimo': e[0],
            'id_livro': e[1],
            'titulo_livro': e[2],
            'status': status_map.get(e[3], 'Desconhecido'),
            'data_reserva': e[4].strftime('%d-%m-%Y') if e[4] else None,
            'data_emprestimo': e[5].strftime('%d-%m-%Y') if e[5] else None,
            'data_devolucao': e[6].strftime('%d-%m-%Y') if e[6] else None,
            'data_devolvida': e[7].strftime('%d-%m-%Y') if e[7] else None
        })

    return jsonify({
        'usuario': id_usuario,
        'historico': resultado
    })


@app.route('/cancelar_reserva/<int:id_emprestimo>', methods=['PUT'])
def cancelar_reserva(id_emprestimo):
    """
    Cancela uma reserva (altera status para 4) apenas se ela estiver com status = 1 (Reservado).
    """
    cursor = con.cursor()
    # Verifica se a reserva existe e está com status = 1 (Reservado)
    cursor.execute("SELECT status FROM emprestimos WHERE id_emprestimo = ?", (id_emprestimo,))
    resultado = cursor.fetchone()

    if not resultado:
        cursor.close()
        return jsonify({'erro': 'Reserva não encontrada.'}), 404

    status = resultado[0]
    if status != 1:
        cursor.close()
        return jsonify({'erro': 'Só é possível cancelar reservas com status \"Reservado\".'}), 400

    # Atualiza o status para 4 (Cancelado)
    cursor.execute("UPDATE emprestimos SET status = 4 WHERE id_emprestimo = ?", (id_emprestimo,))
    con.commit()
    cursor.close()

    return jsonify({'mensagem': 'Reserva cancelada com sucesso!'}), 200


@app.route('/pesquisar_livro_avancado', methods=['GET'])
def pesquisar_livro_avancado():
    try:
        # Parâmetros opcionais de filtro
        nota_min = request.args.get('nota_min')
        nota_max = request.args.get('nota_max')
        paginas_min = request.args.get('paginas_min')
        paginas_max = request.args.get('paginas_max')
        idioma = request.args.get('idioma')
        categoria = request.args.get('categoria')
        disponibilidade = request.args.get('disponibilidade')
        termo = request.args.get('q', '').strip()
        pagina = int(request.args.get('pagina', 1))
        quantidade_por_pagina = 10

        cursor = con.cursor()

        # Query base
        query = """
            SELECT id_livro, titulo, autor, data_publicacao, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA, NOTA, PAGINAS, IDIOMA, STATUS
            FROM livros
            WHERE status = 1
        """
        parametros = []

        # Filtros dinâmicos
        if nota_min:
            query += " AND nota >= ?"
            parametros.append(nota_min)
        if nota_max:
            query += " AND nota <= ?"
            parametros.append(nota_max)
        if paginas_min:
            query += " AND paginas >= ?"
            parametros.append(paginas_min)
        if paginas_max:
            query += " AND paginas <= ?"
            parametros.append(paginas_max)
        if idioma:
            query += " AND LOWER(idioma) = ?"
            parametros.append(idioma.lower())
        if categoria:
            query += " AND categoria = ?"
            parametros.append(categoria)
        if disponibilidade == 'disponivel':
            query += " AND quantidade > 0"
        elif disponibilidade == 'indisponivel':
            query += " AND quantidade <= 0"
        # Busca por título ou autor (parcial, case-insensitive)
        if termo:
            query += " AND (LOWER(titulo) LIKE ? OR LOWER(autor) LIKE ?)"
            termo_lower = f"%{termo.lower()}%"
            parametros.extend([termo_lower, termo_lower])

        # Ordenação
        query += " ORDER BY id_livro"

        # Paginação SQL (ajuste conforme seu banco: exemplo para Firebird/Interbase)
        primeiro_livro = (pagina - 1) * quantidade_por_pagina + 1
        ultimo_livro = pagina * quantidade_por_pagina
        query += f" ROWS {primeiro_livro} TO {ultimo_livro}"

        # Executa busca paginada
        cursor.execute(query, parametros)
        livros = cursor.fetchall()

        # Query para contar total de livros com os mesmos filtros
        count_query = "SELECT COUNT(*) FROM livros WHERE status = 1"
        count_parametros = []
        # Repete os mesmos filtros para a contagem
        if nota_min:
            count_query += " AND nota >= ?"
            count_parametros.append(nota_min)
        if nota_max:
            count_query += " AND nota <= ?"
            count_parametros.append(nota_max)
        if paginas_min:
            count_query += " AND paginas >= ?"
            count_parametros.append(paginas_min)
        if paginas_max:
            count_query += " AND paginas <= ?"
            count_parametros.append(paginas_max)
        if idioma:
            count_query += " AND LOWER(idioma) = ?"
            count_parametros.append(idioma.lower())
        if categoria:
            count_query += " AND categoria = ?"
            count_parametros.append(categoria)
        if disponibilidade == 'disponivel':
            count_query += " AND quantidade > 0"
        elif disponibilidade == 'indisponivel':
            count_query += " AND quantidade <= 0"
        if termo:
            count_query += " AND (LOWER(titulo) LIKE ? OR LOWER(autor) LIKE ?)"
            count_parametros.extend([termo_lower, termo_lower])

        cursor.execute(count_query, count_parametros)
        total_livros = cursor.fetchone()[0]
        total_paginas = (total_livros + quantidade_por_pagina - 1) // quantidade_por_pagina

        cursor.close()

        if not livros:
            return jsonify({'mensagem': 'Nenhum livro encontrado com os filtros fornecidos.'}), 404

        # Formata os resultados
        livros_formatados = []
        for l in livros:
            livros_formatados.append({
                'id_livro': l[0],
                'titulo': l[1],
                'autor': l[2],
                'data_publicacao': l[3],
                'ISBN': l[4],
                'descricao': l[5],
                'quantidade': l[6],
                'categoria': l[7],
                'nota': l[8],
                'paginas': l[9],
                'idioma': l[10],
                'status': l[11]
            })

        return jsonify({
            'mensagem': 'Resultado da pesquisa',
            'pagina_atual': pagina,
            'total_paginas': total_paginas,
            'total_livros': total_livros,
            'livros': livros_formatados
        })

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@app.route('/livros_todos', methods=['GET'])
def livros_todos():
    try:
        cursor = con.cursor()
        cursor.execute("""
            SELECT 
                id_livro, 
                titulo, 
                autor, 
                categoria, 
                nota, 
                paginas, 
                quantidade, 
                idioma
            FROM livros
        """)
        colunas = [desc[0] for desc in cursor.description]
        livros = [dict(zip(colunas, row)) for row in cursor.fetchall()]
        cursor.close()
        return jsonify({"livros": livros})
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@app.route('/todas_categorias', methods=['GET'])
def todas_categorias():
    try:
        cursor = con.cursor()
        cursor.execute("SELECT DISTINCT categoria FROM livros WHERE categoria IS NOT NULL AND categoria != ''")
        categorias = [row[0] for row in cursor.fetchall()]
        cursor.close()
        return jsonify({"categorias": categorias})
    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@app.route('/todos_idiomas', methods=['GET'])
def todos_idiomas():
    try:
        cursor = con.cursor()
        cursor.execute("SELECT DISTINCT idioma FROM livros WHERE idioma IS NOT NULL AND idioma != ''")
        idiomas = [row[0] for row in cursor.fetchall()]
        cursor.close()
        return jsonify({"idiomas": idiomas})
    except Exception as e:
        return jsonify({'erro': str(e)}), 500



@app.route('/pesquisar_usuario', methods=['GET'])
def pesquisar_usuarios():
    try:
        termo = request.args.get('q')
        pagina = int(request.args.get('pagina', 1))
        quantidade_por_pagina = 10

        cursor = con.cursor()

        query = """
            SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, status
            FROM usuarios 
            WHERE 1=1
        """
        parametros = []

        if termo:
            query += " AND (LOWER(nome) LIKE ? OR LOWER(email) LIKE ? OR telefone LIKE ?)"
            termo_lower = f"%{termo.lower()}%"
            parametros.extend((termo_lower, termo_lower, f"%{termo}%"))

        query += " ORDER BY id_usuario"

        cursor.execute(query, parametros)
        usuarios = cursor.fetchall()
        cursor.close()

        total_usuarios = len(usuarios)
        total_paginas = (total_usuarios + quantidade_por_pagina - 1) // quantidade_por_pagina

        inicio = (pagina - 1) * quantidade_por_pagina
        fim = inicio + quantidade_por_pagina
        usuarios_pagina = usuarios[inicio:fim]

        if not usuarios_pagina:
            return jsonify({'mensagem': 'Nenhum usuario encontrado com os filtros fornecidos.'}), 404

        def formatar_data_br(data):
            if not data:
                return ""
            if isinstance(data, str):
                try:
                    data = datetime.strptime(data, "%Y-%m-%d")
                except Exception:
                    try:
                        data = datetime.strptime(data, "%Y-%m-%d %H:%M:%S")
                    except Exception:
                        return data
            return data.strftime("%d/%m/%Y")

        usuarios_formatados = [{
            'id_usuario': u[0],
            'nome': u[1],
            'email': u[2],
            'telefone': u[3],
            'data_nascimento': formatar_data_br(u[4]),
            'cargo': u[5],
            'status': u[6]
        } for u in usuarios_pagina]

        return jsonify({
            'mensagem': 'Resultado da pesquisa',
            'pagina_atual': pagina,
            'total_paginas': total_paginas,
            'total_usuarios': total_usuarios,
            'usuarios': usuarios_formatados
        })

    except Exception as e:
        return jsonify({'erro': str(e)}), 500


@app.route('/usuarioo/<int:id>', methods=['GET'])
def get_usuario(id):
    cur = con.cursor()
    cur.execute('''
        SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, status
        FROM usuarios
        WHERE id_usuario = ?
    ''', (id,))
    u = cur.fetchone()
    if u is None:
        return jsonify({'erro': 'Usuário não encontrado'}), 404

    usuario = {
        'id_usuario': u[0],
        'nome': u[1],
        'email': u[2],
        'telefone': u[3],
        'data_nascimento': u[4],
        'cargo': u[5],
        'status': u[6]
    }
    return jsonify(usuario)