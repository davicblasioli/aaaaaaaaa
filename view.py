from flask import Flask, jsonify, request, send_file, flash
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


class PDFRelatorio(FPDF):
    def header(self):
        self.set_font("Arial", 'B', 16)
        self.cell(200, 10, "Relatório de Empréstimos", ln=True, align='C')
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Gerado em {datetime.now().strftime("%d/%m/%Y %H:%M:%S")}', 0, 0, 'C')


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

def email_emprestimo(email, texto, subject, anexo=None):
    if not email:
        raise ValueError("Informações de sessão inválidas. Certifique-se de que 'email' está definido.")

    sender = "equipe.asa.literaria@gmail.com"
    recipients = [email]
    password = "yjfy kwcr nazh sirp"  # Substitua pela sua senha de aplicativo

    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = ', '.join(recipients)

    msg.attach(MIMEText(texto, 'plain'))

    # Se houver anexo, anexa a imagem do QR Code
    if anexo:
        try:
            with open(anexo, 'rb') as attachment:
                img = MIMEImage(attachment.read())
                img.add_header('Content-Disposition', 'attachment', filename=os.path.basename(anexo))
                msg.attach(img)
        except Exception as e:
            raise RuntimeError(f"Erro ao anexar o arquivo: {e}")

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipients, msg.as_string())
            print("Mensagem enviada com sucesso!")
    except Exception as e:
        raise RuntimeError(f"Erro ao enviar o e-mail: {e}")


@app.route('/usuario', methods=['GET'])
def usuario():
    cur = con.cursor()
    cur.execute('SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, status FROM usuarios')
    usuarios = cur.fetchall()
    usuarios_dic = [{
        'id_usuario': usuario[0],
        'nome': usuario[1],
        'email': usuario[2],
        'telefone': usuario[3],
        'data_nascimento': usuario[4],
        'cargo': usuario[5],
        'status': usuario[6],
    } for usuario in usuarios]

    return jsonify(usuarios_cadastrados=usuarios_dic)


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


@app.route('/login', methods=['POST'])
def login():
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

    # Verifica se o usuário está inativo
    if status == 'Inativo':
        return jsonify({"error": "Você errou seu email ou sua senha 3 vezes, o usuário foi inativado."}), 403

    # Verifica a senha usando o bcrypt
    if bcrypt.check_password_hash(senha_hash, senha):
        # Resetar tentativas de erro no login bem-sucedido
        cursor.execute("UPDATE USUARIOS SET TENTATIVAS_ERRO = 0 WHERE ID_USUARIO = ?", (id_usuario,))
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

    # Se a senha estiver incorreta
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
    cur.execute('SELECT id_livro, titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria FROM livros WHERE id_livro = ?', (id,))
    livro = cur.fetchone()

    if not livro:
        return jsonify({"error": "Nenhum livro encontrado."}), 404

    livro_dic = {
        'id_livro': livro[0],
        'titulo': livro[1],
        'autor': livro[2],
        'data_publicacao': livro[3],
        'ISBN': livro[4],
        'descricao': livro[5],
        'quantidade': livro[6],
        'categoria': livro[7]
    }

    return jsonify(livro=livro_dic), 200


@app.route('/livro', methods=['GET'])
def livro():
    cur = con.cursor()
    cur.execute('SELECT id_livro, titulo, autor, data_publicacao, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA FROM livros')
    livros = cur.fetchall()
    livros_dic = []
    for livros in livros:
        livros_dic.append({
            'id_livro': livros[0],
            'titulo': livros[1],
            'autor': livros[2],
            'data_publicacao': livros[3],
            'ISBN': livros[4],
            'descricao': livros[5],
            'quantidade': livros[6],
            'categoria': livros[7]
        })
    return jsonify(mensagem='Lista de Livros', livros=livros_dic)

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
    imagem = request.files.get('imagem')  # Arquivo enviado

    cursor = con.cursor()

    # Verifica se o livro já existe
    cursor.execute("SELECT 1 FROM livros WHERE TITULO = ?", (titulo,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro já cadastrado"}), 400

    # Insere o novo livro e retorna o ID gerado
    cursor.execute(
        "INSERT INTO livros (TITULO, AUTOR, DATA_PUBLICACAO, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ID_livro",
        (titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria)
    )
    livro_id = cursor.fetchone()[0]
    con.commit()

    # Salvar a imagem se for enviada
    imagem_path = None
    if imagem:
        nome_imagem = f"{livro_id}.jpeg"  # Define o nome fixo com .jpeg
        pasta_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Livros")  # Atualizado para refletir a nova estrutura
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
    cursor.execute('SELECT ID_LIVRO, TITULO, AUTOR, DATA_PUBLICACAO, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA FROM LIVROS WHERE ID_LIVRO = ?', (id,))
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
    imagem = request.files.get('imagem')

    cursor.execute('UPDATE LIVROS SET TITULO = ?, AUTOR = ?, DATA_PUBLICACAO = ?, ISBN = ?, DESCRICAO = ?, QUANTIDADE = ?, CATEGORIA = ? WHERE ID_LIVRO = ?',
                   (titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria, id))

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
            'categoria': categoria
        }
    })


@app.route('/livros/<int:id>', methods=['DELETE'])
def deletar_livro(id):
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
        return jsonify({'error': 'Não é possível excluir o livro com empréstimos em andamento'}), 400

    # Verificar se há reservas ativas (por exemplo, status = 1) com esse livro
    cursor.execute("SELECT 1 FROM emprestimos WHERE id_livro = ? AND status = 1", (id,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({'error': 'Não é possível excluir o livro com reservas ativas'}), 400

    # Se passou pelas verificações, pode excluir o livro
    cursor.execute("DELETE FROM livros WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro excluído com sucesso!",
        'id_livro': id
    })


# ROTAS DE ADM
@app.route('/livros_relatorio', methods=['GET'])
def relatorio():
    cursor = con.cursor()
    cursor.execute("SELECT * FROM livros")
    livros = cursor.fetchall()
    cursor.close()

    def safe_str(texto):
        return str(texto).encode('latin-1', 'replace').decode('latin-1')

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Título do relatório
    pdf.set_font("Arial", style='B', size=16)
    pdf.cell(200, 10, safe_str("Relatório de Livros"), ln=True, align='C')
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())  # Linha abaixo do título
    pdf.ln(5)

    # Define a fonte para o conteúdo
    pdf.set_font("Arial", size=12)

    # Loop para adicionar cada livro em formato de lista
    for livro in livros:
        # ID do livro
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, safe_str(f"Livro ID: {livro[0]}"), ln=True)

        # Informações do livro
        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 7, safe_str(f"Título: {livro[1]}"))
        pdf.multi_cell(0, 7, safe_str(f"Autor: {livro[2]}"))
        pdf.multi_cell(0, 7, safe_str(f"Publicação: {livro[3]}"))
        pdf.multi_cell(0, 7, safe_str(f"ISBN: {livro[4]}"))
        pdf.multi_cell(0, 7, safe_str(f"Descrição: {livro[5]}"))
        pdf.multi_cell(0, 7, safe_str(f"Quantidade: {livro[6]}"))
        pdf.multi_cell(0, 7, safe_str(f"Categoria: {livro[7]}"))

        pdf.ln(5)  # Espaço entre os livros

    # Contador de livros
    pdf.ln(10)
    pdf.set_font("Arial", style='B', size=12)
    pdf.cell(200, 10, safe_str(f"Total de livros cadastrados: {len(livros)}"), ln=True, align='C')

    # Salva o arquivo PDF
    pdf_path = "relatorio_livros.pdf"
    pdf.output(pdf_path)

    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


@app.route('/usuarios_relatorio', methods=['GET'])
def relatorio_usuarios():
    cursor = con.cursor()
    cursor.execute("SELECT id_usuario, nome, email, telefone, data_nascimento, cargo, status FROM usuarios")
    usuairios = cursor.fetchall()
    cursor.close()

    def safe_str(texto):
        return str(texto).encode('latin-1', 'replace').decode('latin-1')

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Título do relatório
    pdf.set_font("Arial", style='B', size=16)
    pdf.cell(200, 10, safe_str("Relatório de Usuarios"), ln=True, align='C')
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())  # Linha abaixo do título
    pdf.ln(5)

    # Define a fonte para o conteúdo
    pdf.set_font("Arial", size=12)

    # Loop para adicionar cada livro em formato de lista
    for usuairio in usuairios:
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, safe_str(f"Usuario ID: {usuairio[0]}"), ln=True)

        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 7, safe_str(f"Nome: {usuairio[1]}"))
        pdf.multi_cell(0, 7, safe_str(f"Email: {usuairio[2]}"))
        pdf.multi_cell(0, 7, safe_str(f"Telefone: {usuairio[3]}"))
        pdf.multi_cell(0, 7, safe_str(f"Data_nascimento: {usuairio[4]}"))
        pdf.multi_cell(0, 7, safe_str(f"Cargo: {usuairio[5]}"))
        pdf.multi_cell(0, 7, safe_str(f"Status: {usuairio[6]}"))

        pdf.ln(5)  # Espaço entre os usuairios

    # Contador de usuairios
    pdf.ln(10)
    pdf.set_font("Arial", style='B', size=12)
    pdf.cell(200, 10, safe_str(f"Total de usuairios cadastrados: {len(usuairios)}"), ln=True, align='C')

    # Salva o arquivo PDF
    pdf_path = "relatorio_usuairios.pdf"
    pdf.output(pdf_path)

    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


@app.route('/multas_relatorio', methods=['GET'])
def relatorio_multas():
    cursor = con.cursor()

    # Consulta para obter as multas com o nome do usuário
    cursor.execute("""
        SELECT m.valor, u.nome, m.data_lancamento 
        FROM multas m
        JOIN usuarios u ON m.id_usuario = u.id_usuario
    """)
    multas = cursor.fetchall()
    cursor.close()

    def safe_str(texto):
        return str(texto).encode('latin-1', 'replace').decode('latin-1')

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Título do relatório
    pdf.set_font("Arial", style='B', size=16)
    pdf.cell(200, 10, safe_str("Relatório de Multas"), ln=True, align='C')
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())  # Linha abaixo do título
    pdf.ln(5)

    # Define a fonte para o conteúdo
    pdf.set_font("Arial", size=12)

    # Loop para adicionar cada multa em formato de lista
    for multa in multas:
        valor, nome_usuario, data_lancamento = multa

        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, safe_str(f"Nome do Usuário: {nome_usuario}"), ln=True)

        pdf.set_font("Arial", size=10)
        pdf.multi_cell(0, 7, safe_str(f"Valor: R$ {valor:.2f}"))
        pdf.multi_cell(0, 7, safe_str(f"Data de lançamento da multa: {data_lancamento}"))

        pdf.ln(5)  # Espaço entre as multas

    # Contador de multas
    pdf.ln(10)
    pdf.set_font("Arial", style='B', size=12)
    pdf.cell(200, 10, safe_str(f"Total de multas cadastradas: {len(multas)}"), ln=True, align='C')

    # Salva o arquivo PDF
    pdf_path = "relatorio_multas.pdf"
    pdf.output(pdf_path)

    return send_file(pdf_path, as_attachment=True, mimetype='application/pdf')


@app.route('/emprestimos_relatorio', methods=['GET'])
def relatorio_emprestimos():
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
                e.data_devolvida
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

    def safe_str(texto):
        return str(texto).encode('latin-1', 'replace').decode('latin-1')

    def formatar_data(data):
        if isinstance(data, datetime):
            return data.strftime('%d/%m/%Y')
        try:
            return datetime.strptime(str(data), '%Y-%m-%d').strftime('%d/%m/%Y')
        except:
            return str(data)

    def traduzir_status(status):
        return {
            1: "Reservado",
            2: "Emprestado",
            3: "Devolvido"
        }.get(status, f"Desconhecido ({status})")

    pdf = PDFRelatorio()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=11)

    grupos = {
        1: "Livros Reservados",
        2: "Livros Emprestados",
        3: "Livros Devolvidos"
    }

    for status_grupo in [1, 2, 3]:
        emprestimos_filtrados = [e for e in emprestimos if e[4] == status_grupo]
        if not emprestimos_filtrados:
            continue

        # Título da seção
        pdf.set_font("Arial", 'B', 13)
        pdf.set_fill_color(200, 220, 255)
        pdf.cell(0, 10, grupos[status_grupo], ln=True, fill=True)
        pdf.ln(2)

        for e in emprestimos_filtrados:
            id_emp, titulo, nome, email, status, data_emp, data_dev, data_devolvida = e

            pdf.set_fill_color(245, 245, 245)
            pdf.set_draw_color(180, 180, 180)

            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 10, f"Empréstimo Nº {id_emp}", ln=True, fill=True, border=1)

            pdf.set_font("Arial", '', 11)
            pdf.cell(0, 8, f"Livro: {safe_str(titulo)}", ln=True, fill=True, border=1)
            pdf.cell(0, 8, f"Usuário: {safe_str(nome)}", ln=True, fill=True, border=1)
            pdf.cell(0, 8, f"Email: {safe_str(email)}", ln=True, fill=True, border=1)
            pdf.cell(0, 8, f"Status: {traduzir_status(status)}", ln=True, fill=True, border=1)

            # Datas
            if status == 1:
                texto_emp = "Ainda não emprestado"
                texto_dev = "Ainda não emprestado"
            elif status == 4:
                texto_emp = "Empréstimo cancelado"
                texto_dev = "Empréstimo cancelado"
            else:
                texto_emp = formatar_data(data_emp)
                texto_dev = formatar_data(data_dev)

            pdf.cell(0, 8, f"Data Empréstimo: {texto_emp}", ln=True, fill=True, border=1)
            pdf.cell(0, 8, f"Data Prevista Devolução: {texto_dev}", ln=True, fill=True, border=1)

            if data_devolvida:
                texto_devolvida = f"Data Devolvida: {formatar_data(data_devolvida)}"
            else:
                texto_devolvida = "Data Devolvida: Livro não devolvido"

            pdf.cell(0, 8, texto_devolvida, ln=True, fill=True, border=1)
            pdf.ln(6)

        pdf.ln(5)

    pdf.set_font("Arial", 'B', 12)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(0, 10, f"Total de empréstimos listados: {len(emprestimos)}", ln=True, align='C', fill=True)

    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    pdf_buffer = BytesIO(pdf_bytes)

    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name="relatorio_emprestimos.pdf",
        mimetype='application/pdf'
    )



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
def reservas_get():
    cur = con.cursor()
    cur.execute('''
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
    ''')
    emprestimos = cur.fetchall()
    emprestimos_dic = [{
        'id_emprestimo': emprestimo[0],
        'data_reserva': emprestimo[1].strftime('%d-%m-%Y') if emprestimo[1] else None,
        'data_emprestimo': emprestimo[2].strftime('%d-%m-%Y') if emprestimo[2] else None,
        'data_devolucao': emprestimo[3].strftime('%d-%m-%Y') if emprestimo[3] else None,
        'data_devolvida': emprestimo[4].strftime('%d-%m-%Y') if emprestimo[4] else None,
        'status': emprestimo[5],
        'id_usuario': emprestimo[6],
        'id_livro': emprestimo[7],
        'nome_usuario': emprestimo[8],
        'titulo_livro': emprestimo[9],
        'autor_livro': emprestimo[10]
    } for emprestimo in emprestimos]

    return jsonify(emprestimos_cadastrados=emprestimos_dic)


@app.route('/reservasusuario/<int:id_usuario>', methods=['GET'])
def reservas_get_usuario(id_usuario=None):
    cur = con.cursor()

    sql = '''
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
    '''

    # Se um id_usuario foi passado na URL, filtra a query
    if id_usuario is not None:
        sql += ' WHERE e.id_usuario = ?'
        cur.execute(sql, (id_usuario,))
    else:
        cur.execute(sql)

    emprestimos = cur.fetchall()
    emprestimos_dic = [{
        'id_emprestimo': emprestimo[0],
        'data_reserva': emprestimo[1].strftime('%d-%m-%Y') if emprestimo[1] else None,
        'data_emprestimo': emprestimo[2].strftime('%d-%m-%Y') if emprestimo[2] else None,
        'data_devolucao': emprestimo[3].strftime('%d-%m-%Y') if emprestimo[3] else None,
        'data_devolvida': emprestimo[4].strftime('%d-%m-%Y') if emprestimo[4] else None,
        'status': emprestimo[5],
        'id_usuario': emprestimo[6],
        'id_livro': emprestimo[7],
        'nome_usuario': emprestimo[8],
        'titulo_livro': emprestimo[9],
        'autor_livro': emprestimo[10]
    } for emprestimo in emprestimos]

    return jsonify(emprestimos_cadastrados=emprestimos_dic)


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
    cursor = con.cursor()

    # Verifica se a configuração de multa existe pelo ID da configuração
    cursor.execute('SELECT ID_Config FROM CONFIGMULTA WHERE ID_Config = ?', (id,))
    config_data = cursor.fetchone()

    if not config_data:
        cursor.close()
        return jsonify({'error': 'Configuração de multa não encontrada'}), 404

    data = request.get_json()
    valorfixo = data.get('valorfixo')
    acrescimo = data.get('acrescimo')
    ano = data.get('ano')

    # Verifica se o novo ano já está em uso por outra configuração
    cursor.execute('SELECT ID_Config FROM CONFIGMULTA WHERE ano = ? AND ID_Config <> ?', (ano, id))
    ano_existente = cursor.fetchone()

    if ano_existente:
        cursor.close()
        return jsonify({'error': 'O ano já está em uso em outra configuração'}), 400

    # 🔥 Verifica se já existe multa pendente para aquele ano (comparação direta com o ano inteiro)
    cursor.execute('''
        SELECT 1 
        FROM EMPRESTIMOS 
        WHERE ano = ? 
          AND status_multa = 'pendente'
        LIMIT 1
    ''', (ano,))

    multa_pendente = cursor.fetchone()

    if multa_pendente:
        cursor.close()
        return jsonify({'error': f'Não é possível editar. Já existe multa pendente para o ano {ano}.'}), 400

    # Atualiza a configuração
    cursor.execute('UPDATE CONFIGMULTA SET valorfixo = ?, acrescimo = ?, ano = ? WHERE ID_Config = ?',
                   (valorfixo, acrescimo, ano, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Configuração de multa editada com sucesso!',
        'Configuração de multa': {
            'id_config': id,
            'valorfixo': valorfixo,
            'acrescimo': acrescimo,
            'ano': ano
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
@app.route('/pesquisar', methods=['GET'])
def pesquisar_livros():
    try:
        termo = request.args.get('q')
        categoria = request.args.get('categoria')
        data_publicacao = request.args.get('data_publicacao')

        cursor = con.cursor()

        query = """
            SELECT id_livro, titulo, autor, categoria, data_publicacao, quantidade 
            FROM livros 
            WHERE 1=1
        """
        parametros = []

        if termo:
            query += " AND (LOWER(titulo) LIKE ? OR LOWER(autor) LIKE ?)"
            termo_lower = f"%{termo.lower()}%"
            parametros.extend((termo_lower, termo_lower))

        if categoria:
            query += " AND LOWER(categoria) = ?"
            parametros.append(categoria.lower())

        if data_publicacao:
            query += " AND data_publicacao = ?"
            parametros.append(data_publicacao)

        cursor.execute(query, parametros)
        livros = cursor.fetchall()
        cursor.close()

        if not livros:
            return jsonify({'mensagem': 'Nenhum livro encontrado com os filtros fornecidos.'}), 404

        livros_formatados = [{
            'id_livro': l[0],
            'titulo': l[1],
            'autor': l[2],
            'categoria': l[3],
            'data_publicacao': l[4],
            'quantidade': l[5]
        } for l in livros]

        return jsonify({
            'mensagem': 'Resultado da pesquisa',
            'livros': livros_formatados
        })

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

    # Verifica se o usuário já avaliou esse livro
    cursor.execute("""
        SELECT id FROM avaliacao WHERE id_usuario = ? AND id_livro = ?
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
