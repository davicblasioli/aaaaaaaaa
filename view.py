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
def email_emprestimo(email, texto):


    if not email:
        raise ValueError("Informações de sessão inválidas. Certifique-se de que 'email' e 'id_usuario' estão definidos.")


    subject = "Emprestimo realizado"
    sender = "equipe.asa.literaria@gmail.com"
    recipients = [email]  # Lista de destinatários
    password = "yjfy kwcr nazh sirp"  # Substitua pela sua senha de aplicativo

    # Enviar o e-mail
    try:
        msg = MIMEText(texto)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = ', '.join(recipients)

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


@app.route('/usuarios/<int:id>', methods=['DELETE'])
def deletar_usuarios(id):
    cursor = con.cursor()

    cursor.execute("SELECT 1 FROM USUARIOS WHERE ID_USUARIO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Usuario não encontrado"}), 404

    cursor.execute("DELETE FROM USUARIOS WHERE ID_USUARIO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuario excluido com sucesso!",
        'id_usuario': id
    })


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
    cursor.execute("SELECT SENHA, ID_USUARIO, NOME, CARGO, EMAIL, MULTA, DATA_NASCIMENTO, TELEFONE, STATUS, TENTATIVAS_ERRO FROM usuarios WHERE EMAIL = ?", (email,))
    usuario = cursor.fetchone()

    if not usuario:
        return jsonify({"error": "Usuário não encontrado"}), 404

    senha_hash = usuario[0]
    id_usuario = usuario[1]
    nome = usuario[2]
    cargo = usuario[3]
    email = usuario[4]
    multa = usuario[5]
    data_nascimento = usuario[6]
    telefone = usuario[7]
    status = usuario[8]
    tentativas_erro = usuario[9]

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
                "multa": multa,
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
    cur.execute('SELECT id_livro, titulo, autor, data_publicacao, ISBN, DESCRICAO, QUANTIDADE, CATEGORIA FROM livros WHERE ID_LIVRO =?', (id,))
    livros = cur.fetchall()

    if not livros:
        return jsonify({"error": "Nenhum livro encontrado."}), 400

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

    # Excluir o livro
    cursor.execute("DELETE FROM livros WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro excluido com sucesso!",
        'id_livro': id
    })


# ROTAS DE ADM
@app.route('/livros_relatorio', methods=['GET'])
def relatorio():
    cursor = con.cursor()
    cursor.execute("SELECT * FROM livros")
    livros = cursor.fetchall()
    cursor.close()

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Título do relatório
    pdf.set_font("Arial", style='B', size=16)
    pdf.cell(200, 10, "Relatório de Livros", ln=True, align='C')
    pdf.ln(5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())  # Linha abaixo do título
    pdf.ln(5)

    # Define a fonte para o conteúdo
    pdf.set_font("Arial", size=12)

    # Loop para adicionar cada livro em formato de lista
    for livro in livros:
        pdf.set_font("Arial", style='B', size=12)
        pdf.cell(0, 10, f"Livro ID: {livro[0]}", ln=True)

        pdf.set_font("Arial", size=10)
        pdf.cell(0, 10, f"Livro ID: {livro[0]}", ln=True)
        pdf.multi_cell(0, 7, f"Título: {livro[1]}")
        pdf.multi_cell(0, 7, f"Autor: {livro[2]}")
        pdf.multi_cell(0, 7, f"Publicação: {livro[3]}")
        pdf.multi_cell(0, 7, f"ISBN: {livro[4]}")
        pdf.multi_cell(0, 7, f"Descrição: {livro[5]}")
        pdf.multi_cell(0, 7, f"Quantidade: {livro[6]}")
        pdf.multi_cell(0, 7, f"Categoria: {livro[7]}")

        pdf.ln(5)  # Adiciona espaço entre os livros

    # Contador de livros
    pdf.ln(10)
    pdf.set_font("Arial", style='B', size=12)
    pdf.cell(200, 10, f"Total de livros cadastrados: {len(livros)}", ln=True, align='C')

    # Salva o arquivo PDF
    pdf_path = "relatorio_livros.pdf"
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

    # Formatação da data para "dia-mês-ano"
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
        texto = f"""
        Olá, {nome}! 👋
        
        Sua reserva foi registrada com sucesso! 📚✨
        
        📝 **Informações da Reserva:**
        • 📖 *Livro:* {titulo}
        • ✍️ *Autor:* {autor}
        • 📆 *Você tem até:* {data_reserva} para buscar seu livro
        
        Lembre-se de buscar o livro até a data informada caso contrário su reserva será cancelada! 😉
                
        Atenciosamente,  
        Equipe Asa Literária 🏛️
        """

        try:
            print(f"Enviando e-mail para: {email}")
            email_emprestimo(email, texto)
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
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
        email = payload['email']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    # 🔧 cursor só é criado após o token ser validado
    cursor = con.cursor()

    # Buscar o ID do livro vinculado ao empréstimo
    cursor.execute("SELECT id_livro FROM emprestimos WHERE id_emprestimo = ?", (id_emprestimo,))
    row = cursor.fetchone()
    if not row:
        cursor.close()
        return jsonify({'mensagem': 'Empréstimo não encontrado'}), 404

    id_livro = row[0]

    # Buscar informações do livro
    cursor.execute("SELECT titulo, autor FROM livros WHERE id_livro = ?", (id_livro,))
    livro_data = cursor.fetchone()
    if not livro_data:
        cursor.close()
        return jsonify({"mensagem": "Livro não encontrado"}), 404

    titulo, autor = livro_data

    # Buscar o nome do usuário
    cursor.execute("SELECT nome FROM usuarios WHERE id_usuario = ?", (id_usuario,))
    usuario_data = cursor.fetchone()
    if not usuario_data:
        cursor.close()
        return jsonify({"mensagem": "Usuário não encontrado"}), 404

    nome = usuario_data[0]

    # Verificar se o empréstimo existe
    cursor.execute('SELECT * FROM EMPRESTIMOS WHERE ID_EMPRESTIMO = ?', (id_emprestimo,))
    livro_data = cursor.fetchone()
    if not livro_data:
        cursor.close()
        return jsonify({'error': 'O empréstimo informado não existe'}), 404

    # Atualizar empréstimo
    data_emprestimo = datetime.now().date()
    data_devolucao = (datetime.now() + timedelta(days=7)).date()
    status = 2  # Supondo que seja "em andamento"

    cursor.execute(
        'UPDATE EMPRESTIMOS SET data_emprestimo = ?, data_devolucao = ?, status = ? WHERE ID_EMPRESTIMO = ?',
        (data_emprestimo, data_devolucao, status, id_emprestimo)
    )

    data_emprestimo = datetime.now().strftime('%d/%m/%Y')
    data_devolucao = (datetime.now() + timedelta(days=7)).strftime('%d/%m/%Y')

    # Mensagem de e-mail personalizada
    texto = f"""
    Olá, {nome}! 👋

    Seu empréstimo foi registrado com sucesso! 📚✨

    📝 **Informações da Reserva:**
    • 📖 *Livro:* {titulo}
    • ✍️ *Autor:* {autor}
    • 📆 *Data do empréstimo:* {data_emprestimo}
    • 📆 *Data da devolução:* {data_devolucao}

    Lembre-se de devolver o livro até a data informada, caso contrário você devera pagar uma multa! 😉

    Atenciosamente,  
    Equipe Asa Literária 🏛️
    """

    try:
        print(f"Enviando e-mail para: {email}")
        email_emprestimo(email, texto)
        print("E-mail enviado com sucesso!")
    except Exception as email_error:
        print(f"Erro ao enviar e-mail: {email_error}")
        flash(f"Erro ao enviar o e-mail: {str(email_error)}", "error")

    con.commit()
    cursor.close()

    return jsonify({
        'message': 'Empréstimo atualizado com sucesso!',
        'livro': {
            'data_emprestimo': data_emprestimo,
            'data_devolucao': data_devolucao,
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


@app.route('/devolucao/<int:id_emprestimo>', methods=['POST'])
def devolucao(id_emprestimo):
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

    # Buscar o empréstimo para obter o ID do livro
    cursor.execute("SELECT id_livro FROM emprestimos WHERE id_emprestimo = ? AND id_usuario = ?",
                   (id_emprestimo, id_usuario))
    emprestimo_data = cursor.fetchone()

    if not emprestimo_data:
        cursor.close()
        return jsonify({"mensagem": "Empréstimo não encontrado ou não pertence ao usuário."}), 404

    id_livro = emprestimo_data[0]

    try:
        # Excluir o registro do empréstimo
        cursor.execute("DELETE FROM emprestimos WHERE id_emprestimo = ?", (id_emprestimo,))

        # Atualizar a quantidade do livro
        cursor.execute("UPDATE livros SET QUANTIDADE = QUANTIDADE + 1 WHERE ID_LIVRO = ?", (id_livro,))
        con.commit()

    except Exception as e:
        return jsonify({"mensagem": f"Erro ao processar a devolução: {str(e)}"}), 500
    finally:
        cursor.close()

    return jsonify({"mensagem": "Devolução realizada com sucesso!"}), 200