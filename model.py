import fdb

class USUARIOS:
    def __init__(self, id_usuario, nome, email, senha, telefone, data_nascimento, multa, cargo, status, tentativas_erro):
        self.id_usuario = id_usuario
        self.nome = nome
        self.email = email
        self.senha = senha
        self.telefone = telefone
        self.data_nascimento = data_nascimento
        self.multa = multa
        self.cargo = cargo
        self.status = status
        self.tentativas_erro = tentativas_erro

class LIVROS:
    def __init__(self, id_livro, titulo, autor, data_publicacao, ISBN, descricao, quantidade, categoria, status):
        self.id_livro = id_livro
        self.titulo = titulo
        self.autor = autor
        self.data_publicacao = data_publicacao
        self.ISBN = ISBN
        self.descricao = descricao
        self.quantidade = quantidade
        self.categoria = categoria
        self.status = status
