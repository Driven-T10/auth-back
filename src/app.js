import bcrypt from "bcrypt"
import cors from "cors"
import dotenv from "dotenv"
import express from "express"
import { MongoClient, ObjectId } from "mongodb"
import { v4 as uuid } from "uuid"

// Criação do App Servidor
const app = express()

// Configurações
app.use(express.json())
app.use(cors())
dotenv.config()

// Conexão com o banco de dados
const mongoClient = new MongoClient(process.env.DATABASE_URL)
await mongoClient.connect()
const db = mongoClient.db()

// Endpoints
app.post("/cadastro", async (req, res) => {
    const { nome, foto, email, senha } = req.body

    try {
        // Verificar se esse e-mail já foi cadastrado
        const usuario = await db.collection("usuarios").findOne({ email })
        if (usuario) return res.status(409).send("E-mail já cadastrado")

        // Criptografar senha
        const hash = bcrypt.hashSync(senha, 10)

        // Criar conta e guardar senha encriptada no banco
        await db.collection("usuarios").insertOne({ nome, foto, email, senha: hash })
        res.status(201).send("Conta criada com sucesso")

    } catch (err) {
        res.status(500).send(err.message)
    }
})

app.post("/login", async (req, res) => {
    const { email, senha } = req.body

    try {
        // Verificar se o e-mail está cadastrado
        const usuario = await db.collection("usuarios").findOne({ email })
        if (!usuario) return res.status(404).send("E-mail não cadastrado")

        // Verificar se a senha digitada corresponde com a criptografada
        const senhaEstaCorreta = bcrypt.compareSync(senha, usuario.senha)
        if (!senhaEstaCorreta) return res.status(401).send("Senha incorreta")

        // Se deu tudo certo, vamos criar um token para enviar ao usuário
        const token = uuid()

        // Guardaremos o token e o id do usuário para saber que ele está logado
        await db.collection("sessoes").insertOne({ idUsuario: usuario._id, token })

        // Finalizar com status de sucesso e enviar token para o cliente
        res.status(200).send(token)

    } catch (err) {
        res.status(500).send(err.message)
    }
})

app.get("/usuario-logado", async (req, res) => {
    // O cliente deve enviar um header de authorization com o token
    const { authorization } = req.headers

    // O formato é assim: Bearer TOKEN, então para pegar o token vamos tirar a palavra Bearer
    const token = authorization?.replace("Bearer ", "")

    // Se não houver token, não há autorização para continuar
    if (!token) return res.status(401).send("Token inexistente")

    try {
        // Caso o token exista, precisamos descobrir se ele é válido
        // Ou seja: se ele está na nossa collection de sessoes
        const sessao = await db.collection("sessoes").findOne({ token })
        if (!sessao) return res.status(401).send("Token inválido")

        // Caso a sessão tenha sido encontrada, irá guardar a variavel sessão duas coisas:
        // O token e o id do usuário. Tendo o id do usuário, podemos procurar seus dados
        const usuario = await db.collection("usuarios").findOne({ _id: new ObjectId(sessao.idUsuario) })

        // O usuario possui _id, nome, email e senha. Mas não podemos enviar a senha!
        delete usuario.senha

        // Agora basta enviar a resposta ao cliente
        res.send(usuario)

    } catch (err) {
        res.status(500).send(err.message)
    }
})

// Deixa o app escutando, à espera de requisições
app.listen(5000, () => console.log("Servidor rodando"))