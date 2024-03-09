require('dotenv').config();

const express = require("express");
const mongoose = require('mongoose');
const bycrypt = require("bcrypt");
const jwt = require('jsonwebtoken');



const app = express();

//Config JSON response
app.use(express.json());;

// Models
const User = require('./src/Models/UserModel');

//main
app.get('/', (req, res) => {
    res.status(200).json({msg:'Bem-vindo a API.'})
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1]; 

    if (!token) {
        return res.status(401).json({msg:"Acesso negado!"});
    }
    
    try {
        const secret = process.env.SECRET;
        console.log(secret)
        console.log(token)
        jwt.verify(token, secret)
        next()
    } catch (err) {
        console.error("Erro ao verificar token:", err);
        return res.status(400).json({msg: "Token inválido!"});
    }
}

// Private Token
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;

    // check if user exists
    const user = await User.findOne(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: "the user was not found" });
    }

    res.status(200).json({user})
})

// Register User
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmpass } = req.body;


    // validation
    if (!name) {
        return res.status(422).json({msg:"O nome é obrigatório!"})
    }
    if (!email) {
        return res.status(422).json({msg:"O email é obrigatório!"})
    }
    if (!password) {
        return res.status(422).json({msg:"A senha é obrigatória!"})
    }
    
    if (password !== confirmpass) {
        return res.status(422).json({msg:"As senhas não coincidem"})
    }

    // check if user exists
    const userExists = await User.findOne({ email: email });
    if (userExists) {
        return res.status(422).json({msg:"Usuário já existe"});
    }

    // creat password
    const salt = await bycrypt.genSalt(12);
    const passwordHash = await bycrypt.hash(password, salt);

    //create user
    const user = new User({
        name, 
        email,
        password: passwordHash
    })

    try {
        user.save()

        res.status(200).json({msg:"Cadastro bem sucedido!"})
    } catch(err) {
        res.status(500).json({msg:"Error"})
    }
})

// Login
app.post("/auth/login", async () => {
    const { email, password } = req.body;

    // Validacao
    if (!email) {
        return res.status(422).json({msg:"O email é obrigatório!"})
    }
    if (!password) {
        return res.status(422).json({msg:"A senha é obrigatória!"})
    }

    // check if user exists
    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(404).json({msg:"Usuário já existe ou não foi encontrado"});
    }
    const checkPassword = bycrypt.compare(password, user.password)
    if (!checkPassword) {
        return res.status(422).json({msg: "Password incorrect!"})
    }

    try {
        const secret = process.env.SECRET;

        const token = jwt.sign({ id: user._id }, secret);

        res.status(200).json({msg:"Autenticação feita com sucesso", token})

    } catch (err) {
        res.status(500).json({msg:"Error"})
    }
})

// Credencials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS


mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@clusterdb.a0ocqpo.mongodb.net/`).then(() => {
    app.listen(3001,
        console.log("Servidor está rodando em http://localhost:3001/")
        );
        console.log("Conexão bem sucedida DB!")
}).catch(err => console.log(err) )



