

import dotenv from 'dotenv'

import express, { json } from "express"
import mongoose, { connect } from "mongoose"
import bcrypt from "bcrypt"
import jwt from 'jsonwebtoken'
import User from './models/User.js'

dotenv.config();
const App = express()
//CONfig json express
App.use(express.json())
// Rota publica 
App.get('/',(req,res)=>{
    res.status(200).json({msg:"Servidor rodando"})
})

//CHekar token
function chekToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg:"Acesso negado"});

    }

    try{
        const secret = process.env.SECRET

        jwt
    }catch(err){
        res.status(400).json({msg:"Token Invalido"})
    }
}
//Privete Router
App.get('/user/:id',chekToken, async(req,res) =>{
    
    const id =  req.params.id;

    //Check se o user existe
    const user = await User.findById(id,'-password')
    if(!user){
        return res.status(404).json({msg:"Usuario não encontrado"})
    }
    res.status(200).json({user});
})

//Register User
App.post('/auth/register',async(req,res)=>{

    if(req.body == undefined){
        return res.status(422).json({msg:"Dados não enviados"})
    }

    const {name,email,password,confirmpassword}= req.body
   
    if(!name){
        return res.status(422).json({msg:"O nome é obrigatorio !"})
    }

    if(!email){
        return res.status(422).json({msg:"O email é obrigatorio !"})
    }

    if(!password){
        return res.status(422).json({msg:"A Senha é obrigatorio !"})
    }

    if(password !== confirmpassword){
        return res.status(422).json({mgs:"As senhas não são iguais"})
    }


    //Chekar se o usuario já não existe
    const userExists = await User.findOne({email:email});

    if(userExists){
        return res.status(422).json({msg:"Email já utilizado"})
    }

    //Create Password
    const salt = await bcrypt.genSalt(12);
    const passWordHash = await bcrypt.hash(password,salt);


    //Criar User

    const user = new User({
        name,
        email,
        password: passWordHash,
    })


    try{

        await user.save()

        res.status(201).json({msg:'Usuario criado com sucesso'})

    }catch(error){
        console.log(erro)
        return res.status(500).json({mgs:"aconteceu um erro"})
    }

})

//Login

App.post('/auth/login', async(req,res) =>{
    if(req.body == undefined){
        return res.status(422).json({msg:"Dados não enviados"})
    }

    const {email,password} = req.body

    //validação

    if(!email){
        return res.status(422).json({msg:"O email é obrigatorio !"})
    }

    if(!password){
        return res.status(422).json({msg:"A Senha é obrigatorio !"})
    }

    //Checar se o usuario existe
    const user = await User.findOne({email:email});

    if(!user){
        return res.status(404).json({msg:"Usuario Não encontrado"})
    }


    //checar a senha do usuario 
    const chekPassword = await bcrypt.compare(password,user.password)

    if(!chekPassword){
        return res.status(422).json({msg:"Senha Invalida"})
    }


    try{//Token do usuario 
        const secret = process.env.SECRET
        const token = jwt.sign({
            id:user._id,

        },secret,)

        res.status(200).json({msg:"Login com sucesso",token})
    }catch(err){
        console.log(erro)
        return res.status(500).json({mgs:"aconteceu um erro"})
    }
})

const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

//Conexão
mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.kna2hrl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`).then(()=>{
    App.listen(1000)
    console.log("Conexão bem sucedidada!")
}).catch((err) =>{
    console.log(err)
})
