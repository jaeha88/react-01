const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser')
const { User } = require("./models/User")

const config = require("./config/key")

app.use(bodyParser.urlencoded({ extended : true}));
app.use(bodyParser.json());

const mongoose = require('mongoose')

mongoose.connect(config.mongoURI,{
    useNewUrlParser : true, useUnifiedTopology : true, useCreateIndex : true, useFindAndModify : false
}).then(() => console.log("MongoDB OK"))
.catch(err => console.log("MongoDB NO : " + err))

app.get('/', (req, res) => res.send('Hello world'))

app.post('/register', (req, res) =>{
    
    // 회원가입 할때 필요한 정보들을 client에서 가져오면
    // 그것들을 DB에 넣어준다.

    const user = new User(req.body)

    user.save((err, doc) => {
        if(err) return res.json({success : false, err})
        return res.status(200).json({success : true, result : doc})
    })
})

app.get('/list', (req, res) => {

    // 회원 전제 목록 조회    

    User.find((err, doc) => {
        if(err) return res.json({success : false, err})
        return res.status(200).json(doc)
    })
})


app.listen(port, () => console.log(`example app listenig on port ${port}!`))


