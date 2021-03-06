const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const { User } = require("./models/User")

const config = require("./config/key")


app.use(bodyParser.urlencoded({ extended : true}));
app.use(bodyParser.json());
app.use(cookieParser());

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

app.post('/login', (req, res) => {
    
    // 1.요청된 이메일을 데이터 베이스에 있는지 찾기
    User.findOne({ email: req.body.email }, (err, user) => {
        // 조회된 user가 없는 경우
        if(!user) {
            return res.json({
                loginSuccess : false,
                message : "제공된 이메일에 해당하는 유저가 없습니다."
            })
        }
    
        // 2.요청된 이메일이 데이터 베이스에 있다면 비밀번호가 맞는지 확인
        
        user.comparePassword(req.body.password, (err, isMatch) => {
            if(!isMatch)
                return res.json({
                    loginSuccess : false,
                    message : "비밀번호가 틀렸습니다."
                })
            
            // 3.비밀번호까지 맞다면 토큰을 생성.
            user.generateToken((err, user) => {
                if(err) return res.status(400).send(err)

                // 토큰을 저장(쿠키, 로컬스토리지 등등)
                // 쿠키에 저장

                res.cookie("x_auth", user.token)
                .status(200)
                .json({
                    loginSuccess : true,
                    userId : user._id 
                    })
            })
        })
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


