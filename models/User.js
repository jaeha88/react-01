
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const saltRounds = 10

const userSchema = mongoose.Schema({
    name: {
        type : String,
        maxlength : 50,
    },
    email: {
        type : String,
        trim : true,
        unique : 1,
    },
    password: {
        type : String,
        maxlength : 5,
    },
    lastname: {
        type : String,
        maxlength : 50,
    },
    role: {
        type : Number,
        default : 0
    },
    image: String,
    token: {
        type : String,
    },
    tokenExp: {
        type : Number,
    },
})

// save 호출 전 
userSchema.pre('save', function(next) {
    
    const user = this;
    if(user.isModified('password')) {
        // 비밀번호 암호화
        bcrypt.genSalt(saltRounds, function (err, salt) {
            if(err) return next(err)
            // 암호화 시킬 데이터, 
            bcrypt.hash(user.password, salt, function(err, hash){
                if(err) return next(err)
                // 암호화된 정보를 다시 넣어준다.
                user.password = hash;
    
                next();
            });
        });
    } else {
        next();
    }
})

// 입력한 비밀번호와 DB에 저장된 비밀번호 확인
userSchema.methods.comparePassword = function (plainPassword, cb){

    // 입력한 비밀번호를 암호화 하여 DB에 있는 데이터와 비교 한다.
    bcrypt.compare(plainPassword, this.password, function(err, isMatch){
        if (err) return cb(err)
        cb(null, isMatch)
    })
}

// jsonwebtoken을 이용한 token 생성
userSchema.methods.generateToken = function (cb){

    const user = this;

    // jsonwebtoken을 이용한 token 생성
    const token = jwt.sign(user._id.toHexString(), 'secretTkoen')

    user.token = token;

    user.save(function(err, user) {
        if(err) return cb(err)
        cb(null, user)
    })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }