const dbConnection = require("../db/dbConfig");
const bcrypt = require ('bcrypt')
const statusCodes =require ('http-status-codes')
const jwt = require ('jsonwebtoken')


async function register(req, res) {
  const { userid, username, firstname, lastname, email, password } = req.body;
  if (!username || !firstname || !lastname || !email || !password) {
    return res
      .status(400)
      .json({ msg: "Please provide all required information" });
  }
  // Ensure your dbConnection.query supports async/await
  try {
    const [user] = await dbConnection.query("SELECT username, email from mezgibo where username =? or email=?", [username, email])
    if(user.length>0){
      return res.status(statusCodes.BAD_REQUEST).json({msg: "User already registered"})
    }
    if(password.length<=8){
      return res.status(400).json({msg:"Password must be at least 8 characters"})
    }
  // bcrypt package to safely store encrypting user's password in our mysql database
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    await dbConnection.query(
      "INSERT INTO mezgibo (userid, username, firstname, lastname, email, password) VALUES (?,?, ?, ?, ?, ?)",
      [userid, username, firstname, lastname, email, hashedPassword]
    );
    return res.status(201).json({ msg: "User Created" });
  } catch (error) {
    console.error("Database Insertion Error:", error);
    return res
      .status(400)
      .json({ msg: "Something went wrong, try again later" });
  }
}

async function login(req, res) {
   const {email, password } = req.body;
    if (!email || !password) {
    return res
      .status(400)
      .json({ msg: "Please provide all required information" });
}
try {
   const [user] = await dbConnection.query("SELECT username, userid,password from mezgibo where email=?", [email])
    if(user.length==0){
      return res.status(statusCodes.BAD_REQUEST).json({msg: "Invalid credentials"});
    }
    const isMatch = await bcrypt.compare(password, user[0].password);
      if(!isMatch){
        return res.status(statusCodes.BAD_REQUEST).json({msg: 'Invalid credentials'})
      }
      // json webToken is further security level
      const username = user[0].username
      const userid = user[0].userid
     const token = jwt.sign({username, userid}, 'secret', {expiresIn: "1d"})

        return res.status(statusCodes.OK).json({msg:'User login successfuly', token, username})
      
} catch (error) {
  console.log(error)
   return res
      .status(400)
      .json({ msg: "Something went wrong, try again later" })
}
}

async function checkUser(req, res) {
  const username = req.user.username
  const userid = req.user.userid
    res.status(statusCodes.OK).json({msg:"Valid user", username, userid})
 
}


module.exports = { register, login, checkUser};
