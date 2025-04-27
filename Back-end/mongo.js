const mongoose=require('mongoose')
const dotenv=require('dotenv')

dotenv.config()
async function mongoConnection(){
    try{
        await mongoose.connect(process.env.MONGO_URI)
        console.log("your databas is connected")
    }
    catch(error){
        console.error("connection failed",error)
    }
}
mongoConnection()